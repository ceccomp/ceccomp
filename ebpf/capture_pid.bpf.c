#include "utils/ebpf_logger.h"
#include "utils/ebpf_share.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <vmlinux.h>

extern struct task_struct *bpf_task_from_pid (s32 pid) __weak __ksym;
extern void bpf_task_release (struct task_struct *p) __weak __ksym;

struct
{
  __uint (type, BPF_MAP_TYPE_RINGBUF);
  __uint (max_entries, 0x400000);
} scmp_events SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_ARRAY);
  __uint (max_entries, 1);
  __type (key, uint32_t);
  __type (value, pid_config);
} scmp_config SEC (".maps");

typedef struct
{
  pid_event_status status;
  struct bpf_prog *prog;
  uint32_t filter_count;
  uint32_t flen;
  ebpf_arch arch;
} dump_ctx;

static long
dump_chunk (uint32_t chunk_index, void *data)
{
  dump_ctx *ctx = data;
  uint32_t chunk_start_offset = chunk_index * CHUNK_INSN_SIZE;

  uint32_t remaining_insns = ctx->flen - chunk_start_offset;
  if (remaining_insns <= CHUNK_INSN_SIZE)
    ctx->status = PROG_DONE;
  else
    {
      ctx->status = CHUNK_DONE;
      remaining_insns = CHUNK_INSN_SIZE;
    }

  pid_event *event;
  bool tmp_cond;
  EBPF_IF (!(event = bpf_ringbuf_reserve (&scmp_events, sizeof (*event), 0)))
    return 1;

  event->ebpf_arch = ctx->arch;
  event->status = ctx->status;
  event->prog.flen = remaining_insns;
  event->flen_total = ctx->flen;
  event->filter_count = ctx->filter_count;

  uint16_t leftover = remaining_insns * sizeof (struct bpf_insn);

  const void *insnsi = (const void *)ctx->prog
                       + bpf_core_field_offset (struct bpf_prog, insnsi)
                       + chunk_start_offset * sizeof (struct bpf_insn);
  EBPF_IF (bpf_core_read (event->prog.filters, leftover & 0x3fff, insnsi) < 0)
    {
      event->status = PROG_ABORTED;
      bpf_ringbuf_submit (event, 0);
      return 1;
    }

  bpf_ringbuf_submit (event, 0);
  return 0;
}

SEC ("fentry/do_seccomp")
int
BPF_PROG (capture_pid, uint32_t op, uint32_t flags, void *uargs)
{
  (void)op;
  (void)flags;
  (void)uargs;

  uint32_t zero = 0;
  bool tmp_cond;
  pid_t trigger_pid = bpf_get_current_pid_tgid ();
  pid_config *config = bpf_map_lookup_elem (&scmp_config, &zero);
  EBPF_IF (config == NULL || config->trigger_pid != trigger_pid)
    return 0;

  struct task_struct *task;
  pid_event_status event_status = ALL_DONE;
  EBPF_IF (!(task = bpf_task_from_pid (config->target_pid)))
    {
      event_status = PID_NOT_FOUND;
      goto end_null;
    }

  struct seccomp_filter *filter = NULL;
  EBPF_IF (BPF_CORE_READ_INTO (&filter, task, seccomp.filter) < 0)
    {
      event_status = TASK_ABORTED;
      goto end;
    }

  uint32_t filter_count = 0;
  EBPF_IF (BPF_CORE_READ_INTO (&filter_count, task, seccomp.filter_count) < 0)
    {
      event_status = TASK_ABORTED;
      goto end;
    }

  ebpf_arch arch;
#if defined(__aarch64__)
  unsigned long tflags;
  EBPF_IF (BPF_CORE_READ_INTO (&tflags, task, thread_info.flags) < 0)
    {
      event_status = TASK_ABORTED;
      goto end;
    }

  arch = COMPAT_ARCH (tflags);
#elif defined(__x86_64__)
  uint32_t status;
  EBPF_IF (BPF_CORE_READ_INTO (&status, task, thread_info.status) < 0)
    {
      event_status = TASK_ABORTED;
      goto end;
    }

  arch = COMPAT_ARCH (status);
#else
  arch = PROC_ARCH_OTHERS;
#endif

  for (uint32_t prog_index = 0; filter != NULL && prog_index < 32;
       prog_index++)
    {
      struct seccomp_filter *next;
      uint32_t flen;
      struct bpf_prog *prog;

      EBPF_IF (BPF_CORE_READ_INTO (&prog, filter, prog) < 0)
        goto next;

      // This shouldn't happen, but it's necessary for ebpf loader
      EBPF_IF (prog == NULL)
        goto next;

      EBPF_IF (BPF_CORE_READ_INTO (&flen, prog, len) < 0)
        goto next;

      dump_ctx ctx = {
        .prog = prog, .flen = flen, .arch = arch, .filter_count = filter_count
      };
      uint32_t loop_times = (ctx.flen + CHUNK_INSN_SIZE - 1) / CHUNK_INSN_SIZE;
      EBPF_IF (bpf_loop (loop_times, dump_chunk, &ctx, 0) < 0)
        goto next;

    next:
      EBPF_IF (BPF_CORE_READ_INTO (&next, filter, prev) < 0)
        {
          event_status = TASK_ABORTED;
          break;
        }
      filter = next;
    }

end:
  bpf_task_release (task);

  pid_event *event;
end_null:
  EBPF_IF (!(event = bpf_ringbuf_reserve (&scmp_events, sizeof (*event), 0)))
    return 0;

  if (event_status == TASK_ABORTED)
    event->status = TASK_ABORTED;
  else if (event_status == PID_NOT_FOUND)
    event->status = PID_NOT_FOUND;
  else if (filter != NULL)
    event->status = TRUNCATED;
  else
    event->status = ALL_DONE;
  bpf_ringbuf_submit (event, 0);

  return 0;
}

char LICENSE[] SEC ("license") = "GPL";
