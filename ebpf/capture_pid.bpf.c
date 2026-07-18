#include "ebpf/vmlinux.h"
#include "utils/ebpf_logger.h"
#include "utils/ebpf_share.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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
  uint32_t flen;
  ebpf_arch arch;
  bool failed;
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

  const void *insnsi = (const void *)ctx->prog
                       + bpf_core_field_offset (struct bpf_prog, insnsi)
                       + chunk_start_offset * sizeof (struct bpf_insn);
  EBPF_IF (bpf_core_read (event->prog.filters,
                          remaining_insns * sizeof (struct bpf_insn), insnsi)
           < 0)
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
  EBPF_IF (!(task = bpf_task_from_pid (config->target_pid)))
  return 0;

  bool failed = false;
  struct seccomp_filter *filter = NULL;
  EBPF_IF (BPF_CORE_READ_INTO (&filter, task, seccomp.filter) < 0)
  failed = true;

  ebpf_arch arch;
#ifdef __TARGET_ARCH_arm64
  unsigned long tflags;
  EBPF_IF_PID (BPF_CORE_READ_INTO (&tflags, task, thread_info.flags) < 0)
  failed = true;

  arch = (tflags & (1 << 22)) ? EBPF_ARCH_ARM : EBPF_ARCH_AARCH64;
#elif defined(__TARGET_ARCH_x86)
  uint32_t status;
  EBPF_IF (BPF_CORE_READ_INTO (&status, task, thread_info.status) < 0)
  failed = true;

  arch = (status & 2) ? EBPF_ARCH_X86 : EBPF_ARCH_X64;
#else
  arch = EBPF_ARCH_OTHERS;
#endif

  for (uint32_t prog_index = 0; !failed && filter != NULL && prog_index < 32;
       prog_index++)
    {
      struct seccomp_filter *next;
      uint32_t flen;
      struct bpf_prog *prog;

      EBPF_IF (BPF_CORE_READ_INTO (&prog, filter, prog) < 0) goto next;

      // This shouldn't happen, but it's necessary for ebpf loader
      EBPF_IF (prog == NULL) goto next;

      EBPF_IF (BPF_CORE_READ_INTO (&flen, prog, len) < 0) goto next;

      dump_ctx ctx
          = { .prog = prog, .flen = flen, .failed = false, .arch = arch };
      uint32_t loop_times = (ctx.flen + CHUNK_INSN_SIZE - 1) / CHUNK_INSN_SIZE;
      EBPF_IF (bpf_loop (loop_times, dump_chunk, &ctx, 0) < 0) goto next;

    next:
      EBPF_IF (BPF_CORE_READ_INTO (&next, filter, prev) < 0)
      {
        failed = true;
        break;
      }
      filter = next;
    }
  bpf_task_release (task);

  pid_event *event;
  EBPF_IF (!(event = bpf_ringbuf_reserve (&scmp_events, sizeof (*event), 0)))
  return 0;

  if (failed)
    event->status = TASK_ABORTED;
  else if (filter != NULL)
    event->status = TRUNCATED;
  else
    event->status = ALL_DONE;
  bpf_ringbuf_submit (event, 0);

  return 0;
}

char LICENSE[] SEC ("license") = "GPL";
