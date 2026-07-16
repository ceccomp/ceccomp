// clang-format off
#include "ebpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <libintl.h>
#include <locale.h>
#include "utils/ebpf_share.h"
// clang-format on

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
} dump_ctx;

static long
dump_chunk (uint32_t chunk_index, void *data)
{
  dump_ctx *ctx = data;
  uint32_t chunk_start_offset = chunk_index * CHUNK_INSN_SIZE;

  uint32_t insn_count = ctx->flen - chunk_start_offset;
  if (insn_count <= CHUNK_INSN_SIZE)
    ctx->status = PROG_DONE;
  else
    {
      insn_count = CHUNK_INSN_SIZE;
      ctx->status = CHUNK_DONE;
    }

  pid_event *event = bpf_ringbuf_reserve (&scmp_events, sizeof (*event), 0);
  if (event == NULL)
    return 1;

  event->status = ctx->status;
  event->prog.flen = insn_count;
  event->flen_total = ctx->flen;

  const void *insnsi = (const void *)ctx->prog
                       + bpf_core_field_offset (struct bpf_prog, insnsi)
                       + chunk_start_offset * sizeof (struct bpf_insn);
  if (bpf_core_read (event->prog.filters,
                     insn_count * sizeof (struct bpf_insn), insnsi)
      < 0)
    {
      bpf_ringbuf_discard (event, 0);
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
  pid_config *config = bpf_map_lookup_elem (&scmp_config, &zero);
  if (config == NULL
      || config->trigger_pid != (pid_t)(bpf_get_current_pid_tgid ()))
    return 0;

  struct task_struct *task = bpf_task_from_pid (config->target_pid);
  if (task == NULL)
    return 0;

  struct seccomp_filter *filter = BPF_CORE_READ (task, seccomp.filter);
  for (uint32_t prog_index = 0; filter != NULL && prog_index < 32;
       prog_index++)
    {
      struct bpf_prog *prog = BPF_CORE_READ (filter, prog);
      // This shouldn't happen, but it's necessary for ebpf loader
      if (prog == NULL)
        break;

      dump_ctx ctx = { .prog = prog, .flen = BPF_CORE_READ (prog, len) };
      uint32_t loop_times = (ctx.flen + CHUNK_INSN_SIZE - 1) / CHUNK_INSN_SIZE;
      if (bpf_loop (loop_times, dump_chunk, &ctx, 0) == 1)
        break;

      filter = BPF_CORE_READ (filter, prev);
    }
  bpf_task_release (task);

  pid_event *event = bpf_ringbuf_reserve (&scmp_events, sizeof (*event), 0);
  if (event == NULL)
    return 0;

  if (filter != NULL)
    event->status = TRUNCATED;
  else
    event->status = ALL_DONE;
  bpf_ringbuf_submit (event, 0);

  return 0;
}

char LICENSE[] SEC ("license") = "GPL";
