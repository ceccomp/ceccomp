// clang-format off
#include "ebpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "utils/ebpf_share.h"
// clang-format on

struct
{
  __uint (type, BPF_MAP_TYPE_RINGBUF);
  __uint (max_entries, 0x400000);
} seccomp_ebpf_events SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_ARRAY);
  __uint (max_entries, 1);
  __type (key, uint32_t);
  __type (value, pid_config);
} seccomp_ebpf_config_map SEC (".maps");

typedef struct
{
  bool missing;
  bool completed;
  struct bpf_prog *prog;
  uint32_t insn_len;
} dump_ctx;

static long
dump_chunk (uint32_t chunk_index, void *data)
{
  dump_ctx *ctx = data;
  uint32_t chunk_start_offset = chunk_index * CHUNK_INSN_SIZE;

  uint32_t insn_count = ctx->insn_len - chunk_start_offset;
  if (insn_count > CHUNK_INSN_SIZE)
    insn_count = CHUNK_INSN_SIZE;

  pid_event *event
      = bpf_ringbuf_reserve (&seccomp_ebpf_events, sizeof (*event), 0);
  if (event == NULL)
    return 1;

  event->prog.flen = ctx->insn_len;
  event->completed = ctx->completed;
  event->missing = ctx->missing;

  const void *insnsi = (const void *)ctx->prog
                       + bpf_core_field_offset (struct bpf_prog, insnsi)
                       + chunk_start_offset * sizeof (struct bpf_insn);
  if (bpf_core_read (event->prog.filters, insn_count * sizeof (struct bpf_insn),
                     insnsi)
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
  pid_config *config = bpf_map_lookup_elem (&seccomp_ebpf_config_map, &zero);
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
      if (prog != NULL)
        {
          dump_ctx ctx = { .completed = false,
                           .prog = prog,
                           .insn_len = BPF_CORE_READ (prog, len) };
          uint32_t loop_times
              = (ctx.insn_len + CHUNK_INSN_SIZE - 1) / CHUNK_INSN_SIZE;
          bpf_loop (loop_times, dump_chunk, &ctx, 0);
        }

      filter = BPF_CORE_READ (filter, prev);
    }

  dump_ctx last_ctx = { .completed = true };
  if (filter != NULL)
    last_ctx.missing = true;
  dump_chunk (0, &last_ctx);

  bpf_task_release (task);
  return 0;
}

char LICENSE[] SEC ("license") = "GPL";
