// clang-format off
#include <linux/bpf.h>
#define _NO_VMLINUX_
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "disasm.h"
#include "capture.h"
#include "ebpf/capture.skel.h"
#include "ebpf/capture_pid.skel.h"
#include "utils/ebpf_share.h"
#include "lexical/token.h"
#include "main.h"
#include "utils/logger.h"
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
// clang-format on

typedef struct
{
  FILE *fp;
  uint32_t scmp_arch;
} global_event_ctx;

typedef struct
{
  pid_event event;
  uint32_t flen;
  struct bpf_insn *ebpf_insns;
} pid_event_ctx;

static uint32_t exiting = 0;

static void
on_sig (int sig)
{
  (void)sig;
  exiting = 1;
}

static int
on_pid_events (void *ctx, void *data, unsigned long size)
{
  (void)size;
  pid_event *event = data;
  pid_event_ctx *c = ctx;
  static uint32_t insn_offset = 0;

  switch (event->status)
    {
    case CHUNK_DONE:
    case PROG_DONE:
      if (c->ebpf_insns == NULL)
        c->ebpf_insns = malloc (event->flen_total * sizeof (struct bpf_insn));
      memcpy (c->ebpf_insns + insn_offset, event->prog.filters,
              event->prog.flen * sizeof (struct bpf_insn));
      insn_offset += event->prog.flen;
      if (event->status == CHUNK_DONE)
        break;

      c->flen = event->flen_total;
      // do some disasm here
    case PROG_ABORTED:
      if (event->status == PROG_ABORTED)
        warn ("%s",
              "one seccomp filter dump is aborted by ebpf program for unknown "
              "reasons");
      // reset everything
      insn_offset = 0;
      free (c->ebpf_insns);
      c->ebpf_insns = NULL;
      break;
    case TRUNCATED:
    case TASK_ABORTED:;
    case ALL_DONE:
      c->event.status = event->status;
      if (event->status == TRUNCATED)
        warn ("%s", "too much seccomp filter in task->seccomp->filter->prev, "
                    "failed dump them all");
      else if (event->status == TASK_ABORTED)
        warn ("%s", "dump failed due to unknown reasons");
      break;
    default:
      assert (!"Unexpected status received from ebpf");
      break;
    }

  return 0;
}

static void
capture_pid (pid_t pid)
{
  struct capture_pid_bpf *skel;
  struct ring_buffer *rb;
  pid_event_ctx ctx = { .ebpf_insns = NULL };
  bool tmp_cond;
  uint32_t zero = 0;
  pid_config config = { .target_pid = pid, .trigger_pid = getpid () };

  IF_WARN (!(skel = capture_pid_bpf__open_and_load ()))
  return;

  IF_WARN (bpf_map_update_elem (bpf_map__fd (skel->maps.scmp_config), &zero,
                                &config, BPF_ANY))
  goto destroy_bpf;

  IF_WARN (!(rb = ring_buffer__new (bpf_map__fd (skel->maps.scmp_events),
                                    on_pid_events, &ctx, NULL)))
  goto destroy_bpf;

  IF_WARN (capture_pid_bpf__attach (skel))
  goto free_ring_buf;

  uint32_t action = SECCOMP_RET_ALLOW;
  syscall (SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action);
  while ((ctx.event.status != ALL_DONE && ctx.event.status != TRUNCATED
          && ctx.event.status != TASK_ABORTED)
         || !exiting)
    {
      if (ring_buffer__poll (rb, 1000) <= 0)
        break;
    }

free_ring_buf:
  ring_buffer__free (rb);
destroy_bpf:
  capture_pid_bpf__destroy (skel);
}

static uint32_t
trans_ebpf_arch (ebpf_arch arch, uint32_t scmp_arch)
{
  switch (arch)
    {
    case EBPF_ARCH_X86:
      return ARCH_X86;
    case EBPF_ARCH_X64:
      return ARCH_X86_64;
    case EBPF_ARCH_ARM:
      return ARCH_ARM;
    case EBPF_ARCH_AARCH64:
      return ARCH_AARCH64;
    case EBPF_ARCH_OTHERS:
      return scmp_arch;
    default:
      return scmp_arch;
    }
}

static int
on_events (void *ctx, void *data, unsigned long size)
{
  (void)size;
  global_event *event = data;
  global_event_ctx *c = ctx;
  if (event->op == SECCOMP_SET_MODE_STRICT)
    {
      info ("%d process enable strict mode", event->pid);
      return 0;
    }
  // event->op == SECCOMP_SET_MODE_FILTER
  info ("capture bpf load in %d process", event->pid);
  fprog prog = { .len = event->prog.flen, .filter = event->prog.filters };

  c->scmp_arch = trans_ebpf_arch (event->ebpf_arch, c->scmp_arch);
  print_prog (c->scmp_arch, &prog, c->fp, true, false);
  return 0;
}

void
capture (pid_t pid, uint32_t scmp_arch)
{
  signal (SIGINT, on_sig);
  signal (SIGTERM, on_sig);

  if (pid != 0)
    {
      capture_pid (pid);
      return;
    }

  struct capture_bpf *skel;
  struct ring_buffer *rb;
  global_event_ctx ctx = { .fp = stdout, .scmp_arch = scmp_arch };
  bool tmp_cond;

  IF_WARN (!(skel = capture_bpf__open_and_load ()))
  return;

  IF_WARN (!(rb = ring_buffer__new (bpf_map__fd (skel->maps.scmp_events),
                                    on_events, &ctx, NULL)));
  goto destroy_bpf;

  IF_WARN (capture_bpf__attach (skel))
  goto free_ring_buf;

  while (!exiting)
    {
      if (ring_buffer__poll (rb, -1) < 0)
        break;
    }

free_ring_buf:
  ring_buffer__free (rb);
destroy_bpf:
  capture_bpf__destroy (skel);
}
