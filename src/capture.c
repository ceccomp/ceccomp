// clang-format off
#define _NO_VMLINUX_
#include "disasm.h"
#include "capture.h"
#include "ebpf/capture.skel.h"
#include "ebpf_share.h"
#include "main.h"
#include "utils/logger.h"
#include <bpf/libbpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
// clang-format on

typedef struct
{
  FILE *fp;
  uint32_t scmp_arch;
} event_ctx;

static uint32_t exiting = 0;

static void
on_sig (int sig)
{
  (void)sig;
  exiting = 1;
}

static int
on_events (void *ctx, void *data, unsigned long size)
{
  (void)size;
  scmp_event *event = data;
  event_ctx *c = ctx;
  if (event->op == SECCOMP_SET_MODE_STRICT)
    {
      info ("%d process enable strict mode", event->pid);
      return 0;
    }
  // event->op == SECCOMP_SET_MODE_FILTER
  info ("capture bpf load in %d process", event->pid);
  fprog prog = { .len = event->arg.len, .filter = event->arg.filters };

  print_prog (c->scmp_arch, &prog, c->fp, true, false);
  return 0;
}

void
capture (uint32_t scmp_arch)
{
  struct capture_bpf *skel;
  struct ring_buffer *rb;
  event_ctx ctx = { .fp = stdout, .scmp_arch = scmp_arch };

  signal (SIGINT, on_sig);
  signal (SIGTERM, on_sig);
  skel = capture_bpf__open_and_load ();
  if (!skel)
    error ("%s", "capture_bpf__open_and_load failed");

  rb = ring_buffer__new (bpf_map__fd (skel->maps.scmp_events), on_events, &ctx,
                         NULL);
  if (!rb)
    {
      warn ("%s", "ring_buffer__new failed");
      goto destroy_bpf;
    }

  int err = capture_bpf__attach (skel);
  if (err)
    {
      warn ("%s", "capture_bpf__attach failed");
      goto free_ring_buf;
    }

  while (!exiting)
    {
      err = ring_buffer__poll (rb, -1);
      if (err < 0)
        break;
    }

free_ring_buf:
  ring_buffer__free (rb);
destroy_bpf:
  capture_bpf__destroy (skel);
}
