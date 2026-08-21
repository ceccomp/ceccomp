#include "attributes.h"
#include "config.h"
#include "utils/proc_status.h"
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/utsname.h>

#if EBPF_SUPPORT == 1
#define _NO_VMLINUX_
#include "capture.h"
#include "disasm.h"
#include "ebpf/capture.skel.h"
#include "ebpf/capture_pid.skel.h"
#include "main.h"
#include "utils/bpf_trans.h"
#include "utils/ebpf_share.h"
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

#include "utils/error.h"
#include "utils/logger.h"

#if EBPF_SUPPORT == 1
static int
libbpf_msg_dispatcher (enum libbpf_print_level level, const char *fmt,
                       va_list ap)
{
  switch (level)
    {
    case LIBBPF_WARN:
      return ceccomp_vprint (true, LV_WARN, NULL, fmt, ap);
    case LIBBPF_INFO:
      return ceccomp_vprint (true, LV_INFO, NULL, fmt, ap);
    case LIBBPF_DEBUG:
#ifdef DEBUG
      return ceccomp_vprint (true, LV_DEBUG, NULL, fmt, ap);
#else
      return 0;
#endif
    default:
      assert (!"Unexpected libbpf_print_level");
    }
}

static bool
linux_have_task_from_pid (int *restrict major, int *restrict minor)
{
  struct utsname uts;
  assert (!uname (&uts));
  char *end = NULL;
  *major = strtoul (uts.release, &end, 10);
  assert (*end == '.');
  *minor = strtoul (end + 1, &end, 10);
  return *major > 6 || (*major == 6 && *minor >= 2);
}

typedef struct
{
  FILE *fp;
  uint32_t scmp_arch;
} global_event_ctx;

typedef struct
{
  pid_event event;
  uint32_t flen;
  uint32_t scmp_arch;
  pid_t target_pid;
  struct bpf_insn *ebpf_insns;
} pid_event_ctx;

AttrConst static uint32_t
trans_ebpf_arch (ebpf_arch arch, uint32_t scmp_arch)
{
  switch (arch)
    {
#if defined(__x86_64__)
    case PROC_ARCH_X86:
      return SCMP_ARCH_X86;
    case PROC_ARCH_X64:
      return SCMP_ARCH_X86_64;
#elif defined(__aarch64__)
    case PROC_ARCH_ARM:
      return SCMP_ARCH_ARM;
    case PROC_ARCH_AARCH64:
      return SCMP_ARCH_AARCH64;
#else
    case PROC_ARCH_OTHERS:
#endif
    default:
      return scmp_arch;
    }
}

static void
do_ebpf_disasm (const pid_event_ctx *c, uint32_t default_scmp_arch)
{
#ifdef EXPORT
#include <stdio.h>
#include <sys/stat.h>
  // FOR DEBUGGING PURPOSE: directly export ebpf insn bytes
  char path[] = "XXXXXX.bin";
  int fd = mkstemps (path, 4);
  fchmod (fd, 0666);
  FILE *f = fdopen (fd, "wb");
  fwrite (c->ebpf_insns, sizeof (filter), c->flen, f);
  fclose (f);
  info ("Writing to %s", path);
#endif

  filter *cbpf_buf = malloc (c->flen * sizeof (filter));
  int32_t cbpf_len = ebpf2cbpf (c->ebpf_insns, c->flen, cbpf_buf, true);
  if (UNLIKELY (cbpf_len == -1))
    error ("%s", M_FAILED_EBPF_CONVERSION);
  fprog prog = { .len = cbpf_len, .filter = cbpf_buf };
  uint32_t scmp_arch = trans_ebpf_arch (c->event.ebpf_arch, default_scmp_arch);

  print_prog (scmp_arch, &prog, 0, stdout, true);
  free (cbpf_buf);
}

static int
on_pid_events (void *ctx, void *data, unsigned long size)
{
  (void)size;
  pid_event *event = data;
  pid_event_ctx *c = ctx;
  static uint32_t insn_offset = 0;
  static bool count_printed = false;
  if (event->status == PID_NOT_FOUND)
    error (M_PID_NOT_FOUND, c->target_pid);
  if (!count_printed)
    {
      info (M_PROCESS_HAS_FILTER_COUNT, c->target_pid, event->filter_count);
      count_printed = true;
    }

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

      c->event.ebpf_arch = event->ebpf_arch;
      c->flen = event->flen_total;
      do_ebpf_disasm (c, c->scmp_arch);
      // fall through
      // do some disasm here
    case PROG_ABORTED:
      if (event->status == PROG_ABORTED)
        warn (M_UNKNOWN_PROG_ABORTED, M_CAPTURE_PID_HELP);
      // reset everything
      insn_offset = 0;
      free (c->ebpf_insns);
      c->ebpf_insns = NULL;
      break;
    case TRUNCATED:
    case TASK_ABORTED:
    case ALL_DONE:
      c->event.status = event->status;
      if (event->status == TRUNCATED)
        warn ("%s", M_PROG_TRUNCATED);
      else if (event->status == TASK_ABORTED)
        warn (M_UNKNOWN_TASK_ABORTED, M_CAPTURE_PID_HELP);
      break;
    default:
      assert (!"Unexpected status received from ebpf");
      break;
    }

  return 0;
}

static void
capture_pid (pid_t pid, uint32_t scmp_arch)
{
  struct capture_pid_bpf *skel;
  struct ring_buffer *rb;
  pid_event_ctx ctx
      = { .ebpf_insns = NULL, .scmp_arch = scmp_arch, .target_pid = pid };
  int32_t err = 0;
  uint32_t zero = 0;
  pid_config config = { .target_pid = pid, .trigger_pid = getpid () };

  skel = capture_pid_bpf__open_and_load ();
  if (!skel)
    {
      int major, minor;
      if (have_bpf_cap () == 0)
        error ("%s", M_EBPF_NOT_CAPABLE);
      if (!linux_have_task_from_pid (&major, &minor))
        error (M_LINUX_NO_TASK_FROM_PID, major, minor);
      error (M_FAILED_OPEN_LOAD, __func__);
    }

  err = bpf_map_update_elem (bpf_map__fd (skel->maps.scmp_config), &zero,
                             &config, BPF_ANY);
  if (err == -1)
    error ("%s", M_FAILED_UPDATE_MAP);

  rb = ring_buffer__new (bpf_map__fd (skel->maps.scmp_events), on_pid_events,
                         &ctx, NULL);
  if (!rb)
    error ("%s", M_FAILED_CREATE_RINGBUF);

  err = capture_pid_bpf__attach (skel);
  if (err < 0)
    error ("%s", M_FAILED_ATTACH);

  uint32_t action = SECCOMP_RET_ALLOW;
  syscall (SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action);
  int rc;
  while ((ctx.event.status != ALL_DONE && ctx.event.status != TRUNCATED
          && ctx.event.status != TASK_ABORTED))
    if ((rc = ring_buffer__poll (rb, 3000)) <= 0)
      {
        if (rc)
          error (M_CAPTURE_POLL_ERROR, strerror (errno));
        else
          error ("%s", M_CAPTURE_POLL_FAIL);
      }

  ring_buffer__free (rb);
  capture_pid_bpf__destroy (skel);
}

static int
on_events (void *ctx, void *data, unsigned long size)
{
  (void)size;
  global_event *event = data;
  global_event_ctx *c = ctx;
  if (event->op == SECCOMP_SET_MODE_STRICT)
    {
      warn (M_FOUND_STRICT_MODE, event->pid);
      return 0;
    }
  // event->op == SECCOMP_SET_MODE_FILTER
  info (M_CAPTURE_EBPF_IN_TASK, event->pid, event->comm);
  fprog prog = { .len = event->prog.flen, .filter = event->prog.filters };

  c->scmp_arch = trans_ebpf_arch (event->ebpf_arch, c->scmp_arch);
  print_prog (c->scmp_arch, &prog, event->pid, c->fp, true);
  return 0;
}

static void
global_capture (uint32_t scmp_arch)
{
  struct capture_bpf *skel;
  struct ring_buffer *rb;
  global_event_ctx ctx = { .fp = stdout, .scmp_arch = scmp_arch };
  int32_t err;

  skel = capture_bpf__open_and_load ();
  if (!skel)
    {
      if (have_bpf_cap () == 0)
        // explicitly ignore broken /proc and enough caps
        error ("%s", M_EBPF_NOT_CAPABLE);
      error (M_FAILED_OPEN_LOAD, __func__);
    }

  rb = ring_buffer__new (bpf_map__fd (skel->maps.scmp_events), on_events, &ctx,
                         NULL);
  if (!rb)
    error ("%s", M_FAILED_CREATE_RINGBUF);

  err = capture_bpf__attach (skel);
  if (err < 0)
    error ("%s", M_FAILED_ATTACH);

  while (ring_buffer__poll (rb, -1) >= 0)
    ;

  ring_buffer__free (rb);
  capture_bpf__destroy (skel);
  error (M_CAPTURE_POLL_ERROR, strerror (errno));
}

void
capture (pid_t pid, uint32_t scmp_arch)
{
  libbpf_set_print (libbpf_msg_dispatcher);

  if (pid != 0)
    capture_pid (pid, scmp_arch);
  else
    global_capture (scmp_arch);
}
#else // EBPF_SUPPORT == 0
void
capture (pid_t pid, uint32_t scmp_arch)
{
  (void)pid, (void)scmp_arch;
  error ("%s", M_CAPTURE_DISABLED);
}
#endif
