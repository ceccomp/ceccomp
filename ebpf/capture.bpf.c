#include "utils/ebpf_logger.h"
#include "utils/ebpf_share.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <vmlinux.h>

struct
{
  __uint (type, BPF_MAP_TYPE_RINGBUF);
  __uint (max_entries, 0x100000);
} scmp_events SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_HASH);
  __uint (max_entries, 8);
  __type (key, pid_t);
  __type (value, ebpf_prog);
} unverified_filters SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_ARRAY);
  __uint (max_entries, 1);
  __type (key, pid_t);
  __type (value, ebpf_prog);
} tmp_buf SEC (".maps");

SEC ("fentry/seccomp_check_filter")
int
BPF_PROG (seccomp_check_filter_entry, struct sock_filter *filter,
          unsigned int flen)
{
  uint32_t pid = bpf_get_current_pid_tgid ();
  uint32_t zero = 0;
  ebpf_prog *tmp;
  bool tmp_cond;

  EBPF_IF_PID (!(tmp = bpf_map_lookup_elem (&tmp_buf, &zero)), pid)
    return 0;

  EBPF_IF_PID (bpf_map_update_elem (&unverified_filters, &pid, tmp, BPF_ANY)
                   < 0,
               pid)
    return 0;

  ebpf_prog *unverified;
  EBPF_IF_PID (!(unverified = bpf_map_lookup_elem (&unverified_filters, &pid)),
               pid)
    {
      EBPF_LOG_IF_PID (bpf_map_delete_elem (&unverified_filters, &pid) < 0,
                       pid);
      return 0;
    }

  unverified->flen = flen;

  // This shouldn't happen. Just ignore this anyway
  uint32_t read_size = (uint16_t)(flen * sizeof (struct sock_filter));
  EBPF_IF_PID (read_size > BPF_MAXINSNS * sizeof (struct sock_filter), pid)
    return 0;

  EBPF_IF_PID (bpf_core_read (unverified->filters, read_size & 0xffff, filter)
                   < 0,
               pid)
    EBPF_LOG_IF_PID (bpf_map_delete_elem (&unverified_filters, &pid) < 0, pid);

  return 0;
}

#define SECCOMP_SET_MODE_STRICT 0
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_GET_ACTION_AVAIL 2
#define SECCOMP_GET_NOTIF_SIZES 3

static inline int
strict_mode (long ret, global_event *event)
{
  if (ret != 0)
    {
      bpf_ringbuf_discard (event, 0);
      return 0;
    }
  bpf_ringbuf_submit (event, 0);
  return 0;
}

static inline int
filter_mode (long ret, pid_t pid, global_event *event)
{
  if (ret != 0)
    {
      bpf_ringbuf_discard (event, 0);
      EBPF_LOG_IF_PID (bpf_map_delete_elem (&unverified_filters, &pid) < 0,
                       pid);
      return 0;
    }

  bool tmp_cond;
#if defined(__aarch64__)
  struct task_struct *task = bpf_get_current_task_btf ();
  unsigned long tflags;
  EBPF_IF_PID (BPF_CORE_READ_INTO (&tflags, task, thread_info.flags) < 0, pid)
    {
      bpf_ringbuf_discard (event, 0);
      EBPF_LOG_IF_PID (bpf_map_delete_elem (&unverified_filters, &pid) < 0,
                       pid);
      return 0;
    }
  event->ebpf_arch = COMPAT_ARCH (tflags);
#elif defined(__x86_64__)
  struct task_struct *task = bpf_get_current_task_btf ();
  uint32_t status;
  EBPF_IF_PID (BPF_CORE_READ_INTO (&status, task, thread_info.status) < 0, pid)
    {
      bpf_ringbuf_discard (event, 0);
      EBPF_LOG_IF_PID (bpf_map_delete_elem (&unverified_filters, &pid) < 0,
                       pid);
      return 0;
    }
  event->ebpf_arch = COMPAT_ARCH (status);
#else
  event->ebpf_arch = PROC_ARCH_OTHERS;
#endif

  ebpf_prog *prog;
  EBPF_IF_PID (!(prog = bpf_map_lookup_elem (&unverified_filters, &pid)), pid)
    {
      bpf_ringbuf_discard (event, 0);
      EBPF_LOG_IF_PID (bpf_map_delete_elem (&unverified_filters, &pid) < 0,
                       pid);
      return 0;
    }

  EBPF_IF_PID (bpf_core_read (&event->prog, sizeof (ebpf_prog), prog) < 0, pid)
    {
      bpf_ringbuf_discard (event, 0);
      EBPF_LOG_IF_PID (bpf_map_delete_elem (&unverified_filters, &pid) < 0,
                       pid);
      return 0;
    }

  bpf_ringbuf_submit (event, 0);
  EBPF_LOG_IF_PID (bpf_map_delete_elem (&unverified_filters, &pid) < 0, pid);
  return 0;
}

// use 'ret == 0' to determine seccomp execute success temporaily
SEC ("fexit/do_seccomp")
int
BPF_PROG (seccomp_ret, uint32_t op, uint32_t flags, void *uargs, long ret)
{
  (void)flags;
  (void)uargs;

  uint32_t pid = bpf_get_current_pid_tgid ();
  if (op == SECCOMP_GET_ACTION_AVAIL || op == SECCOMP_GET_NOTIF_SIZES)
    return 0;

  global_event *event;
  bool tmp_cond;
  EBPF_IF_PID (!(event = bpf_ringbuf_reserve (&scmp_events,
                                              sizeof (global_event), 0)),
               pid)
    {
      EBPF_LOG_IF_PID (bpf_map_delete_elem (&unverified_filters, &pid) < 0,
                       pid);
      return 0;
    }

  event->pid = pid;
  event->op = op;

  if (op == SECCOMP_SET_MODE_STRICT)
    return strict_mode (ret, event);

  // op must be SECCOMP_SET_MODE_FILTER
  filter_mode (ret, pid, event);
  return 0;
}

char LICENSE[] SEC ("license") = "GPL";
