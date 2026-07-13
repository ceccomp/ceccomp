// clang-format off
#include "ebpf/vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"
#include "ebpf_share.h"
// clang-format on

struct
{
  __uint (type, BPF_MAP_TYPE_RINGBUF);
  __uint (max_entries, 0x20000);
} scmp_events SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_HASH);
  __uint (max_entries, 4);
  __type (key, pid_t);
  __type (value, scmp_arg);
} unverified_filter SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_ARRAY);
  __uint (max_entries, 1);
  __type (key, pid_t);
  __type (value, scmp_arg);
} tmp_buf SEC (".maps");

SEC ("fentry/seccomp_check_filter")
int
BPF_PROG (seccomp_check_filter_entry, struct sock_filter *filter,
          unsigned int flen)
{
  uint32_t pid = bpf_get_current_pid_tgid ();
  uint32_t zero = 0;
  scmp_arg *arg = bpf_map_lookup_elem (&tmp_buf, &zero);
  if (arg == NULL)
    return 0;
  arg->len = flen;
  if (flen > 4096)
    {
      bpf_printk ("flen = %d in %d pid", flen, pid);
      return 0;
    }
  bpf_core_read (arg->filters, arg->len * sizeof (struct sock_filter), filter);
  bpf_map_update_elem (&unverified_filter, &pid, arg, BPF_ANY);
  return 0;
}

#define SECCOMP_SET_MODE_STRICT 0
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_GET_ACTION_AVAIL 2
#define SECCOMP_GET_NOTIF_SIZES 3

// use 'ret == 0' to determine seccomp execute success temporaily
SEC ("fexit/do_seccomp")
int
BPF_PROG (seccomp_ret, uint32_t op, uint32_t flags, void *uargs, long ret)
{
  uint32_t pid = bpf_get_current_pid_tgid ();
  if (ret != 0)
    return 0;

  if (op == SECCOMP_GET_ACTION_AVAIL || op == SECCOMP_GET_NOTIF_SIZES)
    return 0;

  scmp_event *event
      = bpf_ringbuf_reserve (&scmp_events, sizeof (scmp_event), 0);
  if (event == NULL)
    return 0;

  if (op == SECCOMP_SET_MODE_STRICT)
    {
      event->op = SECCOMP_SET_MODE_STRICT;
      bpf_ringbuf_submit (event, 0);
      return 0;
    }

  // op must be SECCOMP_SET_MODE_FILTER
  scmp_arg *arg = bpf_map_lookup_elem (&unverified_filter, &pid);
  if (arg == NULL)
  {
    bpf_ringbuf_discard (event, 0);
    return 0;
  }
  bpf_core_read (&event->arg, sizeof (scmp_arg), arg);
  bpf_ringbuf_submit (event, 0);
  return 0;
}
