// clang-format off
#include "ebpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/bpf_common.h>
#include "ebpf_share.h"
#include "utils/ebpf_logger.h"
#include "utils/error.h"
// clang-format on

struct
{
  __uint (type, BPF_MAP_TYPE_RINGBUF);
  __uint (max_entries, 0x20000);
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
  int err = 0;
  ebpf_prog *tmp;
  EBPF_EXPECT (NULL, NULL, NULL, (tmp = bpf_map_lookup_elem (&tmp_buf, &zero)),
               pid);

  // This shouldn't happen. Just ignore this anyway
  EBPF_EXPECT (NULL, NULL, NULL, flen <= BPF_MAXINSNS, pid);

  EBPF_EXPECT (
      NULL, NULL, NULL,
      (err = bpf_map_update_elem (&unverified_filters, &pid, tmp, BPF_ANY))
          >= 0,
      pid);

  ebpf_prog *unverified;
  EBPF_EXPECT (NULL, &unverified_filters, &pid,
               (unverified = bpf_map_lookup_elem (&unverified_filters, &pid)),
               pid);

  unverified->flen = flen;
  EBPF_EXPECT (NULL, &unverified_filters, &pid,
               err = bpf_core_read (
                   unverified->filters,
                   unverified->flen * sizeof (struct sock_filter), filter),
               pid);
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
      bpf_map_delete_elem (&unverified_filters, &pid);
      return 0;
    }

  struct task_struct *task = bpf_get_current_task_btf ();
  unsigned long thread_flags = BPF_CORE_READ (task, thread_info.flags);
#ifdef __TARGET_ARCH_arm64
  event->ebpf_arch
      = (thread_flags & (1 << 22)) ? EBPF_ARCH_ARM : EBPF_ARCH_AARCH64;
#elif defined(__TARGET_ARCH_x86)
  event->ebpf_arch
      = (thread_flags & (1 << 17)) ? EBPF_ARCH_X86 : EBPF_ARCH_X64;
#else
  event->ebpf_arch = EBPF_ARCH_OTHERS;
#endif

  ebpf_prog *prog;
  EBPF_EXPECT (event, 0, 0,
               (prog = bpf_map_lookup_elem (&unverified_filters, &pid)), pid);

  int err;
  EBPF_EXPECT (
      event, &unverified_filters, &pid,
      (err = bpf_core_read (&event->prog, sizeof (ebpf_prog), prog) >= 0), pid);

  bpf_ringbuf_submit (event, 0);
  bpf_map_delete_elem (&unverified_filters, &pid);
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
  EBPF_EXPECT (
      NULL, NULL, NULL,
      (event = bpf_ringbuf_reserve (&scmp_events, sizeof (global_event), 0)),
      pid);
  event->pid = pid;
  event->op = op;
  
  if (op == SECCOMP_SET_MODE_STRICT)
    return strict_mode (ret, event);

  // op must be SECCOMP_SET_MODE_FILTER
  filter_mode (ret, pid, event);
  return 0;
}

char LICENSE[] SEC ("license") = "GPL";
