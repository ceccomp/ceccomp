#ifndef EBPF_SHARE_H
#define EBPF_SHARE_H

#ifndef _NO_VMLINUX_
#include <vmlinux.h>
#else
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#endif

#ifndef BPF_MAXINSNS
#define BPF_MAXINSNS 4096
#endif

typedef struct
{
  unsigned short flen;
  struct sock_filter filters[BPF_MAXINSNS];
} ebpf_prog;

typedef enum
{
  CHUNK_DONE,
  PROG_DONE,
  PROG_ABORTED,
  TRUNCATED,
  TASK_ABORTED,
  ALL_DONE,
  PID_NOT_FOUND
} pid_event_status;

typedef struct
{
  pid_event_status status;
  uint32_t ebpf_arch;
  uint32_t flen_total;
  uint32_t filter_count;
  ebpf_prog prog;
} pid_event;

typedef struct
{
  uint32_t ebpf_arch;
  char comm[16];
  uint32_t op;
  pid_t pid;
  ebpf_prog prog;
} global_event;

typedef enum
{
  PROC_ARCH_X64,
  PROC_ARCH_X86,
  PROC_ARCH_ARM,
  PROC_ARCH_AARCH64,
  PROC_ARCH_OTHERS,
} ebpf_arch;

typedef struct
{
  pid_t target_pid;
  pid_t trigger_pid;
} pid_config;

#if defined(__aarch64__)
#define TIF_32BIT 22
#define COMPAT_ARCH(tflags)                                                   \
  (((tflags) & (1 << TIF_32BIT)) ? PROC_ARCH_ARM : PROC_ARCH_AARCH64)
#elif defined(__x86_64__)
#define TS_COMPAT 2
#define COMPAT_ARCH(status)                                                   \
  (((status) & TS_COMPAT) ? PROC_ARCH_X86 : PROC_ARCH_X64)
#endif

#define CHUNK_SIZE (4096 * sizeof (struct bpf_insn))
#define CHUNK_INSN_SIZE (CHUNK_SIZE / sizeof (struct bpf_insn))

// (flags & NEW_LISTENER) && !(flags & TSYNC)
//     ret >= 0  -> success
//     ret < 0   -> fail
//
// (flags & TSYNC) && !(flags & NEW_LISTENER)
//     ret == 0  -> success
//     ret > 0   -> fail, return TID
//     ret < 0   -> fail
//
// !(flags & TSYNC) && !(flags & NEW_LISTENER)
//     ret > 0   -> unexpected
//     ret == 0  -> success
//     ret < 0   -> fail
//
// (flags & TSYNC) && (flags & NEW_LISTENER)
//     !(flags & TSYNC_ESRCH)
//         ret >= 0 -> unexpected
//         ret < 0  -> fail
//     (flags & TSYNC_ESRCH)
//         ret >= 0 -> success, return fd
//         ret < 0  -> fail, return -errno
static bool
load_success (long ret, uint32_t flags)
{
#define SECCOMP_FILTER_FLAG_TSYNC (1UL << 0)
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH (1UL << 4)
  if (ret < 0)
    return false;

  if (ret == 0)
    return true;

  // ret > 0
  if (!(flags & SECCOMP_FILTER_FLAG_NEW_LISTENER))
    return false;

  // ret > 0 and flags & SECCOMP_FILTER_FLAG_NEW_LISTENER
  if (!(flags & SECCOMP_FILTER_FLAG_TSYNC))
    return true;

  // ret > 0 and flags & SECCOMP_FILTER_FLAG_NEW_LISTENER
  // and flags & SECCOMP_FILTER_FLAG_TSYNC
  if (flags & SECCOMP_FILTER_FLAG_TSYNC_ESRCH)
    return true;

  return false;
}

#endif
