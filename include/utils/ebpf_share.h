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
  ebpf_prog prog;
} pid_event;

typedef struct
{
  uint32_t ebpf_arch;
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

#if defined(__aarch64__)
#define TIF_32BIT 22
#define COMPAT_ARCH(tflags)                                                   \
  (((tflags) & (1 << TIF_32BIT)) ? PROC_ARCH_ARM : PROC_ARCH_AARCH64)
#elif defined(__x86_64__)
#define TS_COMPAT 2
#define COMPAT_ARCH(status)                                                   \
  (((status) & TS_COMPAT) ? PROC_ARCH_X86 : PROC_ARCH_X64)
#endif

#define CHUNK_SIZE (4096 * sizeof(struct bpf_insn))
#define CHUNK_INSN_SIZE (CHUNK_SIZE / sizeof (struct bpf_insn))

typedef struct
{
  pid_t target_pid;
  pid_t trigger_pid;
} pid_config;

#endif
