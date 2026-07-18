#ifndef EBPF_SHARE_H
#define EBPF_SHARE_H

#ifndef _NO_VMLINUX_
#include "ebpf/vmlinux.h"
#else
#include <linux/bpf.h>
#endif
#include <linux/bpf_common.h>

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
  TASK_ABORTED,
  ALL_DONE,
  TRUNCATED,
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
  EBPF_ARCH_X64,
  EBPF_ARCH_X86,
  EBPF_ARCH_ARM,
  EBPF_ARCH_AARCH64,
  EBPF_ARCH_OTHERS,
} ebpf_arch;

#define CHUNK_SIZE 4096
#define CHUNK_INSN_SIZE (CHUNK_SIZE / sizeof (struct bpf_insn))

typedef struct
{
  pid_t target_pid;
  pid_t trigger_pid;
} pid_config;

#endif
