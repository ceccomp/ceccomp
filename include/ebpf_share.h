#ifndef EBPF_SHARE_H
#define EBPF_SHARE_H

#include "ebpf/vmlinux.h"
#include <linux/bpf_common.h>

typedef struct
{
  unsigned short len;
  struct sock_filter filters[BPF_MAXINSNS];
} scmp_arg;

typedef struct
{
  uint32_t op;
  pid_t pid;
  scmp_arg arg;
} scmp_event;

#endif
