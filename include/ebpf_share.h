#ifndef EBPF_SHARE_H
#define EBPF_SHARE_H

typedef struct
{
  unsigned short len;
  struct sock_filter filters[4096];
} scmp_arg;

typedef struct
{
  uint32_t op;
  pid_t pid;
  scmp_arg arg;
} scmp_event;

#endif
