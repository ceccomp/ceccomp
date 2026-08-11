#ifndef EBPF_LOGGER_H
#define EBPF_LOGGER_H

#define EBPF_STRINGIFY_IMPL(x) #x
#define EBPF_STRINGIFY(x) EBPF_STRINGIFY_IMPL (x)
#define EBPF_AT __FILE__ ":" EBPF_STRINGIFY (__LINE__) ": "

#define EBPF_IF(cond)                                                         \
  if ((tmp_cond = (cond)))                                                    \
    bpf_printk (EBPF_AT "Unexpected " #cond);                                 \
  if (tmp_cond)

#define EBPF_IF_PID(cond, pid)                                                \
  if ((tmp_cond = (cond)))                                                    \
    bpf_printk (EBPF_AT "Unexpected " #cond " in process %d", pid);           \
  if (tmp_cond)

#define EBPF_LOG_IF_PID(cond, pid)                                            \
  do                                                                          \
    {                                                                         \
      if (cond)                                                               \
        bpf_printk (EBPF_AT "Unexpected " #cond " in process %d", pid);       \
    }                                                                         \
  while (0)

#endif
