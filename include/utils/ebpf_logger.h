#ifndef EBPF_LOGGER_H
#define EBPF_LOGGER_H

#define EBPF_IF(cond)                                                         \
  if ((tmp_cond = (cond)))                                                    \
    bpf_printk ("Unexpected " #cond);                                         \
  if (tmp_cond)

#define EBPF_IF_PID(cond, pid)                                                \
  if ((tmp_cond = (cond)))                                                    \
    bpf_printk ("Unexpected " #cond " in process %d", pid);                   \
  if (tmp_cond)

#define EBPF_LOG_IF_PID(cond, pid)                                            \
  do                                                                          \
    {                                                                         \
      if (cond)                                                               \
        bpf_printk ("Unexpected " #cond " in process %d", pid);               \
    }                                                                         \
  while (0)

#endif
