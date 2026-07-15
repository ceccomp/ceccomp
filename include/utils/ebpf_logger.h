#ifndef EBPF_LOGGER_H
#define EBPF_LOGGER_H

#define ebpf_log_return(fmt, ...)                                             \
  {                                                                           \
    bpf_printk (fmt, __VA_ARGS__);                                            \
    return 0;                                                                 \
  }

#endif
