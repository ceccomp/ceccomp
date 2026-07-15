#ifndef EBPF_LOGGER_H
#define EBPF_LOGGER_H

#define EBPF_EXPECT(event, map, obj, cond, ...)                               \
  if (!(cond))                                                                \
    {                                                                         \
      _Generic ((event),                                                      \
          scmp_event *: bpf_ringbuf_discard (event, 0),                       \
          default: 0);                                                        \
      _Generic ((obj), pid_t *: bpf_map_delete_elem (map, obj), default: 0);  \
      bpf_printk ("Unexpected !" #cond " in process %d", __VA_ARGS__);        \
      return 0;                                                               \
    }

#endif
