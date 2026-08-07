#ifndef PROCSTATUS_H
#define PROCSTATUS_H

#include "config.h"
#include <sys/types.h>
#define PROCFS_ERROR -1

typedef enum
{
  STATUS_NONE = 0,
  STATUS_STRICT_MODE = 1,
  STATUS_FILTER_MODE = 2,
} seccomp_mode;

typedef enum
{
  STATUS_NOT_KTHREAD = 0,
  STATUS_KTHREAD = 1,
} kthread_mode;

extern seccomp_mode get_proc_seccomp (pid_t pid);
extern kthread_mode is_proc_kthread (pid_t pid);
extern pid_t get_tracer_pid (pid_t pid);

extern int may_be_listener_fd (int pid, long rax);

#if EBPF_SUPPORT == 1
// return -1 if failed to read /proc, return 1 if capable, 0 if not capable
extern int have_bpf_cap (void);
#endif

#endif
