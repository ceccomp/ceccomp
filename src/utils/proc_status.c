#include "utils/proc_status.h"
#include "main.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define SECCOMP "Seccomp:"
// the sizeof simply including appending \t or space
#define SECCOMP_OFFSET (sizeof (SECCOMP))
#define KTHREAD "Kthread:"
#define KTHREAD_OFFSET (sizeof (KTHREAD))
#define TRACER_PID "TracerPid:"
#define TRACER_PID_OFFSET (sizeof (TRACER_PID))

static long
access_proc_with_key (pid_t pid, const char *comparator, size_t strsize)
{
  long value = PROCFS_ERROR;
  char buf[0x40];
  char *end;
  snprintf (buf, sizeof (buf), "/proc/%d/status", pid);

  FILE *f = fopen (buf, "r");
  if (f == NULL)
    return PROCFS_ERROR;

  while (fgets (buf, 0x40, f))
    if (STARTWITH (buf, comparator))
      {
        value = strtoull (buf + strsize, &end, 10);
        if (end == buf + strsize)
          value = PROCFS_ERROR;
        break;
      }

  fclose (f);
  return value;
}

seccomp_mode
get_proc_seccomp (pid_t pid)
{
  return access_proc_with_key (pid, SECCOMP, SECCOMP_OFFSET);
}

kthread_mode
is_proc_kthread (pid_t pid)
{
  return access_proc_with_key (pid, KTHREAD, KTHREAD_OFFSET);
}

pid_t
get_tracer_pid (pid_t pid)
{
  return access_proc_with_key (pid, TRACER_PID, TRACER_PID_OFFSET);
}

#define NOTIFY_S "anon_inode:seccomp notify"
int
may_be_listener_fd (int pid, long rax)
{
  char path[0x40];
  char buf[0x20];
  int32_t size;

  snprintf (path, sizeof (path), "/proc/%d/fd/%ld", pid, rax);
  // this should return anon_inode:seccomp notify if succeed

  size = readlink (path, buf, sizeof (buf));
  if (size < (int32_t)LITERAL_STRLEN (NOTIFY_S))
    return 0;
  return !memcmp (buf, NOTIFY_S, LITERAL_STRLEN (NOTIFY_S));
}
