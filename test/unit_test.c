// this is for separately function testing
#include <assert.h>
#include <linux/audit.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define ARRAY_SIZE(arr) (sizeof (arr) / sizeof (arr[0]))

enum test_case
{
  TEST_TRACE = 0,
  TEST_PROBE = 1,
  TEST_SEIZE = 2,
  TEST_TRACE_PID = 3,
  TEST_FLAGS = 4,
};

static const struct sock_filter filters[] = {
  BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 7),
  BPF_STMT (BPF_LD | BPF_W | BPF_ABS, offsetof (struct seccomp_data, nr)),
  BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 3, 0),
  BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, SYS_sendfile, 3, 0),
  BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, SYS_ptrace, 4, 0),
  BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1),
  BPF_STMT (BPF_LD | BPF_W | BPF_K, SECCOMP_RET_KILL_PROCESS),
  BPF_STMT (BPF_RET | BPF_A, 0),
  BPF_STMT (BPF_ALU | BPF_DIV | BPF_X, 0),
  BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

static void
load_filter (bool tofail)
{
  prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  struct sock_fprog prog = { .len = ARRAY_SIZE (filters),
                             .filter = (struct sock_filter *)filters };

  syscall (SYS_seccomp, SECCOMP_SET_MODE_FILTER, NULL, &prog);

  // test failed loading
  if (tofail)
    syscall (SYS_seccomp, SECCOMP_SET_MODE_FILTER, NULL, NULL);
}

static void
test_flag ()
{
  printf ("pid=%d\n", getpid ());
  prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  struct sock_fprog prog = { .len = ARRAY_SIZE (filters),
                             .filter = (struct sock_filter *)filters };

  syscall (SYS_seccomp, SECCOMP_SET_MODE_FILTER,
           SECCOMP_FILTER_FLAG_LOG | SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
}

int
main (int argc, char **argv)
{
  setvbuf (stdout, NULL, _IOLBF, 0x100);
  int choice = argc < 2 ? 0 : atoi (argv[1]);
  int efd = argc < 3 ? 0 : atoi (argv[2]);
  uint64_t sem;

  switch (choice)
    {
    case TEST_TRACE:
      load_filter (true);
      break;
    case TEST_SEIZE:
      prctl (PR_SET_PTRACER, PR_SET_PTRACER_ANY);
      pid_t pid = getpid ();
      printf ("pid=%d\n", pid);

      assert (efd != 0);
      assert (read (efd, &sem, 8) == 8);
      pid = fork ();
      if (pid)
        {
          waitpid (pid, NULL, 0);
          exit (0);
        }
      // child
      load_filter (false);
      printf ("child=%d\n", getpid ());
      assert (read (efd, &sem, 8) == 8);
      break;
    case TEST_PROBE:
      pid = fork ();
      if (pid != 0)
        {
          wait (NULL);
          exit (0);
        }
      else
        {
          pid = fork ();
          if (pid != 0)
            exit (0);
          // grandchild process
          pid = getpid ();
          printf ("pid=%d\n", pid);

          load_filter (false);

          signal (SIGINT, SIG_IGN);
          sleep (100);
        }
      break;
    case TEST_TRACE_PID:
      load_filter (false);
      printf ("pid=%d\n", getpid ());
      assert (efd != 0);
      assert (read (efd, &sem, 8) == 8);
      break;
    case TEST_FLAGS:
      test_flag ();
      break;
    default:
      load_filter (true);
      break;
    }
  return 0;
}
