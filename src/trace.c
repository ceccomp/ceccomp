#include "trace.h"
#include "disasm.h"
#include "main.h"
#include "utils/error.h"
#include "utils/logger.h"
#include "utils/proc_status.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/bpf_common.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOAD_FAIL 7
#define LOAD_ELSE 8

#define SECCOMP_FLAG_LIST(X)                                                  \
  X (SECCOMP_FILTER_FLAG_TSYNC)                                               \
  X (SECCOMP_FILTER_FLAG_LOG)                                                 \
  X (SECCOMP_FILTER_FLAG_SPEC_ALLOW)                                          \
  X (SECCOMP_FILTER_FLAG_NEW_LISTENER)                                        \
  X (SECCOMP_FILTER_FLAG_TSYNC_ESRCH)                                         \
  X (SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV)

struct flag_name
{
  uint32_t bit;
  uint32_t namelen;
  const char *name;
};

#define FLAG_ENTRY(x) { x, LITERAL_STRLEN (#x), #x },

static const struct flag_name seccomp_flags[]
    = { SECCOMP_FLAG_LIST (FLAG_ENTRY) };
#undef FLAG_ENTRY
#undef SECCOMP_FLAG_LIST

#define MACRO_STR(x) #x

static uint64_t seccomp_nr;
static uint64_t prctl_nr;
static uint32_t saved_arch = -1;

static long
check_scmp_mode (syscall_info *info, int pid, long *rval)
{
  long seccomp_mode = LOAD_ELSE;
  uint64_t nr = info->entry.nr;
  uint64_t arg0 = info->entry.args[0];
  uint64_t arg1 = info->entry.args[1];

  if (nr == seccomp_nr
      && (arg0 == SECCOMP_SET_MODE_FILTER || arg0 == SECCOMP_SET_MODE_STRICT))
    seccomp_mode = arg0;
  else if (nr == prctl_nr && arg0 == PR_SET_SECCOMP)
    {
      if (arg1 == SECCOMP_MODE_STRICT)
        arg1 = SECCOMP_SET_MODE_STRICT;
      else if (arg1 == SECCOMP_MODE_FILTER)
        arg1 = SECCOMP_SET_MODE_FILTER;
      // prctl use different macros
      // transfer it to seccomp macros
      seccomp_mode = arg1;
    }
  else
    return LOAD_ELSE;
  // get seccomp_mode
  // prctl (PR_SET_SECCOMP, seccomp_mode, &prog);
  // seccomp (seccomp_mode, flags, &prog);

  syscall_info exit_info;
  ptrace (PTRACE_SYSCALL, pid, 0, 0);
  waitpid (pid, NULL, 0);
  ptrace (PTRACE_GET_SYSCALL_INFO, pid, sizeof (syscall_info), &exit_info);

  assert (exit_info.op == PTRACE_SYSCALL_INFO_EXIT);

  *rval = exit_info.exit.rval;
  if (*rval < 0)
    seccomp_mode = LOAD_FAIL;
  if (*rval > 0 && !may_be_listener_fd (pid, *rval))
    seccomp_mode = LOAD_FAIL;
  // clang-format off
  // if rval > 0, it could be SECCOMP_FILTER_FLAG_NEW_LISTENER return a
  // fd(success) or fail due to other reasons.
  // if rval < 0, seccomp failed
  // if rval == 0, seccomp succeed. seccomp set failed, nothing happened
  // clang-format on

  return seccomp_mode;
}

static size_t
peek_data_check (pid_t pid, size_t *addr)
{
  errno = 0;
  size_t result = ptrace (PTRACE_PEEKDATA, pid, addr, 0);
  if (result == (size_t)-1 && errno != 0)
    error (M_PEEKDATA_FAILED_ADR, (void *)addr);
  return result;
}

static void
dump_filter (syscall_info *info, int pid, fprog *prog)
{
  size_t *filters = (size_t *)prog->filter;
  // args2 is the prog addrs
  uint64_t args2 = info->entry.args[2];

  uint32_t offset = offsetof (fprog, filter);
  bool is_local_64 = (sizeof (void *) == 8);
  bool is_target_64 = info->arch & __AUDIT_ARCH_64BIT;

  if (UNLIKELY (is_local_64 && !is_target_64))
    offset /= 2;
  else if (UNLIKELY (!is_local_64 && is_target_64))
    error ("%s", M_CANNOT_WORK_FROM_32_TO_64);

  size_t word = peek_data_check (pid, (size_t *)(size_t)info->entry.args[2]);
  // kernel ensure prog->len is not 0
  memcpy (&prog->len, &word, sizeof (prog->len));

  if (UNLIKELY (prog->len == 0 || prog->len > BPF_MAXINSNS))
    error ("%s", M_TRACE_UNDER_ATTACK);

  word = peek_data_check (pid, (size_t *)((size_t)args2 + offset));
  size_t *filter_adr = NULL;
  if (UNLIKELY (is_local_64 && !is_target_64))
    memcpy (&filter_adr, &word, 4);
  else
    filter_adr = (size_t *)word;

  // use size_t so that it can work in both 64 and 32 bits
  for (int i = 0; i * sizeof (size_t) < prog->len * sizeof (filter); i++)
    filters[i] = peek_data_check (pid, &((size_t *)filter_adr)[i]);
}

static void
mode_filter (syscall_info *info, int pid, fprog *prog, FILE *output_fp)
{
  if (UNLIKELY (!g_filters))
    assert (init_global_filters (BPF_MAXINSNS));
  prog->filter = g_filters;

  dump_filter (info, pid, prog);
  print_prog (info->arch, prog, output_fp, true, false);
}

__attribute__ ((noreturn)) static void
child (char *argv[])
{
  ptrace (PTRACE_TRACEME, 0, 0, 0);
  raise (SIGSTOP);

  int err = execv (argv[0], argv);
  if (err)
    error ("%s %s: %s", M_EXECV_ERR, argv[0], strerror (errno));
  assert (!"exec should either succeed or fail with `error`");
}

static void
handle_fork (pid_t pid, int status, bool quiet)
{
  int event = (status >> 16) & 0xffff;
  if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK
      || event == PTRACE_EVENT_CLONE)
    {
      uint64_t new_pid;
      ptrace (PTRACE_GETEVENTMSG, pid, NULL, &new_pid);
      if (!quiet)
        info (M_PROCESS_FORK, pid, (pid_t)new_pid);
    }
}

static void
info_parse (syscall_info *info, pid_t pid)
{
  // prctl (PR_SET_SECCOMP, seccomp_mode, &prog);
  // seccomp (seccomp_mode, flags, &prog);
  uint32_t flag = info->entry.args[1];
  uint32_t nr = info->entry.nr;

  if (nr == prctl_nr)
    return info (M_PID_BPF_PRCTL, pid, MACRO_STR (SECCOMP_MODE_FILTER));

  bool not_first = false;
  char flag_buf[0x100];
  uint32_t offset = 0;
  size_t slen;
  memcpy (flag_buf, "0", sizeof ("0"));
  for (uint32_t i = 0; i < ARRAY_SIZE (seccomp_flags); i++)
    {
      if (!(seccomp_flags[i].bit & flag))
        continue;
      if (not_first)
        {
          memcpy (flag_buf + offset, " | ", 3);
          offset += 3;
          slen = seccomp_flags[i].namelen;
          memcpy (flag_buf + offset, seccomp_flags[i].name, slen + 1); // \0
          offset += slen;
        }
      else
        {
          slen = seccomp_flags[i].namelen;
          memcpy (flag_buf, seccomp_flags[i].name, slen + 1); // \0
          offset = slen;
          not_first = true;
        }
    }
  info (M_PID_BPF_SECCOMP, pid, MACRO_STR (SECCOMP_SET_MODE_FILTER), flag_buf);
}

static bool
handle_syscall (pid_t pid, FILE *output_fp, bool quiet, bool oneshot)
{
  syscall_info info;
  fprog prog;
  long seccomp_mode;
  long rval;

  ptrace (PTRACE_GET_SYSCALL_INFO, pid, sizeof (info), &info);
  if (info.op != PTRACE_SYSCALL_INFO_ENTRY)
    return false;

  if (info.arch != saved_arch)
    {
      saved_arch = info.arch;
      seccomp_nr = seccomp_syscall_resolve_name_arch (saved_arch, "seccomp");
      prctl_nr = seccomp_syscall_resolve_name_arch (saved_arch, "prctl");
      // every arch has prctl, so if prctl has no nr, seccomp has no nr, either
      if (prctl_nr == (uint64_t)__NR_SCMP_ERROR)
        error (M_TRACEE_ARCH_NOT_SUPPORTED, saved_arch);
    }

  seccomp_mode = check_scmp_mode (&info, pid, &rval);

  if (!quiet)
    {
      if (seccomp_mode == LOAD_FAIL)
        if (rval > 0)
          warn (M_PID_BPF_LOAD_FAIL, pid, M_BPF_FAIL_UNKNOWN);
        else
          warn (M_PID_BPF_LOAD_FAIL, pid, strerror (-rval));
      else if (seccomp_mode == SECCOMP_SET_MODE_FILTER)
        info_parse (&info, pid);
    }
  if (seccomp_mode == SECCOMP_SET_MODE_STRICT)
    warn (M_FOUND_STRICT_MODE, pid);
  else if (seccomp_mode == SECCOMP_SET_MODE_FILTER)
    mode_filter (&info, pid, &prog, output_fp);

  if (!oneshot || seccomp_mode == LOAD_FAIL || seccomp_mode == LOAD_ELSE
      || seccomp_mode < 0)
    return false;

  return true;
}

static uint32_t
parent (pid_t child_pid, FILE *output_fp, uint32_t extra_ptrace_flags,
        bool quiet, bool oneshot)
{
  int status;

  waitpid (child_pid, &status, 0);
  // child is stopped after PTRACE_TRACEME
  if (!quiet)
    // write info when we truly start tracing so that
    // script can continue interacting correctly
    info (M_START_TRACING, child_pid);

  // clang-format off
  ptrace (PTRACE_SETOPTIONS, child_pid, 0,
          PTRACE_O_TRACESYSGOOD
          | PTRACE_O_TRACEFORK
          | PTRACE_O_TRACEVFORK
          | PTRACE_O_TRACECLONE
          | extra_ptrace_flags);
  // clang-format on

  ptrace (PTRACE_SYSCALL, child_pid, 0, 0);
  while (1)
    {
      pid_t pid = waitpid (-1, &status, __WALL);
      if (pid == -1)
        {
          if (errno == ECHILD)
            exit (0);
          continue;
        }

      if (WIFEXITED (status) || WIFSIGNALED (status))
        {
          if (!quiet)
            info (M_PROCESS_EXIT, pid);
          continue;
        }

      if (WIFCONTINUED (status))
        continue;

      int sig = WSTOPSIG (status);
      if (sig == (SIGTRAP | 0x80))
        {
          if (handle_syscall (pid, output_fp, quiet, oneshot))
            return saved_arch;
          ptrace (PTRACE_SYSCALL, pid, 0, 0);
        }
      else if (sig == SIGTRAP)
        {
          handle_fork (pid, status, quiet);
          ptrace (PTRACE_SYSCALL, pid, 0, 0);
        }
      else
        ptrace (PTRACE_SYSCALL, pid, 0, sig);
    }
}

static void
exit_on_sig (int signo)
{
  // flush files when recved normal signals
  exit (signo);
}

uint32_t
program_trace (char *argv[], FILE *output_fp, bool quiet, bool oneshot)
{
  signal (SIGINT, exit_on_sig);
  signal (SIGTERM, exit_on_sig);
  int pid = fork ();
  if (pid == 0)
    child (argv);
  else
    return parent (pid, output_fp, PTRACE_O_EXITKILL, quiet, oneshot);
}

static void
einval_get_filter (pid_t pid)
{
  seccomp_mode mode = get_proc_seccomp (pid);
  if ((int)mode == PROCFS_ERROR)
    error ("%s %s, %s", M_PROCFS_NOT_ACCESSIBLE, ACTION_GET_FILTER,
           M_GET_FILTER_UNSUPPORTED_OR_NO_FILTER);
  if (mode == STATUS_STRICT_MODE)
    {
      warn (M_FOUND_STRICT_MODE, pid);
      exit (0);
    }
  else if (mode == STATUS_FILTER_MODE)
    error ("%s", M_GET_FILTER_UNSUPPORTED);
  // if mode == STATUS_NONE, return to print "no filters found"
}

__attribute__ ((noreturn)) static void
eacces_get_filter (pid_t pid)
{
  seccomp_mode mode = get_proc_seccomp (pid);
  if ((int)mode == PROCFS_ERROR)
    error ("%s %s, %s", M_PROCFS_NOT_ACCESSIBLE, ACTION_GET_FILTER,
           M_CAP_SYS_ADMIN_OR_IN_SECCOMP);
  if (mode == STATUS_NONE)
    error ("%s", M_REQUIRE_CAP_SYS_ADMIN);
  else
    error ("%s", M_CECCOMP_IN_SECCOMP);
}

// return true means continue
// else break
static bool
error_get_filter (pid_t pid, int err)
{
  switch (err)
    {
    case ENOENT:
      return false;
    case EINVAL:
      einval_get_filter (pid);
      return false;
    case EACCES:
      eacces_get_filter (getpid ());
    case EMEDIUMTYPE:
      warn ("%s", M_NOT_AN_CBPF);
      return true;
    default:
      error (M_UNKNOWN_GETFILTER_ERR, strerror (err));
    }
}

__attribute__ ((noreturn)) static void
eperm_seize (pid_t pid)
{
  // seizing a thread in the same thread group may cause EPERM
  // but that will probably not happen
  kthread_mode mode = is_proc_kthread (pid);
  if ((int)mode == PROCFS_ERROR)
    error ("%s %s, %s", M_PROCFS_NOT_ACCESSIBLE, ACTION_PTRACE_SEIZE,
           M_CAP_SYS_PTRACE_OR_KTHREAD);
  if (mode == STATUS_KTHREAD)
    error ("%s", M_SEIZING_KERNEL_THREAD);

  pid_t tracer = get_tracer_pid (pid);
  assert (tracer != PROCFS_ERROR);

  if (tracer)
    error (M_TARGET_TRACED_BY, tracer);
  else
    error ("%s", M_REQUIRE_CAP_SYS_PTRACE);
  // seize needs CAP_SYS_PTRACE
  // get_filter needs CAP_SYS_ADMIN
}

static void
error_seize (pid_t pid, int err)
{
  switch (err)
    {
    case EPERM:
      eperm_seize (pid);
    case ESRCH:
      error ("%s", M_SEIZE_NONEXIST_PROC);
    default:
      error (M_UNKNOWN_SEIZE_ERR, strerror (err));
    }
}

static void
pid_seize (int pid, bool quiet)
{
  signal (SIGINT, exit_on_sig);
  signal (SIGTERM, exit_on_sig);

  if (ptrace (PTRACE_ATTACH, pid, NULL, NULL) == -1)
    error_seize (pid, errno);
  parent (pid, stdout, 0, quiet, false);
}

void
pid_trace (int pid, bool seize, bool quiet)
{
  fprog prog;
  assert (init_global_filters (BPF_MAXINSNS));
  prog.filter = g_filters;
  int prog_idx = 0;

  if (seize)
    {
      pid_seize (pid, quiet);
      return;
    }

  if (ptrace (PTRACE_SEIZE, pid, 0, 0) != 0)
    error_seize (pid, errno);

  ptrace (PTRACE_INTERRUPT, pid, 0, 0);
  waitpid (pid, NULL, 0);

  syscall_info info;
  ptrace (PTRACE_GET_SYSCALL_INFO, pid, sizeof (info), &info);
  uint32_t scmp_arch = info.arch;

  while (true)
    {
      prog.len
          = ptrace (PTRACE_SECCOMP_GET_FILTER, pid, prog_idx, prog.filter);

      if (prog.len != (unsigned short)-1)
        {
          print_prog (scmp_arch, &prog, stdout, true, false);
          prog_idx++;
          continue;
        }

      if (!error_get_filter (pid, errno))
        break;
    }

  if (prog_idx == 0)
    info (M_NO_FILTER_FOUND, pid);
  ptrace (PTRACE_DETACH, pid, 0, 0);
}
