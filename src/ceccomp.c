#include "asm.h"
#include "capture.h"
#include "config.h"
#include "disasm.h"
#include "emu.h"
#include "help.h"
#include "probe.h"
#include "trace.h"
#include "utils/color.h"
#include "utils/parse_args.h"
#include <assert.h>
#include <libintl.h>
#include <locale.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

static asm_arg_t asm_arg;
static disasm_arg_t disasm_arg;
static emu_arg_t emu_arg;
static probe_arg_t probe_arg;
static trace_arg_t trace_arg;
static capture_arg_t capture_arg;

static ceccomp_arg_t args = { .cmd = HELP_ABNORMAL,
                              .asm_arg = &asm_arg,
                              .disasm_arg = &disasm_arg,
                              .emu_arg = &emu_arg,
                              .probe_arg = &probe_arg,
                              .trace_arg = &trace_arg,
                              .capture_arg = &capture_arg };

static const struct argp_option options[] = {
  { "quiet", 'q', NULL, 0, NULL, 0 },
  { "color", 'c', "COLOR", 0, NULL, 0 },
  { "ebpf", 'e', NULL, 0, NULL, 0 },
  { "output", 'o', "OUTPUT", 0, NULL, 0 },
  { "arch", 'a', "ARCH", 0, NULL, 0 },
  { "pid", 'p', "PID", 0, NULL, 0 },
  { "fmt", 'f', "FMT", 0, NULL, 0 },
  { "seize", 's', NULL, 0, NULL, 0 },
  { "help", 'h', NULL, 0, NULL, 0 },
  { "usage", 'u', NULL, 0, NULL, 0 },
  { 0 },
};

static void
init_args (ceccomp_arg_t *args)
{
  const char *no_color = getenv ("NO_COLOR");
  if (no_color != NULL && no_color[0] != '\0')
    args->when = NEVER;
  else
    args->when = AUTO;
  set_color (args->when, stderr);

  uint32_t local_arch = seccomp_arch_native ();
  args->asm_arg->scmp_arch = local_arch;
  args->asm_arg->mode = HEXLINE;
  args->asm_arg->text_file = stdin;

  args->disasm_arg->scmp_arch = local_arch;
  args->disasm_arg->ebpf = false;
  args->disasm_arg->raw_file = stdin;

  args->emu_arg->scmp_arch = local_arch;
  args->emu_arg->text_file = stdin;
  for (uint32_t i = 0; i <= 5; i++)
    args->emu_arg->args[i] = 0;
  args->emu_arg->ip = 0;
  args->emu_arg->quiet = false;
  args->emu_arg->sys_name = NULL;

  args->probe_arg->output_file = stderr;
  args->probe_arg->prog_idx = 0;

  args->trace_arg->mode = UNDECIDED;
  args->trace_arg->output_file = stderr;
  args->trace_arg->pid = 0;
  args->trace_arg->prog_idx = 0;
  args->trace_arg->quiet = false;
  args->trace_arg->seize = false;

  args->capture_arg->pid = 0;
  args->capture_arg->scmp_arch = local_arch;
}

__attribute__ ((noreturn)) static void
help (int exit_code)
{
  printf ("%s", M_CECCOMP_USAGE);
  putchar ('\n');
  printf ("%s\n", ASM_HINT);
  printf ("%s\n", DISASM_HINT);
  printf ("%s\n", EMU_HINT);
  printf ("%s\n", PROBE_HINT);
  printf ("%s\n", TRACE_HINT);
  printf ("%s\n", CAPTURE_HINT);
  printf ("%s\n", HELP_HINT);
  printf ("%s\n", VERSION_HINT);

  printf ("\n%s\n", M_SUBCMD_HINT);

  printf ("\n%s\n", M_OPTION_HINT);
  exit (exit_code);
}

__attribute__ ((noreturn)) static void
version (void)
{
  printf (M_VERSION_FORMAT, CECCOMP_VERSION, CECCOMP_TAG_TIME,
          CECCOMP_BUILDER);
  exit (0);
}

int
main (int argc, char *argv[])
{
  lc_c = newlocale (LC_ALL_MASK, "C", NULL);
#ifdef LOCALEDIR
  setlocale (LC_ALL, "");
  bindtextdomain ("ceccomp", LOCALEDIR);
  textdomain ("ceccomp");
#endif

#ifdef DEBUG
  setbuf (stdin, NULL);
  setbuf (stdout, NULL);
  setbuf (stderr, NULL);
#else
  setvbuf (stderr, NULL, _IOLBF, BUFSIZ);
#endif

  init_args (&args);

  static struct argp argp
      = { options, parse_opt, NULL, NULL, NULL, NULL, NULL };
  argp_parse (&argp, argc, argv, ARGP_IN_ORDER, 0, &args);

  if (args.cmd == TRACE_MODE && trace_arg.mode == TRACE_PROG)
    set_color (args.when, trace_arg.output_file);
  else if (args.cmd == PROBE_MODE)
    set_color (args.when, probe_arg.output_file);
  else
    set_color (args.when, stdout);

  switch (args.cmd)
    {
    case ASM_MODE:
      assemble (asm_arg.text_file, asm_arg.scmp_arch, asm_arg.mode);
      break;
    case CAPTURE_MODE:
      capture (capture_arg.scmp_arch);
      break;
    case DISASM_MODE:
      disasm (disasm_arg.raw_file, disasm_arg.scmp_arch, disasm_arg.ebpf);
      break;
    case EMU_MODE:
      if (emu_arg.sys_name == NULL)
        goto incomplete_command;
      emulate (&emu_arg);
      break;
    case TRACE_MODE:
      if (trace_arg.mode == TRACE_PID)
        {
          pid_trace (trace_arg.pid, trace_arg.seize, trace_arg.quiet);
        }
      else if (trace_arg.mode == TRACE_PROG)
        {
          if (trace_arg.prog_idx == 0)
            goto incomplete_command;
          program_trace (&argv[trace_arg.prog_idx], trace_arg.output_file,
                         trace_arg.quiet, false);
        }
      else
        {
          assert (trace_arg.mode == UNDECIDED);
          goto incomplete_command;
        }
      break;
    case PROBE_MODE:
      if (probe_arg.prog_idx == 0)
        goto incomplete_command;
      probe (&argv[probe_arg.prog_idx], probe_arg.output_file,
             probe_arg.quiet);
      break;
    case HELP_MODE:
      help (0);
      break;
    case HELP_ABNORMAL:
    incomplete_command:
      help (1);
      break;
    case VERSION_MODE:
      version ();
      break;
    default:
      assert (!"unknown mode");
    }
}
