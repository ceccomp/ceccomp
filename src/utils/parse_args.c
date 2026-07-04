#include "utils/parse_args.h"
#include "utils/arch_trans.h"
#include "utils/error.h"
#include "utils/logger.h"
#include <argp.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool stop_parse = false;

static uint64_t
fail_fast_strtoull (const char *restrict num, const char *restrict error_msg)
{
  char *end;
  errno = 0;
  uint64_t result = strtoull (num, &end, 0);
  if (*end != '\0' || errno)
    error ("%s", error_msg);
  return result;
}

static FILE *
fail_fast_fopen (const char *restrict filename, const char *restrict mode)
{
  if (!strcmp (filename, "-"))
    {
      if (*mode == 'r')
        return stdin;
      else
        return stdout;
    }

  FILE *fp = fopen (filename, mode);
  if (fp == NULL)
    error (M_UNABLE_OPEN_FILE, filename, strerror (errno));
  fcntl (fileno (fp), F_SETFD, FD_CLOEXEC);
  return fp;
}

static uint32_t
fail_fast_resolve_arch (const char *archname)
{
  uint32_t arch = str_to_scmp_arch (archname, true);
  if (arch == (uint32_t)-1)
    error (M_UNSUPPORTED_ARCH, archname);
  return arch;
}

static subcommand_t
parse_subcommand (const char *arg)
{
  if (!strcmp (arg, "asm"))
    return ASM_MODE;
  else if (!strcmp (arg, "disasm"))
    return DISASM_MODE;
  else if (!strcmp (arg, "emu"))
    return EMU_MODE;
  else if (!strcmp (arg, "trace") || !strcmp (arg, "dump"))
    return TRACE_MODE;
  else if (!strcmp (arg, "probe"))
    return PROBE_MODE;
  else if (!strcmp (arg, "version"))
    return VERSION_MODE;
  else if (!strcmp (arg, "help"))
    return HELP_MODE;
  else
    return HELP_ABNORMAL;
}

static color_mode_t
parse_color_mode (const char *arg)
{
  if (!strcmp (arg, "always"))
    return ALWAYS;
  else if (!strcmp (arg, "auto"))
    return AUTO;
  else if (!strcmp (arg, "never"))
    return NEVER;
  else
    error ("%s: %s", M_INVALID_COLOR_MODE, arg);
}

static print_mode_t
parse_print_mode (const char *arg)
{
  if (!strcmp (arg, "hexfmt"))
    return HEXFMT;
  else if (!strcmp (arg, "hexline"))
    return HEXLINE;
  else if (!strcmp (arg, "raw"))
    return RAW;
  else if (!strcmp (arg, "c-macro"))
    return C_MACRO;
  else
    error ("%s: %s", M_INVALID_FMT_MODE, arg);
}

static int
parse_asm (asm_arg_t *args, int key, const char *arg, struct argp_state *state)
{
  switch (key)
    {
    case ARGP_KEY_ARG:
      if (state->arg_num == 1)
        args->text_file = fail_fast_fopen (arg, "r");
      return 0;
    case 'a':
      args->scmp_arch = fail_fast_resolve_arch (arg);
      return 0;
    case 'f':
      args->mode = parse_print_mode (arg);
      return 0;
    }

  return 0;
}

static int
parse_disasm (disasm_arg_t *args, int key, const char *arg,
              struct argp_state *state)
{
  switch (key)
    {
    case ARGP_KEY_ARG:
      if (state->arg_num == 1)
        args->raw_file = fail_fast_fopen (arg, "r");
      return 0;
    case 'a':
      args->scmp_arch = fail_fast_resolve_arch (arg);
      return 0;
    }

  return 0;
}

static int
parse_emu (emu_arg_t *args, int key, const char *arg, struct argp_state *state)
{
  switch (key)
    {
    case ARGP_KEY_ARG:
      if (state->arg_num == 1)
        args->text_file = fail_fast_fopen (arg, "r");
      else if (state->arg_num == 2)
        args->sys_name = arg;
      else if (state->arg_num >= 3 && state->arg_num <= 8)
        args->args[state->arg_num - 3]
            = fail_fast_strtoull (arg, M_INVALID_NUMBER);
      else if (state->arg_num == 9)
        args->ip = fail_fast_strtoull (arg, M_INVALID_NUMBER);
      return 0;
    case 'a':
      args->scmp_arch = fail_fast_resolve_arch (arg);
      return 0;
    case 'q':
      args->quiet = true;
      return 0;
    }

  return 0;
}

static int
parse_trace (trace_arg_t *args, int key, const char *arg,
             struct argp_state *state)
{
  switch (key)
    {
    case ARGP_KEY_ARG:
      if (state->arg_num != 1 || args->mode != UNDECIDED)
        return 0;
      args->mode = TRACE_PROG;
      args->prog_idx = state->next - 1;
      stop_parse = true;
      return 0;
    case 'p':
      if (args->mode != UNDECIDED)
        return 0;
      args->mode = TRACE_PID;
      args->pid = fail_fast_strtoull (arg, M_INVALID_NUMBER);
      return 0;
    case 'o':
      if (args->mode != UNDECIDED)
        return 0;
      args->output_file = fail_fast_fopen (arg, "w+");
      return 0;
    case 'q':
      args->quiet = true;
      return 0;
    case 's':
      args->seize = true;
      return 0;
    }

  return 0;
}

static int
parse_probe (probe_arg_t *args, int key, const char *arg,
             struct argp_state *state)
{
  switch (key)
    {
    case ARGP_KEY_ARG:
      if (state->arg_num != 1)
        return 0;
      args->prog_idx = state->next - 1;
      stop_parse = true;
      return 0;
    case 'o':
      args->output_file = fail_fast_fopen (arg, "w+");
      return 0;
    case 'q':
      args->quiet = true;
      return 0;
    }

  return 0;
}

error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  ceccomp_arg_t *args = state->input;

  if (stop_parse)
    return 0;

  switch (key)
    {
    case ARGP_KEY_ARG:
      if (state->arg_num == 0)
        args->cmd = parse_subcommand (arg);
      break;
    case 'c':
      args->when = parse_color_mode (arg);
      return 0;
    case 'h':
      if (args->cmd == HELP_ABNORMAL)
        args->cmd = HELP_MODE;
      return 0;
    case 'u':
      if (args->cmd == HELP_ABNORMAL)
        args->cmd = HELP_MODE;
      return 0;
    }

  if (args->cmd == ASM_MODE)
    return parse_asm (args->asm_arg, key, arg, state);
  else if (args->cmd == DISASM_MODE)
    return parse_disasm (args->disasm_arg, key, arg, state);
  else if (args->cmd == EMU_MODE)
    return parse_emu (args->emu_arg, key, arg, state);
  else if (args->cmd == TRACE_MODE)
    return parse_trace (args->trace_arg, key, arg, state);
  else if (args->cmd == PROBE_MODE)
    return parse_probe (args->probe_arg, key, arg, state);

  return 0;
}
