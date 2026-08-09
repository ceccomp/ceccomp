#include "probe.h"
#include "emu.h"
#include "lexical/parser.h"
#include "lexical/scanner.h"
#include "main.h"
#include "resolver/resolver.h"
#include "trace.h"
#include "utils/error.h"
#include "utils/logger.h"
#include "utils/parse_args.h"
#include "utils/read_source.h"
#include "utils/vector.h"
#include <fcntl.h>
#include <linux/bpf_common.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *to_test_list[]
    = { "open", "openat",   "read",     "write",  "execve", "execveat",
        "mmap", "mprotect", "sendfile", "ptrace", "fork" };

static uint32_t
fetch_text_from_trace (FILE **text, char *const argv[], bool quiet)
{
  *text = tmpfile ();
  if (*text == NULL)
    error (M_REQUEST_TMPFILE_FAILED, strerror (errno));
  fcntl (fileno (*text), F_SETFD, FD_CLOEXEC);
  uint32_t scmp_arch = program_trace (argv, *text, quiet, true);
  fflush (*text);
  fseek (*text, 0, SEEK_SET);
  return scmp_arch;
}

static void
init_emu_arg (emu_arg_t *emu_arg, FILE *text, uint32_t scmp_arch)
{
  for (uint32_t i = 0; i < 6; i++)
    emu_arg->args[i] = 0;
  emu_arg->quiet = true;
  emu_arg->text_file = text;
  emu_arg->scmp_arch = scmp_arch;
  emu_arg->ip = 0;
}

void
probe (char *const argv[], FILE *output_fp, bool quiet)
{
  FILE *text;
  emu_arg_t emu_arg;
  uint32_t scmp_arch;

  scmp_arch = fetch_text_from_trace (&text, argv, quiet);
  init_emu_arg (&emu_arg, text, scmp_arch);

  vector_t text_v;
  vector_t code_ptr_v;

  size_t lines = init_source (text) + 1;
  init_scanner (next_line ());
  init_parser (scmp_arch);
  init_table ();

  init_vector (&text_v, sizeof (statement_t), lines);
  init_vector (&code_ptr_v, sizeof (statement_t *),
               MIN (lines, BPF_MAXINSNS + 1));
  parser (&text_v, &code_ptr_v);
  if (resolver (&code_ptr_v))
    error ("%s", M_PROBE_TERMINATED);
  // if ERROR_LINE exists, then exits

  for (size_t i = 0; i < ARRAY_SIZE (to_test_list); i++)
    {
      fprintf (output_fp, "%-10s-> ", to_test_list[i]);
      emu_arg.sys_name = to_test_list[i];
      emulate_v (&text_v, &code_ptr_v, &emu_arg, output_fp);
    }

  free_table ();
  free_source ();
  free_vector (&text_v);
  free_vector (&code_ptr_v);
  fclose (text);
}
