// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * This part of code are adapted from Linux kernel,
 * source files are: net/core/filter.c and kernel/seccomp.c
 *
 * Thanks to following authors and their commit time:
 *
 * 2012       Will Drewry <wad@chromium.org>
 * 2004-2005  Andrea Arcangeli <andrea@cpushare.com>
 * 2011-2014  PLUMgrid, http://plumgrid.com
 *            Jay Schulist <jschlst@samba.org>
 *            Alexei Starovoitov <ast@plumgrid.com>
 *            Daniel Borkmann <dborkman@redhat.com>
 *            Andi Kleen
 *            Kris Katterjohn
 */
#include "decoder/check_prog.h"
#include "main.h"
#include "utils/error.h"
#include "utils/logger.h"
#include "utils/valid_insns.h"
#include "utils/vector.h"
#include <assert.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint16_t *masks, mem_valid = 0;
static uint32_t fatal_count = 0;
static uint32_t error_count = 0;

typedef enum
{
  CODE_ERR,
  JT_ERR,
  JF_ERR,
  K_ERR,
  NONE,
} err_idx;

uint32_t err_len[] = {
  [CODE_ERR] = 0,
  [JT_ERR] = LITERAL_STRLEN ("CODE:0x1234 "),
  [JF_ERR] = LITERAL_STRLEN ("CODE:0x1234 JT:0x56"),
  [K_ERR] = LITERAL_STRLEN ("CODE:0x1234 JF:0x56 JT:0x78 "),
  [NONE] = LITERAL_STRLEN ("CODE:0x1234 JF:0x56 JF:0x78 K:0x9abcdef0"),
};

#define SPRINTF_CAT(...) print += sprintf (print, __VA_ARGS__)
static void
report_error (filter f, uint32_t filter_idx, err_idx idx, bool fatal,
              const char *err_msg)
{
  if (fatal)
    fatal_count++;
  else
    error_count++;

  char buf[0x400];
  char *print = buf;

  SPRINTF_CAT ("#%u: %s\n", filter_idx, err_msg);
  SPRINTF_CAT ("CODE:0x%04x JT:0x%02x JF:0x%02x K:0x%08x\n", f.code, f.jt,
               f.jf, f.k);
  if (idx == NONE)
    {
      memset (print, '~', err_len[NONE]);
      print[err_len[idx]] = '\0';
    }
  else
    {
      memset (print, ' ', err_len[idx]);
      print[err_len[idx]] = '^';
      print[err_len[idx] + 1] = '\0';
    }
  warn ("%s", buf);
}

#define REPORT(err_idx, fatal, err_msg)                                       \
  do                                                                          \
    {                                                                         \
      report_error (f, pc + 1, err_idx, fatal, err_msg);                      \
      return;                                                                 \
    }                                                                         \
  while (0)

#define FATAL true
// return true means stop check
static void
check_filter (filter *fptr, uint32_t pc, uint32_t flen)
{
  filter f = fptr[pc];
  uint16_t code = f.code;
  uint32_t k = f.k;

  if (code > MAX_VALID_INSN || !insn_name_map[code])
    REPORT (NONE, FATAL, M_INVALID_OPERATION);

  switch (code)
    {
    case BPF_LD | BPF_W | BPF_ABS:
      f.code = BPF_LDX | BPF_W | BPF_ABS;
      if (k >= sizeof (struct seccomp_data))
        REPORT (K_ERR, FATAL, M_ATTR_OFFSET_OVERFLOW);
      else if (k & 3)
        REPORT (K_ERR, FATAL, M_INVALID_ATTR_LOAD);
      return;
    case BPF_LD | BPF_W | BPF_LEN:
      f.code = BPF_LD | BPF_IMM;
      f.k = sizeof (struct seccomp_data);
      return;
    case BPF_LDX | BPF_W | BPF_LEN:
      f.code = BPF_LDX | BPF_IMM;
      f.k = sizeof (struct seccomp_data);
      return;
    case BPF_ALU | BPF_DIV | BPF_K:
      if (f.k == 0)
        REPORT (K_ERR, !FATAL, M_ALU_DIV_BY_ZERO);
      return;
    case BPF_ALU | BPF_LSH | BPF_K:
    case BPF_ALU | BPF_RSH | BPF_K:
      if (f.k >= 32)
        REPORT (K_ERR, !FATAL, M_ALU_SH_OUT_OF_RANGE);
      return;
    case BPF_LD | BPF_MEM:
    case BPF_LDX | BPF_MEM:
      if (f.k >= BPF_MEMWORDS)
        REPORT (K_ERR, !FATAL, M_MEM_IDX_OUT_OF_RANGE);
      if (!(mem_valid & (1 << fptr[pc].k)))
        REPORT (K_ERR, !FATAL, M_UNINITIALIZED_MEM);
      return;
    case BPF_ST:
    case BPF_STX:
      if (f.k >= BPF_MEMWORDS)
        REPORT (K_ERR, !FATAL, M_MEM_IDX_OUT_OF_RANGE);
      mem_valid |= (1 << fptr[pc].k);
      return;
    case BPF_JMP | BPF_JA:
      if (f.k >= (uint32_t)(flen - pc - 1))
        REPORT (K_ERR, !FATAL, M_JA_OUT_OF_FILTERS);
      masks[pc + 1 + fptr[pc].k] &= mem_valid;
      mem_valid = ~0;
      return;
    case BPF_JMP | BPF_JEQ | BPF_K:
    case BPF_JMP | BPF_JEQ | BPF_X:
    case BPF_JMP | BPF_JGE | BPF_K:
    case BPF_JMP | BPF_JGE | BPF_X:
    case BPF_JMP | BPF_JGT | BPF_K:
    case BPF_JMP | BPF_JGT | BPF_X:
    case BPF_JMP | BPF_JSET | BPF_K:
    case BPF_JMP | BPF_JSET | BPF_X:
      if (pc + f.jt + 1 >= flen)
        REPORT (JT_ERR, !FATAL, M_JT_INVALID_TAG);
      if (pc + f.jf + 1 >= flen)
        REPORT (JF_ERR, !FATAL, M_JF_INVALID_TAG);
      masks[pc + 1 + fptr[pc].jt] &= mem_valid;
      masks[pc + 1 + fptr[pc].jf] &= mem_valid;
      mem_valid = ~0;
      return;
    }
}

bool
check_prog (fprog *prog)
{
  masks = reallocate (NULL, sizeof (*masks) * prog->len);
  memset (masks, 0xff, sizeof (*masks) * prog->len);
  mem_valid = 0;

  for (uint16_t i = 0; i < prog->len; i++)
    {
      check_filter (prog->filter, i, prog->len);
      // if fatal_count > 5, stop disasm immediately
      // perhaps a wrong file?
      if (fatal_count > 5)
        goto complete;
    }

  filter last = prog->filter[prog->len - 1];
  uint16_t last_code = last.code;
  if ((last_code != (BPF_RET | BPF_A)) && (last_code != (BPF_RET | BPF_K)))
    {
      report_error (last, prog->len, NONE, !FATAL, M_MUST_END_WITH_RET);
      goto complete;
    }

complete:
  reallocate (masks, 0x0);
  // if fatal_error occurs, stop disasm
  if (fatal_count)
    error ("%s", M_DISASM_TERMINATED);

  // some error might cause mem overflow in render
  // if error_count != 0, skip render
  return (bool)error_count;
}
