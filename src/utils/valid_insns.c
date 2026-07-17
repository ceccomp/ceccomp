/* CREDIT:
 * https://elixir.bootlin.com/glibc/glibc-2.43/source/stdio-common/errname.c
 * for the method of implementing X macro strings. */
#include "utils/valid_insns.h"
#include "main.h"
#include <assert.h>
#include <linux/filter.h>
#include <stddef.h>
#include <stdint.h>

#define TOSTR1(x) str##x
#define TOSTR(x) TOSTR1 (x)

static const union insn_name_t
{
  struct
  {
// char str0[sizeof ("BPF_LD | BPF_W | BPF_ABS")];
#define X(idx, val) char TOSTR (__LINE__)[sizeof (#val)];
#include "x-macro/valid_codes.h"
#undef X
  };
  char str[];
} insn_names = { {
// "BPF_LD | BPF_W | BPF_ABS",
#define X(idx, val) #val,
#include "x-macro/valid_codes.h"
#undef X
} };

// [1] = offsetof (union insn_name_t, str0) // "BPF_LD | BPF_W | BPF_ABS"
static const uint16_t insn_name_idxs[] = {
#define X(idx, val) [idx] = offsetof (union insn_name_t, TOSTR (__LINE__)),
#include "x-macro/valid_codes.h"
#undef X
};

// [BPF_LD | BPF_W | BPF_ABS] = 1,
const uint8_t insn_name_map[] = {
#define X(idx, val) [val] = idx,
#include "x-macro/valid_codes.h"
#undef X
};

const char *
get_insn_name (int insn_code)
{
  return insn_names.str + insn_name_idxs[insn_name_map[insn_code]];
}

static_assert (ARRAY_SIZE (insn_name_map) == MAX_VALID_INSN + 1,
               "Unexpected sizeof(insn_name_map) != 173");
