#include "utils/arch_trans.h"
#include "lexical/token.h"
#include <assert.h>
#include <seccomp.h>
#include <stdint.h>
#include <string.h>

static const uint32_t arch_pairs[] = {
// [ARCH_X86] = SCMP_ARCH_X86
#define X(int_arch, scmp_arch) [int_arch] = scmp_arch,
#define FALLBACK_X(int_arch) [int_arch] = -1,
#include "x-macro/arch_table.h"
#undef X
#undef FALLBACK_X
  [ARCH_I686] = SCMP_ARCH_X86,
  [ARCH_ARMV7L] = SCMP_ARCH_ARM,
  [ARCH_ARMV8L] = SCMP_ARCH_ARM,
  [ARCH_SH4] = SCMP_ARCH_SH,
};

uint32_t
internal_arch_to_scmp_arch (uint32_t internal_arch)
{
  // ARCH_X86 = 0, so (arch >= ARCH_X86) is always true;
  if (internal_arch <= ARCH_SHEB)
    return arch_pairs[internal_arch];

  return -1;
}

uint32_t
scmp_arch_to_internal_arch (uint32_t scmp_arch)
{
  switch (scmp_arch)
    {
      // case SCMP_ARCH_X86: return ARCH_X86
      // clang-format off
#define X(int_arch, _scmp_arch) case _scmp_arch: return int_arch;
#define FALLBACK_X(int_arch)
#include "x-macro/arch_table.h"
#undef X
#undef FALLBACK_X
      // clang-format on
    }

  return -1;
}

// match ending \0
#define MAYBE_MATCH_ARCH(arch, ext)                                           \
  if (!strncmp (str, token_pairs[arch].start, token_pairs[arch].len + ext))   \
    return arch;

token_type
str_to_internal_arch (const char *str, bool strict)
{
  int ext = strict ? 1 : 0;
  switch (*str)
    {
    case 'i':
      MAYBE_MATCH_ARCH (ARCH_X86, ext);
      MAYBE_MATCH_ARCH (ARCH_I686, ext);
      break;
    case 'x':
      MAYBE_MATCH_ARCH (ARCH_X86_64, ext);
      MAYBE_MATCH_ARCH (ARCH_X32, ext);
      break;
    case 'a':
      MAYBE_MATCH_ARCH (ARCH_AARCH64, ext);
      MAYBE_MATCH_ARCH (ARCH_ARMV8L, ext)
      MAYBE_MATCH_ARCH (ARCH_ARMV7L, ext)
      MAYBE_MATCH_ARCH (ARCH_ARM, ext);
      break;
    case 'l':
      MAYBE_MATCH_ARCH (ARCH_LOONGARCH64, ext);
      break;
    case 'm':
      MAYBE_MATCH_ARCH (ARCH_M68K, ext);
      MAYBE_MATCH_ARCH (ARCH_MIPSEL64N32, ext);
      MAYBE_MATCH_ARCH (ARCH_MIPSEL64, ext);
      MAYBE_MATCH_ARCH (ARCH_MIPSEL, ext);
      MAYBE_MATCH_ARCH (ARCH_MIPS64N32, ext);
      MAYBE_MATCH_ARCH (ARCH_MIPS64, ext);
      MAYBE_MATCH_ARCH (ARCH_MIPS, ext);
      break;
    case 'p':
      MAYBE_MATCH_ARCH (ARCH_PARISC64, ext);
      MAYBE_MATCH_ARCH (ARCH_PARISC, ext);
      MAYBE_MATCH_ARCH (ARCH_PPC64LE, ext);
      MAYBE_MATCH_ARCH (ARCH_PPC64, ext);
      MAYBE_MATCH_ARCH (ARCH_PPC, ext);
      break;
    case 's':
      MAYBE_MATCH_ARCH (ARCH_S390X, ext);
      MAYBE_MATCH_ARCH (ARCH_S390, ext);
      MAYBE_MATCH_ARCH (ARCH_SH4, ext);
      MAYBE_MATCH_ARCH (ARCH_SH, ext);
      MAYBE_MATCH_ARCH (ARCH_SHEB, ext);
      break;
    case 'r':
      MAYBE_MATCH_ARCH (ARCH_RISCV64, ext);
      break;
    }
  return UNKNOWN;
}

uint32_t
str_to_scmp_arch (const char *str, bool strict)
{
  token_type tk = str_to_internal_arch (str, strict);
  if (tk == UNKNOWN)
    return -1;
  return internal_arch_to_scmp_arch (tk);
}

const string_t *
scmp_arch_to_internal_str (uint32_t scmp_arch)
{
  int32_t idx = scmp_arch_to_internal_arch (scmp_arch);
  if (idx == -1)
    return NULL;
  return &token_pairs[idx];
}

const char *
scmp_arch_to_scmp_str (uint32_t scmp_arch)
{
  switch (scmp_arch)
    {
      // case SCMP_ARCH_X86: return "SCMP_ARCH_X86";
      // clang-format off
#define X(int_arch, _scmp_arch) case _scmp_arch: return #_scmp_arch;
#define FALLBACK_X(int_arch)
#include "x-macro/arch_table.h"
#undef X
#undef FALLBACK_X
      // clang-format on
    }
  assert (!"Unexpected unknown scmp_arch");
}
