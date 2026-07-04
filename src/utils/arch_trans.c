#include "utils/arch_trans.h"
#include "lexical/token.h"
#include <assert.h>
#include <seccomp.h>
#include <stdint.h>
#include <string.h>

static const uint32_t arch_pairs[] = {
  [ARCH_X86] = SCMP_ARCH_X86,
  [ARCH_I686] = SCMP_ARCH_X86,
  [ARCH_X86_64] = SCMP_ARCH_X86_64,
  [ARCH_X32] = SCMP_ARCH_X32,
  [ARCH_AARCH64] = SCMP_ARCH_AARCH64,
  [ARCH_ARMV8L] = SCMP_ARCH_ARM,
  [ARCH_ARMV7L] = SCMP_ARCH_ARM,
  [ARCH_ARM] = SCMP_ARCH_ARM,
#if SCMP_VER_MAJOR >= 2 && SCMP_VER_MINOR >= 6
  [ARCH_LOONGARCH64] = SCMP_ARCH_LOONGARCH64,
  [ARCH_M68K] = SCMP_ARCH_M68K,
#else
  [ARCH_LOONGARCH64] = -1,
  [ARCH_M68K] = -1,
#endif
  [ARCH_MIPSEL64N32] = SCMP_ARCH_MIPSEL64N32,
  [ARCH_MIPSEL64] = SCMP_ARCH_MIPSEL64,
  [ARCH_MIPSEL] = SCMP_ARCH_MIPSEL,
  [ARCH_MIPS64N32] = SCMP_ARCH_MIPS64N32,
  [ARCH_MIPS64] = SCMP_ARCH_MIPS64,
  [ARCH_MIPS] = SCMP_ARCH_MIPS,
  [ARCH_PARISC64] = SCMP_ARCH_PARISC64,
  [ARCH_PARISC] = SCMP_ARCH_PARISC,
  [ARCH_PPC64LE] = SCMP_ARCH_PPC64LE,
  [ARCH_PPC64] = SCMP_ARCH_PPC64,
  [ARCH_PPC] = SCMP_ARCH_PPC,
  [ARCH_S390X] = SCMP_ARCH_S390X,
  [ARCH_S390] = SCMP_ARCH_S390,
  [ARCH_RISCV64] = SCMP_ARCH_RISCV64,
};

uint32_t
internal_arch_to_scmp_arch (uint32_t internal_arch)
{
  // ARCH_X86 = 0, so (arch >= ARCH_X86) is always true;
  if (internal_arch <= ARCH_RISCV64)
    return arch_pairs[internal_arch];

  return -1;
}

uint32_t
scmp_arch_to_internal_arch (uint32_t scmp_arch)
{
  switch (scmp_arch)
    {
      // clang-format off
    case SCMP_ARCH_X86: return ARCH_X86;
    case SCMP_ARCH_X86_64: return ARCH_X86_64;
    case SCMP_ARCH_X32: return ARCH_X32;
    case SCMP_ARCH_ARM: return ARCH_ARM;
    case SCMP_ARCH_AARCH64: return ARCH_AARCH64;
#if SCMP_VER_MAJOR >= 2 && SCMP_VER_MINOR >= 6
    case SCMP_ARCH_LOONGARCH64: return ARCH_LOONGARCH64;
    case SCMP_ARCH_M68K: return ARCH_M68K;
#endif
    case SCMP_ARCH_MIPSEL64N32: return ARCH_MIPSEL64N32;
    case SCMP_ARCH_MIPSEL64: return ARCH_MIPSEL64;
    case SCMP_ARCH_MIPSEL: return ARCH_MIPSEL;
    case SCMP_ARCH_MIPS64N32: return ARCH_MIPS64N32;
    case SCMP_ARCH_MIPS64: return ARCH_MIPS64;
    case SCMP_ARCH_MIPS: return ARCH_MIPS;
    case SCMP_ARCH_PARISC64: return ARCH_PARISC64;
    case SCMP_ARCH_PARISC: return ARCH_PARISC;
    case SCMP_ARCH_PPC64LE: return ARCH_PPC64LE;
    case SCMP_ARCH_PPC64: return ARCH_PPC64;
    case SCMP_ARCH_PPC: return ARCH_PPC;
    case SCMP_ARCH_S390X: return ARCH_S390X;
    case SCMP_ARCH_S390: return ARCH_S390;
    case SCMP_ARCH_RISCV64: return ARCH_RISCV64;
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
