#ifndef REVERSE_ENDIAN_H
#define REVERSE_ENDIAN_H

#include "main.h"
#include <byteswap.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>

static inline bool
need_reverse_endian (uint32_t target_scmp_arch)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return (target_scmp_arch & __AUDIT_ARCH_LE);
#else
  return !(target_scmp_arch & __AUDIT_ARCH_LE);
#endif
}

static inline void
reverse_endian (filter *f)
{
  f->code = bswap_16 (f->code);
  f->k = bswap_32 (f->k);
}

static inline void
reverse_ebpf_endian (struct bpf_insn *insn)
{
  insn->off = bswap_16 (insn->off);
  insn->imm = bswap_32 (insn->imm);
}

#endif
