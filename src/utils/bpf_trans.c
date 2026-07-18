#include "main.h"
#include "utils/error.h"
#include "utils/logger.h"
#include <assert.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* References:
 * FUNC bpf_convert_filter (ebpf 2 cbpf without const blinding)
 * https://elixir.bootlin.com/linux/v7.1.1/source/net/core/filter.c#L580
 * FUNC bpf_jit_blind_insn (const blind after bpf_convert_filter)
 * https://elixir.bootlin.com/linux/v7.1.1/source/kernel/bpf/core.c#L1293
 * FUNC seccomp_check_filter (valid cbpf insns)
 * https://elixir.bootlin.com/linux/v7.1.1/source/kernel/seccomp.c#L278
 * MACROS
 * https://elixir.bootlin.com/linux/v7.1.1/source/include/linux/filter.h
 */

/* Some internal APIs in kernel which is not exposed in user APIs */
#define BPF_REG_CTX BPF_REG_6
#define BPF_REG_FP BPF_REG_10
#define BPF_REG_A BPF_REG_0
#define BPF_REG_X BPF_REG_7
#define BPF_REG_TMP BPF_REG_2
#define BPF_REG_AX __MAX_BPF_REG

#define CBPF_STMT(code, k) (struct sock_filter){ (code), 0, 0, (k) };
#define CBPF_JMP(code, k, jt, jf) (struct sock_filter){ (code), jt, jf, (k) };

static jmp_buf restore;
static int err_line_no;
static const char *err_str;
#define ASSERT_JMP(cond)                                                      \
  do                                                                          \
    {                                                                         \
      if (UNLIKELY (!(cond)))                                                 \
        {                                                                     \
          err_line_no = __LINE__;                                             \
          err_str = #cond;                                                    \
          longjmp (restore, 1);                                               \
        }                                                                     \
    }                                                                         \
  while (0)

typedef struct
{
  // the filter is put `fold` insns ahead, it's sync with ebpf
  uint8_t fold : 3;
  // tracks branch to extinguish explicit JA or RETURN A
  uint8_t targeted : 1;
} InsnFlag;
// if set means insns that need to be deleted
static uint32_t *bitmap;
static InsnFlag *flags;

typedef enum
{
  NOT_CHECK,
  CHECK_DIV_X,
  CHECK_CMP_LARGE_K,
  CHECK_RET_K,
} check_path;

/* Note about the relationship between ebpfp and flag: flag always keep sync
 * with the insn to WRITE while ebpfp always keep sync with the insn to READ,
 * so (ebpfp - ebpfs) may not equal (flag - flags). But
 * (ebpfp - ebpfs == flag - flags + flag->fold).
 * large_k is related to bpf_insn.imm, which is s32, while sock_filter.k is
 * u32.
 * ate is the pointer to tell how many instructions are folded. This is
 * deliberately kept as flag->fold only represents the original location of JMP
 * insn.
 */
static struct sock_filter
jmp_insn (struct bpf_insn *ebpfp, check_path path, uint32_t large_k, int *ate,
          InsnFlag *flag)
{
  // in 1st pass, clear instructions, do relocation later
  struct bpf_insn insn;
  switch (path)
    {
    case NOT_CHECK:
      insn = *ebpfp;
      int op = BPF_OP (insn.code);
      if (op == BPF_EXIT)
        return CBPF_STMT (BPF_RET | BPF_A, 0);
      if (op == BPF_JA)
        {
          // JA is not impacted by constant blinding
          flag[insn.off + 1].targeted = 1;
          return CBPF_JMP (BPF_JMP | BPF_JA, 1, 0, 0);
        }

      int code = insn.code;
      uint32_t k = insn.imm;
      // originally it's comparing BPF_K, modified during bpf_convert_filter
      // set it back to BPF_K
      if (large_k)
        {
          k = large_k;
          code &= ~BPF_X;
        }
      flag[flag->fold + insn.off + 1].targeted = 1;
      // peek next insn, if it's JA (current insn is JMP), it's not targeted,
      // and the current insn is a valid cBPF op, then it's casted from a JMP
      // with both jt & jf (possibly, we will check it in second pass)
      // note that !JSET is always in this branch
      InsnFlag *ja_flag = flag + flag->fold + 1;
      if (ebpfp[1].code == (BPF_JMP | BPF_JA) && !ja_flag->targeted
          && op != BPF_JNE && op != BPF_JLE && op != BPF_JLT)
        {
          ++*ate;
          // flags[i + flag->fold + 1 + ebpfs[i + flag->fold + 1].off + 1]
          ja_flag[ebpfp[1].off + 1].targeted = 1;
          // in this case, insn.code is exactly the same from cBPF
          return CBPF_JMP (code, k, 1, 1);
        }
      if (op == BPF_JEQ || op == BPF_JGT || op == BPF_JGE || op == BPF_JSET)
        return CBPF_JMP (code, k, 1, 0);
      if (op == BPF_JNE)
        return CBPF_JMP ((code & ~BPF_JNE) | BPF_JEQ, k, 0, 1);
      if (op == BPF_JLE)
        return CBPF_JMP ((code & ~BPF_JLE) | BPF_JGT, k, 0, 1);
      if (op == BPF_JLT)
        return CBPF_JMP ((code & ~BPF_JLT) | BPF_JGE, k, 0, 1);
      ASSERT_JMP (!"Unexpected eBPF JMP pattern");
    case CHECK_DIV_X:
      /* MOV X X
       * JNE X 0 2
       * XOR A A
       * EXIT
       * DIV A X 0
       */
      insn = *++ebpfp;
      if (insn.code == (BPF_JMP | BPF_JNE | BPF_K))
        // without blinding
        insn = *++ebpfp;
      else
        {
          // with blinding
          /* ...
           * MOV AX rnd
           * XOR AX rnd
           * JNE X AX 2
           * ...
           */
          ASSERT_JMP (insn.code == (BPF_ALU64 | BPF_MOV | BPF_K));
          insn = *++ebpfp;
          ASSERT_JMP (insn.code == (BPF_ALU64 | BPF_XOR | BPF_K));
          insn = *++ebpfp;
          ASSERT_JMP (insn.code == (BPF_JMP | BPF_JNE | BPF_X)
                      && insn.src_reg == BPF_REG_AX);
          insn = *++ebpfp;
          *ate += 2;
        }
      ASSERT_JMP (insn.code == (BPF_ALU | BPF_XOR | BPF_X));
      insn = *++ebpfp;
      ASSERT_JMP (insn.code == (BPF_JMP | BPF_EXIT));
      *ate += 4;
      return CBPF_STMT (BPF_ALU | BPF_DIV | BPF_X, 0);
    case CHECK_CMP_LARGE_K:
      /* MOV TMP K
       * Jxx TMP A
       */
      ++*ate; // consume MOV TMP K
      flag->fold++;
      return jmp_insn (ebpfp + 1, NOT_CHECK, ebpfp->imm, ate, flag);
    case CHECK_RET_K:
      /* MOV A K
       * EXIT
       * or simply MOV A K?
       */
      if (ebpfp[1].code == (BPF_JMP | BPF_EXIT)
          && !flag[flag->fold + 1].targeted)
        {
          ++*ate;
          return CBPF_STMT (BPF_RET | BPF_K, ebpfp->imm);
        }
      return CBPF_STMT (BPF_LD | BPF_IMM, ebpfp->imm);
    default:
      ASSERT_JMP (!"Unexpected check_path");
    }
}

static struct sock_filter
alu_insn (struct bpf_insn *ebpfp, int *ate, InsnFlag *flag)
{
  struct bpf_insn insn = *ebpfp;
  struct sock_filter filter;
  // remove constant blinding first
  if (BPF_OP (insn.code) == BPF_MOV && insn.dst_reg == BPF_REG_AX)
    {
      /* MOV AX K
       * XOR AX K
       * ??? A AX ...
       */
      *ate += 2;
      flag->fold += 2; // instruction is folded 2 insns ahead
      ebpfp[2].imm = ebpfp[0].imm ^ ebpfp[1].imm;
      ebpfp[2].code &= ~BPF_X; // restore rval to BPF_K
      ebpfp[2].src_reg = 0;
      ebpfp += 2;
      insn = *ebpfp;
    }
  else if (BPF_OP (insn.code) == BPF_XOR && BPF_SRC (insn.code) == BPF_X
           && insn.src_reg == insn.dst_reg)
    {
      // bpf_jit_blind_insn may convert A = 0 and X = 0 to xor
      ebpfp->src_reg = 0;
      ebpfp->code = BPF_ALU | BPF_MOV | BPF_K;
      insn = *ebpfp;
    }

  // spotted JMP after de-blind?
  if (BPF_CLASS (insn.code) == BPF_JMP)
    return jmp_insn (ebpfp, NOT_CHECK, 0, ate, flag);
  if (BPF_OP (insn.code) == BPF_MOV)
    {
      if (BPF_CLASS (insn.code) == BPF_ALU64 && BPF_SRC (insn.code) == BPF_X
          && (insn.src_reg == BPF_REG_X || insn.dst_reg == BPF_REG_X))
        {
          int c = BPF_MISC | (insn.src_reg == BPF_REG_A ? BPF_TAX : BPF_TXA);
          filter = CBPF_STMT (c, 0);
        }
      else if (insn.dst_reg == BPF_REG_A && insn.src_reg == 0)
        {
          filter = jmp_insn (ebpfp, CHECK_RET_K, 0, ate, flag);
          // LD LEN is converted to LD IMM in seccomp_check_filter
          if (filter.code == (BPF_LD | BPF_IMM)
              && filter.k == sizeof (struct seccomp_data))
            filter = CBPF_STMT (BPF_LD | BPF_LEN, 0);
        }
      else if (insn.dst_reg == BPF_REG_X && insn.src_reg == 0)
        {
          filter = CBPF_STMT (BPF_LDX | BPF_IMM, insn.imm);
          // LDX LEN is converted to LDX IMM in seccomp_check_filter
          if (filter.k == sizeof (struct seccomp_data))
            filter = CBPF_STMT (BPF_LDX | BPF_LEN, 0);
        }
      else if (insn.dst_reg == BPF_REG_X && insn.src_reg == BPF_REG_X)
        filter = jmp_insn (ebpfp, CHECK_DIV_X, 0, ate, flag);
      else if (insn.dst_reg == BPF_REG_TMP && insn.src_reg == 0)
        filter = jmp_insn (ebpfp, CHECK_CMP_LARGE_K, 0, ate, flag);
      else
        ASSERT_JMP (!"Unexpected MOV instruction pattern");
      return filter;
    }
  else
    // fall through case: most alu instructions are kept the same
    return CBPF_STMT (insn.code, insn.imm);
}

#define U32BITS (sizeof (uint32_t) * 8)

// mark insns from `fromidx` to `fromidx + count` to be deleted in bitmap
static inline void
setbits (uint32_t fromidx, uint32_t count)
{
  if (count == 0)
    return;
  uint32_t mapidx = fromidx / U32BITS, frombit = fromidx % U32BITS;
  if (mapidx != (fromidx + count) / U32BITS)
    {
      // count is always less than 32
      // we need to set bits on 2 bitsets
      bitmap[mapidx] |= UINT32_MAX << frombit;
      bitmap[mapidx + 1] |= (1u << ((fromidx + count) % U32BITS)) - 1;
    }
  else
    // we only need to set 1 bitset, easy
    bitmap[mapidx] |= ((1u << count) - 1) << frombit;
}

// how many holes in bitmap within the range from `from` bit to `to` bit
static uint32_t
countbits (uint32_t from, uint32_t to)
{
  uint32_t startidx = from / U32BITS, startbit = from % U32BITS;
  uint32_t endidx = to / U32BITS, endbit = to % U32BITS;
  uint32_t bitmask, sum;

  if (startidx == endidx)
    {
      bitmask = ((1u << (endbit - startbit)) - 1) << startbit;
      return __builtin_popcount (bitmap[startidx] & bitmask);
    }

  bitmask = (UINT32_MAX) << startbit;
  sum = __builtin_popcount (bitmap[startidx] & bitmask);
  bitmask = (1u << endbit) - 1;
  sum += __builtin_popcount (bitmap[endidx] & bitmask);
  for (uint32_t idx = startidx + 1; idx < endidx; idx++)
    sum += __builtin_popcount (bitmap[idx]);
  return sum;
}

long
ebpf2cbpf (struct bpf_insn *restrict ebpfs, const uint32_t ebpf_len,
           struct sock_filter *restrict cbpf_buf, bool trustful)
{
  volatile uint32_t i = 0;
  if (setjmp (restore))
    {
      int lineno = err_line_no;
      int no = i + 1;
      if (trustful)
        {
          // unexpected kernel migrated eBPF?
#ifndef __FILE_NAME__
#define __FILE_NAME__ __FILE__
#endif
          char filename[] = "/tmp/ceccomp-XXXXXX";
          int fd = mkstemp (filename);
          long rc = -1;

          warn (M_UNEXPECTED_EBPF_INSN, no, __FILE_NAME__, lineno, err_str);
          if (fd != -1)
            {
              rc = write (fd, ebpfs, sizeof (struct bpf_insn) * ebpf_len);
              if (rc != -1)
                info (M_SAVE_EBPF_SUCCEEDED, filename);
              close (fd);
            }
          if (rc == -1)
            warn (M_SAVE_EBPF_FAILED, strerror (errno));
        }
      else
        {
          // detected errors in user-input eBPF
#define E_G "CODE:0x00 DST_REG:0x0 SRC_REG:0x0 OFF:0x0000 IMM:0x00000000"
#define FMT "CODE:0x%02x DST_REG:0x%x SRC_REG:0x%x OFF:0x%04hx IMM:0x%08x"
#define E_G_LEN LITERAL_STRLEN (E_G)
          char buf[E_G_LEN * 2 + 2];
          struct bpf_insn insn = ebpfs[i];
          snprintf (buf, E_G_LEN + 1, FMT, insn.code, insn.dst_reg,
                    insn.src_reg, insn.off, insn.imm);
          buf[E_G_LEN] = '\n';
          buf[E_G_LEN * 2 + 1] = '\0';
          memset (buf + E_G_LEN + 1, '~', E_G_LEN);

          warn (M_EBPF_INPUT_ERROR, no, __FILE_NAME__, lineno, err_str, buf);
          error ("%s", M_DISASM_TERMINATED);
#undef E_G
#undef FMT
#undef E_G_LEN
        }

      free (bitmap);
      bitmap = NULL;
      free (flags);
      flags = NULL;
      return -1;
    }

  /* PRE-PASS: check jump destinations from untrusted source */
  if (!trustful)
    for (i = 0; i < ebpf_len; i++)
      if ((BPF_CLASS (ebpfs[i].code) == BPF_JMP
           || BPF_CLASS (ebpfs[i].code) == BPF_JMP32)
          && BPF_OP (ebpfs[i].code) != BPF_EXIT)
        ASSERT_JMP (ebpfs[i].off >= 0 && i + 1 + ebpfs[i].off < ebpf_len);

  /* 1ST PASS: fold eBPF insns to cBPF insns */
  // skip prologue
#define SKIP 3
  ASSERT_JMP (BPF_CLASS (ebpfs[0].code) == BPF_ALU
              && BPF_OP (ebpfs[0].code) == BPF_XOR);
  ASSERT_JMP (BPF_CLASS (ebpfs[1].code) == BPF_ALU
              && BPF_OP (ebpfs[1].code) == BPF_XOR);
  ASSERT_JMP (BPF_CLASS (ebpfs[2].code) == BPF_ALU64
              && BPF_OP (ebpfs[2].code) == BPF_MOV);

  bitmap = calloc (ebpf_len / U32BITS + 1, sizeof (uint32_t));
  flags = calloc (ebpf_len, sizeof (*flags));
  assert (bitmap && flags);
  bitmap[0] = 7; // mark prologue to be deleted

  int code, k, ate;
  for (i = SKIP; i < ebpf_len; i++)
    {
      struct bpf_insn insn = ebpfs[i];
      switch (BPF_CLASS (insn.code))
        {
        case BPF_LDX:
          if (insn.src_reg == BPF_REG_CTX)
            {
              code = BPF_LD | BPF_W | BPF_ABS;
              k = insn.off;
            }
          else
            {
              ASSERT_JMP (insn.src_reg == BPF_REG_FP);
              code = BPF_MEM | (insn.dst_reg == BPF_REG_A ? BPF_LD : BPF_LDX);
              k = (-insn.off - 4) / 4;
            }
          cbpf_buf[i] = CBPF_STMT (code, k);
          continue;
        case BPF_STX:
          // note seccomp cBPF only allows BPT_ST, not BPF_ST | BPF_MEM
          code = insn.src_reg == BPF_REG_A ? BPF_ST : BPF_STX;
          cbpf_buf[i] = CBPF_STMT (code, (-insn.off - 4) / 4);
          continue;
        case BPF_ALU:
        case BPF_ALU64:
          ate = 0;
          cbpf_buf[i] = alu_insn (ebpfs + i, &ate, flags + i);
          // *i is folded and kept, so starts from i + 1
          setbits (i + 1, ate);
          i += ate;
          continue;
        case BPF_JMP:
          ate = 0;
          cbpf_buf[i] = jmp_insn (ebpfs + i, NOT_CHECK, 0, &ate, flags + i);
          setbits (i + 1, ate);
          i += ate;
          continue;
        default:
          ASSERT_JMP (!"Unexpected BPF code class");
        }
    }

  /* 2ND PASS: relocate jumps */
  uint32_t mapidx = (ebpf_len - 1) / U32BITS;
  uint32_t bitmask = 1u << ((ebpf_len - 1) % U32BITS);
  uint32_t bitset = bitmap[mapidx];
  uint32_t jmp, patch;
  for (i = ebpf_len - 1; i > SKIP - 1; i--)
    {
      bool deleted = bitset & bitmask;
      bitmask >>= 1;
      if (bitmask == 0)
        {
          bitset = bitmap[--mapidx];
          bitmask = 1u << (U32BITS - 1);
        }

      if (deleted)
        continue;
      struct sock_filter *f = cbpf_buf + i;
      if (BPF_CLASS (f->code) != BPF_JMP)
        continue;
      uint32_t ebpf_idx = i + flags[i].fold;
      if (UNLIKELY (f->jt && f->jf))
        {
          // test jf first (i + 1 due to selecting Jxx [JA])
          patch = countbits (ebpf_idx + 1,
                             ebpf_idx + 1 + ebpfs[ebpf_idx + 1].off + 1);
          // If JA can't fit: JA is cleared in 1st pass and counted, need +1
          // If JA fits: JA.off is the perspective from JA, not Jxx, need +1
          jmp = ebpfs[ebpf_idx + 1].off - patch + 1;
          if (UNLIKELY (jmp > UINT8_MAX))
            {
              // Oops, this JA can't fit into u8, we have to split it out again
              // This is why we are looping reversely: cbpf can't jump back, so
              // modifying cbpf[i] won't impact cbpf[i + x] filters which are
              // already relocated
              f->jf = 0;
              bitmap[(ebpf_idx + 1) / U32BITS]
                  &= ~(1u << ((ebpf_idx + 1) % U32BITS));
              cbpf_buf[ebpf_idx + 1] = CBPF_JMP (BPF_JMP | BPF_JA, jmp, 0, 0);
            }
          else
            f->jf = jmp;

          // now jt
          patch = countbits (i, ebpf_idx + 1 + ebpfs[ebpf_idx].off);
          f->jt = ebpfs[ebpf_idx].off - patch + flags[i].fold;
        }
      else if (f->jt || f->jf)
        {
          patch = countbits (i, ebpf_idx + 1 + ebpfs[ebpf_idx].off);
          jmp = ebpfs[ebpf_idx].off - patch + flags[i].fold;
          if (f->jt)
            f->jt = jmp;
          else
            f->jf = jmp;
        }
      else
        {
          // JA case
          patch = countbits (i, i + 1 + ebpfs[i].off);
          f->k = ebpfs[i].off - patch;
        }
    }

  /* 3RD PASS: compress cBPF filters to discard holes */
  mapidx = 0, bitmask = 8, bitset = bitmap[mapidx];
  struct sock_filter *wp = cbpf_buf, *rp = cbpf_buf + SKIP;
  for (; rp < cbpf_buf + ebpf_len; rp++)
    {
      if (!(bitset & bitmask))
        memcpy (wp++, rp, sizeof (*wp));
      bitmask <<= 1;

      if (bitmask == 0)
        {
          bitset = bitmap[++mapidx];
          bitmask = 1;
        }
    }

  free (bitmap);
  bitmap = NULL;
  free (flags);
  flags = NULL;
  return wp - cbpf_buf;
}
