#include <assert.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdint.h>

/* Some internal APIs in kernel which is not exposed in user APIs */
#define BPF_REG_CTX BPF_REG_6
#define BPF_REG_FP BPF_REG_10
#define BPF_REG_A BPF_REG_0
#define BPF_REG_X BPF_REG_7
#define BPF_REG_TMP BPF_REG_2
#define BPF_REG_AX __MAX_BPF_REG

#define CBPF_STMT(code, k) (struct sock_filter){ (code), 0, 0, (k) };
#define CBPF_JMP(code, k, jt, jf) (struct sock_filter){ (code), jt, jf, (k) };

typedef enum
{
  NOT_CHECK,
  CHECK_DIV_X,
  CHECK_CMP_LARGE_K,
  CHECK_RET_K,
} check_path;

static struct sock_filter
jmp_insn (struct bpf_insn *ebpfp, check_path path, uint32_t large_k, int *ate)
{
  struct bpf_insn insn;
  switch (path)
    {
    case NOT_CHECK:
      insn = *ebpfp;
      int op = BPF_OP (insn.code);
      if (op == BPF_EXIT)
        return CBPF_STMT (BPF_RET | BPF_A, 0);
      if (op == BPF_JA)
        return CBPF_JMP (BPF_JMP | BPF_JA, insn.off, 0, 0);

      uint16_t jt, jf;
      int code = insn.code;
      uint32_t k = insn.imm;
      jt = insn.off;
      // originally it's comparing BPF_K, modified during bpf_convert_filter
      // set it back to BPF_K
      if (large_k)
        {
          k = large_k;
          code &= ~BPF_X;
        }
      // peek next insn, if it's JA (current insn is JMP),
      // then it's casted from a JMP with both jt & jf
      // ONLY IF jf < 256!
      // note that JSET is always in this branch
      if (ebpfp[1].code == (BPF_JMP | BPF_JA) && (uint16_t)ebpfp[1].off < 256)
        {
          jf = ebpfp[1].off;
          ++*ate;
          // in this case, insn.code is exactly the same from cBPF
          return CBPF_JMP (code, k, jt, jf);
        }
      if (op == BPF_JEQ || op == BPF_JGT || op == BPF_JGE || op == BPF_JSET)
        return CBPF_JMP (code, k, jt, 0);
      if (op == BPF_JNE)
        return CBPF_JMP ((code & ~BPF_JNE) | BPF_JEQ, k, 0, jt);
      if (op == BPF_JLE)
        return CBPF_JMP ((code & ~BPF_JLE) | BPF_JGT, k, 0, jt);
      if (op == BPF_JLT)
        return CBPF_JMP ((code & ~BPF_JLT) | BPF_JGE, k, 0, jt);
      assert (!"Unexpected eBPF JMP pattern");
    case CHECK_DIV_X:
      /* MOV X X
       * JNE X 0 2
       * XOR A A
       * EXIT
       * DIV A X 0
       */
      insn = *++ebpfp;
      assert (insn.code == (BPF_JMP | BPF_JNE | BPF_K));
      insn = *++ebpfp;
      assert (insn.code == (BPF_ALU | BPF_XOR | BPF_X));
      insn = *++ebpfp;
      assert (insn.code == (BPF_JMP | BPF_EXIT));
      *ate += 4;
      return CBPF_STMT (BPF_ALU | BPF_DIV | BPF_X, 0);
    case CHECK_CMP_LARGE_K:
      /* MOV TMP K
       * Jxx TMP A
       */
      ++*ate; // consume MOV TMP K
      return jmp_insn (ebpfp + 1, NOT_CHECK, ebpfp->imm, ate);
    case CHECK_RET_K:
      /* MOV A K
       * EXIT
       * or simply MOV A K?
       */
      if (ebpfp[1].code == (BPF_JMP | BPF_EXIT))
        {
          ++*ate;
          return CBPF_STMT (BPF_RET | BPF_K, ebpfp->imm);
        }
      return CBPF_STMT (BPF_LD | BPF_IMM, ebpfp->imm);
    default:
      assert (!"Unexpected check_path");
    }
}

static struct sock_filter
alu_insn (struct bpf_insn *ebpfp, int *ate)
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
      ebpfp[2].imm = ebpfp[0].imm ^ ebpfp[1].imm;
      ebpfp[2].code &= ~BPF_X; // restore rval to BPF_K
      ebpfp[2].src_reg = 0;
      ebpfp += 2;
      insn = *ebpfp;
    }
  else if (BPF_OP (insn.code) == BPF_XOR && insn.src_reg == insn.dst_reg)
    {
      // bpf_jit_blind_insn may convert A = 0 and X = 0 to xor
      ebpfp->src_reg = 0;
      ebpfp->code = BPF_ALU | BPF_MOV | BPF_K;
      insn = *ebpfp;
    }

  // spotted JMP after deblind?
  if (BPF_CLASS(insn.code) == BPF_JMP)
      return jmp_insn(ebpfp, NOT_CHECK, 0, ate);
  if (BPF_OP (insn.code) == BPF_MOV)
    {
      if (BPF_CLASS (insn.code) == BPF_ALU64
          && (insn.src_reg == BPF_REG_X || insn.dst_reg == BPF_REG_X))
        {
          int c = BPF_MISC | (insn.src_reg == BPF_REG_A ? BPF_TAX : BPF_TXA);
          filter = CBPF_STMT (c, 0);
        }
      else if (insn.dst_reg == BPF_REG_A && insn.src_reg == 0)
        {
          filter = jmp_insn (ebpfp, CHECK_RET_K, 0, ate);
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
        filter = jmp_insn (ebpfp, CHECK_DIV_X, 0, ate);
      else if (insn.dst_reg == BPF_REG_TMP && insn.src_reg == 0)
        filter = jmp_insn (ebpfp, CHECK_CMP_LARGE_K, 0, ate);
      else
        assert (!"Unexpected MOV instruction pattern");
      return filter;
    }
  else
    return CBPF_STMT (insn.code, insn.imm);
}

long
ebpf2cbpf (struct bpf_insn *ebpfs, uint32_t ebpf_len,
           struct sock_filter *cbpf_buf)
{
  int code, k, ate;
  for (uint32_t i = 0; i < ebpf_len; i++)
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
          else // insn.src_reg == BPF_REG_FP
            {
              code = BPF_MEM | (insn.dst_reg == BPF_REG_A ? BPF_LD : BPF_LDX);
              k = (-insn.off - 4) / 4;
            }
          cbpf_buf[i] = CBPF_STMT (code, k);
          break;
        case BPF_STX:
          code = insn.src_reg == BPF_REG_A ? BPF_ST : BPF_STX;
          cbpf_buf[i] = CBPF_STMT (code, (-insn.off - 4) / 4);
          break;
        case BPF_ALU:
        case BPF_ALU64:
          ate = 1;
          cbpf_buf[i] = alu_insn (ebpfs + i, &ate);
          break;
        case BPF_JMP:
          ate = 1;
          cbpf_buf[i] = jmp_insn (ebpfs + i, NOT_CHECK, 0, &ate);
          break;
        default:
          assert (!"Unexpected BPF code class");
        }
    }
  return -1;
}
