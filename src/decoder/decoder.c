#include "decoder/decoder.h"
#include "decoder/check_prog.h"
#include "lexical/parser.h"
#include "lexical/token.h"
#include "main.h"
#include "resolver/resolver.h"
#include "utils/vector.h"
#include <assert.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define RSH2(value) ((value) >> 2)
#define RSH4(value) ((value) >> 4)

static const token_type abs_table[] = {
  [RSH2 (offsetof (seccomp_data, nr))] = ATTR_SYSCALL,
  [RSH2 (offsetof (seccomp_data, arch))] = ATTR_ARCH,
  [RSH2 (offsetof (seccomp_data, instruction_pointer))] = ATTR_LOWPC,
  [RSH2 (offsetof (seccomp_data, instruction_pointer) + 4)] = ATTR_HIGHPC,
  [RSH2 (offsetof (seccomp_data, args[0]))] = ATTR_LOWARG,
  [RSH2 (offsetof (seccomp_data, args[0]) + 4)] = ATTR_HIGHARG,
  [RSH2 (offsetof (seccomp_data, args[1]))] = ATTR_LOWARG,
  [RSH2 (offsetof (seccomp_data, args[1]) + 4)] = ATTR_HIGHARG,
  [RSH2 (offsetof (seccomp_data, args[2]))] = ATTR_LOWARG,
  [RSH2 (offsetof (seccomp_data, args[2]) + 4)] = ATTR_HIGHARG,
  [RSH2 (offsetof (seccomp_data, args[3]))] = ATTR_LOWARG,
  [RSH2 (offsetof (seccomp_data, args[3]) + 4)] = ATTR_HIGHARG,
  [RSH2 (offsetof (seccomp_data, args[4]))] = ATTR_LOWARG,
  [RSH2 (offsetof (seccomp_data, args[4]) + 4)] = ATTR_HIGHARG,
  [RSH2 (offsetof (seccomp_data, args[5]))] = ATTR_LOWARG,
  [RSH2 (offsetof (seccomp_data, args[5]) + 4)] = ATTR_HIGHARG,
};

#define SCMP_DATA_LEN_STR "# 0x40"
static void
ld_ldx_line (filter f, statement_t *statement)
{
  statement->type = ASSIGN_LINE;
  assign_line_t *assign_line = &statement->assign_line;

  assign_line->left_var.type = (BPF_CLASS (f.code) == BPF_LD) ? A : X;
  assign_line->operator = EQUAL;

  obj_t *right = &assign_line->right_var;
  switch (BPF_MODE (f.code))
    {
    case BPF_IMM:
      right->type = NUMBER;
      right->data = f.k;
      return;
    case BPF_MEM:
      right->type = MEM;
      right->data = f.k;
      return;
    case BPF_ABS:
      right->type = abs_table[RSH2 (f.k)];
      if (right->type == ATTR_LOWARG || right->type == ATTR_HIGHARG)
        right->data = (f.k - offsetof (seccomp_data, args[0])) / 0x8;
      return;
    case BPF_LEN:
      right->type = ATTR_LEN;
      statement->line_start = SCMP_DATA_LEN_STR;
      statement->comment = 0;
      statement->line_len = LITERAL_STRLEN (SCMP_DATA_LEN_STR);
      static_assert (sizeof (seccomp_data) == 0x40,
                     "struct seccomp_data should be 0x40 bytes large");
      return;
    default:
      assert (!"Unknown BPF_MODE for ld or ldx");
    }
}

static void
st_stx_line (filter f, statement_t *statement)
{
  statement->type = ASSIGN_LINE;
  assign_line_t *assign_line = &statement->assign_line;

  assign_line->left_var.type = MEM;
  assign_line->left_var.data = f.k;
  assign_line->operator = EQUAL;

  assign_line->right_var.type = (BPF_CLASS (f.code) == BPF_ST) ? A : X;
}

static const token_type operator_table[] = {
  [RSH4 (BPF_ADD)] = ADD_TO,   [RSH4 (BPF_SUB)] = SUB_TO,
  [RSH4 (BPF_MUL)] = MULTI_TO, [RSH4 (BPF_DIV)] = DIVIDE_TO,
  [RSH4 (BPF_OR)] = OR_TO,     [RSH4 (BPF_AND)] = AND_TO,
  [RSH4 (BPF_LSH)] = LSH_TO,   [RSH4 (BPF_RSH)] = RSH_TO,
  [RSH4 (BPF_NEG)] = NEGATIVE, [RSH4 (BPF_XOR)] = XOR_TO,
};

static void
alu_line (filter f, statement_t *statement)
{
  statement->type = ASSIGN_LINE;
  assign_line_t *assign_line = &statement->assign_line;

  assign_line->left_var.type = A;
  assign_line->operator = operator_table[RSH4 (BPF_OP (f.code))];

  if (BPF_SRC (f.code) == BPF_X)
    assign_line->right_var.type = X;
  else if (assign_line->operator == NEGATIVE)
    assign_line->right_var.type = A;
  else
    {
      assign_line->right_var.type = NUMBER;
      assign_line->right_var.data = f.k;
    }
}

static const token_type comparator_table[] = {
  [RSH4 (BPF_JEQ)] = EQUAL_EQUAL,
  [RSH4 (BPF_JGT)] = GREATER_THAN,
  [RSH4 (BPF_JGE)] = GREATER_EQUAL,
  [RSH4 (BPF_JSET)] = AND,
};

static const token_type reverse_table[] = {
  [RSH4 (BPF_JEQ)] = BANG_EQUAL,
  [RSH4 (BPF_JGT)] = LESS_EQUAL,
  [RSH4 (BPF_JGE)] = LESS_THAN,
};

static void
condition (filter f, token_type *comparator, obj_t *cmpobj, bool *if_bang)
{
  uint32_t op = BPF_OP (f.code);
  if ((!*if_bang) || op == BPF_JSET)
    *comparator = comparator_table[RSH4 (op)];
  else
    {
      *comparator = reverse_table[RSH4 (op)];
      *if_bang = false;
    }

  if (BPF_SRC (f.code) == BPF_X)
    cmpobj->type = X;
  else
    {
      cmpobj->type = NUMBER;
      cmpobj->data = f.k;
    }
}

static void
jump_line (filter f, statement_t *statement)
{
  statement->type = JUMP_LINE;
  jump_line_t *jump_line = &statement->jump_line;

  if (BPF_OP (f.code) == BPF_JA)
    {
      jump_line->if_bang = false;
      jump_line->if_condition = false;
      jump_line->jt.code_nr = f.k;
      return;
    }

  jump_line->if_condition = true;

  if (f.jt == 0 && f.jf != 0)
    {
      jump_line->if_bang = true;
      jump_line->jf.code_nr = f.jt;
      jump_line->jt.code_nr = f.jf;
    }
  else
    {
      jump_line->jt.code_nr = f.jt;
      jump_line->jf.code_nr = f.jf;
    }

  condition (f, &jump_line->comparator, &jump_line->cmpobj,
             &jump_line->if_bang);
}

token_type
decode_return_k (obj_t *ret_obj, uint32_t k)
{
  token_type tk;
  switch (k & SECCOMP_RET_ACTION_FULL)
    {
    case SCMP_ACT_KILL_PROCESS:
      tk = KILL_PROC;
      break;
    case SCMP_ACT_KILL:
      tk = KILL;
      break;
    case SCMP_ACT_ALLOW:
      tk = ALLOW;
      break;
    case SCMP_ACT_LOG:
      tk = LOG;
      break;
    case SCMP_ACT_NOTIFY:
      tk = NOTIFY;
      break;
    case SCMP_ACT_TRACE (0):
      ret_obj->data = k & SECCOMP_RET_DATA;
      tk = TRACE;
      break;
    case _SCMP_ACT_TRAP (0):
      ret_obj->data = k & SECCOMP_RET_DATA;
      tk = TRAP;
      break;
    case SCMP_ACT_ERRNO (0):
      ret_obj->data = k & SECCOMP_RET_DATA;
      tk = ERRNO;
      break;
    default:
      ret_obj->data = k;
      tk = NUMBER;
    }
  ret_obj->type = tk;
  return tk == NUMBER ? KILL_PROC : tk;
}

static void
return_line (filter f, statement_t *statement)
{
  statement->type = RETURN_LINE;
  return_line_t *return_line = &statement->return_line;

  if (BPF_RVAL (f.code) == BPF_A)
    return_line->ret_obj.type = A;
  else
    decode_return_k (&return_line->ret_obj, f.k);
}

static void
misc_line (filter f, statement_t *statement)
{
  statement->type = ASSIGN_LINE;
  assign_line_t *assign_line = &statement->assign_line;
  assign_line->operator = EQUAL;

  if (BPF_MISCOP (f.code) == BPF_TAX)
    {
      assign_line->left_var.type = X;
      assign_line->right_var.type = A;
    }
  else
    {
      assign_line->left_var.type = A;
      assign_line->right_var.type = X;
    }
}

static void
decode_filter (filter f, statement_t *statement)
{
  switch (BPF_CLASS (f.code))
    {
    case BPF_LD:
    case BPF_LDX:
      ld_ldx_line (f, statement);
      return;
    case BPF_ST:
    case BPF_STX:
      st_stx_line (f, statement);
      return;
    case BPF_ALU:
      alu_line (f, statement);
      break;
    case BPF_JMP:
      jump_line (f, statement);
      break;
    case BPF_RET:
      return_line (f, statement);
      break;
    case BPF_MISC:
      misc_line (f, statement);
      break;
    }
}

bool
decode_filters (const fprog *prog, vector_t *v, bool trustful)
{
  // make sure all filter are valid
  // give warning about fatal and normal errors
  bool error = trustful ? false : check_prog (prog);

  statement_t statement = { 0 };
  push_vector (v, &statement); // skip 1 element

  for (uint32_t i = 0; i < prog->len; i++)
    {
      memset (&statement, '\0', sizeof (statement_t));

      statement.text_nr = i + 1;
      statement.code_nr = i + 1;

      decode_filter (prog->filter[i], &statement);
      push_vector (v, &statement);
    }
  return error;
}
