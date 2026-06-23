#include "emu.h"
#include "decoder/decoder.h"
#include "decoder/formatter.h"
#include "lexical/parser.h"
#include "lexical/scanner.h"
#include "lexical/token.h"
#include "main.h"
#include "resolver/resolver.h"
#include "utils/color.h"
#include "utils/error.h"
#include "utils/logger.h"
#include "utils/parse_args.h"
#include "utils/read_source.h"
#include "utils/vector.h"
#include <assert.h>
#include <errno.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t A_reg = 0;
static uint32_t X_reg = 0;
static uint32_t mem[BPF_MEMWORDS] = { 0 };

static uint32_t syscall_nr = 0;
static uint32_t scmp_arch = 0;
static uint32_t low_pc = 0;
static uint32_t high_pc = 0;
static uint32_t low_args[6] = { 0 };
static uint32_t high_args[6] = { 0 };

static uint32_t scmp_data_len = sizeof (seccomp_data);
#define BASE_vars(value) ((value) - A)
static uint32_t *vars[] = {
  [BASE_vars (A)] = &A_reg,
  [BASE_vars (X)] = &X_reg,
  [BASE_vars (MEM)] = mem,
  [BASE_vars (ATTR_SYSCALL)] = &syscall_nr,
  [BASE_vars (ATTR_ARCH)] = &scmp_arch,
  [BASE_vars (ATTR_LOWPC)] = &low_pc,
  [BASE_vars (ATTR_HIGHPC)] = &high_pc,
  [BASE_vars (ATTR_LOWARG)] = low_args,
  [BASE_vars (ATTR_HIGHARG)] = high_args,
  [BASE_vars (ATTR_LEN)] = &scmp_data_len,
};

#define DO_OPERATE(operator) (*left operator (*right))

// true if interrupted ($A / $X && $X == 0)
static bool
assign_line (assign_line_t *line)
{
  token_type left_type = line->left_var.type;
  uint32_t *left = vars[BASE_vars (left_type)];

  token_type right_type = line->right_var.type;
  uint32_t *right;
  if (right_type == NUMBER)
    right = &line->right_var.data;
  else
    right = vars[BASE_vars (right_type)];

  if (right_type == ATTR_LOWARG || right_type == ATTR_HIGHARG
      || right_type == MEM)
    right += line->right_var.data;
  else if (left_type == MEM)
    left += line->left_var.data;

  switch (line->operator)
    {
    case ADD_TO:
      DO_OPERATE (+=);
      break;
    case SUB_TO:
      DO_OPERATE (-=);
      break;
    case MULTI_TO:
      DO_OPERATE (*=);
      break;
    case DIVIDE_TO:
      if (*right != 0)
        DO_OPERATE (/=);
      else
        return true;
      break;
    case LSH_TO:
      *right = *right & 0x1f;
      DO_OPERATE (<<=);
      break;
    case RSH_TO:
      *right = *right & 0x1f;
      DO_OPERATE (>>=);
      break;
    case AND_TO:
      DO_OPERATE (&=);
      break;
    case OR_TO:
      DO_OPERATE (|=);
      break;
    case XOR_TO:
      DO_OPERATE (^=);
      break;
    case EQUAL:
      DO_OPERATE (=);
      break;
    case NEGATIVE:
      DO_OPERATE (= -);
      break;
    default:
      assert (!"Unknown alu operation");
    }
  return false;
}

#define DO_COMPARE(comparator) (bool)(A_reg comparator right)

static label_t *
jump_line (jump_line_t *line)
{
  label_t *jt = &line->jt;
  label_t *jf = &line->jf;

  if (!line->if_condition)
    return jt;

  bool cond_true = false;
  if (line->if_bang)
    cond_true = true;

  uint32_t right = 0;
  if (line->cmpobj.type == X)
    right = X_reg;
  else
    right = line->cmpobj.data;

  switch (line->comparator)
    {
    case EQUAL_EQUAL:
      cond_true ^= DO_COMPARE (==);
      break;
    case BANG_EQUAL:
      cond_true ^= DO_COMPARE (!=);
      break;
    case GREATER_EQUAL:
      cond_true ^= DO_COMPARE (>=);
      break;
    case GREATER_THAN:
      cond_true ^= DO_COMPARE (>);
      break;
    case LESS_EQUAL:
      cond_true ^= DO_COMPARE (<=);
      break;
    case LESS_THAN:
      cond_true ^= DO_COMPARE (<);
      break;
    case AND:
      cond_true ^= DO_COMPARE (&);
      break;
    default:
      assert (!"Unknown comparator");
    }

  return (cond_true ? jt : jf);
}

/**
 * Process return line if return $A or return NUMBER. Sets real_ret to
 * resolved plain result like KILL; returns a valid string if statement
 * need to add a comment.
 */
static void
return_line (statement_t *statement, bool quiet)
{
  static char formatted_val[0x28];

  obj_t *ret_obj = &statement->return_line.ret_obj;
  obj_t *real_obj = &statement->return_line.real_obj;
  int sz;
  const string_t *tkstr;

  // append addtional return value comment for
  // return $A and return NUMBER
  if (ret_obj->type == A)
    {
      real_obj->type = decode_return_k (real_obj, A_reg);
      tkstr = &token_pairs[real_obj->type];
      sz = snprintf (formatted_val, 0x28, "# $A = %#x, %.*s", A_reg,
                     tkstr->len, tkstr->start);
    }
  else if (ret_obj->type == NUMBER)
    {
      real_obj->type = decode_return_k (real_obj, ret_obj->data);
      tkstr = &token_pairs[real_obj->type];
      sz = snprintf (formatted_val, 0x28, "# %.*s", tkstr->len, tkstr->start);
    }
  else
    {
      // do nothing if ret_obj has KILL/ALLOW/TRACE type
      real_obj->type = ret_obj->type;
      real_obj->data = ret_obj->data;
      return;
    }

  register token_type tk = real_obj->type;
  if (tk == TRACE || tk == TRAP || tk == ERRNO)
    sz += snprintf (formatted_val + sz, 0x28 - sz, "(%u)", real_obj->data);
  assert (sz);

  if (!quiet)
    {
      statement->line_start = formatted_val;
      statement->line_len = sz;
      statement->comment = 0;
    }
  return;
}

static uint32_t
code_nr_to_text_nr (vector_t *text_v, vector_t *code_ptr_v, statement_t *cur,
                    label_t *jmp)
{
  if (jmp->key.len == 0) // if ... goto xxx; false case -> jmp.code_nr is NULL
    return cur->text_nr + 1;
  statement_t **ptr = get_vector (code_ptr_v, cur->code_nr + jmp->code_nr + 1);
  uint32_t text_nr = (*ptr)->text_nr;

  statement_t *statement;
  string_t *label_decl;
  uint32_t cur_line_nr = cur->text_nr; // compiler hint
  while (text_nr > cur_line_nr)
    {
      statement = get_vector (text_v, text_nr);

      label_decl = &statement->label_decl;
      if ((label_decl->start) && (label_decl->len == jmp->key.len)
          && (!strncmp (label_decl->start, jmp->key.start, jmp->key.len)))
        break;
      text_nr--;
    }
  assert (text_nr != cur_line_nr); // should find a tag to jump to
  return text_nr;
}

static void
print_label_decl (statement_t *statement)
{
  string_t *label_decl = &statement->label_decl;
  if (label_decl->start)
    {
      fwrite (label_decl->start, 1, label_decl->len, stdout);
      fputc (':', stdout);
      fputc (' ', stdout);
    }
}

static void
emulate_printer (statement_t *statement, bool is_skipped, bool quiet)
{
  if (quiet)
    return;

  bool global_color = color_enable;
  if (is_skipped && global_color)
    {
      fwrite (LIGHTCLR, 1, LITERAL_STRLEN (LIGHTCLR), stdout);
      push_color (false);
    }

  print_label_decl (statement);
  print_statement (stdout, statement);

  if (is_skipped && global_color)
    {
      pop_color ();
      fwrite (CLR, 1, LITERAL_STRLEN (CLR), stdout);
    }
}

static statement_t *
emulator (vector_t *text_v, vector_t *code_ptr_v, bool quiet)
{
  uint32_t read_idx = 1;
  uint32_t exec_idx = 1;
  label_t *jmp;

  statement_t *statement = NULL;
  for (; read_idx < text_v->count; read_idx++)
    {
      statement = get_vector (text_v, read_idx);

      if (read_idx < exec_idx)
        {
          emulate_printer (statement, true, quiet);
          continue;
        }

      exec_idx++;

      switch (statement->type)
        {
        case ASSIGN_LINE:
          if (assign_line (&statement->assign_line))
            goto out;
          break;
        case JUMP_LINE:
          jmp = jump_line (&statement->jump_line);
          exec_idx = code_nr_to_text_nr (text_v, code_ptr_v, statement, jmp);
          break;
        case RETURN_LINE:
          return_line (statement, quiet);
          goto out;
        case EMPTY_LINE:
          break;
        case EOF_LINE:
        case ERROR_LINE:
          assert (!"Emulating EOF/ERROR line??");
        }
      emulate_printer (statement, false, quiet);
    }

out:
  assert (statement);
  assert (statement->type == RETURN_LINE || statement->type == ASSIGN_LINE);
  return statement;
}

static void
init_attr (emu_arg_t *emu_arg)
{
  A_reg = 0;
  X_reg = 0;
  // mem must be written first to be read, so skip clearing them

  if (emu_arg->sys_name == NULL)
    error ("%s", M_INPUT_SYS_NR);
  syscall_nr = seccomp_syscall_resolve_name_arch (emu_arg->scmp_arch,
                                                  emu_arg->sys_name);

  if ((int32_t)syscall_nr == __NR_SCMP_ERROR)
    {
      char *end;
      uint64_t tmp = strtoull (emu_arg->sys_name, &end, 0);
      if (*end != '\0' || (uint32_t)tmp != tmp)
        error ("%s", M_INVALID_SYSNR);
      syscall_nr = tmp;
    }

  scmp_arch = emu_arg->scmp_arch;
  low_pc = emu_arg->ip & UINT32_MAX;
  high_pc = emu_arg->ip >> 32;
  for (uint32_t i = 0; i < 6; i++)
    {
      low_args[i] = emu_arg->args[i] & UINT32_MAX;
      high_args[i] = emu_arg->args[i] >> 32;
    }
}

void
emulate_v (vector_t *text_v, vector_t *code_ptr_v, emu_arg_t *emu_arg,
           FILE *output_fp)
{
  init_attr (emu_arg);

  statement_t *last = emulator (text_v, code_ptr_v, emu_arg->quiet);
  bool fpe = last->type == ASSIGN_LINE;
  uint32_t line_left = text_v->count - 1 - last->text_nr;

  if (!emu_arg->quiet)
    {
#define FPE_ERR_STR "# $X == 0, returning 0 (KILL) on FPE"
      if (UNLIKELY (fpe))
        {
          last->line_start = FPE_ERR_STR;
          last->comment = 0;
          last->line_len = LITERAL_STRLEN (FPE_ERR_STR);
        }
      emulate_printer (last, false, emu_arg->quiet);
      if (UNLIKELY (fpe))
        last->comment = -1;
#undef FPE_ERR_STR
      if (line_left)
        print_as_comment (output_fp, "... %u line(s) skipped", line_left);
    }
  else
    {
      if (fpe)
        {
          obj_t fpe_obj = { .type = KILL };
          extern_obj_printer (output_fp, &fpe_obj);
        }
      else
        extern_obj_printer (output_fp, &last->return_line.real_obj);
      fputc ('\n', output_fp);
    }
}

void
emulate (emu_arg_t *emu_arg)
{
  size_t lines = init_source (emu_arg->text_file) + 1;
  init_scanner (next_line ());
  init_parser (emu_arg->scmp_arch);
  init_table ();

  vector_t text_v;
  vector_t code_ptr_v;
  init_vector (&text_v, sizeof (statement_t), lines);
  init_vector (&code_ptr_v, sizeof (statement_t *),
               MIN (lines, BPF_MAXINSNS + 1));
  parser (&text_v, &code_ptr_v);
  if (resolver (&code_ptr_v))
    error ("%s", M_EMU_TERMINATED);
  // if ERROR_LINE exists, then exits

  emulate_v (&text_v, &code_ptr_v, emu_arg, stdout);

  free_table ();
  free_source ();
  free_vector (&text_v);
  free_vector (&code_ptr_v);
}
