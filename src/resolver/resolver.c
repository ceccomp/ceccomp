#include "resolver/resolver.h"
#include "attributes.h"
#include "lexical/parser.h"
#include "lexical/token.h"
#include "utils/error.h"
#include "utils/hash.h"
#include "utils/logger.h"
#include "utils/vector.h"
#include <assert.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool has_error;
static statement_t *local;
static uint16_t *masks, mem_valid = 0;
static uint16_t bpf_len = 0;

#define REPORT_ERROR(error_msg)                                               \
  do                                                                          \
    {                                                                         \
      report_error (error_msg);                                               \
      return;                                                                 \
    }                                                                         \
  while (0)

#define SPRINTF_CAT(...) print += sprintf (print, __VA_ARGS__)

static void
report_error (const char *error_msg)
{
  has_error = true;
  char buf[0x400];
  char *print = buf;

  SPRINTF_CAT ("%hu:-: %s\n", local->text_nr, error_msg);
  // During the resolution phase, errors do not have a clear starting point
  // errors in this stage indicate a semantic error in an entire line of code.
  SPRINTF_CAT ("%.*s\n", local->line_len, local->line_start);
  // line_len shouldn't include a '\n'
  memset (print, '~', local->line_len);
  print[local->line_len] = '\0';
  // warn will print a '\n'

  warn ("%s", buf);
}

AttrConst static bool
match_from_to (token_type type, token_type from, token_type to)
{
  return type >= from && type <= to;
}

static void
error_line (void)
{
  has_error = true;
  char buf[0x400];
  char *print = buf;

  const error_line_t *error_line = &local->error_line;

  uint16_t err_len = error_line->error_start - local->line_start;
  SPRINTF_CAT ("%hu:%hu: %s\n", local->text_nr, err_len + 1,
               error_line->error_msg);
  SPRINTF_CAT ("%.*s\n", local->line_len, local->line_start);
  // line_len shouldn't include a '\n'
  memset (print, ' ', err_len);
  print[err_len] = '^';
  print[err_len + 1] = '\0';
  // warn will print a '\n'

  warn ("%s", buf);
}
#undef SPRINTF_CAT

#define IS_ARG_OUT_RANGE(obj) is_out_range (obj, 5)
#define IS_MEM_OUT_RANGE(obj) is_out_range (obj, 15)

AttrPure static bool
is_out_range (const obj_t *obj, uint32_t max_idx)
{
  return obj->data > max_idx;
}

static void
assign_A (const assign_line_t *assign_line)
{
  token_type operator = assign_line->operator;
  const obj_t *right = &assign_line->right_var;

  if (operator == NEGATIVE)
    {
      if (right->type != A)
        REPORT_ERROR (M_RIGHT_SHOULD_BE_A);
      return;
    }
  else if (match_from_to (operator, ADD_TO, XOR_TO))
    {
      if (right->type != X && right->type != NUMBER)
        REPORT_ERROR (M_RIGHT_SHOULD_BE_X_OR_NUM);

      if (operator == DIVIDE_TO && right->type == NUMBER && right->data == 0)
        REPORT_ERROR (M_ALU_DIV_BY_ZERO);

      // clang-format off
      if (match_from_to (operator, LSH_TO, RSH_TO) &&
          right->type == NUMBER && right->data >= 32)
        // clang-format on
        REPORT_ERROR (M_ALU_SH_OUT_OF_RANGE);
      return;
    }

  assert (operator == EQUAL);

  if (right->type == A)
    REPORT_ERROR (M_RIGHT_CAN_NOT_BE_A);
  else if ((right->type == ATTR_LOWARG || right->type == ATTR_HIGHARG)
           && IS_ARG_OUT_RANGE (right))
    REPORT_ERROR (M_ARGS_IDX_OUT_OF_RANGE);
  else if (right->type == MEM)
    {
      if (IS_MEM_OUT_RANGE (right))
        REPORT_ERROR (M_MEM_IDX_OUT_OF_RANGE);
      if (!(mem_valid & (1 << right->data)))
        REPORT_ERROR (M_UNINITIALIZED_MEM);
    }
}

static void
assign_X (const assign_line_t *assign_line)
{
  const token_type *operator = &assign_line->operator;
  const obj_t *right = &assign_line->right_var;

  if (*operator != EQUAL)
    REPORT_ERROR (M_OPERATOR_SHOULD_BE_EQUAL);

  if (match_from_to (right->type, ATTR_SYSCALL, ATTR_HIGHARG))
    REPORT_ERROR (M_LEFT_SHOULD_BE_A);

  else if (right->type == X)
    REPORT_ERROR (M_RIGHT_CAN_NOT_BE_X);
  else if ((right->type == ATTR_LOWARG || right->type == ATTR_HIGHARG)
           && IS_ARG_OUT_RANGE (right))
    REPORT_ERROR (M_ARGS_IDX_OUT_OF_RANGE);
  else if (right->type == MEM)
    {
      if (IS_MEM_OUT_RANGE (right))
        REPORT_ERROR (M_MEM_IDX_OUT_OF_RANGE);
      if (!(mem_valid & (1 << right->data)))
        REPORT_ERROR (M_UNINITIALIZED_MEM);
    }
}

static void
assign_MEM (const assign_line_t *assign_line)
{
  const obj_t *left = &assign_line->left_var;
  token_type operator = assign_line->operator;
  const obj_t *right = &assign_line->right_var;

  if (operator != EQUAL)
    REPORT_ERROR (M_OPERATOR_SHOULD_BE_EQUAL);

  if (IS_MEM_OUT_RANGE (left))
    REPORT_ERROR (M_MEM_IDX_OUT_OF_RANGE);

  if (right->type != A && right->type != X)
    REPORT_ERROR (M_RIGHT_SHOULD_BE_A_OR_X);

  mem_valid |= (1 << left->data);
}

static void
assign_line (void)
{
  const assign_line_t *assign_line = &local->assign_line;
  if (assign_line->left_var.type == A)
    assign_A (assign_line);
  else if (assign_line->left_var.type == X)
    assign_X (assign_line);
  else if (assign_line->left_var.type == MEM)
    assign_MEM (assign_line);
}

static void
set_jt_jf (label_t *label, uint32_t code_nr)
{
  label->code_nr = code_nr - local->code_nr - 1;
}

static void
jump_line (void)
{
  jump_line_t *jump_line = &local->jump_line;

  if (!jump_line->if_condition)
    {
      uint32_t jt = find_key (&jump_line->jt.key);
      if (jt == (uint16_t)-1)
        REPORT_ERROR (M_CANNOT_FIND_LABEL);
      else if (jt > bpf_len)
        REPORT_ERROR (M_JA_OUT_OF_FILTERS);
      set_jt_jf (&jump_line->jt, jt);

      if ((int16_t)jump_line->jt.code_nr < 0)
        REPORT_ERROR (M_JA_MUST_BE_POSITIVE);

      masks[jt] &= mem_valid;
      mem_valid = ~0;
      return;
    }

  uint32_t jt = find_key (&jump_line->jt.key);
  if (jt == (uint16_t)-1)
    REPORT_ERROR (M_CANNOT_FIND_LABEL);
  set_jt_jf (&jump_line->jt, jt);

  if ((int16_t)jump_line->jt.code_nr < 0)
    REPORT_ERROR (M_JT_MUST_BE_POSITIVE);
  if (jump_line->jt.code_nr > UINT8_MAX)
    REPORT_ERROR (M_JT_TOO_FAR);
  if (jt > bpf_len)
    REPORT_ERROR (M_JT_INVALID_TAG);

  uint32_t jf;
  if (jump_line->jf.key.start == NULL)
    jf = local->code_nr + 1;
  else
    {
      jf = find_key (&jump_line->jf.key);
      if (jf == (uint16_t)-1)
        REPORT_ERROR (M_CANNOT_FIND_LABEL);
    }

  set_jt_jf (&jump_line->jf, jf);

  jf = local->code_nr + jump_line->jf.code_nr + 1;
  if ((int16_t)jump_line->jf.code_nr < 0)
    REPORT_ERROR (M_JF_MUST_BE_POSITIVE);
  if (jump_line->jf.code_nr > UINT8_MAX)
    REPORT_ERROR (M_JF_TOO_FAR);
  if (jf > bpf_len)
    REPORT_ERROR (M_JF_INVALID_TAG);

  masks[jt] &= mem_valid;
  masks[jf] &= mem_valid;
  mem_valid = ~0;
}

static void
return_line (void)
{
  const return_line_t *return_line = &local->return_line;
  token_type ret_type = return_line->ret_obj.type;
  if (ret_type == A || ret_type == NUMBER)
    return;

  if ((ret_type == TRACE || ret_type == TRAP || ret_type == ERRNO)
      && return_line->ret_obj.data > 0xffff)
    REPORT_ERROR (M_RET_DATA_OVERFLOW);
  // Don't assume the ret_obj.data == zero when not used
}

static void
resolve_statement (statement_t *statement)
{
  local = statement;

  switch (local->type)
    {
    case ERROR_LINE:
      error_line ();
      return;
    case ASSIGN_LINE:
      assign_line ();
      return;
    case JUMP_LINE:
      jump_line ();
      return;
    case RETURN_LINE:
      return_line ();
      return;
    // nothing need to be done for these line
    case EMPTY_LINE:
    case EOF_LINE:
      assert (!"Resolving EMPTY_LINE/EOF_LINE??");
    }
}

bool
resolver (vector_t *code_ptr_v)
{
  has_error = false;

  masks = reallocate (NULL, sizeof (*masks) * (code_ptr_v->count));
  memset (masks, 0xff, sizeof (*masks) * (code_ptr_v->count));
  mem_valid = 0;

  bpf_len = code_ptr_v->count - 1;
  if (bpf_len == 0)
    error ("%s", M_NO_VALID_CODE);

  for (uint32_t i = 1; i < code_ptr_v->count; i++)
    {
      mem_valid &= masks[i];
      statement_t **ptr = get_vector (code_ptr_v, i);
      resolve_statement (*ptr);
    }

  statement_t **last = get_vector (code_ptr_v, code_ptr_v->count - 1);
  if ((*last)->type != RETURN_LINE)
    report_error (M_MUST_END_WITH_RET);

  reallocate (masks, 0x0);

  return has_error;
}
