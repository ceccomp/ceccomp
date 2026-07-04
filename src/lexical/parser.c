#include "lexical/parser.h"
#include "lexical/scanner.h"
#include "lexical/token.h"
#include "main.h"
#include "utils/arch_trans.h"
#include "utils/error.h"
#include "utils/hash.h"
#include "utils/logger.h"
#include "utils/vector.h"
#include <seccomp.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct
{
  uint16_t text_nr;
  uint16_t code_nr;

  token_t previous;
  token_t current;
  token_t next;
} parse_t;

static parse_t parse = { .text_nr = 0, .code_nr = 0 };
static statement_t *local;
static uint32_t local_arch;
static jmp_buf g_env;

static void error_at (token_t token, const char *err_msg);

static void
advance (void)
{
  parse.previous = parse.current;
  parse.current = parse.next;
  scan_token (&parse.next);
}

static bool
peek (token_type expected)
{
  return expected == parse.next.type;
}

static bool
peek_from_to (token_type from, token_type to)
{
  return parse.next.type >= from && parse.next.type <= to;
}

static bool
match (token_type expected)
{
  if (!peek (expected))
    return false;

  advance ();
  return true;
}

static bool
match_number (void)
{
  if (LIKELY (peek (NUMBER)))
    return advance (), true;
  if (peek (OVERFLOW_NUMBER))
    error_at (parse.next, M_NUMBER_OVERFLOW);
  return false;
}

static bool
match_from_to (token_type expected_start, token_type expected_end)
{
  if (!peek_from_to (expected_start, expected_end))
    return false;

  advance ();
  return true;
}

static void
error_at (token_t token, const char *err_msg)
{
  // sync to the nextline
  while (!(match (EOL) || peek (TOKEN_EOF)))
    advance ();

  local->type = ERROR_LINE;
  local->line_len = parse.current.token_start - local->line_start;
  local->error_line.error_start = token.token_start;
  local->error_line.error_msg = err_msg;
  longjmp (g_env, 1);
}

// paren_num can be ignored, default as 0
static uint32_t
paren_num (void)
{
  if (!match (LEFT_PAREN))
    return 0;
  if (!match_number ())
    error_at (parse.next, M_EXPECT_NUMBER);
  if (!match (RIGHT_PAREN))
    error_at (parse.next, M_EXPECT_PAREN);
  return parse.previous.data;
}

// but bracket_num can not be ignored
static uint32_t
bracket_num (void)
{
  if (!match (LEFT_BRACKET))
    error_at (parse.next, M_EXPECT_BRACKET);
  if (!match_number ())
    error_at (parse.next, M_EXPECT_NUMBER);
  if (!match (RIGHT_BRACKET))
    error_at (parse.next, M_EXPECT_BRACKET);
  return parse.previous.data;
}

static void
empty_line (void)
{
  local->type = EMPTY_LINE;
  parse.code_nr--;
  // empty_line doesn't count
  return;
}

static void
eof_line (void)
{
  local->type = EOF_LINE;
  return;
}

static void
return_line (void)
{
  local->type = RETURN_LINE;

  obj_t *obj = &local->return_line.ret_obj;
  obj->literal.start = parse.next.token_start;

  if (match_from_to (TRACE, ERRNO))
    {
      obj->type = parse.current.type;
      obj->data = paren_num ();
    }
  else if (match_number ())
    {
      obj->type = NUMBER;
      obj->data = parse.current.data;
    }
  else if (match_from_to (KILL_PROC, LOG) || match (A))
    obj->type = parse.current.type;
  else
    error_at (parse.next, M_EXPECT_RETURN_VAL);

  obj->literal.len = parse.current.token_start + parse.current.token_len
                     - obj->literal.start;
  // some obj consume more than one token like TRACE(0xf)
}

static void
label (label_t *label)
{
  if (!match (IDENTIFIER))
    error_at (parse.next, M_EXPECT_LABEL);

  label->key.start = parse.current.token_start;
  label->key.len = parse.current.token_len;
}

static uint32_t
resolve_name_arch (uint32_t arch_token, token_t *sys_token)
{
  char *sysname = sys_token->token_start;
  char *strend = sys_token->token_start + sys_token->token_len;
  char save = *strend;
  *strend = '\0';
  uint32_t sys_nr = seccomp_syscall_resolve_name_arch (arch_token, sysname);
  *strend = save;
  return sys_nr;
}

static void
compare_obj (obj_t *obj, comparator_t *cmptype)
{
  obj->literal.start = parse.next.token_start;
  obj->literal.len = parse.next.token_len;

  if (match (X))
    {
      obj->type = parse.current.type;
      return;
    }

  obj->type = NUMBER;

  if (match_number ())
    {
      obj->data = parse.current.data;
      return;
    }

  if (match (IDENTIFIER))
    {
      obj->data = resolve_name_arch (local_arch, &parse.current);
      if (obj->data == (uint32_t)-1)
        error_at (parse.current, M_EXPECT_SYSCALL);
      *cmptype = CMP_SYSCALL;
      return;
    }
  // read

  if (!match_from_to (ARCH_X86, ARCH_SH))
    error_at (parse.next, M_UNEXPECT_TOKEN);

  if (!match (DOT))
    {
      obj->data = internal_arch_to_scmp_arch (parse.current.type);
      if (UNLIKELY (obj->data == (uint32_t)-1))
        // libseccomp does not support input arch??
        error_at (parse.current, M_EXPECT_ARCH);
      *cmptype = CMP_ARCH;
      return;
    }
  // i386

  if (!peek (IDENTIFIER))
    error_at (parse.next, M_EXPECT_SYSCALL);

  uint32_t scmp_arch = internal_arch_to_scmp_arch (parse.previous.type);
  if (UNLIKELY (scmp_arch == (uint32_t)-1))
    // libseccomp does not support input arch??
    error_at (parse.previous, M_EXPECT_ARCH);
  obj->data = resolve_name_arch (scmp_arch, &parse.next);
  if (obj->data == (uint32_t)-1)
    error_at (parse.next, M_EXPECT_SYSCALL);
  *cmptype = CMP_ARCH_SYSCALL;

  obj->literal.len += parse.next.token_len + 1;
  // +1 is for dot
  advance ();
  // i386.read
}

static void
condition (jump_line_t *jump_line)
{
  jump_line->if_condition = true;

  if (match (BANG))
    jump_line->if_bang = true;

  if (!match (LEFT_PAREN))
    error_at (parse.next, M_EXPECT_PAREN);
  if (!match (A))
    error_at (parse.next, M_EXPECT_A);
  if (!match_from_to (EQUAL_EQUAL, AND))
    error_at (parse.next, M_EXPECT_COMPARTOR);
  jump_line->comparator = parse.current.type;

  compare_obj (&jump_line->cmpobj, &jump_line->cmptype);

  if (!match (RIGHT_PAREN))
    error_at (parse.next, M_EXPECT_PAREN);
}

static void
ja_line (void)
{
  local->type = JUMP_LINE;
  jump_line_t *jump_line = &local->jump_line;
  jump_line->if_condition = false;

  label (&jump_line->jt);
}

static void
jump_line (void)
{
  local->type = JUMP_LINE;
  jump_line_t *jump_line = &local->jump_line;

  condition (jump_line);

  if (!match (GOTO))
    error_at (parse.next, M_EXPECT_GOTO);

  label (&jump_line->jt);
  jump_line->jf.key.start = NULL;
  // jf default as zero

  if (!match (COMMA))
    return;
  // probably this jump_line has no jf

  if (!match (ELSE))
    error_at (parse.next, M_EXPECT_ELSE);
  if (!match (GOTO))
    error_at (parse.next, M_EXPECT_GOTO);

  label (&jump_line->jf);
}

static void
left (obj_t *obj)
{
  obj->type = parse.current.type;
  // expression checked for us, it must be A X MEM here
  obj->literal.start = parse.current.token_start;

  if (parse.current.type == MEM)
    obj->data = bracket_num ();

  obj->literal.len = parse.current.token_start + parse.current.token_len
                     - obj->literal.start;
  // some obj consume more than one token like mem[0xf]
}

static void
right (obj_t *obj)
{
  obj->literal.start = parse.next.token_start;

  if (match (A) || match (X) || match_from_to (ATTR_LEN, ATTR_HIGHPC))
    obj->type = parse.current.type;
  else if (match (MEM) || match (ATTR_LOWARG) || match (ATTR_HIGHARG))
    {
      obj->type = parse.current.type;
      obj->data = bracket_num ();
    }
  else if (match_number ())
    {
      obj->type = parse.current.type;
      obj->data = parse.current.data;
    }
  else
    error_at (parse.next, M_EXPECT_RIGHT_VAR);

  obj->literal.len = parse.current.token_start + parse.current.token_len
                     - obj->literal.start;
  // some obj consume more than one token like mem[0xf]
}

static void
assign_line (void)
{
  local->type = ASSIGN_LINE;
  assign_line_t *assign_line = &local->assign_line;

  left (&assign_line->left_var);

  if (match_from_to (ADD_TO, XOR_TO))
    assign_line->operator = parse.current.type;
  else if (match (EQUAL))
    {
      // if we match NEGATIVE, use NEGATIVE to overwrite operator
      // else use EQUAL as operator
      match (NEGATIVE);
      assign_line->operator = parse.current.type;
    }
  else
    error_at (parse.next, M_EXPECT_OPERATOR);

  right (&assign_line->right_var);
}

static void
expression (void)
{
  if (peek (EOL) || peek (COMMENT))
    empty_line ();
  else if (peek (TOKEN_EOF))
    eof_line ();
  else if (UNLIKELY (parse.code_nr > BPF_MAXINSNS))
    error ("%s", M_STATEMENT_OVERFLOW);
  else if (match (RETURN))
    return_line ();
  else if (match (IF))
    jump_line ();
  else if (match (GOTO))
    ja_line ();
  else if (match_from_to (A, MEM))
    assign_line ();
  else
    error_at (parse.next, M_UNEXPECT_TOKEN);

  if (match (COMMENT))
    local->comment = parse.current.token_start - local->line_start;
  else
    local->comment = -1;

  if (match (EOL))
    local->line_len = parse.current.token_start - local->line_start;
  else if (peek (TOKEN_EOF))
    local->line_len = parse.next.token_start - local->line_start;
  else
    error_at (parse.next, M_UNEXPECT_TOKEN);
}

static void
label_decl (string_t *label_decl)
{
  if (!match (LABEL_DECL))
    return;

  label_decl->start = parse.current.token_start;
  label_decl->len = parse.current.token_len - 1;
  // ignore the ':' character
  if (insert_key (label_decl, parse.code_nr) == 1)
    error_at (parse.current, M_DUPLICATED_LABEL);

  // ignore our disasm useless output
  uint32_t count = 0;
  while (match_number () && count < 4)
    count++;
}

static void
parse_line (statement_t *statement)
{
  local = statement;
  memset (local, 0, sizeof (statement_t));

  parse.text_nr++;
  parse.code_nr++;
  // if statement turns out to be empty_line, code_line--;
  local->code_nr = parse.code_nr;
  local->text_nr = parse.text_nr;
  local->label_decl.start = NULL;
  // label_decl.string default as NULL

  local->line_start = parse.next.token_start;

  if (setjmp (g_env) == 1)
    return;

  label_decl (&statement->label_decl);
  expression ();

  return;
}

void
init_parser (uint32_t scmp_arch)
{
  advance ();
  local_arch = scmp_arch;
}

void
parser (vector_t *text_v, vector_t *code_ptr_v)
{
  statement_t statement = { 0 };
  statement_t *ptr = &statement;
  push_vector (text_v, &statement);
  push_vector (code_ptr_v, &ptr);
  while (true)
    {
      parse_line (&statement);

      if (statement.type == EOF_LINE)
        break;
      push_vector (text_v, &statement);
    }

  // we have to do it after text vector finish
  // because text vector might reallocate
  for (uint32_t i = 1; i < text_v->count; i++)
    {
      ptr = get_vector (text_v, i);
      if (ptr->type == EMPTY_LINE)
        continue;
      push_vector (code_ptr_v, &ptr);
    }
}
