#include "decoder/formatter.h"
#include "lexical/parser.h"
#include "lexical/token.h"
#include "main.h"
#include "utils/color.h"
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

FILE *fp;

static void
print_num (const obj_t *tk)
{
  if (tk->literal.start != NULL)
    fwrite (tk->literal.start, 1, tk->literal.len, fp);
  else
    fprintf (fp, "0x%x", tk->data);
}

static void
print_str (const obj_t *tk)
{
  fwrite (token_pairs[tk->type].start, 1, token_pairs[tk->type].len, fp);
}

static void
print_identifier (const obj_t *tk)
{
  fwrite (tk->literal.start, 1, tk->literal.len, fp);
}

static void
print_dec_bracket (const obj_t *tk)
{
  fwrite (token_pairs[tk->type].start, 1, token_pairs[tk->type].len, fp);
  fprintf (fp, "[%u]", tk->data);
}

static void
print_hex_bracket (const obj_t *tk)
{
  fwrite (token_pairs[tk->type].start, 1, token_pairs[tk->type].len, fp);
  fprintf (fp, "[0x%x]", tk->data);
}

static void
print_paren (const obj_t *tk)
{
  fwrite (token_pairs[tk->type].start, 1, token_pairs[tk->type].len, fp);
  fprintf (fp, "(%u)", tk->data);
}

static const obj_print_t obj_print[] = {
  [A] = { print_str, BRIGHT_YELLOWCLR },
  [X] = { print_str, BRIGHT_YELLOWCLR },

  [MEM] = { print_hex_bracket, BRIGHT_YELLOWCLR },
  [ATTR_LOWARG] = { print_dec_bracket, BRIGHT_BLUECLR },
  [ATTR_HIGHARG] = { print_dec_bracket, BRIGHT_BLUECLR },

  [ATTR_SYSCALL] = { print_str, BRIGHT_BLUECLR },
  [ATTR_ARCH] = { print_str, BRIGHT_BLUECLR },
  [ATTR_LOWPC] = { print_str, BRIGHT_BLUECLR },
  [ATTR_HIGHPC] = { print_str, BRIGHT_BLUECLR },
  [ATTR_LEN] = { print_str, BRIGHT_BLUECLR },
  [IDENTIFIER] = { print_identifier, BRIGHT_CYANCLR },

  [NUMBER] = { print_num, BRIGHT_CYANCLR },

  [KILL_PROC] = { print_str, REDCLR },
  [KILL] = { print_str, REDCLR },
  [ALLOW] = { print_str, GREENCLR },
  [NOTIFY] = { print_str, YELLOWCLR },
  [LOG] = { print_str, YELLOWCLR },
  [TRACE] = { print_paren, YELLOWCLR },
  [TRAP] = { print_paren, YELLOWCLR },
  [ERRNO] = { print_paren, REDCLR },
};

static void
obj_printer (const obj_t *obj)
{
  if (color_enable)
    fprintf (fp, "%s", obj_print[obj->type].color);
  obj_print[obj->type].handler (obj);
  if (color_enable)
    fprintf (fp, "%s", CLR);
}

void
extern_obj_printer (FILE *output_fp, const obj_t *obj)
{
  fp = output_fp;
  obj_printer (obj);
}

static inline void
print_token_pair (token_type type)
{
  fwrite (token_pairs[type].start, 1, token_pairs[type].len, fp);
}

static void
assign_line (const statement_t *statement)
{
  const assign_line_t *line = &statement->assign_line;
  const obj_t *left = &line->left_var;
  const obj_t *right = &line->right_var;

  obj_printer (left);
  fputc (' ', fp);
  if (line->operator == NEGATIVE)
    fprintf (fp, "= -");
  else
    {
      print_token_pair (line->operator);
      fputc (' ', fp);
    }

  obj_printer (right);
}

static inline void
print_label (const label_t *label, uint16_t pc)
{
  if (label->key.start == NULL)
    fprintf (fp, DEFAULT_LABEL, pc + label->code_nr + 1);
  else
    fwrite (label->key.start, 1, label->key.len, fp);
}

static void
print_ja (const statement_t *statement)
{
  print_token_pair (GOTO);
  fputc (' ', fp);
  print_label (&statement->jump_line.jt, statement->code_nr);
}

static void
jump_line (const statement_t *statement)
{
  const jump_line_t *line = &statement->jump_line;
  if (!line->if_condition)
    {
      print_ja (statement);
      return;
    }

  print_token_pair (IF);
  fputc (' ', fp);
  if (line->if_bang)
    print_token_pair (BANG);
  print_token_pair (LEFT_PAREN);
  obj_t obj_A = { .type = A, .data = 0 };
  obj_printer (&obj_A);
  fputc (' ', fp);
  print_token_pair (line->comparator);
  fputc (' ', fp);
  obj_printer (&line->cmpobj);
  print_token_pair (RIGHT_PAREN);
  fputc (' ', fp);
  print_token_pair (GOTO);
  fputc (' ', fp);
  print_label (&line->jt, statement->code_nr);

  if (line->jf.code_nr == 0)
    return;

  print_token_pair (COMMA);
  fputc (' ', fp);
  print_token_pair (ELSE);
  fputc (' ', fp);
  print_token_pair (GOTO);
  fputc (' ', fp);
  print_label (&line->jf, statement->code_nr);
}

static void
return_line (const statement_t *statement)
{
  print_token_pair (RETURN);
  fputc (' ', fp);
  obj_printer (&statement->return_line.ret_obj);
}

static void
print_comment (const statement_t *statement)
{
  if (statement->comment == -1)
    return;

  const char *comment_start = statement->line_start + statement->comment;
  uint16_t comment_len = statement->line_len - statement->comment;
  if (comment_len == 0)
    return;
  if (statement->type != EMPTY_LINE)
    fputc (' ', fp); // prepend a ' ' if a effective line (return 1 # aa)
  if (color_enable)
    fwrite (LIGHTCLR, 1, LITERAL_STRLEN (LIGHTCLR), fp);
  fwrite (comment_start, 1, comment_len, fp);
  if (color_enable)
    fwrite (CLR, 1, LITERAL_STRLEN (CLR), fp);
}

void
print_as_comment (FILE *output_fp, const char *comment_fmt, ...)
{
  fp = output_fp;

  va_list args;
  va_start (args, comment_fmt);

  char buf[0x400];
  buf[0] = '#';
  statement_t statement
      = { .type = EMPTY_LINE, .line_start = buf, .comment = 0 };
  statement.line_len = vsnprintf (buf + 1, 0x3ff, comment_fmt, args) + 1;

  print_comment (&statement);
  fputc ('\n', fp);

  va_end (args);
}

void
print_statement (FILE *output_fp, const statement_t *statement)
{
  fp = output_fp;

  switch (statement->type)
    {
    case ASSIGN_LINE:
      assign_line (statement);
      break;
    case JUMP_LINE:
      jump_line (statement);
      break;
    case RETURN_LINE:
      return_line (statement);
      break;
    case EMPTY_LINE:
      break;
    case ERROR_LINE:
    case EOF_LINE:
      assert (0);
    }
  print_comment (statement);
  fputc ('\n', fp);
}
