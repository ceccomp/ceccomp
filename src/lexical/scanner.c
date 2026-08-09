#include "lexical/scanner.h"
#include "attributes.h"
#include "config.h"
#include "lexical/token.h"
#include "main.h"
#include "utils/arch_trans.h"
#include "utils/read_source.h"
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static scanner_t scanner;
static uint8_t unknown_count = 0;

#define INIT_TOKEN(type)                                                      \
  do                                                                          \
    {                                                                         \
      init_token (token, &scanner, type);                                     \
      return;                                                                 \
    }                                                                         \
  while (0)
#define INIT_TOKEN_DATA(type, data)                                           \
  do                                                                          \
    {                                                                         \
      init_token_data (token, &scanner, type, data);                          \
      return;                                                                 \
    }                                                                         \
  while (0)
#define INIT_TOKEN_ADV1(type)                                                 \
  do                                                                          \
    {                                                                         \
      advance (1);                                                            \
      INIT_TOKEN (type);                                                      \
    }                                                                         \
  while (0)

AttrPure static inline bool
isidentifier (char c)
{
  return isalnum_l (c, lc_c) || c == '_';
}

static char
peek (uint32_t offset)
{
  return scanner.current_char[offset];
}

static void
advance (uint16_t advance_len)
{
  scanner.current_char += advance_len;
}

static bool
match_offset (char expected, uint32_t offset)
{
  if (peek (offset) != expected)
    return false;

  advance (offset + 1);
  return true;
}

static bool
match (char expected)
{
  return match_offset (expected, 0);
}

static bool
match_token (token_type tk)
{
  register string_t token = token_pairs[tk];
  if (strncmp (token.start, scanner.current_char, token.len))
    return false;
  if (UNLIKELY (isidentifier (peek (token.len))))
    return false;

  advance (token.len);
  return true;
}

// from and to all included
static token_type
match_token_range (token_type from, token_type to)
{
  for (uint32_t i = from; i <= to; i++)
    if (match_token (i))
      return i;
  return UNKNOWN;
}

static void
reset_to_nextline (token_t *token)
{
  init_token (token, &scanner, EOL);

  // if nextline == NULL, it means we meet_eof
  char *nextline = next_line ();
  scanner.token_start = nextline;
  scanner.current_char = scanner.token_start;
  scanner.line_nr++;
}

void
init_scanner (char *start)
{
  scanner.token_start = start;
  scanner.current_char = start;
  scanner.line_nr = 1;
}

void
scan_token (token_t *token)
{
  // if scanner.token_start == NULL, we meet_eof
  if (scanner.token_start == NULL)
    INIT_TOKEN (TOKEN_EOF);

  // skip spaces
  while (isspace_l (peek (0), lc_c) && peek (0) != '\n')
    advance (1);

  // sync
  scanner.token_start = scanner.current_char;

  // COMMENT
  if (match ('#'))
    {
      while (peek (0) != '\n')
        advance (1);
      INIT_TOKEN (COMMENT);
    }

  // EOL
  if (match ('\n'))
    {
      reset_to_nextline (token);
      return;
    }

  char cur_char = peek (0);
  if (islower_l (cur_char, lc_c))
    {
      token_type tk = match_token_range (RETURN, ELSE);
      if (tk != UNKNOWN)
        INIT_TOKEN (tk);
      tk = str_to_internal_arch (scanner.current_char, false);
      if (tk != UNKNOWN && !isidentifier (peek (token_pairs[tk].len)))
        {
          advance (token_pairs[tk].len);
          INIT_TOKEN (tk);
        }
    }
  else if (isupper_l (cur_char, lc_c))
    {
      token_type tk = match_token_range (KILL_PROC, ERRNO);
      if (tk != UNKNOWN)
        INIT_TOKEN (tk);
    }
  else if (ispunct_l (cur_char, lc_c))
    {
      switch (cur_char)
        {
        case '$':
          if (match_offset ('A', 1))
            INIT_TOKEN (A);
          if (match_offset ('X', 1))
            INIT_TOKEN (X);
          token_type tk = match_token_range (MEM, ATTR_HIGHARG);
          if (tk != UNKNOWN)
            INIT_TOKEN (tk);
          break;
        case ',':
          INIT_TOKEN_ADV1 (COMMA);
        case '.':
          INIT_TOKEN_ADV1 (DOT);
        case '[':
          INIT_TOKEN_ADV1 (LEFT_BRACKET);
        case ']':
          INIT_TOKEN_ADV1 (RIGHT_BRACKET);
        case '(':
          INIT_TOKEN_ADV1 (LEFT_PAREN);
        case ')':
          INIT_TOKEN_ADV1 (RIGHT_PAREN);
        case '+':
          if (match_offset ('=', 1))
            INIT_TOKEN (ADD_TO);
          break;
        case '-':
          if (match_offset ('=', 1))
            INIT_TOKEN (SUB_TO);
          INIT_TOKEN_ADV1 (NEGATIVE);
        case '*':
          if (match_offset ('=', 1))
            INIT_TOKEN (MULTI_TO);
          break;
        case '/':
          if (match_offset ('=', 1))
            INIT_TOKEN (DIVIDE_TO);
          break;
        case '<':
          if (match_offset ('=', 1))
            INIT_TOKEN (LESS_EQUAL);
          if (peek (1) == '<' && match_offset ('=', 2))
            INIT_TOKEN (LSH_TO);
          INIT_TOKEN_ADV1 (LESS_THAN);
        case '>':
          if (match_offset ('=', 1))
            INIT_TOKEN (GREATER_EQUAL);
          if (peek (1) == '>' && match_offset ('=', 2))
            INIT_TOKEN (RSH_TO);
          INIT_TOKEN_ADV1 (GREATER_THAN);
        case '&':
          if (match_offset ('=', 1))
            INIT_TOKEN (AND_TO);
          INIT_TOKEN_ADV1 (AND);
        case '|':
          if (match_offset ('=', 1))
            INIT_TOKEN (OR_TO);
          break;
        case '^':
          if (match_offset ('=', 1))
            INIT_TOKEN (XOR_TO);
          break;
        case '!':
          if (match_offset ('=', 1))
            INIT_TOKEN (BANG_EQUAL);
          INIT_TOKEN_ADV1 (BANG);
        case '=':
          if (match_offset ('=', 1))
            INIT_TOKEN (EQUAL_EQUAL);
          INIT_TOKEN_ADV1 (EQUAL);
        }
      goto unknown;
    }

  // LABEL_DECL : IDENTIFIER
  // IDENTIFIER include SYSCALL and label
  // We don't want hash the SYSCALL, so leave it later
  if (isalpha_l (peek (0), lc_c))
    {
      do
        advance (1);
      while (isidentifier (peek (0)));

      INIT_TOKEN (match (':') ? LABEL_DECL : IDENTIFIER);
    }

  // NUMBER
  if (isdigit_l (peek (0), lc_c))
    {
      char *end;
      unsigned long num = strtoul (scanner.token_start, &end, 0);
      if (scanner.token_start == end)
        goto unknown;
#if __SIZEOF_POINTER__ == 8
      static_assert (sizeof (unsigned long) == 8,
                     "64-bit machine has 32-bit long?");
      if ((uint32_t)num != num)
        INIT_TOKEN_ADV1 (OVERFLOW_NUMBER);
#else
#include <errno.h>
      static_assert (sizeof (unsigned long) == 4,
                     "long is not 32-bit on 32-bit machine?");
      if (num == ULONG_MAX && errno == ERANGE)
        INIT_TOKEN_ADV1 (OVERFLOW_NUMBER);
#endif
      scanner.current_char = end;
      INIT_TOKEN_DATA (NUMBER, (uint32_t)num);
    }

unknown:
  // perhaps that's a wrong file? tell parser to stop using EOF
  if (unknown_count > 5)
    INIT_TOKEN (TOKEN_EOF);

  unknown_count += 1;
  advance (1);
  INIT_TOKEN (UNKNOWN);
}
