#ifndef PARSER_H
#define PARSER_H

#include "main.h"
#include "token.h"
#include "utils/hash.h"
#include "utils/vector.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct
{
  hkey_t key;
  uint16_t code_nr;
  // when key.string != NULL, key stores the label string
} label_t;

typedef struct
{
  token_type type;
  uint32_t data;
  string_t literal;
  // store idx for MEM | ATTR_LOWARG | ATTR_HIGHARG
  // store value for NUMBER | TRAP | TRACE | ERRNO
} obj_t;

typedef struct
{
  obj_t left_var;
  token_type operator;
  obj_t right_var;
  // if operator is NEGATIVE, then it should be A EQUAL NEGATIVE A
  // but EQUAL is skipped
} assign_line_t;

typedef enum __attribute__((packed)) {
    CMP_NUMBER = 0,
    CMP_ARCH = 1,
    CMP_SYSCALL = 2,
    CMP_ARCH_SYSCALL = 3,
} comparator_t;

typedef struct
{
  // token_t if;
  // jump_line_t must starts with if, so skip it
  bool if_bang;
  // if match '!' before jump_condition
  bool if_condition;
  // does condition exists
  // if true, jt and jf both uint16_t
  // else jt is uint32_t, jf is ignored

  comparator_t cmptype;

  // var A;
  // jump always compare A with something else, so skip it
  token_type comparator;
  obj_t cmpobj;

  label_t jt;
  label_t jf;
  // pc += (jump_condition ? jt : jf) + 1
  // pc += jt + 1
} jump_line_t;

typedef struct
{
  // token_type return
  // return_line_t must have return, so skip it
  obj_t ret_obj;
  obj_t real_obj; // only used in emu quiet
} return_line_t;

typedef void *empty_line_t;
typedef void *eof_line_t;

typedef struct
{
  char *error_start;
  const char *error_msg;
} error_line_t;

typedef enum
{
  ASSIGN_LINE,
  JUMP_LINE,
  RETURN_LINE,
  EMPTY_LINE,
  EOF_LINE,
  ERROR_LINE,
} expr_type;

typedef struct
{
  expr_type type;
  string_t label_decl;
  uint16_t text_nr;
  uint16_t code_nr;
  char *line_start;
  int16_t comment;
  uint16_t line_len;

  union
  {
    assign_line_t assign_line;
    jump_line_t jump_line;
    return_line_t return_line;
    empty_line_t empty_line;
    eof_line_t eof_line;
    error_line_t error_line;
  };
} statement_t;

extern void init_parser (uint32_t scmp_arch);

// see vector.h for vector details
extern void parser (vector_t *text_v, vector_t *code_ptr_v);

#endif
