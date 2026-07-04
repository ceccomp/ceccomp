#include "lexical/token.h"
#include "lexical/scanner.h"
#include "main.h"
#include <stddef.h>
#include <stdint.h>

#define DEFTK(token) { token, LITERAL_STRLEN (token) }
// clang-format off
const string_t token_pairs[] = {
  [ARCH_X86] = DEFTK ("i386"), [ARCH_I686] = DEFTK ("i686"), [ARCH_X86_64] = DEFTK ("x86_64"),
  [ARCH_X32] = DEFTK ("x32"), [ARCH_AARCH64] = DEFTK ("aarch64"),
  [ARCH_ARMV8L] = DEFTK("armv8l"), [ARCH_ARMV7L] = DEFTK("armv7l"), [ARCH_ARM] = DEFTK ("arm"),
  [ARCH_LOONGARCH64] = DEFTK ("loongarch64"), [ARCH_M68K] = DEFTK ("m68k"),
  [ARCH_MIPSEL64N32] = DEFTK ("mipsel64n32"), [ARCH_MIPSEL64] = DEFTK ("mipsel64"),
  [ARCH_MIPSEL] = DEFTK ("mipsel"), [ARCH_MIPS64N32] = DEFTK ("mips64n32"),
  [ARCH_MIPS64] = DEFTK ("mips64"), [ARCH_MIPS] = DEFTK ("mips"),
  [ARCH_PARISC64] = DEFTK ("parisc64"), [ARCH_PARISC] = DEFTK ("parisc"),
  [ARCH_PPC64LE] = DEFTK ("ppc64le"), [ARCH_PPC64] = DEFTK ("ppc64"), [ARCH_PPC] = DEFTK ("ppc"),
  [ARCH_S390X] = DEFTK ("s390x"), [ARCH_S390] = DEFTK ("s390"), [ARCH_RISCV64] = DEFTK ("riscv64"),
  [ARCH_SH4] = DEFTK ("sh4"), [ARCH_SHEB] = DEFTK ("sheb"), [ARCH_SH] = DEFTK ("sh"),

  [KILL_PROC] = DEFTK ("KILL_PROCESS"), [KILL] = DEFTK ("KILL"), [ALLOW] = DEFTK ("ALLOW"),
  [NOTIFY] = DEFTK ("NOTIFY"), [LOG] = DEFTK ("LOG"), [TRACE] = DEFTK ("TRACE"),
  [TRAP] = DEFTK ("TRAP"), [ERRNO] = DEFTK ("ERRNO"),

  [RETURN] = DEFTK ("return"), [IF] = DEFTK ("if"), [GOTO] = DEFTK ("goto"),
  [ELSE] = DEFTK ("else"), [COMMA] = DEFTK (","),

  [A] = DEFTK ("$A"), [X] = DEFTK ("$X"), [MEM] = DEFTK ("$mem"),
  [ATTR_LEN] = DEFTK ("$scmp_data_len"), [ATTR_SYSCALL] = DEFTK ("$syscall_nr"),
  [ATTR_ARCH] = DEFTK ("$arch"), [ATTR_LOWPC] = DEFTK ("$low_pc"),
  [ATTR_HIGHPC] = DEFTK ("$high_pc"), [ATTR_LOWARG] = DEFTK ("$low_args"),
  [ATTR_HIGHARG] = DEFTK ("$high_args"),

  [DOT] = DEFTK ("."),

  [LEFT_BRACKET] = DEFTK ("["), [RIGHT_BRACKET] = DEFTK ("]"), [LEFT_PAREN] = DEFTK ("("),
  [RIGHT_PAREN] = DEFTK (")"), [ADD_TO] = DEFTK ("+="), [SUB_TO] = DEFTK ("-="),
  [MULTI_TO] = DEFTK ("*="), [DIVIDE_TO] = DEFTK ("/="), [LSH_TO] = DEFTK ("<<="),
  [RSH_TO] = DEFTK (">>="), [AND_TO] = DEFTK ("&="), [OR_TO] = DEFTK ("|="),
  [XOR_TO] = DEFTK ("^="),

  [EQUAL_EQUAL] = DEFTK ("=="), [BANG_EQUAL] = DEFTK ("!="), [GREATER_EQUAL] = DEFTK (">="),
  [GREATER_THAN] = DEFTK (">"), [LESS_EQUAL] = DEFTK ("<="), [LESS_THAN] = DEFTK ("<"),
  [AND] = DEFTK ("&"), [EQUAL] = DEFTK ("="), [NEGATIVE] = DEFTK ("-"),
  [BANG] = DEFTK ("!"),

  [NUMBER] = DEFTK ("number"), [IDENTIFIER] = DEFTK ("identifier"),
  [UNKNOWN] = DEFTK ("unknown"), [COMMENT] = DEFTK ("#"),
  [EOL] = DEFTK ("line_end"), [TOKEN_EOF] = DEFTK ("eof"),
  [LABEL_DECL] = DEFTK ("label_decl"), [OVERFLOW_NUMBER] = DEFTK("ERANGE"),
  // label_decl ::= IDENTIFIER + DEFTK(":")
};
// clang-format on

void
init_token (token_t *token, scanner_t *scanner, token_type type)
{
  token->type = type;
  token->token_start = scanner->token_start;
  token->token_len = scanner->current_char - scanner->token_start;
  token->line_nr = scanner->line_nr;
}

void
init_token_data (token_t *token, scanner_t *scanner, token_type type,
                 uint32_t data)
{
  init_token (token, scanner, type);
  token->data = data;
}
