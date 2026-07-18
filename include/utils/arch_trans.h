#ifndef ARCH_TRANS_H
#define ARCH_TRANS_H

#include "lexical/token.h"
#include "main.h"
#include <seccomp.h>
#include <stdbool.h>
#include <stdint.h>

extern uint32_t internal_arch_to_scmp_arch (uint32_t internal_arch);

extern uint32_t scmp_arch_to_internal_arch (uint32_t scmp_arch);

extern uint32_t str_to_scmp_arch (const char *str, bool strict);

extern token_type str_to_internal_arch (const char *str, bool strict);

extern const string_t *scmp_arch_to_internal_str (uint32_t scmp_arch);

extern const char *scmp_arch_to_scmp_str (uint32_t scmp_arch);

#endif
