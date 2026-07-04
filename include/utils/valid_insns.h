#ifndef VALID_INSNS_H
#define VALID_INSNS_H

#include <stdint.h>

#define MAX_VALID_INSN 172
/* A map maps insn code to index in insn_names. The size of the array is
 * exactly `MAX_VALID_INSN + 1`. If a insn code is valid, the corresponding
 * index is non-zero. */
extern const uint8_t insn_name_map[];

/* Convert insn code like BPF_ST to "BPF_ST". Assume `insn_code` is valid in
 * seccomp checks. */
const char *get_insn_name (int insn_code);

#endif
