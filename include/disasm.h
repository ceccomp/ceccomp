#ifndef DISASM_H
#define DISASM_H

#include "main.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

extern void print_prog (uint32_t scmp_arch, fprog *prog, FILE *output_fp,
                        bool trustful, bool from_ebpf);

extern void disasm (FILE *fp, uint32_t scmp_arch, bool ebpf);

extern filter *g_filters;

// return true if success or initialized
extern bool init_global_filters (uint32_t insn_count);

#endif
