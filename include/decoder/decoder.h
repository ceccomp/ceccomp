#ifndef DECODER_H
#define DECODER_H

#include "lexical/parser.h"
#include "lexical/token.h"
#include "main.h"
#include "utils/vector.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * prog: filters read from input
 * v:    initialized statement vector for decoded statements
 * trustful: filters extracted from kernel don't need check as kernel did that
 * Returns true if found any error
 */
extern bool decode_filters (const fprog *prog, vector_t *v, bool trustful);

extern token_type decode_return_k (obj_t *ret_obj, uint32_t k);

#endif
