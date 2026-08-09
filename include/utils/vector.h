#ifndef VECTOR_H
#define VECTOR_H

#include <stddef.h>
#include <stdint.h>

// A vector store statement ordered by code_nr
// A vector stores statement_t ptr ordered by text_nr

// code_nr and text_nr both starts from 1
// statement at index 0 should be ignored

// eof_lines won't be in the vector

typedef struct
{
  uint32_t count;
  uint32_t capacity;
  size_t elem_size;
  void *data;
} vector_t;

extern void *reallocate (void *p, size_t new_size);

// set initial_capcity to 0 to let vector grow itself
extern void init_vector (vector_t *v, size_t elem_size,
                         size_t initial_capcity);

extern void free_vector (vector_t *v);

extern void *push_vector (vector_t *v, const void *elem);

extern void *get_vector (vector_t *v, uint32_t idx);

#endif
