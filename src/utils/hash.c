#include "utils/hash.h"
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "attributes.h"
#include "lib/a5hash-5.25.h"

AttrPure static uint64_t
hash_hkey (hkey_t key)
{
#if __SIZEOF_POINTER__ == 8
  return a5hash (key.start, key.len, 0);
#else
  return a5hash32 (key.start, key.len, 0);
#endif
}

AttrPure static bool
cmpr_hkey (hkey_t key1, hkey_t key2)
{
  if (key1.len != key2.len)
    return false;
  return !memcmp (key1.start, key2.start, key1.len);
}

#define NAME str_table
#define KEY_TY hkey_t
#define VAL_TY uint16_t
#define HASH_FN hash_hkey
#define CMPR_FN cmpr_hkey
#include "lib/verstable-2.2.1.h"

str_table hash_table;

int
insert_key (const hkey_t *key, uint16_t line_nr)
{
  size_t prev_size = vt_size (&hash_table);
  str_table_itr itr = vt_get_or_insert (&hash_table, *key, line_nr);
  if (vt_is_end (itr))
    return -1;
  if (prev_size == vt_size (&hash_table))
    return 1;
  return 0;
}

uint16_t
find_key (const hkey_t *key)
{
  str_table_itr itr = vt_get (&hash_table, *key);
  if (vt_is_end (itr))
    return -1;
  return itr.data->val;
}

void
init_table (void)
{
  vt_init (&hash_table);
}

void
free_table (void)
{
  vt_cleanup (&hash_table);
}
