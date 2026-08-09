#ifndef HASH_H
#define HASH_H

#include "main.h"
#include <stddef.h>
#include <stdint.h>

typedef string_t hkey_t;

// return 0 if successfully inserted; -1 for ENOMEM; 1 for duplicated key
extern int insert_key (const hkey_t *key, uint16_t line_nr);

extern uint16_t find_key (const hkey_t *key);

extern void init_table (void);

extern void free_table (void);

#endif
