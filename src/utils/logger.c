#include "utils/logger.h"
#include "main.h"
#include "utils/color.h"
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define PREFIX_STR(type_str) "[" type_str "]: "
#define PREFIX_INIT(type, colorstr)                                           \
  [LV_##type] = { PREFIX_STR (#type), colorstr PREFIX_STR (#type) CLR }
static const struct print_prefix_t
{
  const char *raw;
  const char *colorful;
} print_prefixes[LV_ERROR + 1] = {
  PREFIX_INIT (DEBUG, CYANCLR),
  PREFIX_INIT (INFO, BLUECLR),
  PREFIX_INIT (WARN, YELLOWCLR),
  PREFIX_INIT (ERROR, REDCLR),
};

int
ceccomp_vprint (bool from_external, print_level_t lv, const char *caller_func,
                const char *fmt, va_list args)
{
  assert (lv <= LV_ERROR);
  const struct print_prefix_t *prefix = print_prefixes + lv;
  fprintf (stderr, "%s", log_color_enable ? prefix->colorful : prefix->raw);

#ifdef DEBUG
  if (LIKELY (!from_external))
    fprintf (stderr, "in %s: ", caller_func);
#else
  (void)caller_func;
#endif

  int rc = vfprintf (stderr, fmt, args);
  if (LIKELY (!from_external))
    putc ('\n', stderr);
  fflush (stderr);
  return rc;
}

void
info_print (print_level_t lv, const char *caller_func, const char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);

  ceccomp_vprint (false, lv, caller_func, fmt, args);

  va_end (args);
}

void
error_print (const char *caller_func, const char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);

  ceccomp_vprint (false, LV_ERROR, caller_func, fmt, args);

  va_end (args);
  exit (1);
}
