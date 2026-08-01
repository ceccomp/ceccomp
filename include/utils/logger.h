#ifndef LOGGER_H
#define LOGGER_H

#include <stdbool.h>
#include <stdio.h>
#include <sys/cdefs.h>

typedef enum
{
  LV_DEBUG = 0,
  LV_INFO = 1,
  LV_WARN = 2,
  LV_ERROR = 3,
} print_level_t;

// clang-format off
__attribute__ ((noinline)) void info_print (print_level_t lv, const char *caller_func, const char *fmt, ...) __attribute__ ((format (printf, 3, 4)));
__attribute__ ((noinline)) __attribute__ ((noreturn)) void error_print (const char *caller_func, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));

// clang-format on
int ceccomp_vprint (bool from_external, print_level_t lv,
                    const char *caller_func, const char *fmt, va_list args);

#ifdef DEBUG
#define debug(fmt, ...) info_print (LV_DEBUG, __func__, fmt, __VA_ARGS__)
#else
#define debug(fmt, ...) ;
#endif // !DEBUG

#define info(fmt, ...) info_print (LV_INFO, __func__, fmt, __VA_ARGS__)
#define warn(fmt, ...) info_print (LV_WARN, __func__, fmt, __VA_ARGS__)
#define error(fmt, ...) error_print (__func__, fmt, __VA_ARGS__)

#endif
