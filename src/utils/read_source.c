#define _GNU_SOURCE
#include "utils/read_source.h"
#include "utils/error.h"
#include "utils/logger.h"
#include <assert.h>
#include <errno.h>
#include <linux/bpf_common.h>
#include <linux/prctl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#define GROW_LEN 0x4000
#define MAX_LINE_LEN 0x180
#define MAX_FILE_LEN 0x400000 // 4MiB

typedef enum
{
  UNKNOWN,
  UNIX,
  WINDOWS,
  MACOS,
} file_type_t;
static file_type_t file_type = UNKNOWN;

static char *source = NULL;
static uint32_t current = 0;
static uint32_t map_len = 0;

static void
clear_color (char *text, uint32_t line_len)
{
  char *cursor = memchr (text, '\x1b', line_len);
  if (!cursor)
    return;
  char *top = text + line_len; // excluding
  char *colorstart = NULL;
  char *clear = cursor;

  for (; cursor < top; cursor++)
    {
      if (!colorstart && *cursor != '\x1b')
        *clear++ = *cursor;
      else if (!colorstart && *cursor == '\x1b')
        colorstart = cursor;
      else if (colorstart && *cursor == 'm')
        colorstart = NULL;
      // else skip
    }
  memset (clear, '\0', top - clear);
}

static char
detect_file_type (void)
{
  char lf = '\n';
  char *line_break = memchr (source, lf, current);
  if (!line_break)
    {
      if (memchr (source, '\r', current)) // perhaps the file is from macos?
        {
          file_type = MACOS;
          return '\r';
        }
      else
        error ("%s", M_FOUND_SUS_NO_LF);
    }
  else
    {
      if (line_break != source && *(line_break - 1) == '\r')
        file_type = WINDOWS;
      else
        file_type = UNIX;
    }
  return '\n';
}

static unsigned
process_source (void)
{
  register char lf = detect_file_type ();

  char *line_break;
  char *line_start = source;
  char *top = source + current;
  uint32_t line_nr = 1;
  while (true)
    {
      if (line_start + MAX_LINE_LEN <= top)
        {
          line_break = memchr (line_start, lf, MAX_LINE_LEN);
          if (!line_break)
            error (M_FOUND_SUS_LINE, line_nr, MAX_LINE_LEN);
        }
      else
        {
          // the rest space is less than MAX_LINE_LEN
          line_break = memchr (line_start, lf, top - line_start);
          if (!line_break)
            break;
        }

      if (file_type == WINDOWS)
        memcpy (line_break - 1, "\n", 2);
      else
        *line_break = '\n';

      clear_color (line_start, line_break - line_start + 1);

      line_nr++;
      line_start = line_break + 1;
    }

  if (line_nr >= 4 * BPF_MAXINSNS)
    error ("%s", M_LINES_TOO_MANY);
  if (top == line_start)
    return line_nr;
  clear_color (line_start, top - line_start + 1);
  return line_nr + 1;
}

static void
init_map (void)
{
  source = mmap (NULL, GROW_LEN, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (source == MAP_FAILED)
    error ("mmap: %s", strerror (errno));

  map_len = GROW_LEN;
}

static void
increase_map (void)
{
  if (source == NULL)
    {
      init_map ();
      return;
    }

  if (current + GROW_LEN <= map_len)
    return;

  source = mremap (source, map_len, map_len + GROW_LEN, MREMAP_MAYMOVE);
  if (source == MAP_FAILED)
    error ("mremap: %s", strerror (errno));

  map_len += GROW_LEN;
}

unsigned
init_source (FILE *read_fp)
{
  uint32_t read_len = 0;
  int fd = fileno (read_fp); // give compiler some hint

  do
    {
      increase_map ();
      read_len = read (fd, source + current, GROW_LEN);
      if (read_len == (uint32_t)-1)
        error (M_READ_FAIL, strerror (errno));
      current += read_len;
      if (current > MAX_FILE_LEN)
        error ("%s", M_FILE_TOO_LARGE);
    }
  while (read_len > 0); // reading via char device may get less than GROW_LEN

  const char *found0;
  if ((found0 = memchr (source, '\0', current)))
    error (M_FOUND_SUS_ZERO, (unsigned long)(found0 - source));

  if (current % GROW_LEN == 0 || current % GROW_LEN > GROW_LEN - 0x20)
    increase_map (); // scanner expect a trailing \n, which may increase map

#ifdef PR_SET_VMA
  prctl (PR_SET_VMA, PR_SET_VMA_ANON_NAME, source, map_len, "asm source");
#endif

  return process_source ();
}

void
free_source (void)
{
  munmap (source, map_len);
}

char *
next_line (void)
{
  static uint32_t cursor = 0;
  if (cursor >= current)
    return NULL;

  char *read_ptr = source + cursor;

  char *line_break = memchr (read_ptr, '\n', current - cursor);
  if (!line_break)
    {
      // meet eof
      source[current] = '\n';
      cursor = current;
      return read_ptr;
    }

  char *top = source + current; // give compiler some hint
  do
    line_break++;
  while (line_break < top && (*line_break == '\0'));
  cursor = line_break - source;

  return read_ptr;
}
