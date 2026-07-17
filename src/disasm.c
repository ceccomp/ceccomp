#include <linux/prctl.h>
#define _GNU_SOURCE
#include "decoder/decoder.h"
#include "decoder/formatter.h"
#include "disasm.h"
#include "lexical/parser.h"
#include "main.h"
#include "resolver/render.h"
#include "utils/bpf_trans.h"
#include "utils/error.h"
#include "utils/logger.h"
#include "utils/reverse_endian.h"
#include "utils/str_pile.h"
#include "utils/vector.h"
#include <assert.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

filter *g_filters;
static uint32_t g_sz;

bool
init_global_filters (uint32_t insn_count)
{
  if (g_filters)
    return true;
  g_sz = (sizeof (filter) * (insn_count + 1) + 0xfff) & ~0xfff;
  void *map = mmap (NULL, g_sz, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,
                    -1, 0);
  if (map == MAP_FAILED)
    return false;
#ifdef PR_SET_VMA
  prctl (PR_SET_VMA, PR_SET_VMA_ANON_NAME, map, g_sz, "global filters");
#endif
  g_filters = map;
  return true;
}

__attribute__ ((destructor)) static void
free_global_filters (void)
{
  if (g_filters)
    munmap (g_filters, g_sz);
}

static uint32_t
read_filters (filter *filters, FILE *from)
{
  uint32_t todo = sizeof (filter) * (BPF_MAXINSNS + 1);
  uint8_t *ptr = (uint8_t *)filters;
  int fd = fileno (from);
  assert (fd != -1);
  while (todo)
    {
      long rc = read (fd, ptr, todo);
      if (rc == -1)
        error (M_READ_FAIL, strerror (errno));
      if (rc == 0)
        break;
      ptr += rc;
      todo -= rc;
    }
  if (!todo)
    error ("%s", M_TOO_LARGE_INPUT);
  uint32_t leftover = ((size_t)ptr - (size_t)filters) & 7;
  if (leftover)
    warn (M_INPUT_HAS_LEFTOVER, leftover);
  return (ptr - (uint8_t *)filters) >> 3;
}

#define BLK_SIZE 0x2000
// Returned bpf_insn pointer requested with mmap, release it later!
static struct bpf_insn *
read_insns (FILE *from, uint32_t *count, uint32_t *map_sizep)
{
  void *base;
  uint32_t offset = 0, map_size = BLK_SIZE, todo = BLK_SIZE;
  int fd = fileno (from);
  assert (fd != -1);

  base = mmap (NULL, map_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,
               -1, 0);
  if (base == MAP_FAILED)
    return NULL;

  while (true)
    {
      long rc = read (fd, (uint8_t *)base + offset, todo);
      if (UNLIKELY (rc == -1))
        error (M_READ_FAIL, strerror (errno));
      if (rc == 0)
        break;
      offset += rc;
      todo -= rc;

      if (todo == 0)
        {
          // read BLK_SIZE? enlarge buffer if some more bytes to read
          void *old_base = base;
          base = mremap (base, map_size, map_size + BLK_SIZE, MREMAP_MAYMOVE);
          if (UNLIKELY (base == MAP_FAILED))
            {
              munmap (old_base, map_size);
              return NULL;
            }
          todo = BLK_SIZE;
          map_size += BLK_SIZE;
        }
    }

  uint32_t leftover = offset % sizeof (struct bpf_insn);
  if (leftover)
    warn (M_INPUT_HAS_LEFTOVER, leftover);
#ifdef PR_SET_VMA
  prctl (PR_SET_VMA, PR_SET_VMA_ANON_NAME, base, map_size, "user eBPF insns");
#endif

  *count = offset / sizeof (struct bpf_insn);
  *map_sizep = map_size;
  return base;
}

void
print_prog (uint32_t scmp_arch, fprog *prog, FILE *output_fp, bool trustful,
            bool from_ebpf)
{
  if (need_reverse_endian (scmp_arch) && !from_ebpf)
    for (uint32_t i = 0; i < prog->len; i++)
      reverse_endian (&prog->filter[i]);

  vector_t v;

  // str pile for syscall names
  assert (prog->len);
  assert (init_pile (prog->len * 40 /* statistical choice */));
  init_vector (&v, sizeof (statement_t), prog->len + 1);
  // check_prog in decode_filters might decect some errors
  // render might mem overflow, so skip render
  if (!decode_filters (prog, &v, trustful))
    render (&v, scmp_arch);
  print_as_comment (output_fp, "Label  CODE  JT   JF      K");
  print_as_comment (output_fp, "---------------------------------");

  filter *filters = prog->filter; // give compiler some hint
  for (uint32_t i = 1; i < v.count; i++)
    {
      filter f = filters[i - 1];
      fprintf (output_fp, " " DEFAULT_LABEL ": 0x%02x 0x%02x 0x%02x 0x%08x ",
               i, f.code, f.jt, f.jf, f.k);
      print_statement (output_fp, get_vector (&v, i));
    }

  print_as_comment (output_fp, "---------------------------------");

  free_vector (&v);
  free_pile ();
}

void
disasm (FILE *fp, uint32_t scmp_arch, bool ebpf)
{
  fprog prog;
  if (ebpf)
    {
      uint32_t count, map_size;
      struct bpf_insn *insns = read_insns (fp, &count, &map_size);
      assert (insns);

      if (need_reverse_endian (scmp_arch))
        for (uint32_t i = 0; i < count; i++)
          reverse_ebpf_endian (insns + i);

      assert (init_global_filters (count));
      long filter_len = ebpf2cbpf (insns, count, g_filters, false);
      assert (filter_len >= 0);
      prog.len = filter_len;

      munmap (insns, map_size);
    }
  else
    {
      assert (init_global_filters (BPF_MAXINSNS));
      prog.len = read_filters (g_filters, fp);
    }
  prog.filter = g_filters;
  if (prog.len == 0)
    {
      warn ("%s", M_NO_FILTER);
      return;
    }

  print_prog (scmp_arch, &prog, stdout, false, ebpf);
}
