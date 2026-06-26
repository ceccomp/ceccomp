#ifndef BPF_TRANS_H
#define BPF_TRANS_H

#include "config.h"

#if EBPF_SUPPORT == 1

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <stdint.h>

/* ebpf2cbpf: translate from migrated eBPF seccomp filters back to cBPF form.
 * Warning: eBPF migration is not strictly reversable, this function can't
 * fully recover original filters.
 *
 * ebpfs: Binary migrated seccomp filters captured from kernel with eBPF.
 *        Note that some insns may be modified when processing (if constant
 *        blinding is present), so no const modifier.
 * ebpf_len: The amount of migrated filters.
 * cbpf_buf: The buffer to put recovered cBPF filters. Should be at least as
 *           large as ebpfs.
 *
 * Returns -1 if unexpected instruction details spotted, warnings are printed
 * in the funtion. Returns the amount of recovered cBPF filters if successfully
 * recovered.
 */
extern long ebpf2cbpf (struct bpf_insn *restrict ebpfs,
                       const uint32_t ebpf_len,
                       struct sock_filter *restrict cbpf_buf);
#endif

#endif
