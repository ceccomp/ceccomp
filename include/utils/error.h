#ifndef ERROR_H
#define ERROR_H

#include "i18n.h"

#define M_UNSUPPORTED_ARCH _ ("Architecture name %s is not supported")
// probe
#define M_PROBE_TERMINATED _ ("Found errors when assembling BPF from trace")
#define M_REQUEST_TMPFILE_FAILED _ ("Failed to request a temporary file: %s")

// emu
#define M_EMU_TERMINATED                                                      \
  _ ("Found errors when assembling text before emulating")
#define M_INPUT_SYS_NR _ ("Please input syscall_nr (syscall name or number)")
#define M_INVALID_SYSNR _ ("Invalid syscall_nr")

// asm
#define M_ASM_TERMINATED _ ("Found errors when assembling")
#define M_STATEMENT_OVERFLOW _ ("Input file has more than 4096 statements!")

// disasm
#define M_DISASM_TERMINATED _ ("Found fatal errors when disassembling")
#define M_NO_FILTER _ ("The input is empty")
#define M_TOO_LARGE_INPUT                                                     \
  _ ("The input is larger than 4096 filters! Perhaps inputting a wrong "      \
     "file?")
#define M_INPUT_HAS_LEFTOVER                                                  \
  _ ("%u byte(s) at the end of input could not fit into a filter")

// trace
#define M_START_TRACING _ ("Start tracing process %d")
#define M_PEEKDATA_FAILED_ADR _ ("Peekdata failed at %p")
#define M_EXECV_ERR _ ("Failed to execute new program")
#define M_PROCESS_FORK _ ("Process %d spawned a new pid %d")
#define M_PROCESS_EXIT _ ("Process %d exited")
#define M_PID_BPF_SECCOMP _ ("Process %d invoked seccomp (%s, %s, &prog)")
#define M_PID_BPF_PRCTL                                                       \
  _ ("Process %d invoked prctl (PR_SET_SECCOMP, %s, &prog)")
#define SECCOMP_SET_MODE_STRICT_S ("SECCOMP_SET_MODE_STRICT")
#define SECCOMP_SET_MODE_FILTER_S ("SECCOMP_SET_MODE_FILTER")
#define M_PID_BPF_LOAD_FAIL _ ("Process %d failed to load seccomp filter: %s")
#define M_BPF_FAIL_UNKNOWN _ ("Unknown reason")
#define M_PROCFS_NOT_ACCESSIBLE _ ("Procfs not accessible, unable to perform")
#define M_NOT_AN_CBPF _ ("Found unresolvable non-classic BPF, skipping")
#define M_SEIZING_KERNEL_THREAD _ ("Kernel thread can not be seized")
#define M_NO_FILTER_FOUND _ ("No seccomp filters found in process %d")
#define M_TARGET_TRACED_BY                                                    \
  _ ("Target process is already being traced by process %d")
#define M_FOUND_STRICT_MODE                                                   \
  _ ("Process %d loaded strict seccomp mode, which only allows read, "        \
     "write, exit_group and sigreturn!")
#define M_UNKNOWN_GETFILTER_ERR _ ("Unknown error when get filter: %s")
#define M_UNKNOWN_SEIZE_ERR _ ("Unknown error when seizing process: %s")
#define M_SEIZE_NONEXIST_PROC _ ("The process to seize does not exist")
// no translation due to terms
#define ACTION_GET_FILTER "ptrace get seccomp filters"
#define ACTION_PTRACE_SEIZE "ptrace seizing"
#define M_TRACE_UNDER_ATTACK                                                  \
  _ ("Unexpected race condition detected when reading seccomp filters, "      \
     "please consider use eBPF-based trace in next version")

#define M_CAP_SYS_PTRACE_OR_KTHREAD                                           \
  _ ("perhaps seizing kthread or lacking CAP_SYS_PTRACE")
#define M_REQUIRE_CAP_SYS_ADMIN                                               \
  _ ("Run with CAP_SYS_ADMIN capability to fetch seccomp filters")
#define M_REQUIRE_CAP_SYS_PTRACE                                              \
  _ ("Run with CAP_SYS_PTRACE capability to seize a foreign process")
#define M_CANNOT_WORK_FROM_32_TO_64                                           \
  _ ("32-bit tracer can not ptrace 64-bit tracee")
#define M_TRACEE_ARCH_NOT_SUPPORTED                                           \
  _ ("libseccomp does not support the tracee's arch (%#x)")
#define M_CAP_SYS_ADMIN_OR_IN_SECCOMP                                         \
  _ ("perhaps lacking CAP_SYS_ADMIN or ceccomp is in seccomp mode")
#define M_GET_FILTER_UNSUPPORTED                                              \
  _ ("PTRACE_GET_SECCOMP_FILTER is not supported on your system")
#define M_CECCOMP_IN_SECCOMP                                                  \
  _ ("Ceccomp is in seccomp mode, fetching seccomp filters of other process " \
     "is not permitted")
#define M_GET_FILTER_UNSUPPORTED_OR_NO_FILTER                                 \
  _ ("perhaps PTRACE_GET_SECCOMP_FILTER is not supported or no seccomp "      \
     "filter in target process")

// parse_args
#define M_INVALID_COLOR_MODE _ ("Invalid color mode")
#define M_INVALID_ASM_FMT _ ("Invalid asm format")
#define M_INVALID_NUMBER _ ("Invalid number")
#define M_UNABLE_OPEN_FILE _ ("Unable to open file %s: %s")

// read_source
#define M_READ_FAIL _ ("Reading input failed: %s")
#define M_FOUND_SUS_ZERO                                                      \
  _ ("Found '\\0' at file offset %lu, perhaps it's not a text file?")
#define M_FOUND_SUS_NO_LF                                                     \
  _ ("No line break in source file, perhaps it's not a text file?")
#define M_FOUND_SUS_LINE                                                      \
  _ ("Line %u has more than %u bytes, perhaps the input is not a text file?")
#define M_FILE_TOO_LARGE _ ("The input file is greater than 4 MiB!")
#define M_LINES_TOO_MANY                                                      \
  _ ("Found more than 16384 lines of text, perhaps it's not for ceccomp?")

// hash
#define M_CANNOT_FIND_LABEL _ ("Can not find label declaration")

// parser
#define M_UNEXPECT_TOKEN _ ("Unexpected token")
#define M_DUPLICATED_LABEL _ ("Found duplicated label declaration")
#define M_NUMBER_OVERFLOW _ ("Input number exceeds 32-bit range")

#define M_EXPECT_OPERATOR _ ("Expect operator")
#define M_EXPECT_RIGHT_VAR _ ("Expect rvalue")
#define M_EXPECT_RETURN_VAL _ ("Expect return value")

#define M_EXPECT_NUMBER _ ("Expect number")
#define M_EXPECT_PAREN _ ("Expect parenthesis")
#define M_EXPECT_BRACKET _ ("Expect bracket")
#define M_EXPECT_COMPARTOR _ ("Expect comparator")
#define M_EXPECT_LABEL _ ("Expect label")
#define M_EXPECT_SYSCALL _ ("Expect valid syscall name")
#define M_EXPECT_ARCH                                                         \
  _ ("Architecture token does not match any libseccomp arch, perhaps system " \
     "libseccomp is too old")
// EXPECT_SYSCALL also use in resolver

#define M_EXPECT_GOTO _ ("Expect 'goto'")
#define M_EXPECT_A _ ("Expect '$A'")
#define M_EXPECT_ELSE _ ("Expect 'else'")

// resolver and check_prog
#define M_RIGHT_SHOULD_BE_A _ ("Rvalue should be '$A'")
#define M_RIGHT_CAN_NOT_BE_A _ ("Rvalue can not be '$A'")
#define M_RIGHT_CAN_NOT_BE_X _ ("Rvalue can not be '$X'")

#define M_RIGHT_SHOULD_BE_A_OR_X _ ("Rvalue should be '$A' or '$X'")
#define M_RIGHT_SHOULD_BE_X_OR_NUM _ ("Rvalue should be '$X' or number")
#define M_OPERATOR_SHOULD_BE_EQUAL _ ("Operator should be '='")
#define M_LEFT_SHOULD_BE_A _ ("Lvalue should be '$A'")
#define M_INVALID_ATTR_LOAD                                                   \
  _ ("seccomp_data load offset must be 4-byte aligned")
#define M_ATTR_OFFSET_OVERFLOW                                                \
  _ ("seccomp_data load offset greater than the struct")

#define M_ARGS_IDX_OUT_OF_RANGE _ ("Args index out of range (0-5)")
#define M_MEM_IDX_OUT_OF_RANGE _ ("Mem index out of range (0-15)")
#define M_UNINITIALIZED_MEM _ ("Accessing uninitialized mem")
#define M_ALU_DIV_BY_ZERO _ ("Dividing by zero")
#define M_ALU_SH_OUT_OF_RANGE _ ("Left or right shifting more than 32 bits")

#define M_RET_DATA_OVERFLOW _ ("Data carried by return motion exceeds 0xffff")
#define M_JT_TOO_FAR _ ("JT is larger than 0xff")
#define M_JT_MUST_BE_POSITIVE _ ("JT must be positive")
#define M_JF_TOO_FAR _ ("JF is larger than 0xff")
#define M_JF_MUST_BE_POSITIVE _ ("JF must be positive")
#define M_JT_INVALID_TAG _ ("JT out of filters")
#define M_JF_INVALID_TAG _ ("JF out of filters")
#define M_JA_OUT_OF_FILTERS _ ("JA out of filters")
#define M_JA_MUST_BE_POSITIVE _ ("JA must be positive")

#define M_MUST_END_WITH_RET _ ("BPF filters must end with return")
#define M_NO_VALID_CODE _ ("The input does not contain any valid statement")

#define M_INVALID_OPERATION _ ("Invalid or unknown operation")

// capture
#define M_UNEXPECTED_EBPF_INSN                                                \
  _ ("Unexpected bpf_insn (#%u) in kernel migrated eBPF (assertion failed "   \
     "at %s#L%d: %s), please open an issue and upload your eBPF case")
#define M_SAVE_EBPF_SUCCEEDED                                                 \
  _ ("Your eBPF case has been saved in %s (binary file)")
#define M_SAVE_EBPF_FAILED _ ("Failed to save your eBPF case due to %s")
#define M_EBPF_INPUT_ERROR                                                    \
  _ ("#%u: Input eBPF insn does not meet assertion at %s#L%d: %s\n%s")

#endif
