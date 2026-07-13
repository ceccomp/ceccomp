#ifndef HELP_H
#define HELP_H

#include "i18n.h"
#define M_CECCOMP_USAGE _ ("Usage: ceccomp <subcommand> <args> <options>\n")
#define ASM_HINT "ceccomp asm     [ -c WHEN ] [ -a ARCH ] [ -f FMT ] [ text ]"

#define DISASM_HINT "ceccomp disasm  [ -c WHEN ] [ -a ARCH ] [ -e ] [ raw ]"

#define EMU_HINT                                                              \
  "ceccomp emu     [ -c WHEN ] [ -a ARCH ] [ -q ] text syscall_nr [ "         \
  "args[0-5] ip ]"

#define PROBE_HINT                                                            \
  "ceccomp probe   [ -c WHEN ] [ -o FILE ] [ -q ] PROGRAM [ program-args ]"

#define TRACE_HINT                                                            \
  "ceccomp trace   [ -c WHEN ] [ -o FILE ] [ -q ] PROGRAM [ program-args ]\n" \
  "                [ -c WHEN ] [ -s ] [ -q ] -p PID"

#define CAPTURE_HINT "ceccomp capture [ -p PID ]"

#define HELP_HINT "ceccomp help"
#define VERSION_HINT "ceccomp version"

#define M_SUBCMD_HINT                                                         \
  _ ("asm          -- Assemble bpf text to raw bytes\n"                       \
     "capture      -- Install eBPF prog to capture all seccomp filters "      \
     "during installation or extract installed filters in a process\n"        \
     "disasm       -- Disassemble raw bytes to bpf text\n"                    \
     "emu          -- Emulate bpf program with given syscall and bpf text\n"  \
     "help         -- Display ceccomp help information\n"                     \
     "probe        -- Trace the program for the first filter and emulate "    \
     "common syscalls\n"                                                      \
     "trace (dump) -- Run program or trace pid, extract bpf filter and then " \
     "print to text\n"                                                        \
     "version      -- Display ceccomp version\n")

#define M_OPTION_HINT                                                         \
  _ ("Options:\n"                                                             \
     "-a, --arch (x86_64|aarch64|...)  Which architecture to resolve "        \
     "syscall_nr, read or write bytestream by the byteorder of arch, "        \
     "default as your arch\n"                                                 \
                                                                              \
     "-c, --color (auto|always|never)  When to print in color, default as "   \
     "auto\n"                                                                 \
                                                                              \
     "-e, --ebpf                       Disassemble eBPF-migrated seccomp "    \
     "filter bytes instead\n"                                                 \
                                                                              \
     "-f, --fmt (hexline|hexfmt|raw)   Output format, default as hexline\n"   \
                                                                              \
     "-o, --output file                Print to file to avoid mixing "        \
     "ceccomp output and tracee program output, default as stderr\n"          \
                                                                              \
     "-p, --pid system_process_id      Extract bpf filters from process (or " \
     "thread) and print with bpf text form; CAP_SYS_ADMIN is needed to "      \
     "work\n"                                                                 \
                                                                              \
     "-q, --quiet                      Print emulate result only "            \
     "or suppress the process info message in trace and probe\n"              \
                                                                              \
     "-s, --seize                      Follow process to trace load-filter "  \
     "operation\n"                                                            \
                                                                              \
     "syscall_nr                       System call number or name (e.g. "     \
     "0|read)\n"                                                              \
     "args[0-5], ip                    args and ip (instruction pointer) "    \
     "used for emulation, default as 0\n"                                     \
     "raw, text                        File with BPF RAW or BPF TEXT, see "   \
     "docs for detail, default as stdin\n")

#endif
