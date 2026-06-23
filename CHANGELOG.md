# CHANGELOG
Items marked with :star: is the major change why we release a new version.

<!-- When referencing issues and PRs, add #num at the end of line for issues -->
<!-- and !num at the end of line for PRs. If the issue or PR is external, -->
<!-- write user/repo#num or user/repo!num to reference. If PR is made by some one else, -->
<!-- write @some*user !num to reference user and PR at the same time. The order can not be -->
<!-- reversed. Then run scripts/complete-url.py to format raw ref to URL. -->

## 4.3 (INCOMING)
* :star: Prints seccomp flags when tracing and applies stricter check on return value
* :star: `$A / $X` (`$X == 0`) should return `KILL` instead of continuing
## 4.2.2
* :star: Keep `CC` as string in `configure` :link: [#37]
* :star: Fix flaky seize test with `eventfd` :link: [#38]
* Flush stdout in `configure` immediately

[#37]: https://github.com/dbgbgtf1/Ceccomp/issues/37
[#38]: https://github.com/dbgbgtf1/Ceccomp/issues/38
## 4.2.1
* Fix test error on different architectures
## 4.2
* **BREAKING** :star: Default installation path is set to `/usr/local` like normal programs
* :star: Fix seccomp argument comparison in trace since v2.8
* :star: Allow `zig cc` and other compilers that has multiple arguments in `configure`
* :star: Reject `ceccomp trace/probe/emu` without positional arguments
* :star: Clear value of register A and X when start emulation
* :star: Fix in-place return object modification which impacts probe emulations
* :star: Lexical scanner now scan a whole word and treat pattern like "ifx" as identifier
* Packager is set to `NAME` from `/etc/os-release` if prefix is `/usr` and packager is not set
* Print reason when failed to load in trace
* Fix potential buffer overflow via TOCTOU :link: [#31]
* Add some info in `configure` about devmode :heart: [@k4lizen] :link: [!33]
* `dump` is now an alias of `trace` :heart: [@k4lizen] :link: [!35]
* Make objects depend on `Makefile` to apply new rules after configure :link: [#34]
* Reject invalid architecture name
* Add support for 32-bit arm, armv7l and armv8l

[#31]: https://github.com/dbgbgtf1/Ceccomp/issues/31
[@k4lizen]: https://github.com/k4lizen
[!33]: https://github.com/dbgbgtf1/Ceccomp/pulls/33
[!35]: https://github.com/dbgbgtf1/Ceccomp/pulls/35
[#34]: https://github.com/dbgbgtf1/Ceccomp/issues/34
## 4.1
* :star: Fix asm handle STX incorrectly
* :star: Fix big endian machine tracing failure :link: [#29]
* :star: Fix emulate not accessing `$mem[idx]`
* :star: Fix disasm render using rval status to track lval mem status
* :star: Fix BPF instruction limit to 4096 :link: [#30]
* :star: Fix asm allow negative JA
* :star: Fix emulate `A /= X, X = 0` crash
* :star: Fix disasm symbol tracking only works on 256 lines
* :star: Fix disasm not decoding NOTIFY
* Fix leaked fd when using trace with specified output file
* Allocate global filters lazily
* Fix too loose cli number parsing
* Add more hints when unexpectedly disasming
* Skip `check_prog` if disasming filters from kernel
* Correct disasm leftover calculation
* Increase timeout in test for slow vm
* Add missing `$` in emu comment for `return $A`

Special credit for codex, which helps us hunt lots of bugs.

[#29]: https://github.com/dbgbgtf1/Ceccomp/issues/29
[#30]: https://github.com/dbgbgtf1/Ceccomp/issues/30
## 4.0
* **BREAKING** :star: :fire: **We aggressively refactored our code and the asm grammar is a bit different from v3. Please refer to documentation for new grammar.** :fire:
* :star: Add seize subfunction in trace pid :link: [#23]
* :star: Remove `-mno-omit-leaf-frame-pointer` flag if not supported by cc
* :star: Fix asm and disasm endianness problems :link: [#22]
* :star: Handle '>=' '>' '<=' '<' correctly :link: [#25]
* :star: Find python by `env` for compatibility in `configure` :heart: [@tesuji] :link: [!19]
* :star: Migrate to pytest for testing
* :star: Migrate to po4a for documentation translation
* Print messages in dynamic tests
* Add `-q` for trace to suppress `[INFO]` output
* Reject text that are error ones for kernel :link: [#17]
* Print info when trace found failed seccomp syscall
* Support `-` to refer to stdin or stdout
* Allow returning numbers or `$A`
* Fixed a typo in README :heart: [@k4lizen] :link: [!28]

[#22]: https://github.com/dbgbgtf1/Ceccomp/issues/22
[#25]: https://github.com/dbgbgtf1/Ceccomp/issues/25
[#23]: https://github.com/dbgbgtf1/Ceccomp/issues/23
[#17]: https://github.com/dbgbgtf1/Ceccomp/issues/17
[@tesuji]: https://github.com/tesuji
[!19]: https://github.com/dbgbgtf1/Ceccomp/pulls/19
[@k4lizen]: https://github.com/k4lizen
[!28]: https://github.com/dbgbgtf1/Ceccomp/pulls/28
## 3.5
* **BREAKING** :star: Now `trace` and `probe` no more accepts `-a`; arch is automatically retrieved via ptrace
* :star: Add `i686` arch support
* :star: Handle unknown system arch
* Fix 32-bit ceccomp `strtol` error
* Generalize test script to for different archs
* `trace` now follows tracee's arch instead of system's
* Fix Makefile implicit rules
## 3.4
* :star: Fix cross arch trace problems :link: [#16]
* :star: Add support for NO_COLOR env check :link: [#15]
* :star: Fix heap oob write if `goto` exceeds bpf range
* :star: Correctly kill children processes when recved signals
* :star: Fix potential invalid `%s` access in `ALU` and `ST_STX`
* Fix ambiguous `idx` in `ST_STX`
* Fix color display in emu
* Use `git describe --long` to have unified name pattern in `configure` devmode
* Add more tests to check ceccomp behaviour

[#15]: https://github.com/dbgbgtf1/Ceccomp/issues/15
[#16]: https://github.com/dbgbgtf1/Ceccomp/issues/16
## 3.3
* :star: Add `--enable-static` in `configure` to build statically
* Portable release in pip, for x86_64, i386, aarch64, armhf, riscv64
* Fix not-null-terminated argp option array
* Fix copyright as GPLv3 or later
## 3.2
* **BREAKING** :star: Enhance arch/syscall prediction :link: [#12]
* :star: Add support for Debian build system :link: [#13]
* :star: Improve syntax highlighting
* Hide unused bpf operation in emu :link: [#14]
* Fix `CECCOMP_USAGE` warning as it's a function call
* Add a dark-mode css for html doc
* Sort source object for reproducible build

[#13]: https://github.com/dbgbgtf1/Ceccomp/issues/13
[#12]: https://github.com/dbgbgtf1/Ceccomp/issues/12
[#14]: https://github.com/dbgbgtf1/Ceccomp/issues/14
## 3.1
* **BREAKING** :star: Add support for multiple process tracing :link: [#3]
* :star: Cover all cases of trace pid errors :link: [#11]
* :star: Add support for internationalization/localization :link: [#1]
* :star: Fix `ld` error when compiling on Kali Linux
* Fix potential misuse of `Info` in trace
* Improve log system and related color management
* Fix output file may not be opened correctly
* Add a GitHub action to issue new release easily

[#3]: https://github.com/dbgbgtf1/Ceccomp/issues/3
[#11]: https://github.com/dbgbgtf1/Ceccomp/issues/11
[#1]: https://github.com/dbgbgtf1/Ceccomp/issues/1
## 3.0
* **BREAKING** Remove `-o FILE` for `trace` pid mode
* :star: Add doc system powered by *asciidoc* :link: [#2]
* :star: Add signal forwarding to `trace` in expected way :link: [#5]
* :star: Add subcommand description :link: [#7]
* :star: Add color option, can be set to always, auto, never :link: [#10]
* :star: Add Python-version configure script :link: [#9]
* Warn invalid seccomp filter instead of refuse directly :link: [#4]
* Raise errors on corrupted TEXT in `emu`
* Suppress printing function if not debugging
* Set `$?` to 1 when failed to parse args
* Limit truncating file on `-o` flag by checking subcommand
* Update color in `return $A` BPF OP for better visual effect
* Implement assigning `len(struct seccomp_data)` to `A` or `X`
* Implement uninstall operation and verbose control in Makefile

[#2]: https://github.com/dbgbgtf1/Ceccomp/issues/2
[#5]: https://github.com/dbgbgtf1/Ceccomp/issues/5
[#7]: https://github.com/dbgbgtf1/Ceccomp/issues/7
[#10]: https://github.com/dbgbgtf1/Ceccomp/issues/10
[#4]: https://github.com/dbgbgtf1/Ceccomp/issues/4
[#9]: https://github.com/dbgbgtf1/Ceccomp/issues/9
## 2.9
* :star: Fix Makefile compatibility among shells :link: [#6]
* Add git-hook to remind dev to update version string
* Update color in `return` BPF OP for better visual effect

[#6]: https://github.com/dbgbgtf1/Ceccomp/issues/6
## 2.8
* :star: Improve compatibility among compilers
* :star: Add Kbuild-like build prompt with progress
* Improve logging implementation
## 2.7
* :star: Fix `trace` and `probe` foreground interaction issue
* Refactor method to terminate children
## 2.6
* :star: Fix Makefile link order (should be put in the end of line)
* Suppress compiler warning by `// fall through`
* Applying more checks on `asm`
## 2.5
* :star: Add parentheses for `TRAP` as it has `ret_data`, but *libseccomp* hasn't implement it :link: [seccomp/libseccomp#466]
* Add check script
* Fix uninitialized memory access

[seccomp/libseccomp#466]: https://github.com/seccomp/libseccomp/issues/466
## 2.4
* :star: Port kernel filter check
* Add some logging functions
## 2.3
* Fix `asm` lacking `ALU_NEG` operation
* Fix `asm` hanging if
## 2.2
* Fix `emu` emulates wrong ALU operations
* Better help message
## 2.1
* Remove `CXX` in Makefile, now it's purely in C
* Fix Makefile typo
## 2.0
* :star: Turn to `argp` to parse arguments
* :star: Add `-o` mode to output filters
* :star: Use C to implement `parsefilter`
## 1.5
* :star: New probe mode to test common syscalls instantly
* Adapt completion script to latest code base
## 1.4
* Fix lacking `\n` in trace
## 1.3
* `trace` now accept pid to grab filters
* Zsh completion script is capable of completing pid
## 1.2
* :star: Ready for PKGBUILD to build package
* Fix zsh completion script
## 1.1
* First release version
* Add basic zsh completion script
