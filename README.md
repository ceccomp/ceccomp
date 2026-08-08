# Ceccomp <img src="https://raw.githubusercontent.com/ceccomp/.github/main/ceccomp-icon.png" alt="ceccomp icon" width="128" height="128" align="right" />

→ Read this in [简体中文](README.zh_CN.md) ←

C reimplementation of `seccomp-tools` with advanced features. We basically pronounce
ceccomp in "C-comp" (/siːˈkɒmp/) or "seccomp" (/ˈsɛk.kɒmp/).

## Features

- :gear: Robust assembler and disassembler
- :blue_book: Complete documentation
- :1234: Various architecture support powered by libseccomp
- :globe_with_meridians: Multi-language support
- :feather: Minimum build dependencies for core binary
- :paintbrush: Enhanced syntax highlighting
- :100: Informational error messages
- :shell: Powerful Zshell completion
- :no_entry_sign: Pure C without LLM-generated garbage
- :bee: Advanced function powered by eBPF

## Doc & Screenshots

[English Version](docs/ceccomp.adoc) | [中文文档](docs/ceccomp.zh_CN.adoc)

## Install

- Arch Linux users:

    ceccomp is available in official extra repo now:
    [![Arch](https://repology.org/badge/version-for-repo/arch/ceccomp.svg?header=Arch%20Linux%20extra)](https://repology.org/project/ceccomp/versions)
    [![Manjaro Stable](https://repology.org/badge/version-for-repo/manjaro_stable/ceccomp.svg?header=Manjaro%20Stable)](https://repology.org/project/ceccomp/versions)

- Debian, Ubuntu or Kali users:

    ceccomp is available with `apt` now if you are using distros below:

    [![Debian testing](https://repology.org/badge/version-for-repo/debian_14/ceccomp.svg?header=Debian%20testing)](https://repology.org/project/ceccomp/versions)
    [![Debian unstable](https://repology.org/badge/version-for-repo/debian_unstable/ceccomp.svg?header=Debian%20unstable)](https://repology.org/project/ceccomp/versions)
    [![Ubuntu 26.04](https://repology.org/badge/version-for-repo/ubuntu_26_04/ceccomp.svg?header=Ubuntu%2026.04)](https://repology.org/project/ceccomp/versions)
    [![Ubuntu 26.10](https://repology.org/badge/version-for-repo/ubuntu_26_10/ceccomp.svg?header=Ubuntu%2026.10)](https://repology.org/project/ceccomp/versions)
    [![Kali Linux](https://repology.org/badge/version-for-repo/kali_rolling/ceccomp.svg?header=Kali%20Linux)](https://repology.org/project/ceccomp/versions)

- NixOS users:

    @tesuji helps us submit a PR at NixOS, but it's blocked as currently... If you
    like our software, please :+1: in NixOS/nixpkgs#462592 to help ceccomp into nixpkgs!

# Build

- Stable installation:

    Clone the whole repo, then run `./configure`. Dependencies will be detected automatically,
    please keep an eye on the output since components are automatically disabled if not available.
    For documentation generation, you need `asciidoctor`. For multi-language support, you need
    `gettext` package. For eBPF support, you need `libbpf`, `bpftool` and a bpf C compiler,
    `clang` with `llvm` package or `gcc-bpf>=15`. You could use `--without-doc`, `--without-i18n`
    and `--without-ebpf` to disable them explicitly.
    Please run `./configure --help` for more details.

    ```sh
    git clone https://github.com/ceccomp/ceccomp.git
    cd Ceccomp
    ./configure
    ./configure # run this again if Makefile is not generated
    make
    make install # install at /usr/local/bin
    ```

- Testing installation:

    Clone the whole repo, and then run `./configure --devmode`.

    ```sh
    git clone https://github.com/ceccomp/ceccomp.git
    cd Ceccomp
    ./configure --devmode
    make
    ```

> [!NOTE]
> To build this project or enable some features, the lowest denpendency version
> baselines are:
> * Linux >= 5.3, libseccomp >= 2.5.0 (functions excluding capture)
> * Linux >= 5.11, libbpf >= 0.6.0 (global capture, only x86_64 guaranteed)
> * Linux >= 6.2, libbpf >= 0.6.0 (capture pid)

## Run Test

Run configure and make, then invoke `pytest test` from repo root. Trace pid case will be skipped if no
CAP_SYS_ADMIN. If you find some checks failed, please submit an issue to report your case.

To run the test, you need 2 extra packages: `pkgconf` (required by `pkg-config`) and `python-pytest`
(required by `pytest`).

## CheatSheet

<img width="2200" height="1182" alt="image" src="https://github.com/user-attachments/assets/74a427d6-8e26-46dc-9883-9aad818d6d64" />

## Credits

- [libseccomp](https://github.com/seccomp/libseccomp): The library to support syscall lookups
- [libbpf](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html): The library to support eBPF functions
- [seccomp-tools](https://github.com/david942j/seccomp-tools): The tool in Ruby inspires us to write ceccomp
- [Bootswatch](https://bootswatch.com/slate/): Provides awesome css for html doc under MIT
- [Linux kernel](https://github.com/torvalds/linux): Port some bpf checks
- [Verstable](https://github.com/JacksonAllan/Verstable): High-performance hash table implementation in C
- [a5hash](https://github.com/avaneev/a5hash): High-performance hash implementation for short strings in C

Any Issue or PR are welcome! :heart: Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Copyright (C) 2025-present, ceccomp contributors, distributed under GNU General Public License v3.0 or Later
