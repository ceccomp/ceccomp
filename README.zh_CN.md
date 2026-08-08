# Ceccomp <img src="https://raw.githubusercontent.com/ceccomp/.github/main/ceccomp-icon.png" alt="ceccomp icon" width="128" height="128" align="right" />

→ 用 [English](README.md) 阅读文档 ←

具有高级功能的对于 `seccomp-tools` 的 C 语言重新实现。我们基本上把 ceccomp 读作 “C-comp” (/siːˈkɒmp/)
或者 “seccomp” (/ˈsɛk.kɒmp/)。

## 功能

- :gear: 健壮的汇编器和反汇编器
- :blue_book: 完善的文档
- :1234: 由 libseccomp 驱动的多架构支持
- :globe_with_meridians: 多语言支持
- :feather: 构建核心二进制的依赖很少
- :paintbrush: 更好的语法高亮
- :100: 详实的错误信息
- :shell: 强大的 Zshell 补全脚本
- :no_entry_sign: 纯 C 编写，没有 LLM 垃圾
- :bee: 由 eBPF 驱动的高级功能

## 文档 & 截图

[English Version](docs/ceccomp.adoc) | [中文文档](docs/ceccomp.zh_CN.adoc)

## 安装

- Arch Linux 用户：

    ceccomp 已在官方 extra 仓库可用：
    [![Arch](https://repology.org/badge/version-for-repo/arch/ceccomp.svg?header=Arch%20Linux%20extra)](https://repology.org/project/ceccomp/versions)
    [![Manjaro Stable](https://repology.org/badge/version-for-repo/manjaro_stable/ceccomp.svg?header=Manjaro%20Stable)](https://repology.org/project/ceccomp/versions)

- Debian, Ubuntu 或 Kali 用户：

    如果您在使用如下发行版，那么 ceccomp 可以使用 `apt` 获取：

    [![Debian testing](https://repology.org/badge/version-for-repo/debian_14/ceccomp.svg?header=Debian%20testing)](https://repology.org/project/ceccomp/versions)
    [![Debian unstable](https://repology.org/badge/version-for-repo/debian_unstable/ceccomp.svg?header=Debian%20unstable)](https://repology.org/project/ceccomp/versions)
    [![Ubuntu 26.04](https://repology.org/badge/version-for-repo/ubuntu_26_04/ceccomp.svg?header=Ubuntu%2026.04)](https://repology.org/project/ceccomp/versions)
    [![Ubuntu 26.10](https://repology.org/badge/version-for-repo/ubuntu_26_10/ceccomp.svg?header=Ubuntu%2026.10)](https://repology.org/project/ceccomp/versions)
    [![Kali Linux](https://repology.org/badge/version-for-repo/kali_rolling/ceccomp.svg?header=Kali%20Linux)](https://repology.org/project/ceccomp/versions)

- NixOS 用户：

    @tesuji 帮我们在 NixOS 提交了一个 PR，但是目前进度停滞不前...
    如果您喜欢我们的软件，请在 NixOS/nixpkgs#462592 :+1: 来帮助 ceccomp 进入 nixpkgs！

# 构建

- 稳定版安装：

    克隆整个仓库，然后运行 `./configure`。依赖会被自动检测，请小心输出结果，
    因为组件不可用时会被自动禁用。要生成文档，您需要 `asciidoctor`，要启用多语言支持，
    您需要 `gettext` 软件包。要启用 eBPF 支持，您需要 `libbpf` 和 `bpftool`。您可以使用
    `--without-doc`, `--without-i18n` 和 `--without-ebpf` 标志来显式禁用它们。
    请运行 `./configure --help` 查看详情。

    ```sh
    git clone https://github.com/ceccomp/ceccomp.git
    cd Ceccomp
    ./configure
    ./configure # 如果 Makefile 没有生成就再运行一次
    make
    make install # 安装在 /usr/local/bin
    ```

- 测试版安装：

   克隆完整仓库，然后运行 `./configure --devmode`。

    ```sh
    git clone https://github.com/ceccomp/ceccomp.git
    cd Ceccomp
    ./configure --devmode
    make
    ```

> [!NOTE]
> 要想构建这个项目或启用某些特性，最低的依赖版本基线是：
> * Linux >= 5.3, libseccomp >= 2.5.0 (除了 libbpf 部分以外)
> * Linux >= 5.11, libbpf >= 0.6.0 (全局捕获，只保证 x86_64)
> * Linux >= 6.2, libbpf >= 0.6.0 (捕获 PID)

## 运行测试

运行 configure 后 make，然后再项目根目录下运行 `pytest test`。如果没有 CAP_SYS_ADMIN，追踪 pid
的测试案例会被跳过。如果您发现一些测试失败了，请开一个 issue 并上报您的案例。

要想运行测试，您需要 2 个额外的软件包: `pkgconf` (被 `pkg-config` 需要) 和 `python-pytest` (被
`pytest` 需要)。

## 速览表

<img width="2200" height="1182" alt="image" src="https://github.com/user-attachments/assets/74a427d6-8e26-46dc-9883-9aad818d6d64" />

## 致谢

- [libseccomp](https://github.com/seccomp/libseccomp): 用于支持系统调用查询的软件库
- [libbpf](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html): 用来支持
  eBPF 功能的软件库
- [seccomp-tools](https://github.com/david942j/seccomp-tools): 启发我们编写
  ceccomp 的 Ruby 工具
- [Bootswatch](https://bootswatch.com/slate/): 提供了基于 MIT 协议的用于 html 文档的精美
  CSS
- [Linux kernel](https://github.com/torvalds/linux): 移植了一些 BPF 的检查
- [Verstable](https://github.com/JacksonAllan/Verstable): C 语言高性能哈希表实现
- [a5hash](https://github.com/avaneev/a5hash): C 语言高性能短字符串哈希实现

欢迎任何 issue 或 PR！ :heart: 详情请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

Copyright (C) 2025-现在，ceccomp 贡献者，按 GNU General Public License v3.0 or Later
分发
