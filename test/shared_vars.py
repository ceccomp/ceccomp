import os
import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path
from sys import stdin
from types import SimpleNamespace

from pytest import skip

PROJ_DIR = Path(__file__).parent.parent
TEST_DIR = PROJ_DIR / 'test'
TXT_DIR = TEST_DIR / 'text'
BPF_DIR = TEST_DIR / 'bpf'
EMU_DIR = TEST_DIR / 'emu_result'
BE_DIR  = TEST_DIR / 'big_endian_cases'
ERR_CASE_DIR = TEST_DIR / 'errors'
CECCOMP = str(PROJ_DIR / 'build' / 'ceccomp')
FILENAMES = sorted([p.stem for p in TXT_DIR.iterdir()])

COMMON_OPTS = ['-c', 'always', '-a', 'x86_64']

def run_process(
    argv: list[str], is_binary: bool=False, extra_fd: int | None=None,
    stdin: str | bytes | None=None,
) -> tuple[int, str | bytes, str | bytes]:
    if extra_fd is None:
        result = subprocess.run(argv, timeout=5, capture_output=True,
                                text=not is_binary, input=stdin)
    else:
        result = subprocess.run(argv, timeout=5, capture_output=True,
                                text=not is_binary, pass_fds=(extra_fd, ), input=stdin)
    return result.returncode, result.stdout, result.stderr

_, _verstr, _ = run_process(['pkg-config', '--modversion', 'libseccomp'], False)
SKIP_CHROMIUM = tuple(_verstr.split('.')) < ('2', '5', '6')
SKIP_REASON = 'libseccomp too old (<2.5.6)'
def maybe_skip(filename: str):
    if SKIP_CHROMIUM and filename == 'chromium':
        skip(SKIP_REASON)

def filter2text(filters: bytes) -> str:
    length = len(filters) # leftover (less than 8 bytes) will be discarded
    return '\n'.join(filters[i:i + 8].hex(' ') for i in range(0, length, 8))

os.environ['LC_ALL'] = 'C'

TIER_1_ARCH = [ # tested
    'x86_64', 'i386', 'i686', 'riscv64', 'loongarch64', 'aarch64',
    'ppc', 'ppc64le', 's390x', 'arm', 'armv8l', 'armv7l',
]
TIER_2_ARCH = [ # untested, but listed in libseccomp
    'x32', 'parisc', 'parisc64', 'mips', 'm68k', 's390', 'ppc64',
    'sh', 'sh4', 'shel',
]
XFAIL_DYNAMIC = platform.machine() not in TIER_1_ARCH \
    or (platform.machine() == 'x86_64' and platform.architecture()[0] == '32bit')
XFAIL_REASON = 'Dynamic test may fail on this unsupported platform'

STANDARD_HELP = run_process([CECCOMP, 'help'])[1]

def slice_lines(text: str, positions: list[int]) -> list[str | None]:
    items = []
    for pos_idx, item_idx in enumerate(positions):
        if item_idx == -1:
            items.append(None)
            continue
        for iter_idx in range(pos_idx + 1, len(positions)):
            iter_item_idx = positions[iter_idx]
            if iter_item_idx != -1:
                items.append(text[text.find('\n', item_idx) + 1:
                                  iter_item_idx])
                break
        else:
            items.append(text[text.find('\n', item_idx) + 1:])
            continue
    return items

@dataclass
class CornerCaseFile:
    cli: str | None
    stdin: str
    stdout: str | None
    stderr: str | None

    @staticmethod
    def parse(content: str) -> CornerCaseFile:
        pos_list = [
            content.find('CLI'),
            content.find('STDIN'),
            content.find('STDOUT'),
            content.find('STDERR'),
        ]
        return CornerCaseFile(*slice_lines(content, pos_list))
