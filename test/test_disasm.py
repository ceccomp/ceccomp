import pytest
from shared_vars import *

@pytest.mark.parametrize('filename', FILENAMES)
def test_disasm(filename: str, errns: SimpleNamespace):
    maybe_skip(filename)
    input_file = BPF_DIR / f'{filename}.bpf'
    expect_file = TXT_DIR / filename
    _, stdout, stderr = run_process(
        [CECCOMP, 'disasm', *COMMON_OPTS, str(input_file)],
    )
    errns.stderr = stderr

    with expect_file.open('r') as expect:
        assert stdout == expect.read()

def test_s390x_disasm(errns: SimpleNamespace):
    input_file = BE_DIR / 's390x.bpf'
    expect_file = BE_DIR / 's390x.disasm'
    _, stdout, stderr = run_process(
        [CECCOMP, 'disasm', str(input_file), '-a', 's390x'],
    )
    errns.stderr = stderr

    with expect_file.open() as expect:
        assert stdout == expect.read()

def test_normal_ebpf_disasm(errns: SimpleNamespace):
    input_file = EBPF_DIR / 'normal.bin'
    expect_file = EBPF_DIR / 'original'
    _, stdout, stderr = run_process(
        [CECCOMP, 'disasm', '-ea', 'x86_64', str(input_file)],
    )
    errns.stderr = stderr

    with expect_file.open() as expect:
        assert stdout == expect.read()

def test_hardened_ebpf_disasm(errns: SimpleNamespace):
    input_file = EBPF_DIR / 'hardened.bin'
    expect_file = EBPF_DIR / 'original'
    _, stdout, stderr = run_process(
        [CECCOMP, 'disasm', '-ea', 'x86_64', str(input_file)],
    )
    errns.stderr = stderr

    with expect_file.open() as expect:
        assert stdout == expect.read()

ERROR_IDS = sorted([p.stem[1:] for p in ERR_CASE_DIR.glob('b*')])

@pytest.mark.parametrize('errorid', ERROR_IDS)
def test_error_cases(errorid: str):
    chunk_file = ERR_CASE_DIR / f'b{errorid}'
    with chunk_file.open() as f:
        blob = f.read()
    parsed = CornerCaseFile.parse(blob)
    assert parsed.stdin
    assert parsed.stderr

    args = ['-a', 'x86_64']
    if parsed.cli and '-e' in parsed.cli:
        args.append('-e')

    stdin = bytes.fromhex(parsed.stdin)
    _, stdout, stderr = run_process(
        [CECCOMP, 'disasm', '-', *args], stdin=stdin, is_binary=True,
    )
    assert stderr.decode() == parsed.stderr
    if parsed.stdout:
        assert stdout.decode() == parsed.stdout
