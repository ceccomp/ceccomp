import pytest
from shared_vars import *

@pytest.mark.parametrize('filename', FILENAMES)
def test_asm(filename: str, errns: SimpleNamespace):
    maybe_skip(filename)
    input_file = TXT_DIR / f'{filename}.casm'
    expect_file = BPF_DIR / f'{filename}.bpf'
    _, stdout, stderr = run_process(
        [CECCOMP, 'asm', *COMMON_OPTS, '-f', 'raw', str(input_file)], True,
    )
    errns.stderr = stderr.decode()

    with expect_file.open('rb') as expect:
        assert filter2text(stdout) == filter2text(expect.read())

def test_s390x_asm(errns: SimpleNamespace):
    input_file = BE_DIR / 's390x.casm'
    expect_file = BE_DIR / 's390x.hexfmt'
    _, stdout, stderr = run_process(
        [CECCOMP, 'asm', '-f', 'hexfmt', str(input_file), '-a', 's390x'],
    )
    errns.stderr = stderr

    with expect_file.open() as expect:
        assert stdout == expect.read()

ERROR_IDS = sorted([p.stem[1:] for p in ERR_CASE_DIR.glob('a*')])

@pytest.mark.parametrize('errorid', ERROR_IDS)
def test_error_cases(errorid: str):
    chunk_file = ERR_CASE_DIR / f'a{errorid}'
    with chunk_file.open() as f:
        blob = f.read()
    parsed = CornerCaseFile.parse(blob)
    assert parsed.stdin
    assert parsed.stderr

    _, _, stderr = run_process(
        # error case for asm will not print to stdout,
        # so no need to specify arch
        [CECCOMP, 'asm', '-'], stdin=parsed.stdin,
    )
    assert stderr == parsed.stderr
