import pytest
from shared_vars import *

EMU_TARGETS = []
for filename in FILENAMES:
    EMU_TARGETS.append((filename, 'accept'))
    EMU_TARGETS.append((filename, 'open'))
    EMU_TARGETS.append((filename, 'pipe'))

@pytest.mark.parametrize('filename, suffix', EMU_TARGETS)
def test_emu(filename: str, suffix: str, errns: SimpleNamespace):
    maybe_skip(filename)
    input_file = TXT_DIR / f'{filename}.casm'
    expect_file = EMU_DIR / f'{filename}.{suffix}.casm'
    emu_args = [suffix, '1', '2', '3', '4', '5', '6']
    _, stdout, stderr = run_process(
        [CECCOMP, 'emu', *COMMON_OPTS, str(input_file), *emu_args],
    )
    errns.stderr = stderr

    with expect_file.open('r') as expect:
        assert stdout == expect.read()

def test_s390x_emu(errns: SimpleNamespace):
    input_file = BE_DIR / 's390x.casm'
    expect_file = BE_DIR / 's390x.mmap.casm'
    _, stdout, stderr = run_process(
        [CECCOMP, 'emu', str(input_file), 'mmap', '-a', 's390x'],
    )
    errns.stderr = stderr

    with expect_file.open() as expect:
        assert stdout == expect.read()

def test_return_A(errns: SimpleNamespace):
    input_str = '$A = 0x50005\nreturn $A\n'
    _, stdout, stderr = run_process(
        [CECCOMP, 'emu', '-', '1', '-q'], stdin=input_str,
    )
    errns.stderr = stderr
    assert stdout == 'ERRNO(5)\n'

def test_return_A_long(errns: SimpleNamespace):
    input_str = 'return $A\n'
    _, stdout, stderr = run_process(
        [CECCOMP, 'emu', '-', '1'], stdin=input_str,
    )
    errns.stderr = stderr
    assert stdout == 'return $A # $A = 0, KILL\n'

def test_return_number(errns: SimpleNamespace):
    input_str = 'return 0x13371337\n'
    _, stdout, stderr = run_process(
        [CECCOMP, 'emu', '-', '1', '-q'], stdin=input_str,
    )
    errns.stderr = stderr
    assert stdout == 'KILL_PROCESS\n'

def test_return_number_long(errns: SimpleNamespace):
    input_str = 'return 0x7ff01000\n'
    _, stdout, stderr = run_process(
        [CECCOMP, 'emu', '-', '1'], stdin=input_str,
    )
    errns.stderr = stderr
    assert stdout == 'return 0x7ff01000 # TRACE(4096)\n'
