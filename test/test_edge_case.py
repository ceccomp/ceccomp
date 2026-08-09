import pytest
from shared_vars import *

def test_asm_large_file():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '/dev/zero'],
    )
    assert stderr == '[ERROR]: The input file is greater than 4 MiB!\n'

def test_asm_no_lf():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='1' * 0x400,
    )
    assert stderr == "[ERROR]: No line break in source file, perhaps it's not a text file?\n"

def test_asm_long_line():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='\n\n' + '1' * 0x400 + '\n',
    )
    assert stderr == '[ERROR]: Line 3 has more than 384 bytes, perhaps the input is not a text file?\n'

def test_asm_many_lines():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='\n' * 0x4001,
    )
    assert stderr == "[ERROR]: Found more than 16384 lines of text, perhaps it's not for ceccomp?\n"

def test_asm_0_file():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='\n\n\0\n',
    )
    assert stderr == "[ERROR]: Found '\\0' at file offset 2, perhaps it's not a text file?\n"

def test_asm_empty_file():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='# \n',
    )
    assert stderr == '[ERROR]: The input does not contain any valid statement\n'

def test_asm_4096_statements(errns: SimpleNamespace):
    exit_code, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='return ALLOW\n\n' * 4096,
    )
    errns.stderr = stderr
    assert exit_code == 0

def test_asm_4097_statements():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='return ALLOW\n' * 4097,
    )
    assert stderr == '[ERROR]: Input file has more than 4096 statements!\n'

def test_disasm_large_file():
    _, _, stderr = run_process(
        [CECCOMP, 'disasm', '/dev/zero'],
    )
    assert stderr == '[ERROR]: The input is larger than 4096 filters! Perhaps inputting a wrong file?\n'

EDGE_IDS = sorted([p.stem[1:] for p in ERR_CASE_DIR.glob('e*')])

@pytest.mark.parametrize('edgeid', EDGE_IDS)
def test_edge_cases(errns: SimpleNamespace, edgeid: str):
    chunk_file = ERR_CASE_DIR / f'e{edgeid}'
    with chunk_file.open() as f:
        blob = f.read()
    parsed = CornerCaseFile.parse(blob)
    assert parsed.cli

    cli = parsed.cli.strip().split()
    stdin = parsed.stdin
    is_disasm = cli[0] == 'disasm'
    if is_disasm:
        stdin = bytes.fromhex(parsed.stdin)

    _, stdout, stderr = run_process(
        [CECCOMP, *cli], stdin=stdin, is_binary=is_disasm,
    )
    errns.stderr = stderr
    if is_disasm:
        assert stdout.decode() == parsed.stdout
    elif parsed.stdout.rstrip() == '$STANDARD_HELP':
        assert stdout == STANDARD_HELP
    else:
        assert stdout == parsed.stdout
    if parsed.stderr:
        assert stderr == parsed.stderr
