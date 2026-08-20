import platform
import select
import signal
import time
from enum import IntEnum
from subprocess import DEVNULL, PIPE

import pytest
from shared_vars import *


class UnitTests(IntEnum):
    TRACE = 0
    PROBE = 1
    SEIZE = 2
    TRACE_PID = 3
    FLAGS = 4
    LOTS_OF_FILTERS = 5
    CAPTURE = 6

    def arg(self) -> str:
        return str(self.value)

capeff = None # cache capeff

def lookup_self_caps() -> str | int:
    global capeff
    if capeff is not None:
        return capeff

    try:
        with open('/proc/self/status') as f:
            for line in f:
                if line.startswith('CapEff:'):
                    capeff = int(line.split()[1], 16)
                    break
            else:
                return 'Capability can not be found in status'
    except OSError:
        return 'Can not query /proc to know capability'
    return capeff

def is_not_cap_sys_admin() -> str | None:
    capeff = lookup_self_caps()
    if isinstance(capeff, str):
        return capeff
    if bool(capeff & (1 << 21)): # CAP_SYS_ADMIN = 21
        return None
    return 'Lack of CAP_SYS_ADMIN capability'

def is_not_cap_bpf() -> str | None:
    capeff = lookup_self_caps()
    if isinstance(capeff, str):
        return capeff
    if capeff & ((1 << 39) | (1 << 38)) == ((1 << 39) | (1 << 38)): # CAP_BPF + CAP_PERFMON
        return None
    if bool(capeff & (1 << 21)): # CAP_SYS_ADMIN = 21
        return None
    return 'Incapable of loading eBPF'

kver, libbpf_enabled = None, None
def does_not_support_capture(pid_mode: bool) -> str | None:
    global kver, libbpf_enabled
    if libbpf_enabled is None:
        _, stdout, _ = run_process([CECCOMP, 'version'])
        libbpf_idx = stdout.find('libbpf')
        assert libbpf_idx != -1
        libbpf_enabled = stdout.find('-', libbpf_idx) == -1
    if not libbpf_enabled:
        return 'capture module opted out'
    if kver is None:
        krel = platform.release().split('.')
        kver = (int(krel[0]), int(krel[1]))
    if (not pid_mode and kver < (5, 15)) or (pid_mode and kver < (6, 2)):
        return 'Kernel too old'
    if msg := is_not_cap_bpf():
        return msg
    return None

TEST_BIN = PROJ_DIR / 'build' / 'test'
TEST_SRC = PROJ_DIR / 'test' / 'unit_test.c'
if not TEST_BIN.exists() or TEST_BIN.stat().st_mtime <= TEST_SRC.stat().st_mtime:
    assert run_process(['make', '-C', str(PROJ_DIR), 'test'], False)[0] == 0
TEST = str(TEST_BIN)

def pid_state(pid: int) -> str | None:
    """
    Race condition: perhaps kernel killed process but ceccomp hasn't exit,
    so test is zombie and not being collected. Test this case
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    try:
        with open(f'/proc/{pid}/stat') as f:
            state = f.read().split(' ', 4)[2]
    except:
        return None
    else:
        return None if state == 'Z' else state

def filter_execve_k(text: str) -> str:
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if 'execve' in line or 'sendfile' in line or 'ptrace' in line:
            lines[i] = line[:23] + ' MAY VARY ' + line[33:]
    return '\n'.join(lines)

def fill_pid(log: str, pid: int) -> str:
    idx = log.find('------')
    assert idx != -1
    prefix = f'PID={pid} '
    return log[:idx] + prefix + log[idx + len(prefix):]

# -a x86_64 option in COMMON_OPTS will be ignored in trace/probe

##### TEST CASES #####
@pytest.mark.xfail(XFAIL_DYNAMIC, reason=XFAIL_REASON)
def test_probe(errns: SimpleNamespace):
    piper, pipew = os.pipe()
    os.set_inheritable(pipew, True)
    argv = [CECCOMP, 'probe', *COMMON_OPTS, '-o', f'/proc/self/fd/{pipew}',
            TEST, UnitTests.PROBE.arg()]
    _, stdout, stderr = run_process(argv, False, pipew)
    os.close(pipew)
    errns.stderr = stderr

    expect_file = TEST_DIR / 'dyn_log' / 'probe.log'
    with expect_file.open() as f:
        expect = f.read()
    with os.fdopen(piper) as f:
        assert f.read() == expect

    pid = int(stdout.split('=')[1])
    end = time.time() + 3
    while pid_state(pid) and time.time() < end:
        time.sleep(0.0625)
    last_state = pid_state(pid)
    assert last_state is None or last_state == 'X'


@pytest.mark.xfail(XFAIL_DYNAMIC, reason=XFAIL_REASON)
def test_trace(errns: SimpleNamespace):
    piper, pipew = os.pipe()
    os.set_inheritable(pipew, True)
    argv = [CECCOMP, 'trace', *COMMON_OPTS, '-o', f'/proc/self/fd/{pipew}',
            TEST, UnitTests.TRACE.arg()]
    _, stdout, stderr = run_process(argv, False, pipew)
    os.close(pipew)
    errns.stderr = stderr

    pid = int(stdout.split('=')[1])

    expect_file = TEST_DIR / 'dyn_log' / 'trace.log'
    with expect_file.open() as f:
        expect = fill_pid(f.read(), pid)
    with os.fdopen(piper) as f:
        assert filter_execve_k(f.read()) == filter_execve_k(expect)
    assert 'WARN' in stderr


@pytest.mark.xfail(XFAIL_DYNAMIC, reason=XFAIL_REASON)
def test_seize(errns: SimpleNamespace):
    pytest.skip('t')
    efd = os.eventfd(0, 0)
    tp = subprocess.Popen([TEST, UnitTests.SEIZE.arg(), str(efd)],
        stdin=DEVNULL, stdout=PIPE, stderr=DEVNULL, text=True, pass_fds=(efd,))
    pid = int(tp.stdout.readline().split('=')[1])

    argv = [CECCOMP, 'trace', *COMMON_OPTS, '-p', str(pid), '-s']
    cp = subprocess.Popen(argv, stdin=DEVNULL, stdout=PIPE, stderr=PIPE, text=True)
    pre_line = cp.stderr.readline()

    os.eventfd_write(efd, 1)

    rl, _, _ = select.select([tp.stdout], [], [], 2)
    if rl:
        pid = int(rl[0].readline().split('=')[1]) # child pid
    else:
        with open(f'/proc/{tp.pid}/wchan') as f:
            t_kfunc = f.read()
        with open(f'/proc/{cp.pid}/wchan') as f:
            c_kfunc = f.read()
        errns.stderr = f'TEST in {t_kfunc}\nCECCOMP in {c_kfunc}'
        tp.terminate()
        cp.terminate()
        tp.wait(0.5)
        cp.wait(0.5)
        assert False, 'Found signal race condition? Pls report to upstream'

    cp.terminate()
    stdout, stderr = cp.communicate()
    errns.stderr = pre_line + stderr
    cp.wait(0.5)

    pid_exist = True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pid_exist = False
    else:
        os.eventfd_write(efd, 1)
    assert pid_exist is True
    assert tp.wait(0.5) == 0

    expect_file = TEST_DIR / 'dyn_log' / 'trace.log'
    with expect_file.open() as f:
        expect = filter_execve_k(fill_pid(f.read(), pid))
        assert filter_execve_k(stdout) == expect

@pytest.mark.xfail(XFAIL_DYNAMIC, reason=XFAIL_REASON)
def test_trace_pid(errns: SimpleNamespace):
    if msg := is_not_cap_sys_admin():
        pytest.skip(msg)

    efd = os.eventfd(0, 0)
    tp = subprocess.Popen([TEST, UnitTests.TRACE_PID.arg(), str(efd)],
        stdin=DEVNULL, stdout=PIPE, stderr=DEVNULL, text=True, pass_fds=(efd,))
    pid = int(tp.stdout.readline().split('=')[1])

    _, stdout, stderr = run_process(
        [CECCOMP, 'trace', *COMMON_OPTS, '-p', str(pid)],
    )
    errns.stderr = stderr

    os.eventfd_write(efd, 1)
    assert tp.wait(0.5) == 0

    expect_file = TEST_DIR / 'dyn_log' / 'trace.log'
    with expect_file.open() as f:
        expect = filter_execve_k(fill_pid(f.read(), pid))
        assert filter_execve_k(stdout) == expect

@pytest.mark.xfail(XFAIL_DYNAMIC, reason=XFAIL_REASON)
def test_seccomp_flags(errns: SimpleNamespace):
    piper, pipew = os.pipe()
    os.set_inheritable(pipew, True)
    argv = [CECCOMP, 'trace', *COMMON_OPTS, '-o', f'/proc/self/fd/{pipew}',
            TEST, UnitTests.FLAGS.arg()]
    _, stdout, stderr = run_process(argv, False, pipew)
    os.close(pipew)
    pid = int(stdout.split('=')[1])
    errns.stderr = stderr

    expect_file = TEST_DIR / 'dyn_log' / 'trace.log'
    with expect_file.open() as f:
        expect = fill_pid(f.read(), pid)
    with os.fdopen(piper) as f:
        assert filter_execve_k(f.read()) == filter_execve_k(expect)
    expect_file = TEST_DIR / 'dyn_log' / 'flag_stderr.log'
    with expect_file.open() as f:
        assert stderr.replace(str(pid), '$PID') == f.read()

@pytest.mark.xfail(XFAIL_DYNAMIC, reason=XFAIL_REASON)
def test_capture_global(errns: SimpleNamespace):
    if reason := does_not_support_capture(False):
        pytest.skip(reason)

    cp = subprocess.Popen([CECCOMP, 'capture', '-c', 'always'],
                          stdin=DEVNULL, stdout=PIPE, stderr=PIPE, text=True)

    os.set_blocking(cp.stdout.fileno(), False)

    expect_file = TEST_DIR / 'dyn_log' / 'trace.log'
    with expect_file.open() as f:
        expect = f.read()

    end = time.time() + 10
    while time.time() < end:
        _, pid_text, _ = run_process([TEST, UnitTests.TRACE.arg()])
        pid = int(pid_text.split('=')[1])
        disasm = filter_execve_k(fill_pid(expect, pid))
        rl, _, _ = select.select([cp.stdout], [], [], 0.375)
        if not rl:
            continue
        if disasm in filter_execve_k(cp.stdout.read()):
            break
        time.sleep(0.125)
    else:
        cp.terminate()
        _, errns.stderr = cp.communicate()
        cp.wait(0.5)
        pytest.fail('Can not see expected output after 10s')

    cp.terminate()
    _, stderr = cp.communicate()
    cp.wait(0.5)
    errns.stderr = stderr
    assert f'{pid} (test)' in stderr

@pytest.mark.xfail(XFAIL_DYNAMIC, reason=XFAIL_REASON)
def test_capture_pid(errns: SimpleNamespace):
    if reason := does_not_support_capture(True):
        pytest.skip(reason)

    efd = os.eventfd(0, 0)
    tp = subprocess.Popen([TEST, UnitTests.TRACE_PID.arg(), str(efd)],
        stdin=DEVNULL, stdout=PIPE, stderr=DEVNULL, text=True, pass_fds=(efd,))
    pid = int(tp.stdout.readline().split('=')[1])

    _, stdout, stderr = run_process(
        [CECCOMP, 'capture', '-c', 'always', '-p', str(pid)],
    )
    errns.stderr = stderr

    os.eventfd_write(efd, 1)
    assert tp.wait(0.5) == 0

    assert f'{pid} has 1 seccomp filter(s)' in stderr
    expect_file = TEST_DIR / 'dyn_log' / 'trace.log'
    with expect_file.open() as f:
        expect = filter_execve_k(f.read())
        assert filter_execve_k(stdout) == expect

@pytest.mark.xfail(XFAIL_DYNAMIC, reason=XFAIL_REASON)
def test_capture_pid_too_many(errns: SimpleNamespace):
    if reason := does_not_support_capture(True):
        pytest.skip(reason)

    efd = os.eventfd(0, 0)
    tp = subprocess.Popen([TEST, UnitTests.LOTS_OF_FILTERS.arg(), str(efd)],
                          stdin=DEVNULL, stdout=PIPE, stderr=PIPE, text=True,
                          pass_fds=(efd,))
    pid = int(tp.stdout.readline().split('=')[1])

    _, stdout, stderr = run_process([CECCOMP, 'capture', '-p', str(pid)])
    errns.stderr = stderr

    os.eventfd_write(efd, 1)
    assert tp.wait(0.5) == 0

    assert stdout.count('#Label') == 32
    assert f'{pid} has 40 seccomp filter(s)' in stderr
    assert 'Too many seccomp filters (> 32)' in stderr
