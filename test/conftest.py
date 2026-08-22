from types import SimpleNamespace
import pytest

@pytest.fixture
def errns() -> SimpleNamespace:
    return SimpleNamespace()

def fail_or_xfail(report) -> bool:
    return (
        report.skipped and getattr(report, "wasxfail", None) is not None
    ) or report.failed

# hook pytest report to print stderr
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()

    if report.when == 'call' and fail_or_xfail(report):
        ns = item.funcargs.get('errns')
        if hasattr(ns, 'stderr'):
            report.sections.append(('Process Standard Error', ns.stderr))
