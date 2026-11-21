"""``run_checks(max_workers=N)``: services in parallel, checks in a service in order.

Offline: the session refuses every client build and the identity cache is
seeded. Every wait has a timeout, so a regression fails instead of hanging.
"""
from __future__ import annotations

import gc
import inspect
import signal
import threading
from pathlib import Path
from typing import Any, Callable, Iterator

import pytest

from sraverify import scanner as scanner_module
from sraverify.core.check import SecurityCheck
from sraverify.core.enums import AccountType, Severity, Status
from sraverify.core.errors import ScanPreconditionError
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.tests.property.test_context_isolation_property import (
    _isolated_registry,
    _production_log_handling,
    _recording_scan_context,
    _RefusingSession,
)
from sraverify.utils.outputs import write_csv_output

TIMEOUT = 5.0
REGION = "us-east-1"

Body = Callable[[SecurityCheck], Iterator[Finding]]


def _check(service: str, index: int, body: Body) -> type[SecurityCheck]:
    check_id = f"SRA-{service.upper()}-{index:02d}"
    meta = CheckMeta(
        check_id=check_id,
        title=f"{service} probe {index} is configured",
        description="Synthetic check for the concurrent scan tests. It reaches no AWS API.",
        check_logic="Runs the body the test installs",
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service=service,
        resource_type="AWS::Probe::Resource",
        remediation=Remediation(text="Configure the probe control."),
    )
    return type(
        check_id.replace("-", "_"),
        (SecurityCheck,),
        {
            "__module__": __name__,
            "meta": meta,
            "execute": body,
            "_setup_clients": lambda self: self._clients.clear(),
        },
    )


def _passing(before: Callable[[SecurityCheck], None] | None = None) -> Body:
    def execute(self: SecurityCheck) -> Iterator[Finding]:
        if before is not None:
            before(self)
        yield self.passed(
            region=REGION,
            resource_id=f"probe/{self.meta.check_id}",
            actual_value="configured",
        )
    return execute


def _sra() -> Any:
    return scanner_module.SRAVerify(session=_RefusingSession(), regions=[REGION])


def _scan(classes: list[type[SecurityCheck]], sra: Any = None, **kwargs: Any) -> list[Finding]:
    sra = sra if sra is not None else _sra()
    with _isolated_registry(classes), _recording_scan_context():
        return sra.run_checks(**kwargs)


class _SpyThread(threading.Thread):
    instances: list["_SpyThread"] = []
    joining = threading.Event()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        _SpyThread.instances.append(self)

    def join(self, timeout: float | None = None) -> None:
        _SpyThread.joining.set()
        super().join(timeout)


@pytest.fixture
def spy_thread(monkeypatch: pytest.MonkeyPatch) -> type[_SpyThread]:
    _SpyThread.instances = []
    _SpyThread.joining = threading.Event()
    monkeypatch.setattr(scanner_module, "Thread", _SpyThread)
    return _SpyThread


def test_max_workers_is_keyword_only_and_defaults_to_one() -> None:
    parameter = inspect.signature(scanner_module.SRAVerify.run_checks).parameters["max_workers"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default == 1


@pytest.mark.parametrize("value", [0, -1, True, False, 1.5, "2", None])
def test_an_invalid_max_workers_raises_value_error_before_any_work(value: Any) -> None:
    sra = _sra()
    with _isolated_registry([_check("Alpha", 1, _passing())]), _recording_scan_context() as created:
        with pytest.raises(ValueError, match="max_workers"):
            sra.run_checks(max_workers=value)
    assert created == []


def test_services_overlap_and_checks_within_a_service_stay_sequential() -> None:
    barrier = threading.Barrier(2, timeout=TIMEOUT)
    lock = threading.Lock()
    active = {"Alpha": 0, "Bravo": 0}
    peak = dict(active)
    events: list[tuple[str, str]] = []

    def body(meet_at_barrier: bool) -> Body:
        def execute(self: SecurityCheck) -> Iterator[Finding]:
            service = self.meta.service
            with lock:
                active[service] += 1
                peak[service] = max(peak[service], active[service])
                events.append(("start", self.meta.check_id))
            try:
                if meet_at_barrier:
                    barrier.wait()
            finally:
                with lock:
                    active[service] -= 1
                    events.append(("end", self.meta.check_id))
            yield self.passed(region=REGION, resource_id=None, actual_value="configured")
        return execute

    classes = [
        _check("Alpha", 1, body(True)),
        _check("Alpha", 2, body(False)),
        _check("Bravo", 1, body(True)),
        _check("Bravo", 2, body(False)),
    ]

    findings = _scan(classes, max_workers=2)

    assert [(f.check_id, f.status) for f in findings] == [
        ("SRA-ALPHA-01", Status.PASS),
        ("SRA-ALPHA-02", Status.PASS),
        ("SRA-BRAVO-01", Status.PASS),
        ("SRA-BRAVO-02", Status.PASS),
    ]
    assert peak == {"Alpha": 1, "Bravo": 1}
    for prefix in ("SRA-ALPHA-", "SRA-BRAVO-"):
        assert [e for e in events if e[1].startswith(prefix)] == [
            ("start", f"{prefix}01"),
            ("end", f"{prefix}01"),
            ("start", f"{prefix}02"),
            ("end", f"{prefix}02"),
        ]


@pytest.mark.parametrize(
    "max_workers,services",
    [
        pytest.param(1, ("Alpha", "Bravo"), id="one-worker"),
        pytest.param(4, ("Alpha",), id="one-service"),
    ],
)
def test_one_worker_or_one_service_runs_on_the_calling_thread(
    spy_thread: type[_SpyThread], max_workers: int, services: tuple[str, ...]
) -> None:
    threads: list[threading.Thread] = []

    def record(self: SecurityCheck) -> None:
        threads.append(threading.current_thread())

    classes = [_check(s, i, _passing(record)) for s in services for i in (1, 2)]

    _scan(classes, max_workers=max_workers)

    assert len(threads) == len(classes)
    assert all(t is threading.current_thread() for t in threads)
    assert spy_thread.instances == []


def test_the_pool_never_exceeds_the_selected_services(spy_thread: type[_SpyThread]) -> None:
    classes = [_check(s, 1, _passing()) for s in ("Alpha", "Bravo", "Charlie")]

    findings = _scan(classes, max_workers=8)

    assert len(findings) == 3
    assert len(spy_thread.instances) == 3


def _reverse_completion_catalog(gates: dict[str, threading.Event], finished: list[str]) -> list[type[SecurityCheck]]:
    def last(service: str, waits_for: str | None, body: Body) -> Body:
        def execute(self: SecurityCheck) -> Iterator[Finding]:
            if waits_for is not None:
                assert gates[waits_for].wait(TIMEOUT), f"{service} waited for {waits_for}"
            yield from body(self)
            finished.append(service)
            gates[service].set()
        return execute

    def two_rows(self: SecurityCheck) -> Iterator[Finding]:
        for suffix in ("a", "b"):
            yield self.passed(region=REGION, resource_id=f"probe/{suffix}", actual_value="configured")

    def failing(self: SecurityCheck) -> Iterator[Finding]:
        yield self.failed(region=REGION, resource_id="probe/missing", actual_value="not configured")

    def yields_then_raises(self: SecurityCheck) -> Iterator[Finding]:
        yield self.passed(region=REGION, resource_id="probe/partial", actual_value="partial")
        raise RuntimeError("probe failure after the first yield")

    def precondition(self: SecurityCheck) -> Iterator[Finding]:
        raise ScanPreconditionError(
            check_id=self.meta.check_id,
            lookup="regions",
            error={"Operation": "DescribeRegions", "Code": "AccessDenied", "Message": "not allowed"},
        )
        yield

    return [
        _check("Alpha", 1, two_rows),
        _check("Alpha", 2, yields_then_raises),
        _check("Alpha", 3, last("Alpha", "Bravo", failing)),
        _check("Bravo", 1, precondition),
        _check("Bravo", 2, last("Bravo", "Charlie", two_rows)),
        _check("Charlie", 1, failing),
        _check("Charlie", 2, last("Charlie", None, two_rows)),
    ]


def test_reverse_completion_writes_the_same_csv_bytes_as_one_worker(tmp_path: Path) -> None:
    services = ("Alpha", "Bravo", "Charlie")

    open_gates = {s: threading.Event() for s in services}
    for gate in open_gates.values():
        gate.set()
    sequential_order: list[str] = []
    sequential = _scan(_reverse_completion_catalog(open_gates, sequential_order))

    parallel_order: list[str] = []
    parallel = _scan(
        _reverse_completion_catalog({s: threading.Event() for s in services}, parallel_order),
        max_workers=3,
    )

    assert sequential_order == ["Alpha", "Bravo", "Charlie"]
    assert parallel_order == ["Charlie", "Bravo", "Alpha"]
    errors = [f for f in sequential if f.status is Status.ERROR]
    assert [f.check_id for f in errors] == ["SRA-ALPHA-02", "SRA-BRAVO-01"]
    assert errors[0].actual_value.startswith("Error running SRA-ALPHA-02: RuntimeError")
    assert errors[1].actual_value == "DescribeRegions failed: AccessDenied: not allowed"

    write_csv_output(sequential, str(tmp_path / "one.csv"))
    write_csv_output(parallel, str(tmp_path / "three.csv"))
    assert (tmp_path / "three.csv").read_bytes() == (tmp_path / "one.csv").read_bytes()


def test_a_later_run_without_progress_writes_nothing_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    sra = _sra()
    classes = [_check("Alpha", 1, _passing())]

    _scan(classes, sra=sra, show_progress=True)
    assert capsys.readouterr().out != ""

    _scan(classes, sra=sra, show_progress=False)
    assert capsys.readouterr().out == ""


def test_parallel_progress_runs_on_the_calling_thread_and_counts_every_check(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    instances: list[Any] = []
    callers: set[threading.Thread] = set()

    class _SpyProgress(scanner_module.ScanProgress):
        def __init__(self, total_checks: int) -> None:
            super().__init__(total_checks)
            instances.append(self)

        def update(self, service: str) -> None:
            callers.add(threading.current_thread())
            super().update(service)

        def increment(self) -> None:
            callers.add(threading.current_thread())
            super().increment()

        def finish(self) -> None:
            callers.add(threading.current_thread())
            super().finish()

    monkeypatch.setattr(scanner_module, "ScanProgress", _SpyProgress)
    classes = [_check(s, i, _passing()) for s in ("Alpha", "Bravo", "Charlie") for i in (1, 2)]

    _scan(classes, max_workers=3, show_progress=True)

    assert len(instances) == 1
    assert instances[0].completed_checks == instances[0].total_checks == 6
    assert callers == {threading.current_thread()}
    assert capsys.readouterr().out.endswith("\n")


def test_a_parallel_scan_releases_its_context_on_return() -> None:
    def raising(self: SecurityCheck) -> Iterator[Finding]:
        yield self.passed(region=REGION, resource_id=None, actual_value="partial")
        raise RuntimeError("probe failure after the first yield")

    classes = [
        _check("Alpha", 1, _passing()),
        _check("Alpha", 2, raising),
        _check("Bravo", 1, raising),
        _check("Charlie", 1, _passing()),
    ]
    sra = _sra()

    with _isolated_registry(classes), _production_log_handling(), _recording_scan_context() as created:
        findings = sra.run_checks(max_workers=3)

    assert [f.status for f in findings] == [Status.PASS, Status.ERROR, Status.ERROR, Status.PASS]
    gc.collect()
    assert len(created) == 1
    assert created[0]() is None


@pytest.mark.skipif(not hasattr(signal, "pthread_kill"), reason="needs signal.pthread_kill")
def test_ctrl_c_skips_pending_work_waits_for_running_checks_and_releases_the_context(
    spy_thread: type[_SpyThread],
) -> None:
    if (
        threading.current_thread() is not threading.main_thread()
        or signal.getsignal(signal.SIGINT) is not signal.default_int_handler
    ):
        pytest.skip("SIGINT must reach this thread as KeyboardInterrupt")

    main_ident = threading.main_thread().ident
    alpha_started = threading.Event()
    lock = threading.Lock()
    log: list[str] = []

    def note(entry: str) -> None:
        with lock:
            log.append(entry)

    def wait_for_join() -> None:
        assert spy_thread.joining.wait(TIMEOUT)

    def alpha_first(self: SecurityCheck) -> None:
        note("start SRA-ALPHA-01")
        alpha_started.set()
        wait_for_join()
        note("end SRA-ALPHA-01")

    def bravo_first(self: SecurityCheck) -> None:
        note("start SRA-BRAVO-01")
        assert alpha_started.wait(TIMEOUT)
        signal.pthread_kill(main_ident, signal.SIGINT)
        wait_for_join()
        note("end SRA-BRAVO-01")

    def must_not_run(self: SecurityCheck) -> None:
        note(f"start {self.meta.check_id}")

    classes = [
        _check("Alpha", 1, _passing(alpha_first)),
        _check("Alpha", 2, _passing(must_not_run)),
        _check("Bravo", 1, _passing(bravo_first)),
        _check("Bravo", 2, _passing(must_not_run)),
        _check("Charlie", 1, _passing(must_not_run)),
    ]
    sra = _sra()

    with _isolated_registry(classes), _production_log_handling(), _recording_scan_context() as created:
        with pytest.raises(KeyboardInterrupt) as excinfo:
            sra.run_checks(max_workers=2)
        note("raised")
        del excinfo

    assert sorted(log[:-1]) == sorted(
        ["start SRA-ALPHA-01", "end SRA-ALPHA-01", "start SRA-BRAVO-01", "end SRA-BRAVO-01"]
    )
    assert log[-1] == "raised"
    gc.collect()
    assert len(created) == 1
    assert created[0]() is None
