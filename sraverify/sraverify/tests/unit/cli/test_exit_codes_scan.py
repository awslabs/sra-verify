"""CLI exit 0 with findings, and exit 1 on a write failure (task 20.2).

**Validates: Requirements 9.13, 9.14**

Sibling of ``test_exit_codes.py``, which covers the two exit-**2** usage-error
paths against the real catalog. This module covers the other two statuses the
CodeBuild fan-out reads, and both are about a scan that *ran*:

  * **exit 0** once the report is written, no matter how many FAIL and ERROR
    rows it holds (9.13);
  * **exit 1** when the report could not be written, with the path and the
    reason logged and no scan summary on stdout (9.14).

Why exit 0 with FAIL rows is load-bearing
-----------------------------------------

The instinct runs the other way -- a tool that found problems "failed" -- and
acting on that instinct breaks the fan-out. ``2-sraverify-codebuild-deploy.yaml``
runs one ``sraverify`` process per ACTIVE organization account under
``parallel -j ${PARALLEL_ACCOUNTS}``, and GNU ``parallel`` treats a job's
non-zero exit as that job having failed: it counts the failure into the exit
status it eventually returns, and with ``--halt`` in play it stops dispatching
work. Since a FAIL row is the *normal* result of scanning an account that is
not fully SRA-conformant, a status keyed on finding counts would mark most
accounts as failed jobs and make the one signal the buildspec actually needs --
"this invocation produced no usable report" -- unreadable. The same argument
covers ERROR rows: one check that could not be evaluated is one row, not a
failed account.

So the status is keyed on the report, not on its contents. The consolidation
step then reads a missing CSV as a real problem and a CSV full of FAIL rows as
a successful scan, which is the distinction 9.13 and 9.14 exist to preserve.

How a scan is driven without AWS
--------------------------------

The catalog is swapped for three synthetic checks -- one yielding a PASS, one a
FAIL, one raising so the orchestrator synthesizes the ERROR row -- following
``tests/property/test_context_isolation_property.py``:

  * ``_isolated_registry`` empties ``registry._REGISTRY`` in place and registers
    the probes. Emptying is load-bearing, not tidiness: with the real 158-check
    catalog present, ``--account-type all`` would select all of it and the scan
    would go to AWS.
  * ``_seeded_scan_context`` patches the ``ScanContext`` name in ``main`` with a
    factory that pre-seeds ``_account_info``, so ``get_account_info()`` returns
    from its cache and never reaches ``sts:GetCallerIdentity``. ``run_checks``
    calls it once before the loop and every ``passed()`` / ``failed()`` call
    goes through it.
  * the session is a ``_NoAwsSession`` that records and refuses every
    ``client()`` build, so "this test reaches no AWS" is structural rather than
    conventional.

The ERROR row is produced by a check that genuinely raises, rather than by
handing ``main()`` a pre-built list. That keeps ``_synthetic_error`` and the
per-check guard inside what is being confirmed: an ERROR row reaching the CSV
and still exiting 0 is the whole of 9.13's "regardless of how many ERROR
Findings were produced".

The evidence this automates
---------------------------

``.tmp/acceptance/after.csv`` is a real capture from a live account -- 35 PASS,
38 FAIL, 1 ERROR, CLI exited 0 -- so 9.13 is confirmed against AWS as well.
That is a one-off artifact of the acceptance gate, though, and cannot fail in
CI. This module is the standing check.
"""
from __future__ import annotations

import contextlib
import csv
import errno
import logging
import os
import re
from pathlib import Path
from typing import Any, Iterator

import pytest

from sraverify.core import registry
from sraverify.core.check import SecurityCheck
from sraverify.core.enums import AccountType, Severity, Status
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.core.scan_context import ScanContext
from sraverify import main as main_module
from sraverify.utils.outputs import write_csv_output as real_write_csv_output

# Reused verbatim from the task 20.1 module rather than re-derived. ``logged``
# is a fixture, and importing it into this namespace is what makes it
# resolvable here; ``caplog`` cannot substitute for it, because
# ``core/logging.py`` sets ``logger.propagate = False`` deliberately and
# ``capsys`` misses the logger's handler, which captured ``sys.stderr`` at
# import time.
from sraverify.tests.unit.cli.test_exit_codes import _run_cli, logged  # noqa: F401


# --------------------------------------------------------------------------- #
# Probe account identity and regions
# --------------------------------------------------------------------------- #

#: Pre-seeded into ``ctx._account_info``, so no STS call is made. Twelve digits,
#: matching the shape of a real account ID, so a failure message reads like the
#: real thing.
_PROBE_ACCOUNT_ID = "111122223333"
_PROBE_ACCOUNT_NAME = "probe-account"

#: Supplied as ``--regions`` so region resolution never falls back to a lazy
#: ``ec2:DescribeRegions``. One region keeps the expected row count at exactly
#: one per probe, which is what makes the summary tallies assertable as
#: literals.
_PROBE_REGION = "us-east-1"


class _NoAwsSession:
    """A ``boto3.Session`` stand-in that records and refuses every client build.

    ``region_name`` is a real attribute because ``main()`` reads
    ``sra.session.region_name`` while evaluating ``print_banner``'s arguments.

    ``print_banner`` asks for an ``sts`` client and swallows the failure in a
    bare ``except Exception``, printing "Unable to retrieve identity
    information" instead of the account line. That is expected here and is why
    ``client()`` records before it raises: the recording survives a caller that
    swallows the exception, so the assertion below can say the precise thing --
    that the *scan* built no client -- rather than the vague thing.
    """

    region_name = _PROBE_REGION

    def __init__(self) -> None:
        self.client_calls: list[tuple] = []

    def client(self, *args: Any, **kwargs: Any) -> Any:
        self.client_calls.append((args, kwargs))
        raise AssertionError(
            f"this scan must reach no AWS API; a client was requested: "
            f"args={args!r} kwargs={kwargs!r}"
        )

    def service_names(self) -> list[str]:  # pragma: no cover - defensive
        """Present so an accidental introspection call fails loudly, not oddly."""
        raise AssertionError("this scan must not enumerate boto3 services")


# --------------------------------------------------------------------------- #
# The three synthetic checks: one PASS, one FAIL, one that raises
# --------------------------------------------------------------------------- #

def _execute_pass(self: SecurityCheck) -> Iterator[Finding]:
    """Yield exactly one PASS row."""
    yield self.passed(
        region=_PROBE_REGION,
        resource_id="probe/configured",
        actual_value="Probe control is configured",
    )


def _execute_fail(self: SecurityCheck) -> Iterator[Finding]:
    """Yield exactly one FAIL row.

    ``remediation`` is omitted, so the row carries ``meta.remediation.text``.
    A FAIL is the status this whole module is about: it must reach the CSV and
    it must not move the exit status.
    """
    yield self.failed(
        region=_PROBE_REGION,
        resource_id="probe/misconfigured",
        actual_value="Probe control is not configured",
    )


def _execute_raise(self: SecurityCheck) -> Iterator[Finding]:
    """Raise, so the orchestrator contributes one synthetic ERROR row.

    Deliberately a genuine failure rather than a hand-built ERROR ``Finding``:
    the row then comes from ``_synthetic_error`` through the real per-check
    guard, which is the path a broken check actually takes in production.
    """
    raise RuntimeError("probe failure inside execute()")
    yield  # pragma: no cover - unreachable, but makes this a generator


def _setup_clients_noop(self: SecurityCheck) -> None:
    """Register no client wrappers. Nothing here reaches ``ctx.get_client``."""
    self._clients.clear()


#: (index, execute body, the Status its single row carries).
_PROBE_SHAPES = (
    (1, _execute_pass, Status.PASS),
    (2, _execute_fail, Status.FAIL),
    (3, _execute_raise, Status.ERROR),
)


def _make_probe_check(index: int, execute: Any) -> type[SecurityCheck]:
    """Build one throwaway check class carrying a real, validated ``CheckMeta``.

    Created with ``type()`` inside this module, whose file stem does not begin
    with ``sra_``, so ``__init_subclass__`` returns silently: no identity
    cross-check runs and the class does not self-register. Registration is
    explicit, in ``_isolated_registry``, which is what scopes the synthetic
    catalog to one test.

    The ``meta`` is a genuine ``CheckMeta`` because so much reads it --
    ``_select`` reads two fields, ``passed()`` and ``failed()`` six,
    ``_synthetic_error`` eight -- that a stand-in object would only move the
    failure somewhere less obvious.

    Args:
        index: 1-based position, giving the check its ``NN`` segment.
        execute: The body to install as ``execute``.

    Returns:
        A concrete ``SecurityCheck`` subclass, unregistered.
    """
    check_id = f"SRA-PROBE-{index:02d}"
    meta = CheckMeta(
        check_id=check_id,
        title=f"Probe control {index} is configured",
        description=(
            "Synthetic check used by the CLI exit-code tests. It reaches no "
            "AWS API and exists only to place a row of a known status into "
            "the report."
        ),
        check_logic="Yields one row of a fixed status for a fixed region",
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="Probe",
        resource_type="AWS::Probe::Resource",
        remediation=Remediation(text="Configure the probe control."),
    )
    return type(
        check_id.replace("-", "_"),
        (SecurityCheck,),
        {
            "__doc__": "Throwaway probe check for the CLI exit-code tests.",
            "__module__": __name__,
            "meta": meta,
            "execute": execute,
            "_setup_clients": _setup_clients_noop,
        },
    )


# --------------------------------------------------------------------------- #
# Isolation helpers
# --------------------------------------------------------------------------- #

@contextlib.contextmanager
def _isolated_registry(classes: list[type[SecurityCheck]]) -> Iterator[None]:
    """Replace the catalog with *classes* for the duration of the block.

    ``_REGISTRY`` is emptied first and restored by mutating the same dict in
    place rather than rebinding the name, so a module holding a reference to it
    sees the restored contents.
    """
    saved = dict(registry._REGISTRY)
    registry._REGISTRY.clear()
    try:
        for cls in classes:
            registry.register(cls.meta.check_id, cls)
        yield
    finally:
        registry._REGISTRY.clear()
        registry._REGISTRY.update(saved)


@contextlib.contextmanager
def _seeded_scan_context(monkeypatch) -> Iterator[None]:
    """Patch ``main.ScanContext`` with a factory that pre-seeds account identity.

    ``get_account_info()`` checks ``_account_info`` first, under the lock, and
    returns it on a hit, so seeding it is what keeps ``sts:GetCallerIdentity``
    and ``account:GetAccountInformation`` out of the scan. The object built is
    still a real ``ScanContext``; only its identity cache is warm.
    """
    original = main_module.ScanContext

    def factory(**kwargs: Any) -> ScanContext:
        ctx = original(**kwargs)
        ctx._account_info = {
            "account_id": _PROBE_ACCOUNT_ID,
            "account_name": _PROBE_ACCOUNT_NAME,
        }
        return ctx

    monkeypatch.setattr(main_module, "ScanContext", factory)
    yield


@pytest.fixture
def probe_scan(monkeypatch) -> Iterator[_NoAwsSession]:
    """Install the three-probe catalog, a warm context, and a refusing session.

    Yields:
        The ``_NoAwsSession`` handed to ``SRAVerify``, so a test can assert
        which client builds were attempted.
    """
    session = _NoAwsSession()
    monkeypatch.setattr(main_module, "get_session", lambda **kwargs: session)

    classes = [_make_probe_check(index, body) for index, body, _ in _PROBE_SHAPES]
    with _isolated_registry(classes), _seeded_scan_context(monkeypatch):
        yield session


def _read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    """Read *path* as the contract CSV.

    ``newline=""`` because the writer pins ``\\r\\n`` and universal-newline
    translation would rewrite it before ``csv`` saw it.

    Returns:
        ``(fieldnames, rows)``.
    """
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


#: Markers unique to ``print_summary``'s block, so their absence really does mean
#: the summary was suppressed.
#:
#: ``"Output:"`` is deliberately NOT among them. ``print_banner`` prints its own
#: ``· Output: <path>`` line *before* the scan, announcing where the report is
#: intended to go, so it appears on the write-failure path too and would make
#: this helper fail for the wrong reason. The heading and the four tallies are
#: printed only by ``print_summary``, and all five are checked rather than the
#: heading alone, so a regression that printed the tallies without the heading
#: is caught as well.
_SUMMARY_MARKERS = (
    "-> Scan complete!",
    "Total findings:",
    "Pass:",
    "Fail:",
    "Error:",
)


def _stdout_has_no_summary(out: str) -> None:
    """Assert no scan summary appears in *out*."""
    for marker in _SUMMARY_MARKERS:
        assert marker not in out, (
            f"a scan summary reached stdout: {marker!r} is present in {out!r}"
        )


# --------------------------------------------------------------------------- #
# Requirement 9.13 -- exit 0 with PASS, FAIL, and ERROR rows
# --------------------------------------------------------------------------- #

def test_a_scan_with_fail_and_error_rows_exits_0(
    probe_scan: _NoAwsSession,
    logged: list[logging.LogRecord],
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """One PASS, one FAIL, one ERROR: the report is written and the status is 0.

    The exit status does not read the findings at all. In ``main()`` the only
    ``sys.exit`` reachable once ``write_csv_output`` returns is the trailing
    ``sys.exit(0)``; nothing between the writer and it inspects a status or a
    severity, and ``print_summary`` only counts for the operator's benefit.
    That is the whole of 9.13's implementation, and this test is what keeps a
    later "return non-zero when something failed" from looking harmless.

    Validates: Requirements 9.13
    """
    output_file = tmp_path / "findings.csv"

    status = _run_cli(
        monkeypatch,
        [
            "--output", str(output_file),
            "--regions", _PROBE_REGION,
        ],
    )

    assert status == 0, (
        f"a scan with FAIL and ERROR rows exited {status}; a non-zero status "
        f"here marks the account as a failed job in the CodeBuild "
        f"`parallel -j` fan-out, and a FAIL row is the tool working (9.13)"
    )

    # ---- The report exists, at the path that was asked for ------------- #
    assert output_file.exists(), f"exit 0 but nothing was written to {output_file}"
    fieldnames, rows = _read_csv(output_file)
    assert fieldnames == list(Finding.FIELDS), (
        f"header is {fieldnames!r}, expected the 16-column contract "
        f"{list(Finding.FIELDS)!r}"
    )

    # ---- All three statuses genuinely reached the CSV ------------------- #
    # Without this the exit-0 assertion would hold vacuously over a scan that
    # produced only PASS rows, which is the one case 9.13 is not about.
    by_check = {row["CheckId"]: row for row in rows}
    assert len(rows) == 3, (
        f"expected one row per probe, got "
        f"{[(r['CheckId'], r['Status']) for r in rows]}"
    )
    for index, _, expected_status in _PROBE_SHAPES:
        check_id = f"SRA-PROBE-{index:02d}"
        assert check_id in by_check, f"{check_id} contributed no row"
        assert by_check[check_id]["Status"] == expected_status.value, (
            f"{check_id} carries Status={by_check[check_id]['Status']!r}, "
            f"expected {expected_status.value!r}"
        )
        assert by_check[check_id]["AccountId"] == _PROBE_ACCOUNT_ID
        assert by_check[check_id]["AccountName"] == _PROBE_ACCOUNT_NAME

    # The ERROR row came from the orchestrator's synthetic builder, so it
    # carries the check's real severity and names the exception type -- not the
    # pre-change "UNKNOWN" severity with no account name.
    error_row = by_check["SRA-PROBE-03"]
    assert error_row["Severity"] == Severity.MEDIUM.value
    assert "RuntimeError" in error_row["ActualValue"], (
        f"the synthetic ERROR row does not name the exception type: "
        f"{error_row['ActualValue']!r}"
    )

    # ---- The scan summary DID reach stdout ------------------------------ #
    # Its presence is the operator's evidence that a usable report exists,
    # which is exactly why 9.14 suppresses it on the write-failure path below.
    out = capsys.readouterr().out
    assert "-> Scan complete!" in out, f"no scan summary on stdout: {out!r}"
    # Everything after the heading, so the path assertion below is about the
    # summary's echo and not about the banner's earlier "Output:" line, which
    # states an intention rather than a fact.
    summary = out.split("-> Scan complete!", 1)[1]
    assert "Total findings: 3" in summary, f"summary tally is wrong: {summary!r}"
    assert "Pass: 1" in summary, f"summary tally is wrong: {summary!r}"
    assert "Fail: 1" in summary, f"summary tally is wrong: {summary!r}"
    assert "Error: 1" in summary, f"summary tally is wrong: {summary!r}"
    assert str(output_file) in summary, (
        f"the summary does not echo the resolved output path: {summary!r}"
    )

    # ---- The scan itself reached no AWS API ----------------------------- #
    # print_banner asks for an sts client and swallows the refusal, so that one
    # attempt is expected. Anything else means a probe, the orchestrator, or
    # the writer went to AWS.
    scan_calls = [
        call for call in probe_scan.client_calls if call[0][:1] != ("sts",)
    ]
    assert scan_calls == [], f"the scan built an AWS client: {scan_calls!r}"

    # The broken check was logged with a traceback and cost exactly one row,
    # not the scan (10.2). Asserted here because it is what makes the ERROR row
    # above attributable rather than incidental.
    errors = [r for r in logged if r.levelno >= logging.ERROR]
    assert any("SRA-PROBE-03" in r.getMessage() for r in errors), (
        f"the failing check was not logged: "
        f"{[r.getMessage() for r in errors]!r}"
    )


def test_the_exit_status_does_not_move_with_the_fail_and_error_counts(
    probe_scan: _NoAwsSession,
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """Narrowing to only the FAIL check, then only the ERROR check, still exits 0.

    The test above has a PASS row present, so an implementation keyed on
    "any PASS at all" would survive it. These two runs have none: the first
    report holds a single FAIL row and nothing else, the second a single ERROR
    row and nothing else. Both are the shape a bare account and a
    permission-starved account respectively produce in the fan-out, and both
    must still be worth 0.

    Validates: Requirements 9.13
    """
    for check_id, expected_status in (
        ("SRA-PROBE-02", Status.FAIL),
        ("SRA-PROBE-03", Status.ERROR),
    ):
        output_file = tmp_path / f"{check_id}.csv"

        status = _run_cli(
            monkeypatch,
            [
                f"--check={check_id}",
                "--output", str(output_file),
                "--regions", _PROBE_REGION,
            ],
        )

        assert status == 0, (
            f"a scan whose only row is {expected_status.value} exited {status}"
        )
        _, rows = _read_csv(output_file)
        assert [row["Status"] for row in rows] == [expected_status.value], (
            f"expected exactly one {expected_status.value} row, got "
            f"{[(r['CheckId'], r['Status']) for r in rows]}"
        )
        assert "-> Scan complete!" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Requirement 9.14 -- exit 1 on a write failure
# --------------------------------------------------------------------------- #

#: The three ways an ``--output`` path is unwritable, each raising a distinct
#: ``OSError`` subclass out of ``open()``.
#:
#: ``chmod`` is deliberately not among them. A mode-000 directory is no
#: obstacle to uid 0, so a ``chmod``-based case silently stops testing anything
#: in a root container -- which is precisely where CI and the CodeBuild image
#: run. These three are structural and behave identically for every uid.
_UNWRITABLE_FLAVORS = (
    # A regular file where a directory component is expected -> ENOTDIR.
    ("parent_is_a_file", "blocker.txt/findings.csv"),
    # A directory component that does not exist -> ENOENT. main() creates no
    # directory, which outputs.py documents as deliberate.
    ("parent_is_missing", "no/such/directory/findings.csv"),
    # The output path is itself an existing directory -> EISDIR.
    ("output_is_a_directory", "findings.csv"),
)


#: The shape ``main()`` resolves when ``--output`` is omitted: the default base
#: name with ``_YYYYmmdd_HHMMSS`` inserted before the extension (9.12).
_STAMPED_DEFAULT_RE = re.compile(r"sraverify_findings_\d{8}_\d{6}\.csv", re.ASCII)


def _build_unwritable(flavor: str, tmp_path: Path, relative: str) -> Path:
    """Create the obstacle for *flavor* and return the unwritable output path."""
    if flavor == "parent_is_a_file":
        (tmp_path / "blocker.txt").write_text("not a directory\n", encoding="utf-8")
    elif flavor == "output_is_a_directory":
        (tmp_path / "findings.csv").mkdir()
    # "parent_is_missing" needs no obstacle: the absence *is* the obstacle.
    return tmp_path / relative


@pytest.mark.parametrize(
    "flavor,relative", _UNWRITABLE_FLAVORS, ids=[f for f, _ in _UNWRITABLE_FLAVORS]
)
def test_an_unwritable_output_exits_1_naming_the_path_and_the_reason(
    flavor: str,
    relative: str,
    probe_scan: _NoAwsSession,
    logged: list[logging.LogRecord],
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """The scan succeeds, the write fails: exit 1, path and reason logged, no summary.

    All three flavors reach the same ``except OSError`` in ``main()`` -- they
    differ only in errno -- and the point of covering three is that the handler
    catches ``OSError`` rather than any one subclass. ``NotADirectoryError``,
    ``FileNotFoundError``, and ``IsADirectoryError`` are siblings, and a handler
    narrowed to one of them would let the other two escape as a traceback.

    Status 1 rather than 2 is a deliberate distinction, not an arbitrary
    numbering: 2 is reserved for arguments that will not work on a second run,
    whereas a write failure is often transient -- a full disk, a stale working
    directory -- so it is worth retrying.

    Validates: Requirements 9.14
    """
    output_file = _build_unwritable(flavor, tmp_path, relative)

    # Establish what the OS actually says, so the "reason" assertion below
    # compares against the real message rather than a guessed one. This is also
    # the non-vacuity guard: if the path turned out to be writable, the exit-1
    # assertion would be testing nothing.
    with pytest.raises(OSError) as probe:
        output_file.open("w", encoding="utf-8").close()
    expected_reason = probe.value.strerror
    assert expected_reason, "the OS reported no strerror to assert against"

    # Wrap the real writer so the test can prove the *scan* succeeded and only
    # the write failed. Without this, an exit 1 caused by an empty or aborted
    # scan would look identical from outside.
    write_calls: list[int] = []

    def recording_write(findings, path):
        write_calls.append(len(findings))
        return real_write_csv_output(findings, path)

    monkeypatch.setattr(main_module, "write_csv_output", recording_write)

    status = _run_cli(
        monkeypatch,
        [
            "--output", str(output_file),
            "--regions", _PROBE_REGION,
        ],
    )

    # ---- Exactly 1, and distinct from the 2 reserved for usage errors --- #
    assert status == 1, (
        f"an unwritable --output exited {status}, expected exactly 1 (9.14)"
    )

    # ---- The scan ran to completion; only the write failed -------------- #
    assert write_calls == [3], (
        f"the writer was called {write_calls!r}; expected one call carrying "
        f"the three rows the probes produced, so that exit 1 is attributable "
        f"to the write and not to an empty scan"
    )

    # ---- Nothing was left behind at the resolved path ------------------- #
    assert not output_file.is_file(), (
        f"the write-failure path left a file at {output_file}"
    )

    # ---- The logged error names BOTH the path and the reason ------------ #
    errors = [r for r in logged if r.levelno >= logging.ERROR]
    write_errors = [
        r.getMessage() for r in errors
        if str(output_file) in r.getMessage()
    ]
    assert write_errors, (
        f"no logged error names the output path {str(output_file)!r}: "
        f"{[r.getMessage() for r in errors]!r}"
    )
    assert any(expected_reason in message for message in write_errors), (
        f"the logged error names the path but not the reason "
        f"{expected_reason!r}: {write_errors!r}"
    )

    # ---- No scan summary on stdout -------------------------------------- #
    # The summary is the operator's evidence that a usable report exists at the
    # path it echoes. Printing it after a failed write would assert the exact
    # opposite of the truth, and would do it on stdout, where the buildspec and
    # the operator both look.
    _stdout_has_no_summary(capsys.readouterr().out)

    # ---- The failure was caught at the write boundary ------------------- #
    # ``_run_cli`` already proves it: it asserts a ``SystemExit``, so an OSError
    # escaping ``main()`` would surface as that OSError instead. The record
    # check adds the other half -- the error was reported as a message, with no
    # ``exc_info``, so an operator sees one line naming the path and the reason
    # rather than a traceback for a condition the tool understands perfectly
    # well.
    boundary = [
        r for r in errors
        if str(output_file) in r.getMessage() and r.exc_info is None
    ]
    assert boundary, (
        f"the write failure was logged with a traceback rather than as a "
        f"handled condition: {[(r.getMessage(), r.exc_info) for r in errors]!r}"
    )


def test_a_write_failure_at_the_default_output_path_names_the_resolved_path(
    probe_scan: _NoAwsSession,
    logged: list[logging.LogRecord],
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """The timestamp-injecting branch reaches the same handler, naming its own path.

    With ``--output`` omitted, ``main()`` resolves the path itself by injecting
    ``_YYYYmmdd_HHMMSS`` before the extension (9.12), and the handler has to
    name *that* resolved path. Naming the unstamped default base name instead
    would tell the operator a write to ``sraverify_findings.csv`` failed when no
    such write was ever attempted, and would send them looking for the wrong
    file.

    The ``OSError`` is injected at the writer rather than arranged on disk,
    which is what 9.14 describes -- "IF the CSV_Writer reports that it could not
    write" -- and lets this test use ``ENOSPC``, the transient full-disk case
    ``main()``'s own comment names as the reason this is status 1 and not 2.
    A full disk cannot be arranged portably; the three flavors above cover the
    genuine filesystem origins.

    Validates: Requirements 9.12, 9.14
    """
    monkeypatch.chdir(tmp_path)

    attempted: list[str] = []

    def failing_write(findings, path):
        attempted.append(path)
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC), path)

    monkeypatch.setattr(main_module, "write_csv_output", failing_write)

    status = _run_cli(monkeypatch, ["--regions", _PROBE_REGION])

    assert status == 1, f"a failed write at the default path exited {status}"
    assert len(attempted) == 1, f"the writer was called {len(attempted)} times"

    resolved = attempted[0]
    # The resolved path is stamped, so it is not the default base name.
    assert resolved != main_module.DEFAULT_OUTPUT, (
        f"--output was omitted, so a timestamp should have been injected, but "
        f"the resolved path is the bare default {resolved!r} (9.12)"
    )
    assert _STAMPED_DEFAULT_RE.fullmatch(resolved), (
        f"the resolved default path {resolved!r} does not match "
        f"{_STAMPED_DEFAULT_RE.pattern!r}"
    )

    errors = [r.getMessage() for r in logged if r.levelno >= logging.ERROR]
    assert any(resolved in message for message in errors), (
        f"no logged error names the resolved path {resolved!r}; the operator "
        f"needs the path that was actually attempted: {errors!r}"
    )
    assert any(
        resolved in message and os.strerror(errno.ENOSPC) in message
        for message in errors
    ), (
        f"the logged error does not carry both the resolved path and the "
        f"reason {os.strerror(errno.ENOSPC)!r}: {errors!r}"
    )

    _stdout_has_no_summary(capsys.readouterr().out)
    assert not list(tmp_path.iterdir()), (
        f"the write-failure path left "
        f"{[p.name for p in tmp_path.iterdir()]} behind"
    )


# --------------------------------------------------------------------------
# The check_done gate marker (Requirement 6.3)
#
# The acceptance gate attributes each aws_call_failed record to a check by
# position: execution within one invocation is single-threaded, so every failure
# logged since the previous marker belongs to the check whose marker comes next.
# That only works if there is exactly one marker per check, in execution order,
# on both the healthy and the degraded path. The three probes give one of each
# plus a raiser, so this asserts the whole shape in one pass.
# --------------------------------------------------------------------------

_CHECK_DONE_RE = re.compile(
    r"^check_done check_id=(?P<check_id>\S+) rows=(?P<rows>\S+)$", re.ASCII
)


def _check_done_markers(records):
    """Return the parsed ``check_done`` markers, in emission order.

    Args:
        records: Captured ``sraverify`` log records.

    Returns:
        A list of ``(check_id, rows)`` pairs.
    """
    markers = []
    for record in records:
        match = _CHECK_DONE_RE.match(record.getMessage())
        if match:
            markers.append((match.group("check_id"), match.group("rows")))
    return markers


def test_each_check_emits_exactly_one_check_done_marker_in_execution_order(
    probe_scan, monkeypatch, tmp_path, logged, capsys
):
    # One marker per check, in the order the checks ran, with the raising probe
    # reporting `synthetic` rather than a count.
    #
    # The raiser is the case worth having: without a marker on the degraded path
    # its diagnostics would fold into the *next* check's window and the gate
    # would attribute another check's failure to it. `rows=synthetic` also
    # doubles as the evidence the acceptance gate needs to admit a row that
    # appears in the candidate scan and not the reference one.
    monkeypatch.chdir(tmp_path)

    status = _run_cli(monkeypatch, ["--regions", _PROBE_REGION])
    assert status == 0, f"the probe scan exited {status}"

    markers = _check_done_markers(logged)

    assert markers == [
        ("SRA-PROBE-01", "1"),
        ("SRA-PROBE-02", "1"),
        ("SRA-PROBE-03", "synthetic"),
    ], (
        f"expected one marker per probe in execution order with the raiser "
        f"reporting synthetic, got {markers}"
    )


def test_the_marker_is_visible_without_the_debug_flag(
    probe_scan, monkeypatch, tmp_path, logged, capsys
):
    # Requirement 6.3 is explicit that the buildspec must NOT pass --debug: it
    # would bury the markers under every boto3 detail and inflate the artefact.
    # The marker is therefore `info`, and the `sraverify` logger's default level
    # of INFO is what makes it visible as shipped. If someone lowered the marker
    # to `debug`, the gate would silently see no markers at all and attribute
    # every failure in an invocation to one check.
    monkeypatch.chdir(tmp_path)

    _run_cli(monkeypatch, ["--regions", _PROBE_REGION])

    markers = _check_done_markers(logged)
    assert markers, "no check_done marker was emitted without --debug"

    levels = {
        record.levelno
        for record in logged
        if _CHECK_DONE_RE.match(record.getMessage())
    }
    assert levels == {logging.INFO}, (
        f"check_done must be emitted at exactly INFO, got {levels}"
    )


def test_the_marker_goes_to_the_logger_and_not_to_stdout(
    probe_scan, monkeypatch, tmp_path, logged, capsys
):
    # The marker is a diagnostic, so it belongs on stderr with everything else --
    # the MCP server shares stdout with its JSON-RPC transport. Requirement 8.1
    # names this line as one of the paths that must go through the logger.
    monkeypatch.chdir(tmp_path)

    _run_cli(monkeypatch, ["--regions", _PROBE_REGION])

    assert _check_done_markers(logged), "the marker was not logged"
    assert "check_done" not in capsys.readouterr().out, (
        "check_done reached stdout; it must go through the sraverify logger"
    )


def test_the_marker_count_matches_the_number_of_checks_selected(
    probe_scan, monkeypatch, tmp_path, logged, capsys
):
    # With --check narrowing the selection to one probe, exactly one marker is
    # emitted. A marker emitted per *finding* or per Region rather than per check
    # would break the gate's windowing without changing any CSV cell, so the
    # count is worth pinning against a second selection size.
    monkeypatch.chdir(tmp_path)

    status = _run_cli(
        monkeypatch, ["--regions", _PROBE_REGION, "--check", "SRA-PROBE-02"]
    )
    assert status == 0, f"the single-check scan exited {status}"

    assert _check_done_markers(logged) == [("SRA-PROBE-02", "1")]
