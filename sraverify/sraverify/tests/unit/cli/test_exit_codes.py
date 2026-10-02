"""CLI exit-2 paths, asserted against the real 158-check catalog (task 20.1).

**Validates: Requirements 9.4, 9.7**

Two invocations must exit 2 and leave nothing behind:

  * ``--check SRA-TYPO-99`` -- an ID absent from the registry (9.4);
  * ``--account-type audit --service CloudTrail`` -- a *real-but-empty* filter
    combination, where each filter alone matches something and the
    intersection is empty (9.5 reached through 9.6).

Both previously logged an error, returned an empty finding list, wrote a
header-only CSV, and exited 0. In the CodeBuild fan-out that outcome is
indistinguishable from a member account that genuinely produced nothing: the
pandas consolidation step reads a valid CSV, finds no rows, and the account
disappears from the report without anything having reported a failure.

Why this module exists alongside the property tests
--------------------------------------------------

``tests/property/test_unknown_check_exit_property.py`` already covers the
unknown-ID path exhaustively, and ``tests/unit/core/test_select.py`` covers
``NoChecksSelectedError`` from ``select_checks``. Both install a **synthetic**
seven-key catalog, which is what makes their exact suggestion lists assertable.
Neither reaches ``main()`` for the ``NoChecksSelectedError`` path, and neither
says anything about the real catalog. Two gaps follow, and this module closes
exactly those:

  * the ``NoChecksSelectedError`` branch of ``main()``'s exit-2 handler -- the
    same ``except`` clause as the unknown-ID branch, but reached by a different
    exception, and the branch whose "no file was created" promise nothing
    currently checks;
  * the standing fact that ``audit`` + ``CloudTrail`` really is empty. That is
    a property of the live catalog, not of a fixture: if a CloudTrail check
    were ever declared ``account_type="audit"``, the test above would still
    pass for the wrong reason. ``test_the_audit_cloudtrail_combination_is_real_but_empty``
    is the guard, and it fails loudly rather than turning the exit-2 assertion
    vacuous.

The AWS boundary is asserted, not assumed. ``main()`` builds a real session and
calls ``print_banner``, which calls ``sts:GetCallerIdentity``. On the exit-2
path neither should reach AWS, because ``select_checks`` raises while
``print_banner``'s arguments are still being evaluated. Rather than trusting
that reading, every test here installs a session that records and refuses each
``client()`` build, and asserts nothing was recorded.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

from sraverify.core.registry import all_checks
from sraverify.cli import DEFAULT_OUTPUT, main


# --------------------------------------------------------------------------- #
# The two filter values under test
# --------------------------------------------------------------------------- #

#: The account type of the empty combination. Matched against
#: ``meta.account_type``, a ``StrEnum`` member, so the plain string compares
#: equal without ``.value``.
EMPTY_ACCOUNT_TYPE = "audit"

#: The service of the empty combination, spelled as ``meta.service`` spells it.
EMPTY_SERVICE = "CloudTrail"

#: A check ID absent from the registry, and far enough from every real key that
#: the suggestion list is legitimately empty -- the best real match scores
#: 0.5926, below the 0.6 cutoff 9.4 fixes. Asserted below rather than assumed,
#: because "no suggestions" and "suggestions suppressed by a bug" look the same
#: from outside.
UNKNOWN_CHECK_ID = "SRA-TYPO-99"

#: A one-character typo of a real key, which *does* clear the cutoff. Included
#: so this module covers the populated branch of the suggestion list against
#: the real catalog as well as the empty one.
NEAR_MISS_CHECK_ID = "SRA-CLOUDTRAL-01"


class _RefusingSession:
    """A boto3 ``Session`` stand-in that records and refuses every client build.

    ``region_name`` is a real attribute because ``main()`` resolves the scan
    Region -- falling back to the session's Region without ``--regions`` --
    before the banner and before ``select_checks`` raises.

    ``client()`` records the call and *then* raises, so the recording survives a
    caller that swallows the exception -- which ``print_banner`` does, in a bare
    ``except Exception``. Asserting ``client_calls == []`` therefore detects an
    attempted AWS call whether or not anyone noticed it failing.
    """

    region_name = "us-east-1"

    def __init__(self) -> None:
        self.client_calls: list[tuple] = []

    def client(self, *args, **kwargs):
        self.client_calls.append((args, kwargs))
        raise AssertionError(
            "the exit-2 usage-error path must build no AWS client; "
            f"asked for {args!r} {kwargs!r}"
        )


@pytest.fixture
def refusing_session(monkeypatch) -> _RefusingSession:
    """Install a ``_RefusingSession`` in place of the real session builder.

    Patches the name ``get_session`` in ``sraverify.scanner``'s namespace,
    which is where ``SRAVerify.__init__`` looks it up, so no credential
    resolution, no profile lookup, and no ``assume_role`` happens even before
    the question of an API call arises.
    """
    session = _RefusingSession()
    monkeypatch.setattr("sraverify.scanner.get_session", lambda **kwargs: session)
    return session


@pytest.fixture
def logged() -> list[logging.LogRecord]:
    """Collect the records the shared ``sraverify`` logger emits during a test.

    ``pytest``'s ``caplog`` cannot be used: ``cli.configure_logging`` sets
    ``logger.propagate = False`` deliberately, so once ``main()`` has run
    nothing reaches the root handler ``caplog`` installs. Attaching a handler
    directly to the named logger observes the same records the CLI's stderr
    handler writes.
    """
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collector()
    logger = logging.getLogger("sraverify")
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


def _run_cli(monkeypatch, argv: list[str]) -> int:
    """Invoke ``main()`` with *argv* and return the status it would exit with.

    ``main()`` returns its status and the console script wraps it in
    ``sys.exit``; argparse's own usage errors still raise ``SystemExit`` from
    inside ``parse_args``. Both are folded into one integer here.

    Args:
        monkeypatch: Used to install ``argv`` too, so a code path that reads
            ``sys.argv`` directly sees the same arguments.
        argv: The arguments after the program name.

    Returns:
        The integer exit status.
    """
    monkeypatch.setattr(sys, "argv", ["sraverify", *argv])
    try:
        status = main(argv)
    except SystemExit as exc:
        status = exc.code
    assert isinstance(status, int), (
        f"exited with {status!r}; a non-integer argument to sys.exit makes the "
        f"process exit 1 and print that value to stderr, which loses the "
        f"1-versus-2 distinction the fan-out reads"
    )
    return status


# --------------------------------------------------------------------------- #
# The vacuity guard: the combination really is empty
# --------------------------------------------------------------------------- #

def test_the_audit_cloudtrail_combination_is_real_but_empty() -> None:
    """Each filter alone matches something; together they match nothing.

    Without this, the exit-2 assertion below would still pass if ``CloudTrail``
    stopped being a real service display name, or if ``audit`` stopped being a
    declared account type -- the combination would be empty for an
    uninteresting reason and the test would prove nothing about 9.6.

    Validates: Requirements 9.5, 9.6
    """
    registry = all_checks()

    by_account_type = [
        check_id for check_id, cls in registry.items()
        if cls.meta.account_type == EMPTY_ACCOUNT_TYPE
    ]
    by_service = [
        check_id for check_id, cls in registry.items()
        if cls.meta.service.lower() == EMPTY_SERVICE.lower()
    ]

    assert by_account_type, (
        f"no check declares account_type={EMPTY_ACCOUNT_TYPE!r}, so the "
        f"combination below is empty for the wrong reason"
    )
    assert by_service, (
        f"no check declares service={EMPTY_SERVICE!r}, so the combination "
        f"below is empty for the wrong reason"
    )
    assert set(by_account_type).isdisjoint(by_service), (
        f"{EMPTY_SERVICE} now has {EMPTY_ACCOUNT_TYPE}-typed checks "
        f"{sorted(set(by_account_type) & set(by_service))}, so this "
        f"combination is no longer empty; pick another pair for these tests"
    )


# --------------------------------------------------------------------------- #
# Exit 2, no file: the real-but-empty filter combination
# --------------------------------------------------------------------------- #

def test_an_empty_filter_combination_exits_2_and_creates_no_file(
    refusing_session: _RefusingSession,
    logged: list[logging.LogRecord],
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """``--account-type audit --service CloudTrail`` exits 2 writing nothing.

    ``--output`` is explicit and inside ``tmp_path``, so the resolved path is
    exactly the path named here -- no timestamp is injected -- and its absence
    afterwards is unambiguous. The directory is checked as a whole as well, so
    a CLI that synthesized a neighbouring file name is caught too.

    Validates: Requirements 9.7
    """
    output_file = tmp_path / "findings.csv"

    status = _run_cli(
        monkeypatch,
        [
            "--account-type", EMPTY_ACCOUNT_TYPE,
            "--service", EMPTY_SERVICE,
            "--output", str(output_file),
            # Supplied so lazy region resolution is never even a possibility.
            "--regions", "us-east-1",
        ],
    )

    assert status == 2, f"exited {status}, expected 2"
    assert not output_file.exists(), f"the exit-2 path created {output_file}"
    assert list(tmp_path.iterdir()) == [], (
        f"the exit-2 path created "
        f"{[p.name for p in tmp_path.iterdir()]} under {tmp_path}"
    )

    # No client was built, so no API call was attempted: selection is a pure
    # read of cls.meta, and it raises before print_banner's body runs.
    assert refusing_session.client_calls == [], (
        f"the exit-2 path built an AWS client: {refusing_session.client_calls!r}"
    )

    # Both supplied filter values are logged, so the operator can see which
    # combination was rejected (9.7).
    errors = [r.getMessage() for r in logged if r.levelno >= logging.ERROR]
    assert errors, "the exit-2 path logged no error"
    assert any(EMPTY_ACCOUNT_TYPE in message for message in errors), (
        f"the logged error does not name the account-type filter: {errors!r}"
    )
    assert any(EMPTY_SERVICE in message for message in errors), (
        f"the logged error does not name the service filter: {errors!r}"
    )

    # Nothing on stdout: no banner, and above all no scan summary. The summary
    # is the operator's evidence that a usable report exists.
    out = capsys.readouterr().out
    assert "Scan complete" not in out, (
        f"the exit-2 path printed a scan summary: {out!r}"
    )


def test_an_empty_filter_combination_creates_nothing_at_the_default_path(
    refusing_session: _RefusingSession,
    tmp_path: Path,
    monkeypatch,
) -> None:
    """The same, on the branch that injects a timestamp into the output path.

    With ``--output`` omitted there is no single path to assert the absence of,
    so the working directory is moved into ``tmp_path`` and the assertion
    becomes that it stayed empty -- which covers every name the stamp could
    have produced, and keeps a regression from depositing a stray CSV in the
    repository.

    Validates: Requirements 9.7
    """
    monkeypatch.chdir(tmp_path)

    status = _run_cli(
        monkeypatch,
        [
            "--account-type", EMPTY_ACCOUNT_TYPE,
            "--service", EMPTY_SERVICE,
            "--regions", "us-east-1",
        ],
    )

    assert status == 2
    assert list(tmp_path.iterdir()) == [], (
        f"the exit-2 path created {[p.name for p in tmp_path.iterdir()]} in "
        f"the working directory; the default output base name is "
        f"{DEFAULT_OUTPUT}"
    )
    assert refusing_session.client_calls == []


# --------------------------------------------------------------------------- #
# Exit 2, no file: an unknown check ID, against the real catalog
# --------------------------------------------------------------------------- #

def test_an_unknown_check_id_exits_2_and_creates_no_file(
    refusing_session: _RefusingSession,
    logged: list[logging.LogRecord],
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """``--check SRA-TYPO-99`` exits 2 writing nothing, and offers no hint.

    The empty suggestion list is the correct answer here and is asserted as
    such: no real key reaches the 0.6 cutoff against this ID, the closest
    scoring 0.5926. 9.4 admits an empty list, and it must not render as a
    dangling ``Did you mean: ?``.

    Validates: Requirements 9.4, 9.7
    """
    output_file = tmp_path / "findings.csv"

    status = _run_cli(
        monkeypatch,
        [
            f"--check={UNKNOWN_CHECK_ID}",
            "--output", str(output_file),
            "--regions", "us-east-1",
        ],
    )

    assert status == 2, f"exited {status}, expected 2"
    assert not output_file.exists(), f"the exit-2 path created {output_file}"
    assert list(tmp_path.iterdir()) == [], (
        f"the exit-2 path created "
        f"{[p.name for p in tmp_path.iterdir()]} under {tmp_path}"
    )
    assert refusing_session.client_calls == [], (
        f"the exit-2 path built an AWS client: {refusing_session.client_calls!r}"
    )

    errors = [r.getMessage() for r in logged if r.levelno >= logging.ERROR]
    assert any(UNKNOWN_CHECK_ID in message for message in errors), (
        f"the logged error does not name the supplied ID: {errors!r}"
    )
    assert not any("Did you mean" in message for message in errors), (
        f"a hintless error still rendered a hint: {errors!r}"
    )

    assert "Scan complete" not in capsys.readouterr().out


def test_a_near_miss_check_id_is_offered_the_best_three_in_9_4_order(
    refusing_session: _RefusingSession,
    logged: list[logging.LogRecord],
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A real-catalog typo yields three suggestions in the order 9.4 fixes.

    ``SRA-CLOUDTRAL-01`` scores 0.9697 against ``SRA-CLOUDTRAIL-01`` and 0.9091
    against each of ``02`` through ``13``, so the strict winner comes first and
    the two remaining slots are filled from that twelve-way tie in **ascending**
    check ID order. ``difflib.get_close_matches`` would fill them from the other
    end -- it selects with ``heapq.nlargest`` over ``(ratio, key)`` tuples, so
    ties come back descending -- and would suggest ``13, 12`` here. That is why
    ``scanner._near_misses`` scores the keys itself, and this is the assertion that
    catches a future simplification back to the stdlib helper against the real
    catalog rather than a fixture.

    Validates: Requirements 9.4, 9.7
    """
    output_file = tmp_path / "findings.csv"

    status = _run_cli(
        monkeypatch,
        [
            f"--check={NEAR_MISS_CHECK_ID}",
            "--output", str(output_file),
            "--regions", "us-east-1",
        ],
    )

    assert status == 2
    assert not output_file.exists()
    assert refusing_session.client_calls == []

    errors = [r.getMessage() for r in logged if r.levelno >= logging.ERROR]
    hinted = [message for message in errors if "Did you mean" in message]
    assert hinted, f"a near-miss ID was offered no suggestions: {errors!r}"
    assert (
        "Did you mean: SRA-CLOUDTRAIL-01, SRA-CLOUDTRAIL-02, "
        "SRA-CLOUDTRAIL-03?"
    ) in hinted[0], (
        f"suggestions are not the best three in 9.4 order: {hinted[0]!r}"
    )


# --------------------------------------------------------------------------- #
# Exit 2, no file, no AWS call: the scan Region cannot be determined
# (failfast tests 19-23a; Requirement 2.8, Property 33)
# --------------------------------------------------------------------------- #

ROLE = "arn:aws:iam::999988887777:role/SRAMemberRole"


class _RegionlessRefusingSession(_RefusingSession):
    """A refusing session with no Region, so only ``--regions`` could supply one."""

    region_name = None


class _RecordingSession(_RefusingSession):
    """Records and refuses every client build; carries a configurable Region."""

    def __init__(self, region_name: str) -> None:
        super().__init__()
        self.region_name = region_name  # type: ignore[assignment]


def _install_session(monkeypatch, session) -> None:
    """Hand ``session`` to ``SRAVerify`` in place of the real session builder."""
    monkeypatch.setattr("sraverify.scanner.get_session", lambda **kwargs: session)


def _install_regionless_boto3(monkeypatch) -> list[tuple]:
    """Replace ``boto3.Session`` as the real ``get_session`` sees it.

    Every session it builds has ``region_name = None`` and records and refuses
    every client build, so the real ``get_session`` -- including its AssumeRole
    path -- runs without credentials or network.

    Returns:
        The shared list of recorded ``client()`` calls.
    """
    import sraverify.core.session as session_module

    calls: list[tuple] = []

    class _FakeSession:
        def __init__(self, **kwargs) -> None:
            self.region_name = kwargs.get("region_name")

        def client(self, *args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError(f"no client may be built; asked for {args!r} {kwargs!r}")

    monkeypatch.setattr(session_module.boto3, "Session", _FakeSession)
    return calls


def _errors(logged: list[logging.LogRecord]) -> list[str]:
    return [r.getMessage() for r in logged if r.levelno >= logging.ERROR]


# 19
def test_an_undetermined_scan_region_exits_2_with_no_file_and_no_call(
    logged: list[logging.LogRecord], tmp_path: Path, monkeypatch, capsys
) -> None:
    """No ``--regions`` and no session Region: exit 2 before the banner."""
    session = _RegionlessRefusingSession()
    _install_session(monkeypatch, session)
    output_file = tmp_path / "findings.csv"

    status = _run_cli(monkeypatch, ["--output", str(output_file)])

    assert status == 2
    assert not output_file.exists()
    assert list(tmp_path.iterdir()) == []
    assert session.client_calls == []
    assert "Starting SRA Verify scan" not in capsys.readouterr().out
    errors = _errors(logged)
    assert len(errors) == 1, errors
    assert "--regions" in errors[0] and "AWS_DEFAULT_REGION" in errors[0]


def _real_boto3_env(monkeypatch, tmp_path: Path, **env: str) -> list[tuple]:
    """Run the real ``boto3.Session`` against a hermetic AWS environment.

    Clears every variable that could supply a Region or a profile, points the
    shared config and credentials files at empty files, then applies ``env``,
    so the result does not depend on the developer's shell or ``~/.aws``.
    ``Session.client`` records and refuses every build: no client is needed on
    the paths under test, and a refused banner build is swallowed by
    ``print_banner`` after being recorded.

    Returns:
        The list of recorded ``client()`` calls.
    """
    import boto3.session

    for name in ("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        monkeypatch.delenv(name, raising=False)
    aws_dir = tmp_path / "aws"
    aws_dir.mkdir()
    (aws_dir / "config").write_text("", encoding="utf-8")
    (aws_dir / "credentials").write_text("", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(aws_dir / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(aws_dir / "credentials"))
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    calls: list[tuple] = []

    def _refuse(self, *args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError(f"no client may be built; asked for {args!r} {kwargs!r}")

    monkeypatch.setattr(boto3.session.Session, "client", _refuse)
    return calls


# 19a
def test_aws_region_alone_does_not_supply_a_scan_region(
    logged: list[logging.LogRecord], tmp_path: Path, monkeypatch, capsys
) -> None:
    """boto3 does not read ``AWS_REGION``, so it alone is exit 2.

    Observed live: with ``AWS_REGION=us-west-2``, no ``AWS_DEFAULT_REGION``, no
    profile ``region =`` and no ``--regions``, the scan was refused while the
    message then in place advised setting ``AWS_REGION``. botocore maps
    ``region`` to ``AWS_DEFAULT_REGION`` only, and the library deliberately
    takes the Region exactly as boto3 resolves it, so the guard and the
    clients cannot disagree. The pinned behaviour is the refusal; the message
    must name the variable that does work.
    """
    calls = _real_boto3_env(monkeypatch, tmp_path, AWS_REGION="us-west-2")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    output_file = out_dir / "findings.csv"

    status = _run_cli(monkeypatch, ["--output", str(output_file)])

    assert status == 2
    assert not output_file.exists()
    assert list(out_dir.iterdir()) == []
    assert calls == []
    assert "Starting SRA Verify scan" not in capsys.readouterr().out
    errors = _errors(logged)
    assert len(errors) == 1, errors
    assert "--regions" in errors[0] and "AWS_DEFAULT_REGION" in errors[0]
    # The remedy that did not work must not be offered again, and the trap is named.
    assert "set AWS_REGION" not in errors[0]
    assert "does not read AWS_REGION" in errors[0]


# 19b
def test_aws_default_region_supplies_the_scan_region(
    tmp_path: Path, monkeypatch
) -> None:
    """``AWS_DEFAULT_REGION`` reaches the scan through the real ``boto3.Session``."""
    calls = _real_boto3_env(monkeypatch, tmp_path, AWS_DEFAULT_REGION="us-west-2")
    monkeypatch.setattr(
        "sraverify.scanner.SRAVerify.run_checks", lambda self, **kwargs: []
    )

    status = _run_cli(monkeypatch, ["--output", str(tmp_path / "findings.csv")])

    assert status == 0
    assert [kw.get("region_name") for args, kw in calls if args[:1] == ("sts",)] == [
        "us-west-2"
    ]


# 20
def test_the_partition_error_is_reported_ahead_of_a_bad_check_id(
    logged: list[logging.LogRecord], tmp_path: Path, monkeypatch
) -> None:
    """Both the partition and ``--check`` are bad: the partition error wins."""
    session = _RegionlessRefusingSession()
    _install_session(monkeypatch, session)
    output_file = tmp_path / "findings.csv"

    status = _run_cli(
        monkeypatch, [f"--check={UNKNOWN_CHECK_ID}", "--output", str(output_file)]
    )

    assert status == 2
    assert not output_file.exists()
    assert session.client_calls == []
    errors = _errors(logged)
    assert len(errors) == 1, errors
    assert "Cannot determine the AWS partition" in errors[0]
    assert UNKNOWN_CHECK_ID not in errors[0]


# 21
def test_role_without_a_region_exits_2_before_assume_role(
    logged: list[logging.LogRecord], tmp_path: Path, monkeypatch
) -> None:
    """``--role`` with no Region: the real ``get_session`` refuses before STS."""
    calls = _install_regionless_boto3(monkeypatch)
    output_file = tmp_path / "findings.csv"

    status = _run_cli(monkeypatch, ["--role", ROLE, "--output", str(output_file)])

    assert status == 2
    assert not output_file.exists()
    assert list(tmp_path.iterdir()) == []
    assert calls == []
    errors = _errors(logged)
    assert len(errors) == 1, errors
    assert "--regions" in errors[0]


# 22
def test_listing_checks_needs_no_region(monkeypatch, capsys) -> None:
    """``--list-checks`` without ``--role`` stays region-free and credential-free."""
    calls = _install_regionless_boto3(monkeypatch)

    status = _run_cli(monkeypatch, ["--list-checks"])

    assert status == 0
    assert calls == []
    assert "Available checks:" in capsys.readouterr().out


# 22a
def test_listing_checks_with_a_role_and_no_region_exits_2(
    logged: list[logging.LogRecord], monkeypatch, capsys
) -> None:
    """``--list-checks --role R`` would AssumeRole, so with no Region it is refused."""
    calls = _install_regionless_boto3(monkeypatch)

    status = _run_cli(monkeypatch, ["--list-checks", "--role", ROLE])

    assert status == 2
    assert calls == []
    assert capsys.readouterr().out == ""
    assert len(_errors(logged)) == 1


def _stub_scan(monkeypatch) -> None:
    """Stop the scan after the banner: ``run_checks`` returns no findings."""
    monkeypatch.setattr(
        "sraverify.scanner.SRAVerify.run_checks", lambda self, **kwargs: []
    )


def _banner_sts_regions(session: _RefusingSession) -> list:
    return [kw.get("region_name") for args, kw in session.client_calls if args[:1] == ("sts",)]


# 23
def test_the_session_region_is_the_scan_region_without_regions(
    tmp_path: Path, monkeypatch
) -> None:
    """Precedence (b) at the CLI: the banner's STS build uses the session Region."""
    session = _RecordingSession("us-west-2")
    _install_session(monkeypatch, session)
    _stub_scan(monkeypatch)

    status = _run_cli(monkeypatch, ["--output", str(tmp_path / "findings.csv")])

    assert status == 0
    assert _banner_sts_regions(session) == ["us-west-2"]


# 23a
def test_the_first_explicit_region_beats_the_session_region(
    tmp_path: Path, monkeypatch
) -> None:
    """Precedence (a) at the CLI: ``--regions us-gov-west-1`` over a ``us-east-1`` session."""
    session = _RecordingSession("us-east-1")
    _install_session(monkeypatch, session)
    _stub_scan(monkeypatch)

    status = _run_cli(
        monkeypatch,
        ["--regions", "us-gov-west-1", "--output", str(tmp_path / "findings.csv")],
    )

    assert status == 0
    assert _banner_sts_regions(session) == ["us-gov-west-1"]
