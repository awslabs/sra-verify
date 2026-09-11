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
``NoChecksSelectedError`` from ``_select``. Both install a **synthetic**
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
path neither should reach AWS, because ``_select`` raises while
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
from sraverify.main import DEFAULT_OUTPUT, main


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

    ``region_name`` is a real attribute because ``main()`` reads
    ``sra.session.region_name`` while evaluating ``print_banner``'s arguments,
    which happens before ``_select`` raises.

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

    Patches the name ``get_session`` in ``sraverify.main``'s namespace, which is
    where ``SRAVerify.__init__`` looks it up, so no credential resolution, no
    profile lookup, and no ``assume_role`` happens even before the question of
    an API call arises.
    """
    session = _RefusingSession()
    monkeypatch.setattr("sraverify.main.get_session", lambda **kwargs: session)
    return session


@pytest.fixture
def logged() -> list[logging.LogRecord]:
    """Collect the records the shared ``sraverify`` logger emits during a test.

    ``pytest``'s ``caplog`` cannot be used: ``core/logging.py`` sets
    ``logger.propagate = False`` deliberately, so nothing reaches the root
    handler ``caplog`` installs. Its stderr handler also captured ``sys.stderr``
    at import time, so ``capsys`` does not see it either. Attaching a handler
    directly to the named logger is what actually observes the output an
    operator sees.
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
    """Invoke ``main()`` with *argv* and return the status it exited with.

    Args:
        monkeypatch: Used to install ``argv`` for the duration of the call.
        argv: The arguments after the program name.

    Returns:
        The integer ``SystemExit.code``.

    Raises:
        Failed: ``main()`` returned without exiting, which none of the paths
            under test may do.
    """
    monkeypatch.setattr(sys, "argv", ["sraverify", *argv])
    with pytest.raises(SystemExit) as excinfo:
        main()
    assert isinstance(excinfo.value.code, int), (
        f"exited with {excinfo.value.code!r}; a non-integer argument to "
        f"sys.exit makes the process exit 1 and print that value to stderr, "
        f"which loses the 1-versus-2 distinction the fan-out reads"
    )
    return excinfo.value.code


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
    ``main._near_misses`` scores the keys itself, and this is the assertion that
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
