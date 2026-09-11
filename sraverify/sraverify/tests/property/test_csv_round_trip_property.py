"""Property-based test for CSV round-trip fidelity (task 10.4).

This module implements **Property 20: CSV round-trip fidelity**:

    ∀ fs: list[Finding].
        list(csv.DictReader(open(path, newline="", encoding="utf-8")))
            == [f.to_row() for f in fs]

after ``write_csv_output(fs, path)`` -- reading the written file back with a
conforming CSV reader recovers, for every row, exactly the mapping ``to_row()``
produced, cell for cell.

**Validates: Requirements 1.15, 8.7, 8.8**

Why the round trip is the right shape for this
----------------------------------------------

Quoting lives in exactly one layer. ``Finding.to_row()`` applies no quoting, no
escaping, and no truncation (1.15); ``write_csv_output`` applies
``QUOTE_MINIMAL`` with ``doublequote=True`` (8.7). A reader inverts exactly one
round of that quoting, so the round trip is an identity **only** while the two
layers stay disjoint. Add escaping to ``to_row()`` -- doubling a quote, say, or
wrapping a comma-bearing cell -- and the writer escapes the escape, so the first
cell containing a ``"`` comes back wrong. That is the alarm this property exists
to raise, and it is why the assertion is stated against ``to_row()`` rather than
against hand-written expected text.

Three cell shapes carry the weight, and the shared ``cell_text()`` strategy in
``tests/property/strategies.py`` was written to produce all of them:

* a cell containing the **delimiter** -- unquoted, it splits one cell into two
  and shifts every column after it, which is the classic way an AWS ARN or an
  error message silently corrupts a report;
* a cell containing the **quote character**, including an already-doubled
  ``""`` -- the input that distinguishes "quoted once, correctly" from
  "escaped twice";
* a cell containing ``\\r``, ``\\n``, or ``\\r\\n`` -- a logical row that spans
  several physical lines, which a naive line-splitting consumer reads as extra
  rows and a writer opened without ``newline=""`` mangles.

Non-ASCII text is the fourth, and it covers 8.8 as a side effect: the writer
pins ``encoding="utf-8"`` rather than taking the locale default, and the only
way to see that pin do its job is to write a non-ASCII cell from a process whose
locale encoding is not UTF-8. ``test_round_trip_survives_a_c_locale`` does that
in a subprocess, since the locale is process-global and cannot be swapped
underneath a running test.

Reading side of 8.8: the read-back opens with ``newline=""`` and an explicit
``encoding="utf-8"``, so a writer that emitted the platform line ending or the
locale encoding fails here rather than downstream in a dashboard.
"""
from __future__ import annotations

import csv
import json
import locale
import subprocess
import sys
import tempfile
from dataclasses import replace as dataclass_replace
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sraverify.core import finding as _finding_module
from sraverify.core.enums import AccountType, Severity, Status
from sraverify.core.finding import Finding
from sraverify.tests.property.strategies import cell_text, findings
from sraverify.utils.outputs import write_csv_output

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

#: The package directory, handed to the subprocess in the locale test so the
#: child does not depend on how this process happened to be installed.
_PACKAGE_DIR = Path(_finding_module.__file__).resolve().parents[1]

#: One valid Finding to derive targeted cases from. Every free-text cell is
#: replaced per test; the enum and identity cells stay fixed.
_BASE_FINDING = Finding(
    check_id="SRA-GUARDDUTY-01",
    status=Status("FAIL"),
    region="us-east-1",
    severity=Severity("HIGH"),
    title="SRA-GUARDDUTY-01 GuardDuty is enabled in the account",
    description="baseline description",
    resource_id="detector-abc123",
    resource_type="AWS::GuardDuty::Detector",
    account_id="111122223333",
    account_name="audit-account",
    checked_value="GuardDuty Configuration",
    actual_value="baseline actual value",
    remediation="baseline remediation",
    service="GuardDuty",
    check_logic="baseline check logic",
    account_type=AccountType("application"),
)

#: The free-text cells a hostile value is injected into. ``title`` is excluded
#: because ``__post_init__`` constrains its prefix; it gets its own suffix
#: injection instead.
_FREE_TEXT_FIELDS = (
    "description",
    "resource_id",
    "actual_value",
    "remediation",
    "checked_value",
    "check_logic",
    "account_name",
    "service",
    "resource_type",
    "region",
)


def _finding_with_value_everywhere(value: str) -> Finding:
    """Return a Finding carrying *value* in every free-text cell at once.

    Injecting into one cell at a time would miss the failure mode where an
    unquoted delimiter in cell *n* is absorbed by cell *n+1*: with a distinct
    value in the neighbouring cell the corruption is obvious, but the point is
    that it must not happen at all, in any adjacency. Filling every cell also
    puts a hostile value on both sides of every comma the writer emits.

    Args:
        value: The cell text to place in each free-text field.

    Returns:
        A valid Finding whose title suffix also carries *value*.
    """
    overrides = {name: value for name in _FREE_TEXT_FIELDS}
    overrides["title"] = f"{_BASE_FINDING.check_id} {value}"
    return dataclass_replace(_BASE_FINDING, **overrides)


def _round_trip(findings_list: list[Finding]) -> tuple[list[str], list[dict]]:
    """Write *findings_list*, read it back, and return the header and the rows.

    Uses a fresh temporary directory per call rather than the ``tmp_path``
    fixture: ``tmp_path`` is function-scoped, and a function-scoped fixture
    shared across ``hypothesis`` examples is exactly what
    ``HealthCheck.function_scoped_fixture`` exists to flag.

    The read side pins ``newline=""`` and ``encoding="utf-8"`` per Requirement
    8.8. ``newline=""`` is load-bearing on the reader too: without it Python's
    universal-newline translation rewrites a ``\\r\\n`` inside a quoted cell
    before the CSV reader ever sees it, and the round trip fails on a writer
    that was in fact correct.

    Args:
        findings_list: Findings to write, in output order.

    Returns:
        A pair of the reader's ``fieldnames`` and the list of row mappings.
    """
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "findings.csv"
        write_csv_output(findings_list, str(path))
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            rows = [dict(row) for row in reader]
            header = list(reader.fieldnames or [])
    return header, rows


def _write_bytes(findings_list: list[Finding]) -> bytes:
    """Write *findings_list* and return the file's raw bytes.

    Args:
        findings_list: Findings to write.

    Returns:
        The exact bytes on disk, so the encoding and line-terminator pins can
        be asserted without a decoding step in between.
    """
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "findings.csv"
        write_csv_output(findings_list, str(path))
        return path.read_bytes()


# --------------------------------------------------------------------------- #
# Property 20 -- the generated form
# --------------------------------------------------------------------------- #


@settings(
    max_examples=60,
    deadline=None,  # each example does real file I/O
    suppress_health_check=[HealthCheck.too_slow],
)
@given(drawn=st.lists(findings(), max_size=6))
def test_read_back_recovers_every_to_row_mapping(drawn: list[Finding]) -> None:
    """Property 20: the read-back rows equal ``[f.to_row() for f in findings]``.

    The whole property in one assertion, over findings whose cells are drawn
    from ``cell_text()`` and therefore routinely carry commas, quotes, CR, LF,
    CRLF, tabs, edge whitespace, and non-ASCII text.

    Validates: Requirements 1.15, 8.7, 8.8.
    """
    expected = [finding.to_row() for finding in drawn]

    _, rows = _round_trip(drawn)

    assert rows == expected, (
        "CSV round trip lost or altered a cell. "
        f"expected={expected!r} got={rows!r}"
    )


@settings(max_examples=40, deadline=None)
@given(drawn=st.lists(findings(), min_size=1, max_size=4))
def test_read_back_key_order_equals_fields(drawn: list[Finding]) -> None:
    """Property 20: every recovered row is keyed by ``Finding.FIELDS`` in order.

    ``rows == expected`` above compares dicts, and dict equality ignores key
    order, so it would pass on a file whose header was a permutation of the
    sixteen columns as long as the writer permuted the cells to match. The
    published contract is positional -- both HTML dashboards read the columns
    by position -- so the order is asserted separately here, on the header and
    on each row.

    Validates: Requirements 8.7, 8.8.
    """
    header, rows = _round_trip(drawn)

    assert tuple(header) == Finding.FIELDS, (
        f"header diverged from Finding.FIELDS: header={header!r}"
    )
    for row in rows:
        assert tuple(row) == Finding.FIELDS
    assert len(rows) == len(drawn), (
        f"expected {len(drawn)} rows, recovered {len(rows)}"
    )


@settings(max_examples=60, deadline=None)
@given(value=cell_text())
def test_a_single_hostile_value_in_every_cell_round_trips(value: str) -> None:
    """Property 20, narrowed: one drawn value in every free-text cell at once.

    The list-valued property above varies sixteen cells independently, so a
    shrunk counterexample there can be hard to read. This one varies a single
    value and puts it everywhere, which makes the minimal failing input a
    single string -- the shape a fix starts from.

    Validates: Requirements 1.15, 8.7.
    """
    finding = _finding_with_value_everywhere(value)

    _, rows = _round_trip([finding])

    assert rows == [finding.to_row()]


# --------------------------------------------------------------------------- #
# The four named cell shapes, pinned as explicit cases
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("delimiter", "a,b"),
        ("delimiter only", ","),
        ("delimiter run", ",,,"),
        ("arn with comma", "arn:aws:s3:::bucket/key,with-comma"),
        ("quote char", '"'),
        ("already doubled quote", '""'),
        ("quoted phrase", 'he said "no"'),
        ("quote and delimiter", 'a,"b",c'),
        ("bare cr", "\r"),
        ("bare lf", "\n"),
        ("crlf", "\r\n"),
        ("multiline", "line one\nline two"),
        ("multiline crlf", "line one\r\nline two"),
        ("quote plus newline", 'said "no"\nthen left'),
        ("tab", "\t"),
        ("leading spaces", "   leading"),
        ("trailing spaces", "trailing   "),
        ("non ascii latin", "é"),
        ("non ascii cjk", "日本語"),
        ("non ascii emoji", "emoji \U0001f600"),
        ("everything at once", 'é,"\r\n"\t日本語 '),
        ("empty", ""),
    ],
)
def test_named_hostile_cell_shapes_round_trip(label: str, value: str) -> None:
    """Each cell shape the requirements name recovers unchanged.

    Requirement 8.7 names the comma, the double quote, the carriage return, and
    the line feed specifically, and 1.15 says ``to_row()`` hands those through
    untouched. The generated properties above cover these, but only
    probabilistically and only until someone edits the strategy. Pinning them
    as cases means a regression names the shape it broke.

    ``"already doubled quote"`` is the discriminating case: it comes back as
    ``""`` only if exactly one layer quotes. Double-escape it and it returns as
    ``"``; forget to quote it and the cell is unparseable.

    Validates: Requirements 1.15, 8.7.
    """
    finding = _finding_with_value_everywhere(value)

    _, rows = _round_trip([finding])

    assert rows == [finding.to_row()], f"{label} did not survive the round trip"


def test_an_embedded_newline_makes_one_logical_row_span_physical_lines() -> None:
    """A cell with a line break really does produce a multi-line record.

    Without this, ``test_named_hostile_cell_shapes_round_trip`` could pass on a
    writer that stripped or replaced the newline -- ``to_row()`` and the
    read-back would agree on a value neither of them contains a break in. So
    assert both halves: the file holds more physical lines than it holds
    records, and the reader still recovers exactly one row.

    Validates: Requirements 1.15, 8.7, 8.8.
    """
    finding = _finding_with_value_everywhere("first\nsecond\r\nthird")

    raw = _write_bytes([finding])
    header, rows = _round_trip([finding])

    # One header record plus one data record, but many more physical lines.
    assert raw.count(b"\n") > 2, (
        "the embedded line breaks did not reach the file; "
        f"raw={raw!r}"
    )
    assert len(rows) == 1, (
        f"a multi-line cell was read as {len(rows)} rows -- the reader is "
        "splitting on physical lines"
    )
    assert rows == [finding.to_row()]
    assert tuple(header) == Finding.FIELDS


def test_a_delimiter_bearing_cell_does_not_shift_the_columns() -> None:
    """An unquoted comma would shift every later column; assert it does not.

    Stated as its own test because the failure is not "a cell is wrong" but
    "every cell after it is wrong, and the row has too many cells" -- and
    ``csv.DictReader`` hides the latter in ``restkey`` rather than raising. So
    check ``restkey`` explicitly: it is absent from a correctly quoted file.

    Validates: Requirement 8.7.
    """
    finding = _finding_with_value_everywhere("us-east-1,us-west-2,eu-west-1")

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "findings.csv"
        write_csv_output([finding], str(path))
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle, restkey="__extra__", restval="__missing__")
            rows = [dict(row) for row in reader]

    assert len(rows) == 1
    assert "__extra__" not in rows[0], (
        "the row parsed into more than sixteen cells, so a delimiter was "
        f"written unquoted: extra={rows[0].get('__extra__')!r}"
    )
    assert "__missing__" not in rows[0].values()
    assert rows[0] == finding.to_row()


# --------------------------------------------------------------------------- #
# Requirement 8.8 -- the bytes on disk
# --------------------------------------------------------------------------- #


def test_file_is_crlf_terminated_utf8_with_no_byte_order_mark() -> None:
    """The emitted bytes are CRLF-terminated UTF-8 and carry no BOM.

    Requirement 8.8 is about bytes, so it is asserted on bytes. The round-trip
    properties cover it only indirectly -- a file written with ``\\n`` endings
    and read back with ``newline=""`` still round-trips, because the CSV reader
    accepts either ending.

    Validates: Requirement 8.8.
    """
    finding = _finding_with_value_everywhere("plain")

    raw = _write_bytes([finding])

    assert not raw.startswith(b"\xef\xbb\xbf"), "the file carries a UTF-8 BOM"
    assert raw.startswith(",".join(Finding.FIELDS).encode("ascii") + b"\r\n"), (
        f"header line is not the comma-joined FIELDS ending in CRLF: {raw[:200]!r}"
    )
    assert raw.endswith(b"\r\n")
    # No bare LF: every \n in this fixture is the second half of a \r\n.
    assert raw.count(b"\n") == raw.count(b"\r\n") == 2


def test_non_ascii_is_encoded_as_utf8_not_as_the_locale_default() -> None:
    """A non-ASCII cell lands on disk as its UTF-8 bytes.

    The pairing matters: the bytes decode as UTF-8 and do **not** decode as
    ASCII. A writer that had silently fallen back to ``errors="replace"`` would
    still round-trip -- it would write ``?`` and read ``?`` back -- and would
    still decode as ASCII, which is what the second half catches.

    Validates: Requirement 8.8.
    """
    finding = _finding_with_value_everywhere("héllo 日本語")

    raw = _write_bytes([finding])

    assert "héllo 日本語".encode("utf-8") in raw
    with pytest.raises(UnicodeDecodeError):
        raw.decode("ascii")
    assert "héllo 日本語" in raw.decode("utf-8")


# --------------------------------------------------------------------------- #
# Requirement 8.8 under a hostile locale
# --------------------------------------------------------------------------- #

_LOCALE_CHILD = '''\
"""Round-trip one non-ASCII finding in a process with a non-UTF-8 locale."""
import csv
import importlib
import importlib.machinery
import json
import locale
import sys
import types
from pathlib import Path

package_dir = Path(sys.argv[1])
out_path = Path(sys.argv[2])
sys.path.insert(0, str(package_dir.parent))

# Same bootstrap as the root conftest: the sraverify package __init__ cannot run
# while check migration is in progress, but its submodules import fine through a
# stub parent carrying __path__.
try:
    importlib.import_module("sraverify")
except Exception:
    sys.modules.pop("sraverify", None)
    stub = types.ModuleType("sraverify")
    stub.__path__ = [str(package_dir)]
    spec = importlib.machinery.ModuleSpec("sraverify", loader=None, is_package=True)
    spec.submodule_search_locations = stub.__path__
    stub.__spec__ = spec
    sys.modules["sraverify"] = stub

from sraverify.core.enums import AccountType, Severity, Status
from sraverify.core.finding import Finding
from sraverify.utils.outputs import write_csv_output

CELL = "h\\u00e9llo \\u65e5\\u672c\\u8a9e \\U0001f600"

finding = Finding(
    check_id="SRA-GUARDDUTY-01",
    status=Status("FAIL"),
    region="us-east-1",
    severity=Severity("HIGH"),
    title="SRA-GUARDDUTY-01 " + CELL,
    description=CELL,
    resource_id=CELL,
    resource_type="AWS::GuardDuty::Detector",
    account_id="111122223333",
    account_name=CELL,
    checked_value=CELL,
    actual_value=CELL,
    remediation=CELL,
    service="GuardDuty",
    check_logic=CELL,
    account_type=AccountType("application"),
)

# Does this locale actually restrict the default text encoding? If a plain
# open() can write the cell, the child is running under an effectively UTF-8
# locale and the assertion below is weaker than intended.
control_raises = False
try:
    with (out_path.parent / "control.txt").open("w", newline="") as handle:
        handle.write(CELL)
except UnicodeEncodeError:
    control_raises = True

write_csv_output([finding], str(out_path))

with out_path.open(newline="", encoding="utf-8") as handle:
    rows = [dict(row) for row in csv.DictReader(handle)]

print(json.dumps({
    "preferred_encoding": locale.getpreferredencoding(False),
    "control_raises": control_raises,
    "match": rows == [finding.to_row()],
    "row_count": len(rows),
}))
'''


def test_round_trip_survives_a_c_locale() -> None:
    """Property 20 holds in a process whose locale encoding is not UTF-8.

    This is the case the encoding pin exists for. The pre-change writer opened
    the file without an ``encoding``, so under ``LANG=C`` the first non-ASCII
    character in an AWS error message raised ``UnicodeEncodeError`` and lost a
    completed scan's report -- a failure that reproduces on neither a developer
    machine nor a correctly configured build image, which is why it is asserted
    here from a deliberately hostile child process rather than in-process.

    ``PYTHONUTF8=0`` and ``PYTHONCOERCECLOCALE=0`` are both required: without
    them CPython either enables UTF-8 mode or coerces the C locale to a UTF-8
    one, and the child would silently prove nothing. The child reports whether
    a plain ``open()`` really did reject the cell, so a platform that resists
    all of that degrades to a documented weaker assertion rather than a false
    pass.

    Validates: Requirement 8.8.
    """
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "locale_child.py"
        script.write_text(_LOCALE_CHILD, encoding="utf-8")
        target = Path(directory) / "findings.csv"

        completed = subprocess.run(
            [sys.executable, str(script), str(_PACKAGE_DIR), str(target)],
            capture_output=True,
            text=True,
            env={
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "C",
                "LANG": "C",
                "PYTHONUTF8": "0",
                "PYTHONCOERCECLOCALE": "0",
                # stdout stays ASCII: the child prints JSON with ensure_ascii.
                "PYTHONIOENCODING": "ascii",
            },
            timeout=120,
        )

    assert completed.returncode == 0, (
        "writing a non-ASCII finding under LC_ALL=C failed. "
        f"stdout={completed.stdout!r} stderr={completed.stderr!r}"
    )

    report = json.loads(completed.stdout.strip().splitlines()[-1])

    assert report["row_count"] == 1
    assert report["match"], (
        "the round trip lost a cell under a non-UTF-8 locale: "
        f"{report!r}"
    )
    if not report["control_raises"]:
        pytest.skip(
            "child locale still resolved to a UTF-8-capable default encoding "
            f"({report['preferred_encoding']!r}), so the pin was not stressed; "
            "the round trip itself passed"
        )


def test_in_process_locale_is_recorded_for_the_reader() -> None:
    """Document the host's default encoding, so a green run is interpretable.

    Not an assertion about the code. If the host default is already UTF-8 --
    the usual case, and the reason the original bug never reproduced locally --
    then every test in this module except the subprocess one would also pass
    against a writer with no ``encoding`` argument at all. Recording the value
    is what tells a reader of a passing run which tests actually carried weight.
    """
    assert isinstance(locale.getpreferredencoding(False), str)
