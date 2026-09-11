"""Property-based test for the header-only empty report (task 10.3).

This module implements **Property 11: zero findings still write a header**:

    write_csv_output([], path) creates ``path`` with exactly one line: the
    header.

**Validates: Requirements 8.3**

What the property is actually defending
---------------------------------------

A scan that found nothing and a scan that never ran are two different
outcomes, and in the CodeBuild fan-out they are told apart by exactly one
signal: whether the CSV exists and carries the sixteen-column header. A writer
that skipped the file for an empty list -- an easy and locally reasonable
optimization -- would make a clean account indistinguishable from a crashed
process, and the pandas consolidation step in the buildspec would silently
drop that account from the report rather than report zero findings for it.

So the assertion is deliberately exact rather than merely "the file exists and
starts with the header". The entire content must be::

    ",".join(Finding.FIELDS) + "\\r\\n"

encoded UTF-8 with no byte-order mark. Anything else -- a trailing blank line,
a stray data row of sixteen empty cells, a locale-dependent encoding, an
LF-only terminator, a BOM that a strict parser reads as part of the
``AccountId`` column name -- is a different artifact than the one the
downstream consumers parse, and every one of those is a real failure mode of
CSV writing rather than a hypothetical.

Where the generation comes in
-----------------------------

The core claim quantifies over an empty list, so there is only one input to it.
What is worth generating is everything *around* that call, because the claim
that would fail in production is not "an empty write produces a header" in
isolation but "an empty write produces a header **regardless of what came
before it**":

  * the destination already holds a full report -- an arbitrary list drawn from
    the shared ``findings()`` strategy, complete with hostile cell values -- and
    an empty write must leave the header and nothing else. This is where
    criterion 8.2's replace-any-existing-content clause meets 8.3: a writer
    opening in append mode, or truncating only as far as it wrote, passes the
    fresh-file case and fails here.
  * the destination already holds arbitrary non-CSV bytes.
  * the file name varies, so nothing about the assertion depends on one path.
  * the same empty write repeated is idempotent.

The one thing this module does not do is derive its expected header from
``Finding.FIELDS`` alone and stop there. It also parses the file back with the
``csv`` module and asserts the recovered header row equals ``FIELDS`` and that
zero data rows follow, so a header written as one already-comma-containing
quoted cell could not pass.
"""
from __future__ import annotations

import csv
import io
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sraverify.core.finding import Finding
from sraverify.tests.property.strategies import findings
from sraverify.utils.outputs import write_csv_output

#: The complete, byte-exact content of an empty report: the comma-joined
#: sixteen column names and one CRLF. Requirement 8.2 fixes the header as the
#: comma-joined ``Finding.FIELDS``, 8.3 fixes that no data row follows it, and
#: 8.8 fixes the terminator. None of the sixteen names contains a comma, a
#: quote, or a line break, so ``QUOTE_MINIMAL`` quotes none of them and the
#: naive join is the correct expectation.
EXPECTED_HEADER_TEXT = ",".join(Finding.FIELDS) + "\r\n"

#: The same value as bytes. UTF-8 with no BOM: ``codecs.BOM_UTF8`` must not
#: appear, since a consumer reading the file as plain UTF-8 would see it glued
#: to the front of the first column name.
EXPECTED_HEADER_BYTES = EXPECTED_HEADER_TEXT.encode("utf-8")

#: File names that exercise the path being an ordinary caller-supplied one.
#: Requirement 8.9 makes the complete file path the caller's responsibility, so
#: nothing here relies on the writer synthesizing or normalizing a name.
_FILE_NAMES = (
    "findings.csv",
    "sraverify_findings_20260101_000000.csv",
    "no-extension",
    "name with spaces.csv",
    "UPPER.CSV",
    "dotted.name.csv",
)


def _read_bytes(path: Path) -> bytes:
    """Read *path* with no decoding, no newline translation, and no guessing.

    Reading bytes rather than text is the whole point: ``Path.read_text()``
    would apply universal-newline translation and silently turn a ``\\r\\n``
    terminator into ``\\n``, which is precisely one of the things this module
    exists to detect.

    Args:
        path: File to read.

    Returns:
        The file's exact bytes.
    """
    return path.read_bytes()


def _assert_is_exactly_the_header(path: Path) -> None:
    """Assert *path* holds the header row and nothing else.

    Four independent readings of the same file, because each catches a
    different way of being wrong:

      * the raw bytes, which pin the encoding, the absence of a BOM, and the
        CRLF terminator;
      * a line count, which is the literal statement of Property 11;
      * a ``csv.reader`` pass, which recovers the sixteen column names as
        sixteen separate cells and so catches a header that was written as one
        quoted cell containing commas;
      * a ``csv.DictReader`` pass, which is how a consumer actually reads the
        file, and which must report the sixteen field names and iterate zero
        rows.

    Args:
        path: The output file to inspect.

    Raises:
        AssertionError: If the file is anything other than the bare header.
    """
    assert path.exists(), f"write_csv_output created no file at {path}"
    assert path.is_file(), f"{path} is not a regular file"

    raw = _read_bytes(path)

    # No byte-order mark. Asserted before the equality below so the failure
    # message says "BOM" rather than showing two nearly identical byte strings.
    assert not raw.startswith(b"\xef\xbb\xbf"), (
        "empty report begins with a UTF-8 BOM; a consumer reading it as plain "
        f"UTF-8 sees it as part of the first column name: {raw[:24]!r}"
    )

    assert raw == EXPECTED_HEADER_BYTES, (
        "empty report is not exactly the header row.\n"
        f"  expected: {EXPECTED_HEADER_BYTES!r}\n"
        f"  actual:   {raw!r}"
    )

    # Decoding with errors="strict" makes a non-UTF-8 byte a failure here
    # rather than a mojibake comparison above.
    text = raw.decode("utf-8", errors="strict")
    assert text == EXPECTED_HEADER_TEXT

    # Exactly one line, terminated. `splitlines(keepends=True)` counts the
    # terminated header as one line and would count a trailing blank line as a
    # second, which `str.split("\r\n")` would not.
    lines = text.splitlines(keepends=True)
    assert len(lines) == 1, (
        f"expected exactly 1 line in an empty report, got {len(lines)}: "
        f"{lines!r}"
    )
    assert lines[0].endswith("\r\n"), (
        f"header line is not CRLF-terminated: {lines[0]!r}"
    )

    # Recovered as cells, not as one blob.
    rows = list(csv.reader(io.StringIO(text, newline="")))
    assert rows == [list(Finding.FIELDS)], (
        f"csv.reader recovered {rows!r}, expected one row of the sixteen "
        f"column names"
    )

    # And as a consumer reads it: sixteen field names, zero data rows.
    reader = csv.DictReader(io.StringIO(text, newline=""))
    assert reader.fieldnames == list(Finding.FIELDS), (
        f"DictReader read fieldnames {reader.fieldnames!r}"
    )
    assert list(reader) == [], "an empty report must carry no data row"


# --------------------------------------------------------------------------- #
# Property 11 -- the core claim
# --------------------------------------------------------------------------- #


@given(file_name=st.sampled_from(_FILE_NAMES))
@settings(
    # tmp_path is function-scoped, so hypothesis reuses one directory across
    # the draws of a single test. Harmless here: each draw writes its own file
    # name, and re-writing one is on-contract per criterion 8.2.
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_zero_findings_writes_exactly_the_header(
    file_name: str, tmp_path: Path
) -> None:
    """Property 11: ``write_csv_output([], path)`` creates a header-only file.

    The file is created rather than skipped, and its entire content is the
    comma-joined ``Finding.FIELDS`` plus one CRLF -- which is what lets a
    consumer read "this scan ran and found nothing" instead of having to guess
    whether the scan ran at all.

    Validates: Requirements 8.3
    """
    output_file = tmp_path / file_name

    write_csv_output([], str(output_file))

    _assert_is_exactly_the_header(output_file)


def test_zero_findings_creates_the_file_where_none_existed(
    tmp_path: Path,
) -> None:
    """Property 11: the file is *created*, not merely left in a good state.

    Stated separately from the generated test above so the creation half of
    8.3 has an assertion that cannot be satisfied by a pre-existing file:
    ``tmp_path`` is fresh per test, and the absence of the path is asserted
    before the write.

    Validates: Requirements 8.3
    """
    output_file = tmp_path / "brand_new.csv"
    assert not output_file.exists()

    write_csv_output([], str(output_file))

    _assert_is_exactly_the_header(output_file)


# --------------------------------------------------------------------------- #
# Property 11 -- the claim holds regardless of what the path already held
# --------------------------------------------------------------------------- #


@given(drawn=st.lists(findings(), min_size=1, max_size=8))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_empty_write_over_a_full_report_leaves_only_the_header(
    drawn: list[Finding], tmp_path: Path
) -> None:
    """Property 11 against a path already holding a real report.

    This is the draw that matters. A writer opening the file in append mode,
    or truncating only as far as it writes, produces a correct header-only file
    on a fresh path and a header followed by yesterday's rows here -- rows a
    consumer would attribute to today's scan. Criterion 8.2 requires the write
    to replace any existing content; 8.3 requires what remains to be the
    header alone.

    The prior report is drawn with hostile cell values, so the content being
    replaced can be many times longer than the header that replaces it.

    Validates: Requirements 8.3
    """
    output_file = tmp_path / "findings.csv"

    write_csv_output(drawn, str(output_file))
    populated = _read_bytes(output_file)
    # Guard against a vacuous pass: the first write must really have produced
    # more than the header, or there is nothing here to replace.
    assert len(populated) > len(EXPECTED_HEADER_BYTES), (
        f"the {len(drawn)}-finding report is no longer than the header, so "
        f"this test would prove nothing: {populated!r}"
    )

    write_csv_output([], str(output_file))

    _assert_is_exactly_the_header(output_file)


@given(prior=st.binary(max_size=512))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_empty_write_over_arbitrary_prior_bytes_leaves_only_the_header(
    prior: bytes, tmp_path: Path
) -> None:
    """Property 11 against a path holding arbitrary non-CSV bytes.

    Generalizes the previous test past well-formed CSV: whatever was at the
    path, an empty write leaves exactly the header. Drawing raw bytes rather
    than text also covers the case where the existing file is not valid UTF-8,
    which the writer must overwrite rather than read.

    Validates: Requirements 8.3
    """
    output_file = tmp_path / "findings.csv"
    output_file.write_bytes(prior)

    write_csv_output([], str(output_file))

    _assert_is_exactly_the_header(output_file)


def test_repeated_empty_writes_are_idempotent(tmp_path: Path) -> None:
    """Three consecutive empty writes leave the same single header line.

    Catches the specific shape of an append-mode regression that a single
    write cannot: three appended headers is a file whose every line parses,
    whose column names are all correct, and which reports two data rows made
    entirely of column names.

    Validates: Requirements 8.3
    """
    output_file = tmp_path / "findings.csv"

    for _ in range(3):
        write_csv_output([], str(output_file))
        _assert_is_exactly_the_header(output_file)


# --------------------------------------------------------------------------- #
# The header an empty report carries is the same one a full report carries
# --------------------------------------------------------------------------- #


@given(drawn=st.lists(findings(), max_size=6))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_header_is_identical_whether_or_not_findings_follow(
    drawn: list[Finding], tmp_path: Path
) -> None:
    """The first line of a report does not depend on the findings in it.

    Property 11 is only useful if the header an empty report carries is the
    *same* header a populated report carries -- otherwise a consumer would
    need two parsers, and the empty file would not be a degenerate case of the
    normal one. Requirement 8.5 gives the mechanism (column names come solely
    from ``Finding.FIELDS``); this asserts the observable consequence, with the
    findings drawn arbitrarily including the empty list.

    Validates: Requirements 8.3
    """
    populated = tmp_path / "populated.csv"
    empty = tmp_path / "empty.csv"

    write_csv_output(drawn, str(populated))
    write_csv_output([], str(empty))

    populated_first_line = _read_bytes(populated).split(b"\r\n", 1)[0]
    empty_first_line = _read_bytes(empty).split(b"\r\n", 1)[0]

    assert populated_first_line == empty_first_line
    assert empty_first_line + b"\r\n" == EXPECTED_HEADER_BYTES


def test_expected_header_is_the_sixteen_column_contract() -> None:
    """The expectation this module compares against is the published contract.

    ``EXPECTED_HEADER_TEXT`` is built from ``Finding.FIELDS``, so on its own it
    would follow ``FIELDS`` anywhere it went. The column *order* is pinned
    against the requirements Glossary in
    ``test_finding_row_contract_property.py``; what is worth asserting here is
    the shape of the header line itself -- sixteen comma-separated names, none
    of them quoted, nothing else on the line.

    Validates: Requirements 8.3
    """
    assert EXPECTED_HEADER_TEXT.count(",") == 15
    assert '"' not in EXPECTED_HEADER_TEXT, (
        "a column name now needs quoting; the naive join is no longer the "
        "correct expectation for the header line"
    )
    assert EXPECTED_HEADER_TEXT.endswith("\r\n")
    assert EXPECTED_HEADER_TEXT[:-2].split(",") == list(Finding.FIELDS)
    assert len(Finding.FIELDS) == 16
