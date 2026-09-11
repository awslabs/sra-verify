"""Property-based test for CSV writer purity (task 10.2).

This module implements **Property 10: ``write_csv_output`` does not mutate its
input**:

    write_csv_output(findings, path) leaves ``findings`` and every element of
    it unmodified.

**Validates: Requirements 8.4**

Why this needs a test at all
----------------------------

The rewritten writer (task 10.1) is a pure render: it derives column names
from ``Finding.FIELDS`` and each row from ``to_row()``. Nothing in it touches
the list or an element. That is precisely why the property is worth pinning --
the *previous* writer did mutate, twice over. It backfilled missing keys with
``''`` and it migrated a legacy ``CheckType`` key onto ``AccountType``, both
in place, on the caller's own dicts. A caller that wrote a report and then
inspected its findings saw different objects than the ones it handed over.

Requirement 8.4 splits into four claims, and this property asserts all four
rather than settling for equality:

  * no element added and no element removed -- checked by length;
  * the same objects in the same order -- checked by ``is``, position by
    position, not by ``==``. Identity is the stronger assertion and it is the
    one that matters: ``Finding`` is a frozen dataclass with a value-based
    ``__eq__``, so a writer that helpfully replaced an element with a
    normalized copy would satisfy ``==`` and still have broken the contract;
  * every field value of every finding unchanged -- checked field by field,
    read out of ``dataclasses.fields`` so a field added to ``Finding`` later is
    covered without editing this test;
  * the list itself unchanged -- the caller's list object still holds what it
    held, so ``findings`` is safe to reuse after a write.

The draws come from the shared ``findings()`` strategy, which supplies hostile
cell values -- commas, bare and doubled double quotes, ``\\r``, ``\\n``,
``\\r\\n``, leading and trailing spaces, non-ASCII text, and ``resource_id=None``.
For this property that is more than decoration: a value needing to be quoted
or escaped is exactly the value a writer would be tempted to "fix" on the
finding before rendering it. Escaping belongs to the CSV layer alone, and a
finding must arrive at the writer and leave it byte-identical.

The write really happens -- the assertion that the file exists keeps a writer
that silently did nothing from passing this property vacuously. What the file
*contains* is Property 11's and Property 20's business, not this one's.
"""
from __future__ import annotations

from dataclasses import fields as dataclass_fields
from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sraverify.core.finding import Finding
from sraverify.tests.property.strategies import findings
from sraverify.utils.outputs import write_csv_output


def _field_snapshot(finding: Finding) -> tuple[tuple[str, Any], ...]:
    """Capture every field value of *finding* as a comparable snapshot.

    Field names are read from the dataclass rather than listed here, so a
    seventeenth field added to ``Finding`` is compared automatically instead of
    being silently skipped by a hand-maintained list.

    Args:
        finding: The finding to snapshot.

    Returns:
        A tuple of ``(field_name, value)`` pairs in declaration order. The
        values are the finding's own objects; ``Finding`` holds only ``str``,
        ``None``, and enum members, all immutable, so capturing references is
        sufficient and no copy is needed.
    """
    return tuple(
        (field.name, getattr(finding, field.name))
        for field in dataclass_fields(finding)
    )


@given(drawn=st.lists(findings(), max_size=8))
@settings(
    # tmp_path is function-scoped, so hypothesis reuses one directory across
    # the draws of a single test. That is harmless and in fact on-contract
    # here: criterion 8.2 requires each write to replace any existing content
    # at the path, so writing repeatedly to the same file is a valid sequence.
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_write_csv_output_does_not_mutate_its_input(
    drawn: list[Finding], tmp_path: Path
) -> None:
    """Property 10: writing a report leaves the findings it reported untouched.

    Validates: Requirements 8.4
    """
    output_file = tmp_path / "findings.csv"

    # Snapshots taken before the write. `elements_before` is a separate list
    # object holding the same element references, which is what lets the
    # position-by-position identity comparison below detect a reorder, an
    # insertion, or an in-place replacement.
    elements_before = list(drawn)
    fields_before = [_field_snapshot(finding) for finding in drawn]
    rows_before = [finding.to_row() for finding in drawn]

    write_csv_output(drawn, str(output_file))

    # The write genuinely happened; a no-op writer must not pass vacuously.
    assert output_file.exists(), (
        f"write_csv_output created no file at {output_file}"
    )

    # No element added and no element removed.
    assert len(drawn) == len(elements_before), (
        f"write_csv_output changed the list length: "
        f"{len(elements_before)} before, {len(drawn)} after"
    )

    # The same objects, in the same order. `is` rather than `==`: a writer that
    # substituted an equal-but-normalized copy has still broken 8.4.
    for index, (after, before) in enumerate(zip(drawn, elements_before)):
        assert after is before, (
            f"write_csv_output replaced the finding at index {index}: "
            f"{before!r} became {after!r}"
        )

    # Every field value of every finding unchanged.
    for index, (finding, before) in enumerate(zip(drawn, fields_before)):
        assert _field_snapshot(finding) == before, (
            f"write_csv_output altered a field of the finding at index "
            f"{index}: {before} became {_field_snapshot(finding)}"
        )

    # And the rendered view is unchanged too, which catches a mutation to a
    # field that a snapshot comparison could miss if the field's own value were
    # ever made mutable.
    assert [finding.to_row() for finding in drawn] == rows_before, (
        "write_csv_output altered what to_row() renders"
    )
