"""Property-based test for the CSV column contract (task 2.3).

This module implements **Property 6: ``to_row`` yields exactly ``FIELDS`` in
order**:

    ∀ f: Finding. tuple(f.to_row()) == Finding.FIELDS

-- exactly 16 keys, in order, none missing, none extra.

**Validates: Requirements 1.4, 1.5, 13.4**

Why the property needs a companion anchor
-----------------------------------------

Stated on its own, ``tuple(f.to_row()) == Finding.FIELDS`` is only half a
test, because both sides are declared in the same module. Reorder ``FIELDS``
and reorder ``to_row``'s dict literal to match, and the property still passes
while both HTML dashboards -- which parse the 16 columns positionally -- start
reading ``Severity`` out of the ``Status`` column.

So this module asserts two things that together discharge the requirement:

  * the ``hypothesis``-driven property over arbitrary findings, which is what
    catches ``to_row`` drifting away from ``FIELDS`` (Requirement 1.5). That
    drift is the live risk: ``to_row`` writes the sixteen keys out by hand
    rather than deriving them from ``FIELDS``, a deliberate design choice that
    trades this test for a readable, statically checkable renderer.
  * a pin of ``FIELDS`` against the column order written literally in the
    requirements Glossary, which is what catches ``FIELDS`` itself being
    reordered (Requirements 1.4, 13.4). The literal is repeated here on
    purpose: a test that imports the value it is checking cannot detect a
    change to it.

The property draws hostile cell values -- commas, quotes, ``\\r\\n``,
non-ASCII -- through the shared ``findings()`` strategy. For this property that
is a strengthening move: the key set and key *order* of a row must not depend
on the contents of any cell, and the only way to exercise that independence is
to vary the contents. It also means a future change that made ``to_row`` skip
or rename a key for, say, an empty value would be caught here rather than in
production.

The ``findings()`` strategy lives in ``tests/property/strategies.py`` so
Properties 7, 8, and 9 quantify over the same population.
"""
from __future__ import annotations

import re
from dataclasses import fields as dataclass_fields
from dataclasses import replace as dataclass_replace

from hypothesis import find, given

from sraverify.core.finding import Finding
from sraverify.tests.property.strategies import cell_text, findings

# --------------------------------------------------------------------------- #
# The Glossary column order, repeated as a literal
# --------------------------------------------------------------------------- #
#
# Copied verbatim from the requirements Glossary entry for the 16-column
# contract, which Requirement 1.4 names as the authority for the order and
# Requirement 13.4 requires the scanner to keep emitting. This is intentionally
# a second copy of the order rather than an import of ``Finding.FIELDS``:
# comparing ``FIELDS`` against itself would prove nothing about 13.4.

GLOSSARY_COLUMNS: tuple[str, ...] = (
    "AccountId",
    "AccountName",
    "Region",
    "CheckId",
    "Status",
    "Severity",
    "Title",
    "Description",
    "ResourceId",
    "ResourceType",
    "CheckedValue",
    "ActualValue",
    "Remediation",
    "Service",
    "CheckLogic",
    "AccountType",
)


def _to_snake_case(column: str) -> str:
    """Render a CSV column name as the field name Requirement 1.4 pairs it with.

    ``"AccountId"`` -> ``"account_id"``, ``"Region"`` -> ``"region"``.

    Args:
        column: One CSV column name in upper camel case.

    Returns:
        The lower-case snake-case spelling of ``column``.
    """
    return re.sub(r"(?<!^)(?=[A-Z])", "_", column).lower()


# --------------------------------------------------------------------------- #
# Property 6 -- the generated half
# --------------------------------------------------------------------------- #


@given(finding=findings())
def test_to_row_keys_equal_fields_in_order(finding: Finding) -> None:
    """Property 6: ``tuple(f.to_row()) == Finding.FIELDS`` for every Finding.

    ``tuple()`` over a ``dict`` yields its keys in insertion order, so this one
    assertion covers all four failure modes at once: a missing key, an extra
    key, a renamed key, and a correct key set in the wrong order.

    Validates: Requirements 1.5, 13.4.
    """
    row = finding.to_row()

    assert tuple(row) == Finding.FIELDS, (
        "to_row() key order diverged from Finding.FIELDS. "
        f"row keys={tuple(row)!r} FIELDS={Finding.FIELDS!r}"
    )


@given(finding=findings())
def test_to_row_has_exactly_sixteen_keys_with_none_missing_and_none_extra(
    finding: Finding,
) -> None:
    """Property 6, stated as a set relation so a failure reports the delta.

    The ordered assertion above already implies this one. It is kept separate
    because when it fails it names *which* columns went missing or turned up
    extra, and that is a materially more useful failure message than a
    16-element tuple mismatch.

    Validates: Requirements 1.5, 13.4.
    """
    row = finding.to_row()

    assert len(row) == 16, f"expected 16 columns, got {len(row)}"

    missing = set(Finding.FIELDS) - set(row)
    extra = set(row) - set(Finding.FIELDS)
    assert not missing, f"to_row() omitted column(s) {sorted(missing)!r}"
    assert not extra, f"to_row() produced unexpected column(s) {sorted(extra)!r}"


@given(finding=findings())
def test_to_row_is_a_fresh_mapping_with_stable_order_across_calls(
    finding: Finding,
) -> None:
    """Property 6: repeated rendering of one Finding yields the same key order.

    A ``to_row`` that built its result by iterating a set, or that mutated a
    shared module-level dict, could satisfy the single-call assertions and
    still hand two different orders to two callers. The writer renders the
    header from ``FIELDS`` and each row from ``to_row()``, so a per-call order
    difference would misalign cells against the header.

    Validates: Requirements 1.5, 13.4.
    """
    first = finding.to_row()
    second = finding.to_row()

    assert tuple(first) == tuple(second) == Finding.FIELDS
    assert first is not second, "to_row() must not hand callers a shared dict"


@given(
    finding=findings(),
    unrelated=cell_text(),
)
def test_row_key_order_is_independent_of_a_mutated_copy(
    finding: Finding, unrelated: str
) -> None:
    """Property 6: hostile cell contents cannot perturb the column contract.

    Builds a second Finding from the first with one arbitrary field replaced by
    an arbitrary -- possibly comma-, quote-, or newline-bearing -- value, and
    asserts both render the same sixteen keys in the same order. ``to_row``
    applies no quoting or escaping by design, so nothing about a cell's content
    may reach the key set.

    Validates: Requirements 1.4, 1.5, 13.4.
    """
    mutated = dataclass_replace(finding, actual_value=unrelated)

    assert tuple(mutated.to_row()) == tuple(finding.to_row()) == Finding.FIELDS


# --------------------------------------------------------------------------- #
# Property 6 -- the anchor half: FIELDS is the published order
# --------------------------------------------------------------------------- #


def test_fields_equals_the_glossary_column_order() -> None:
    """``Finding.FIELDS`` is the Glossary's sixteen columns, in that order.

    The generated property above compares ``to_row()`` against ``FIELDS``.
    This one compares ``FIELDS`` against the order written down in the
    requirements, which is what makes the pair sound: reordering both
    ``FIELDS`` and ``to_row`` together passes the property and fails here.

    Validates: Requirements 1.4, 13.4.
    """
    assert Finding.FIELDS == GLOSSARY_COLUMNS


def test_fields_is_an_immutable_sequence() -> None:
    """``FIELDS`` is a ``tuple``, so a caller cannot reorder the contract in place.

    Requirement 1.4 asks for an immutable sequence specifically. A ``list``
    would let any consumer -- a dashboard export helper, say -- ``sort()`` the
    published column order and silently change what every subsequent scan
    writes.

    Validates: Requirement 1.4.
    """
    assert isinstance(Finding.FIELDS, tuple)
    assert len(Finding.FIELDS) == 16
    assert len(set(Finding.FIELDS)) == 16, "FIELDS contains a duplicate column"


def test_every_column_pairs_with_exactly_one_snake_case_finding_field() -> None:
    """Each ``FIELDS`` entry is one ``Finding`` field's name in upper camel case.

    Requirement 1.4's second clause: the sixteen columns and the sixteen fields
    are the same set under the camel-case/snake-case rendering. This is the
    assertion that catches a field renamed on the dataclass without its column
    following, and vice versa.

    Validates: Requirement 1.4.
    """
    field_names = {f.name for f in dataclass_fields(Finding)}
    assert len(field_names) == 16

    paired = {_to_snake_case(column) for column in Finding.FIELDS}
    assert paired == field_names, (
        "FIELDS and the Finding fields disagree. "
        f"columns->fields={sorted(paired - field_names)!r} "
        f"fields with no column={sorted(field_names - paired)!r}"
    )


@given(finding=findings())
def test_each_row_value_comes_from_the_paired_field(finding: Finding) -> None:
    """Every cell carries the value of the field its column name pairs with.

    ``to_row`` writes sixteen keys by hand, so the failure this catches is a
    transposition -- ``"CheckedValue": self.actual_value`` -- which produces a
    perfectly well-formed row with two columns swapped. The key-order property
    is blind to it, and so is every downstream consumer.

    Enum fields are compared against ``.value`` and a null ``resource_id``
    against ``""``, matching the rendering rules; every other column must carry
    the stored string unchanged.

    Validates: Requirements 1.4, 1.5.
    """
    row = finding.to_row()

    for column in Finding.FIELDS:
        stored = getattr(finding, _to_snake_case(column))
        if stored is None:
            expected = ""
        else:
            # StrEnum members carry .value; plain strings do not.
            expected = getattr(stored, "value", stored)
        assert row[column] == expected, (
            f"column {column!r} does not carry field "
            f"{_to_snake_case(column)!r}: row={row[column]!r} "
            f"field={expected!r}"
        )


# --------------------------------------------------------------------------- #
# The generator itself is worth one assertion
# --------------------------------------------------------------------------- #


@given(finding=findings())
def test_generator_produces_constructible_findings(finding: Finding) -> None:
    """The shared ``findings()`` strategy yields real, valid ``Finding`` objects.

    A strategy that silently degenerated -- always drawing the same value, or
    never drawing ``resource_id=None`` -- would make every property above
    vacuous without failing anything. This keeps the generator honest at the
    cheapest possible level: what it produces is a ``Finding``, and the one
    cross-field rule ``__post_init__`` enforces actually held on it.
    """
    assert isinstance(finding, Finding)
    assert finding.title.startswith(f"{finding.check_id} ")


def test_generator_reaches_both_resource_id_shapes() -> None:
    """``findings()`` can draw a string ``resource_id`` and can draw ``None``.

    Property 6 is insensitive to which one it gets, but ``resource_id`` is the
    one nullable field and Property 7's ``None`` -> ``""`` rendering rule turns
    on it. Since the generator is shared, its coverage of both shapes is
    asserted here once rather than in each dependent module.

    ``find`` raises if no example satisfying the predicate exists, so a
    generator that stopped producing either shape fails this test.
    """
    assert find(findings(), lambda f: f.resource_id is None) is not None
    assert find(findings(), lambda f: isinstance(f.resource_id, str)) is not None
