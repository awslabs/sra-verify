"""Property-based test for the immutability of the formalized finding model.

This module implements **Property 9: Findings are immutable**, which validates
Requirements 1.9 and 1.11 of the check-contract-formalization spec.

Three things are asserted, all quantified over ``hypothesis``-generated
Findings:

  (a) Requirement 1.9 -- assignment to *any* of the sixteen fields raises
      ``dataclasses.FrozenInstanceError``. Both the field name and the value
      being assigned are generated, so the property covers "no field, and no
      value, gets through". Deletion is covered the same way, because
      ``del f.status`` is the other half of the mutation surface that
      ``frozen=True`` closes.

  (b) Requirement 1.11 -- every field holds only a ``str``, a member of
      ``Status`` / ``Severity`` / ``AccountType``, or a null value in
      ``resource_id``. This is the structural statement behind "a Finding
      holds no reference to a check instance, to the per-scan context, or to
      any mutable object": if no field can hold anything but an immutable
      scalar, there is nothing for a Finding to keep alive. Requirement 1.10's
      slotted-storage rule is asserted alongside it, because the absence of a
      per-instance ``__dict__`` is what stops a caller smuggling an
      *undeclared* mutable attribute onto a Finding and thereby defeating (b).

  (c) Requirement 1.7 -- ``to_row()`` leaves the receiver unmodified. It sits
      naturally here: a frozen dataclass that coerces its enum fields through
      ``object.__setattr__`` in ``__post_init__`` has demonstrated it *can*
      write to its own slots, so "the read path does not use that door" is
      worth pinning down rather than assuming.

Feature: check-contract-formalization, Property 9: Findings are immutable.

**Validates: Requirements 1.9, 1.11**
"""
from __future__ import annotations

import dataclasses
from typing import Any, Dict

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from sraverify.core.enums import AccountType, Severity, Status
from sraverify.core.finding import Finding


# --------------------------------------------------------------------------- #
# The sixteen field names
# --------------------------------------------------------------------------- #
#
# Spelled out literally rather than derived from ``Finding``, so that a field
# renamed or dropped in ``core/finding.py`` fails this module instead of
# silently narrowing what the property quantifies over. Requirement 1.1 fixes
# this set, and ``test_field_set_is_the_declared_sixteen`` below ties the
# literal list back to the dataclass.

FIELD_NAMES = (
    "check_id", "status", "region", "severity", "title", "description",
    "resource_id", "resource_type", "account_id", "account_name",
    "checked_value", "actual_value", "remediation", "service", "check_logic",
    "account_type",
)

#: The three enum-typed fields and their enum (Requirement 1.3).
ENUM_FIELD_TYPES: Dict[str, type] = {
    "status": Status,
    "severity": Severity,
    "account_type": AccountType,
}

#: The one field admitting a null value (Requirement 1.2).
NULLABLE_FIELD = "resource_id"


# --------------------------------------------------------------------------- #
# Finding strategy
# --------------------------------------------------------------------------- #
#
# A shared Finding strategy helper does not yet exist under tests/property/,
# so one is defined locally here. If a shared helper lands later, this block
# is the thing to replace.
#
# The generated text is deliberately nasty -- commas, quotes, newlines,
# leading/trailing spaces, non-ASCII -- because immutability must not depend
# on the *content* of a field, and because those are the values that actually
# occur in ``ActualValue`` (an AWS error message) and ``Remediation`` (a
# multi-line CLI snippet).

_NASTY_TEXT = st.one_of(
    st.just(""),
    st.text(max_size=40),
    st.sampled_from([
        "a,b",
        'he said "no"',
        'already ""doubled""',
        "line1\nline2",
        "line1\r\nline2",
        "  padded  ",
        "naïve-ü-日本語",
        "arn:aws:s3:::bucket/key,with,commas",
    ]),
)


@st.composite
def findings(draw: st.DrawFn) -> Finding:
    """Draw a valid ``Finding``.

    ``title`` is built from the drawn ``check_id`` so the Requirement 1.12
    prefix rule is satisfied by construction -- this strategy generates only
    *constructible* Findings, because the property under test is about what
    happens to a Finding after it exists.

    The three enum fields are drawn as either the member or the member's
    string value, exercising both arms of the Requirement 1.14 coercion, so
    the property holds regardless of which form the caller supplied.
    """
    check_id = draw(st.sampled_from([
        "SRA-GUARDDUTY-01", "SRA-S3-04", "SRA-ORGANIZATIONS-09",
        "SRA-SECURITYLAKE-17",
    ]))

    def enum_or_value(enum_cls: type) -> st.SearchStrategy[Any]:
        members = list(enum_cls)
        return st.one_of(
            st.sampled_from(members),
            st.sampled_from([m.value for m in members]),
        )

    return Finding(
        check_id=check_id,
        status=draw(enum_or_value(Status)),
        region=draw(st.sampled_from(["us-east-1", "eu-west-2", "global"])),
        severity=draw(enum_or_value(Severity)),
        title=f"{check_id} {draw(_NASTY_TEXT)}",
        description=draw(_NASTY_TEXT),
        resource_id=draw(st.one_of(st.none(), _NASTY_TEXT)),
        resource_type=draw(_NASTY_TEXT),
        account_id=draw(st.one_of(st.just(""), st.just("111111111111"))),
        account_name=draw(_NASTY_TEXT),
        checked_value=draw(_NASTY_TEXT),
        actual_value=draw(_NASTY_TEXT),
        remediation=draw(_NASTY_TEXT),
        service=draw(_NASTY_TEXT),
        check_logic=draw(_NASTY_TEXT),
        account_type=draw(enum_or_value(AccountType)),
    )


# --------------------------------------------------------------------------- #
# Attempted-assignment value strategy
# --------------------------------------------------------------------------- #
#
# The value must be irrelevant: assigning a *plausible* value (a legal enum
# member, a legal region string) must be refused exactly as firmly as
# assigning nonsense. Mutable containers are included because Requirement
# 1.11's stated purpose is that no Finding holds a mutable object, and the
# assignment path is the obvious way one would arrive.

_ATTEMPTED_VALUES = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=20),
    st.sampled_from(list(Status) + list(Severity) + list(AccountType)),
    st.sampled_from(["PASS", "FAIL", "ERROR", "global", "us-east-1", ""]),
    st.lists(st.text(max_size=5), max_size=3),
    st.dictionaries(st.text(max_size=5), st.text(max_size=5), max_size=3),
    st.builds(object),
)


def _field_values(finding: Finding) -> Dict[str, Any]:
    """Snapshot every field of ``finding`` as a plain dict.

    ``dataclasses.asdict`` is avoided: it deep-copies, which would defeat the
    identity comparisons the mutation tests rely on.
    """
    return {name: getattr(finding, name) for name in FIELD_NAMES}


# --------------------------------------------------------------------------- #
# The field set itself
# --------------------------------------------------------------------------- #


def test_field_set_is_the_declared_sixteen() -> None:
    """The literal FIELD_NAMES tuple is exactly ``Finding``'s dataclass fields.

    Guards the rest of this module: every property below quantifies over
    FIELD_NAMES, so if a field were renamed in ``core/finding.py`` and this
    tuple not updated, the properties would keep passing while no longer
    covering that field.

    Validates: Requirement 1.1.
    """
    declared = tuple(f.name for f in dataclasses.fields(Finding))
    assert declared == FIELD_NAMES, (
        f"Finding's dataclass fields {declared!r} no longer match the sixteen "
        f"names this property quantifies over {FIELD_NAMES!r}"
    )
    assert len(FIELD_NAMES) == 16


# --------------------------------------------------------------------------- #
# (a) Requirement 1.9: assignment to any field raises FrozenInstanceError
# --------------------------------------------------------------------------- #


@settings(max_examples=200)
@given(finding=findings(), field_name=st.sampled_from(FIELD_NAMES),
       value=_ATTEMPTED_VALUES)
def test_assignment_to_any_field_raises_frozen_instance_error(
    finding: Finding, field_name: str, value: Any
) -> None:
    """Property 9: ``setattr`` on any of the sixteen fields raises.

    The error type is asserted precisely as ``dataclasses.FrozenInstanceError``
    rather than as ``AttributeError``. ``FrozenInstanceError`` *is* a subclass
    of ``AttributeError``, and ``slots=True`` alone would already produce a
    bare ``AttributeError`` for an unknown attribute -- so accepting the
    superclass would let a ``Finding`` that had lost ``frozen=True`` pass this
    test on a typo'd field name.

    Validates: Requirement 1.9.
    """
    before = _field_values(finding)

    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(finding, field_name, value)

    assert _field_values(finding) == before, (
        f"assignment to {field_name!r} raised but still altered the Finding"
    )


@settings(max_examples=100)
@given(finding=findings(), field_name=st.sampled_from(FIELD_NAMES))
def test_deletion_of_any_field_raises_frozen_instance_error(
    finding: Finding, field_name: str
) -> None:
    """Property 9: ``delattr`` on any of the sixteen fields raises.

    Deletion is the other half of the mutation surface ``frozen=True`` closes.
    A Finding that permitted deletion would satisfy "no field can be
    reassigned" while still being able to lose a CSV column between
    construction and ``to_row()``.

    Validates: Requirement 1.9.
    """
    before = _field_values(finding)

    with pytest.raises(dataclasses.FrozenInstanceError):
        delattr(finding, field_name)

    assert _field_values(finding) == before


@settings(max_examples=100)
@given(finding=findings(), name=st.text(min_size=1, max_size=12),
       value=_ATTEMPTED_VALUES)
def test_no_new_attribute_can_be_attached(
    finding: Finding, name: str, value: Any
) -> None:
    """A Finding admits no attribute outside the declared sixteen.

    Requirement 1.10's slotted storage is what makes Requirement 1.11
    airtight: without it, ``f._ctx = ctx`` would succeed and a Finding could
    hold a reference to the per-scan context even though all sixteen declared
    fields were immutable scalars.

    ``AttributeError`` is the assertion here rather than
    ``FrozenInstanceError``, because for a name that is not a field the two
    mechanisms differ in which one fires first, and either refusal is correct.

    Validates: Requirements 1.10, 1.11.
    """
    if name in FIELD_NAMES:
        return  # covered by the assignment property above

    with pytest.raises(AttributeError):
        setattr(finding, name, value)


# --------------------------------------------------------------------------- #
# (b) Requirement 1.11: only strings, enum members, or a null resource_id
# --------------------------------------------------------------------------- #


@settings(max_examples=200)
@given(finding=findings())
def test_every_field_holds_only_an_immutable_scalar(finding: Finding) -> None:
    """Property 9: no field of a Finding holds a mutable object.

    Per field:

      - ``status`` / ``severity`` / ``account_type`` hold a member of their
        enum. Asserted as ``isinstance(value, enum_cls)`` -- these are
        ``StrEnum`` members, so a bare-``str`` check would pass on an
        uncoerced string and miss exactly the Requirement 1.14 failure.
      - ``resource_id`` holds ``str`` or ``None``.
      - Every remaining field holds a ``str``. Asserted as
        ``type(value) is str``, not ``isinstance``, so a ``str`` *subclass*
        carrying arbitrary state does not slip through.

    Taken together this is the statement Requirement 1.11 makes: there is no
    field through which a Finding could reach a check instance, the
    ``ScanContext``, or a mutable container.

    Validates: Requirement 1.11.
    """
    for field_name in FIELD_NAMES:
        value = getattr(finding, field_name)

        if field_name in ENUM_FIELD_TYPES:
            enum_cls = ENUM_FIELD_TYPES[field_name]
            assert isinstance(value, enum_cls), (
                f"Finding.{field_name} holds {value!r} "
                f"({type(value).__name__}), not a {enum_cls.__name__} member"
            )
            continue

        if field_name == NULLABLE_FIELD:
            assert value is None or type(value) is str, (
                f"Finding.{field_name} holds {value!r} "
                f"({type(value).__name__}), not str or None"
            )
            continue

        assert type(value) is str, (
            f"Finding.{field_name} holds {value!r} "
            f"({type(value).__name__}), not str"
        )

        # The concrete consequence: nothing hashable-by-identity, and nothing
        # with attributes of its own, is reachable from a Finding field.
        assert not isinstance(value, (list, dict, set, tuple, bytearray))


@settings(max_examples=50)
@given(finding=findings())
def test_finding_allocates_no_instance_dict(finding: Finding) -> None:
    """Property 9: construction allocates no per-instance attribute dictionary.

    Validates: Requirement 1.10.
    """
    assert not hasattr(finding, "__dict__"), (
        "Finding has a per-instance __dict__; slots=True was lost, and with "
        "it the guarantee that no undeclared attribute can be attached"
    )
    assert set(Finding.__slots__) == set(FIELD_NAMES), (
        f"Finding.__slots__ {Finding.__slots__!r} does not match the sixteen "
        f"declared fields"
    )


# --------------------------------------------------------------------------- #
# (c) Requirement 1.7: to_row() leaves the receiver unmodified
# --------------------------------------------------------------------------- #


@settings(max_examples=200)
@given(finding=findings())
def test_to_row_leaves_the_receiver_unmodified(finding: Finding) -> None:
    """Property 9: reading a Finding as a row does not write to it.

    Every field is compared by *identity* (``is``), not equality, because
    ``__post_init__`` already writes to this object's slots via
    ``object.__setattr__`` to coerce the enum fields. That door stays open for
    the lifetime of the instance, so "``to_row()`` does not use it" needs
    checking rather than assuming. Identity also catches a re-coercion that
    produced an equal-but-distinct value.

    Calling ``to_row()`` twice and comparing the two mappings closes the
    remaining gap: a ``to_row`` that mutated on first call and then reported
    consistently would satisfy a single-call snapshot.

    Validates: Requirement 1.7.
    """
    before = _field_values(finding)

    first = finding.to_row()

    after = _field_values(finding)
    for field_name in FIELD_NAMES:
        assert after[field_name] is before[field_name], (
            f"to_row() replaced Finding.{field_name}: "
            f"{before[field_name]!r} -> {after[field_name]!r}"
        )

    second = finding.to_row()
    assert second == first, "to_row() is not idempotent; the first call mutated"

    # The returned mapping is a fresh object, so a caller mutating the row it
    # was handed cannot reach back into the Finding.
    assert first is not second
    first["Status"] = "TAMPERED"
    assert finding.status is before["status"]
