"""
Property-based test for the finding model's cell types (task 2.4).

This module implements **Property 7: Every row value is a string** from the
``check-contract-formalization`` design:

    ∀ ``f: Finding``: every value of ``f.to_row()`` is a ``str``; no value is
    ``None``.

The property has two halves, and both are exercised here because either one
alone leaves the CSV exposed:

  (a) *Rendering.* For any validly constructed ``Finding``, every one of the
      sixteen ``to_row()`` cells is a ``str`` and none is ``None``. The three
      enum-typed fields render as the member's plain ``value``, never as an
      enum ``repr`` such as ``"Status.PASS"``, and a null ``resource_id``
      renders as the empty string (Requirement 1.6).

  (b) *Rejection at construction.* A non-``str`` supplied for any of the
      twelve non-nullable string fields raises ``TypeError`` naming that
      field, so a null value can never reach the CSV as the text ``"None"``
      (Requirement 1.16). Half (a) can only hold for every ``Finding`` in
      existence because half (b) makes an ill-typed ``Finding``
      unconstructible.

Feature: check-contract-formalization, Property 7: Every row value is a string.

**Validates: Requirements 1.6, 1.16**
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from sraverify.core.enums import AccountType, Severity, Status
from sraverify.core.finding import Finding


# --------------------------------------------------------------------------- #
# Strategies
# --------------------------------------------------------------------------- #
#
# A Finding is validated at construction, so a generator that ignores those
# rules would spend its budget on ValueError rather than on the property. Two
# rules constrain the shape of a valid instance:
#
#   - ``title`` must begin with ``check_id`` followed by exactly one space
#     (Requirement 1.12), so the two are generated together rather than
#     independently.
#   - ``status``, ``severity``, and ``account_type`` must each be a member of
#     their enum or a string equal to one member's ``value`` (Requirement
#     1.14). Both spellings are generated, because coercion is exactly what
#     half (a) is checking: a caller who passed the string must still get a
#     plain-``str`` cell out.
#
# Cell text deliberately includes commas, double quotes, and line breaks: the
# model applies no quoting or escaping, so those characters must survive as
# ordinary string content and must not perturb the type of the cell.


#: Text that a check might plausibly put in a cell, plus the delimiter
#: characters the model must pass through untouched.
CELL_TEXT = st.one_of(
    st.text(),
    st.text(alphabet=',";\n\r\t\\'),
    st.just(""),
)

#: A check ID. Not required to match ``CHECK_ID_RE`` -- that pattern is
#: enforced by ``CheckMeta``, not by ``Finding`` -- but kept free of the
#: leading/trailing space that would make the ``title`` rule ambiguous.
CHECK_ID = st.text(
    alphabet=st.characters(min_codepoint=33, max_codepoint=126),
    min_size=1,
    max_size=24,
)


def _enum_or_value(enum_cls: type[Enum]) -> st.SearchStrategy[Any]:
    """Members of ``enum_cls``, and the string values of those members.

    Both spellings are legal input (Requirement 1.14), and both must render
    identically, so the strategy covers each.
    """
    members = list(enum_cls)
    return st.sampled_from(members) | st.sampled_from([m.value for m in members])


@st.composite
def findings(draw: st.DrawFn) -> Finding:
    """Draw a validly constructed ``Finding``.

    ``title`` is derived from the drawn ``check_id`` so the prefix rule holds,
    and ``resource_id`` is drawn as either text or ``None`` because it is the
    one nullable field.
    """
    check_id = draw(CHECK_ID)
    title_tail = draw(CELL_TEXT)
    return Finding(
        check_id=check_id,
        status=draw(_enum_or_value(Status)),
        region=draw(CELL_TEXT),
        severity=draw(_enum_or_value(Severity)),
        title=f"{check_id} {title_tail}",
        description=draw(CELL_TEXT),
        resource_id=draw(st.none() | CELL_TEXT),
        resource_type=draw(CELL_TEXT),
        account_id=draw(CELL_TEXT),
        account_name=draw(CELL_TEXT),
        checked_value=draw(CELL_TEXT),
        actual_value=draw(CELL_TEXT),
        remediation=draw(CELL_TEXT),
        service=draw(CELL_TEXT),
        check_logic=draw(CELL_TEXT),
        account_type=draw(_enum_or_value(AccountType)),
    )


#: The twelve fields that must hold a ``str``. ``resource_id`` is excluded (it
#: is the one nullable field) and so are the three enum fields (they are
#: coerced, and their rejection path raises ``ValueError``, covered by
#: Property 8 rather than here).
NON_NULLABLE_STR_FIELDS = (
    "check_id", "region", "title", "description", "resource_type",
    "account_id", "account_name", "checked_value", "actual_value",
    "remediation", "service", "check_logic",
)

#: Values that are not ``str``. ``None`` leads the list because rendering it
#: as the text ``"None"`` is the concrete defect Requirement 1.16 names.
NON_STR_VALUES = st.one_of(
    st.none(),
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.booleans(),
    st.lists(st.text(), max_size=2),
    st.dictionaries(st.text(max_size=3), st.text(max_size=3), max_size=2),
    st.tuples(st.text(max_size=3)),
    st.binary(max_size=4),
)


def _valid_kwargs() -> Dict[str, Any]:
    """A minimal, fully valid keyword set for ``Finding``.

    Used as the base for half (b): exactly one field is replaced with a
    non-``str``, so the ``TypeError`` that follows is attributable to that
    field and to nothing else.
    """
    return {
        "check_id": "SRA-GUARDDUTY-01",
        "status": Status.PASS,
        "region": "us-east-1",
        "severity": Severity.HIGH,
        "title": "SRA-GUARDDUTY-01 A detector exists in every enabled Region",
        "description": "A detector must exist in every enabled Region.",
        "resource_id": "detector-abc",
        "resource_type": "AWS::GuardDuty::Detector",
        "account_id": "111111111111",
        "account_name": "test-account",
        "checked_value": "GuardDuty Configuration",
        "actual_value": "Detector detector-abc is enabled",
        "remediation": "",
        "service": "GuardDuty",
        "check_logic": "Resolve the detector ID in each Region in scope.",
        "account_type": AccountType.APPLICATION,
    }


# --------------------------------------------------------------------------- #
# (a) Every rendered cell is a plain str, and none is None
# --------------------------------------------------------------------------- #


@given(finding=findings())
@settings(max_examples=200, deadline=None)
def test_every_row_value_is_a_plain_str(finding: Finding) -> None:
    """Property 7 (a): every ``to_row()`` value is a ``str``, and none is ``None``.

    ``type(value) is str`` rather than ``isinstance`` is the load-bearing
    assertion. ``Status``, ``Severity``, and ``AccountType`` are ``StrEnum``
    subclasses, so a member would satisfy ``isinstance(value, str)`` while
    still carrying enum identity into the CSV writer. Only the exact-type
    check separates the member from its ``value``.

    Validates: Requirements 1.6, 1.16.
    """
    row = finding.to_row()

    for column, value in row.items():
        assert value is not None, (
            f"to_row()[{column!r}] is None; every cell must be a str so that "
            f"no cell can render as the text 'None' (Requirement 1.16)."
        )
        assert type(value) is str, (
            f"to_row()[{column!r}] is {type(value).__name__} "
            f"({value!r}); every cell must be a plain str (Requirement 1.6)."
        )
        assert not isinstance(value, Enum), (
            f"to_row()[{column!r}] is an enum member ({value!r}); enum fields "
            f"must render as the member's .value, not as the member "
            f"(Requirement 1.6)."
        )


@given(finding=findings())
@settings(max_examples=200, deadline=None)
def test_enum_cells_render_as_the_member_value(finding: Finding) -> None:
    """Property 7 (a), enum half: the three enum cells equal the member's ``value``.

    A plain ``str`` cell is necessary but not sufficient: ``str(member)`` and
    ``f"{member}"`` are also plain strings, and what they produce for a
    str-mixin enum has varied across Python versions. Asserting equality with
    ``.value`` pins the rendered text as well as its type, which is what stops
    ``"Status.PASS"`` reaching the ``Status`` column.

    Validates: Requirement 1.6.
    """
    row = finding.to_row()

    assert row["Status"] == finding.status.value
    assert row["Severity"] == finding.severity.value
    assert row["AccountType"] == finding.account_type.value

    # The enum repr must not be what lands in the cell.
    for column, member in (
        ("Status", finding.status),
        ("Severity", finding.severity),
        ("AccountType", finding.account_type),
    ):
        assert row[column] != repr(member), (
            f"to_row()[{column!r}] rendered the enum repr {row[column]!r} "
            f"instead of the member value {member.value!r}."
        )


@given(finding=findings())
@settings(max_examples=200, deadline=None)
def test_null_resource_id_renders_as_empty_string(finding: Finding) -> None:
    """Property 7 (a), nullable half: a null ``resource_id`` renders as ``""``.

    ``resource_id`` is the single field admitting ``None``, so it is the only
    field from which ``None`` could otherwise escape into a cell.

    Validates: Requirement 1.6.
    """
    row = finding.to_row()

    if finding.resource_id is None:
        assert row["ResourceId"] == "", (
            f"a null resource_id rendered as {row['ResourceId']!r}; it must "
            f"render as the empty string (Requirement 1.6)."
        )
    else:
        assert row["ResourceId"] == finding.resource_id


# --------------------------------------------------------------------------- #
# (b) A non-str in any non-nullable string field is unconstructible
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("field_name", NON_NULLABLE_STR_FIELDS)
@given(bad_value=NON_STR_VALUES)
@settings(max_examples=100, deadline=None)
def test_non_str_field_value_raises_type_error_naming_the_field(
    field_name: str, bad_value: Any
) -> None:
    """Property 7 (b): a non-``str`` in any of the twelve fields raises ``TypeError``.

    Every other field is left valid, so the raised ``TypeError`` is
    attributable to ``field_name`` alone, and the message is asserted to name
    it. This is what makes half (a) hold universally: an ill-typed ``Finding``
    never exists, so ``to_row()`` has no ill-typed cell to render.

    Validates: Requirement 1.16.
    """
    kwargs = _valid_kwargs()
    kwargs[field_name] = bad_value

    with pytest.raises(TypeError) as excinfo:
        Finding(**kwargs)

    message = str(excinfo.value)
    assert field_name in message, (
        f"TypeError for a non-str {field_name!r} must name the field; got "
        f"{message!r} (Requirement 1.16)."
    )


@pytest.mark.parametrize("field_name", NON_NULLABLE_STR_FIELDS)
def test_none_never_reaches_a_cell_as_the_text_none(field_name: str) -> None:
    """Property 7 (b), the named defect: ``None`` cannot become the text ``"None"``.

    The concrete failure Requirement 1.16 exists to prevent, asserted directly
    rather than only as one draw of the generated case above.

    Validates: Requirement 1.16.
    """
    kwargs = _valid_kwargs()
    kwargs[field_name] = None

    with pytest.raises(TypeError, match=field_name):
        Finding(**kwargs)


@given(bad_value=NON_STR_VALUES.filter(lambda v: v is not None))
@settings(max_examples=100, deadline=None)
def test_non_str_resource_id_also_raises_type_error(bad_value: Any) -> None:
    """``resource_id`` admits ``None`` but nothing else non-``str``.

    Included so the nullable field is not a hole in half (b): ``None`` is
    legal there and renders as ``""``, while any other non-``str`` is rejected
    with a ``TypeError`` naming the field.

    Validates: Requirement 1.16.
    """
    kwargs = _valid_kwargs()
    kwargs["resource_id"] = bad_value

    with pytest.raises(TypeError, match="resource_id"):
        Finding(**kwargs)
