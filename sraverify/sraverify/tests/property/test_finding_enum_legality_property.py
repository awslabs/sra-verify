"""
Property-based test for the finding model's enum-typed fields (task 2.5).

This module implements **Property 8: No out-of-enum status or severity** from
the ``check-contract-formalization`` design.

``Finding`` annotates ``status``, ``severity``, and ``account_type`` with their
enums, but an annotation performs no run-time check, and because ``Status``,
``Severity``, and ``AccountType`` are ``StrEnum`` subclasses a member and a
plain string are both ``str``. Without ``__post_init__`` doing the work,
``Finding(status="MAYBE", ...)`` would construct happily and render "MAYBE"
straight into a CSV cell. The two halves below pin the two behaviors that
close that hole:

  (a) A string that is not one of the enum's member values is rejected with
      ``ValueError`` naming both the field and the rejected value. Asserted for
      all three enum-typed fields, with ``hypothesis`` generating the
      non-member strings (Requirement 1.8).
  (b) A legal value is coerced to the enum *member*, whether the caller
      supplied the member itself or that member's string value, so a
      constructed ``Finding`` always carries a member (Requirement 1.14).

Half (b) is what makes half (a) non-vacuous in the other direction: rejecting
everything would satisfy (a) alone.

There is no shared ``Finding`` strategy helper under ``tests/property/`` yet
(task 2.3 has not landed), so this module carries its own minimal legal-kwargs
builder. When that helper appears, this builder is the thing to replace.

Feature: check-contract-formalization, Property 8: No out-of-enum status or
severity.

**Validates: Requirements 1.8, 1.14**
"""
from __future__ import annotations

from enum import EnumMeta
from typing import Any, Dict, Tuple

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from sraverify.core.enums import AccountType, Severity, Status
from sraverify.core.finding import Finding


# --------------------------------------------------------------------------- #
# The three enum-typed fields, and a legal-kwargs builder
# --------------------------------------------------------------------------- #
#
# ``ENUM_FIELDS`` mirrors ``finding._ENUM_FIELDS`` rather than importing it:
# the test states the contract independently, so deleting a pair from the
# module's private tuple shows up here as a failure instead of silently
# shrinking the test's coverage.

ENUM_FIELDS: Tuple[Tuple[str, EnumMeta], ...] = (
    ("status", Status),
    ("severity", Severity),
    ("account_type", AccountType),
)

_CHECK_ID = "SRA-GUARDDUTY-01"


def _finding_kwargs(**overrides: Any) -> Dict[str, Any]:
    """Return a complete set of legal ``Finding`` kwargs, with overrides applied.

    Every one of the sixteen fields is required and has no default, so a test
    that wants to vary one field still has to supply the other fifteen. The
    baseline here is deliberately legal in every respect -- including the
    ``title`` starting with ``check_id`` plus exactly one space -- so that a
    ``ValueError`` raised from a call using it can only have come from the
    field the test overrode.
    """
    kwargs: Dict[str, Any] = {
        "check_id": _CHECK_ID,
        "status": Status.PASS,
        "region": "us-east-1",
        "severity": Severity.HIGH,
        "title": f"{_CHECK_ID} GuardDuty is enabled",
        "description": "GuardDuty must be enabled in every enabled region.",
        "resource_id": "detector-abc",
        "resource_type": "AWS::GuardDuty::Detector",
        "account_id": "111111111111",
        "account_name": "test-account",
        "checked_value": "GuardDuty Configuration",
        "actual_value": "Detector detector-abc is ENABLED",
        "remediation": "Enable GuardDuty in the region.",
        "service": "GuardDuty",
        "check_logic": "Calls ListDetectors and GetDetector per region.",
        "account_type": AccountType.APPLICATION,
    }
    kwargs.update(overrides)
    return kwargs


def _legal_values(enum_cls: EnumMeta) -> frozenset:
    """Return the set of strings ``enum_cls`` accepts by value."""
    return frozenset(member.value for member in enum_cls)


ALL_LEGAL_VALUES = frozenset().union(
    *(_legal_values(enum_cls) for _, enum_cls in ENUM_FIELDS)
)


def non_member_strings() -> st.SearchStrategy[str]:
    """Generate strings that are not a member value of any of the three enums.

    Filtering against the union of all three enums' values (rather than
    per-field) keeps one strategy usable for every field and costs nothing:
    the eleven legal strings are a vanishingly small slice of the text space,
    so the filter almost never rejects a draw.

    The explicit ``sampled_from`` branch supplies the near-misses that random
    text will not find on its own -- correct spelling in the wrong case, a
    member *name* where its value belongs (``LOG_ARCHIVE`` vs ``log-archive``),
    surrounding whitespace, and the empty string.
    """
    near_misses = st.sampled_from([
        "",
        " ",
        "MAYBE",
        "UNKNOWN",
        "pass",
        "Pass",
        "PASSED",
        " PASS",
        "PASS ",
        "PASS\n",
        "high",
        "SEVERE",
        "INFORMATIONAL",
        "LOG_ARCHIVE",   # the member *name*; its value is "log-archive"
        "log archive",
        "APPLICATION",   # the member *name*; its value is "application"
        "account",       # the invalid account_type still present in the tree
        "all",           # a CLI-only choice, never a Finding value
    ])
    return st.one_of(near_misses, st.text(max_size=40)).filter(
        lambda s: s not in ALL_LEGAL_VALUES
    )


def legal_inputs(enum_cls: EnumMeta) -> st.SearchStrategy[Any]:
    """Generate every legal input for ``enum_cls``: each member and each value.

    Requirement 1.14 treats the two forms as interchangeable at the call site,
    so both belong in one strategy. ``member.value`` is wrapped in ``str()`` to
    hand the constructor a plain ``str`` rather than the member itself --
    without it, ``StrEnum``'s ``str`` mixin would make the two branches
    indistinguishable and half of this strategy would be dead weight.
    """
    return st.one_of(
        st.sampled_from(list(enum_cls)),
        st.sampled_from([str(member.value) for member in enum_cls]),
    )


# --------------------------------------------------------------------------- #
# (a) A non-member string is rejected, naming the field and the value
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("field_name", "enum_cls"),
    ENUM_FIELDS,
    ids=[name for name, _ in ENUM_FIELDS],
)
@given(bad=non_member_strings())
@settings(max_examples=100)
def test_non_member_string_raises_value_error(
    field_name: str, enum_cls: EnumMeta, bad: str
) -> None:
    """Property 8 (a): an out-of-enum string cannot reach a constructed Finding.

    For each of ``status``, ``severity``, and ``account_type``, a generated
    string that is not one of the enum's member values must raise
    ``ValueError``, and the message must name both the field and the rejected
    value so the check that produced it is identifiable from the traceback
    alone.

    ``repr(bad)`` is what the message is required to contain, not ``bad``: the
    empty string and a whitespace-only string are legal draws, and only the
    repr makes them visible in an error message.

    Validates: Requirement 1.8.
    """
    with pytest.raises(ValueError) as excinfo:
        Finding(**_finding_kwargs(**{field_name: bad}))

    message = str(excinfo.value)
    assert f"Finding.{field_name}" in message, (
        f"ValueError for an illegal {field_name} must name the field; "
        f"got {message!r}"
    )
    assert repr(bad) in message, (
        f"ValueError for an illegal {field_name} must name the rejected "
        f"value {bad!r}; got {message!r}"
    )
    assert enum_cls.__name__ in message, (
        f"ValueError for an illegal {field_name} must name "
        f"{enum_cls.__name__}; got {message!r}"
    )


@given(
    bad_status=non_member_strings(),
    bad_severity=non_member_strings(),
    bad_account_type=non_member_strings(),
)
@settings(max_examples=100)
def test_first_illegal_enum_field_is_the_one_reported(
    bad_status: str, bad_severity: str, bad_account_type: str
) -> None:
    """Property 8 (a), all three fields illegal at once: ``status`` is reported.

    Coercion walks the three fields in declaration order and raises on the
    first failure, so a Finding built with all three illegal reports
    ``status``. Pinning the order keeps the diagnostic for a given bad
    construction reproducible instead of depending on dict iteration.

    Validates: Requirement 1.8.
    """
    with pytest.raises(ValueError) as excinfo:
        Finding(**_finding_kwargs(
            status=bad_status,
            severity=bad_severity,
            account_type=bad_account_type,
        ))

    message = str(excinfo.value)
    assert "Finding.status" in message, (
        f"With all three enum fields illegal, the reported field must be "
        f"status; got {message!r}"
    )
    assert repr(bad_status) in message


# --------------------------------------------------------------------------- #
# (b) A legal value is coerced to the member, member or string alike
# --------------------------------------------------------------------------- #


@given(
    status=legal_inputs(Status),
    severity=legal_inputs(Severity),
    account_type=legal_inputs(AccountType),
)
@settings(max_examples=100)
def test_legal_value_is_coerced_to_enum_member(
    status: Any, severity: Any, account_type: Any
) -> None:
    """Property 8 (b): a constructed Finding always carries enum members.

    Whether the caller passes ``Status.PASS`` or ``"PASS"``, the constructed
    Finding must hold ``Status.PASS``. ``isinstance`` is the assertion that
    separates the two: a ``StrEnum`` member compares equal to its own string
    value, so ``finding.status == "PASS"`` would hold even if no coercion had
    happened at all.

    The three fields are varied together rather than one at a time, which also
    confirms coercing one field does not disturb another -- a real risk given
    that ``__post_init__`` writes through ``object.__setattr__`` on a frozen,
    slotted instance.

    Validates: Requirement 1.14.
    """
    finding = Finding(**_finding_kwargs(
        status=status,
        severity=severity,
        account_type=account_type,
    ))

    assert isinstance(finding.status, Status), (
        f"status supplied as {status!r} ({type(status).__name__}) must be "
        f"coerced to a Status member; got {type(finding.status).__name__}"
    )
    assert isinstance(finding.severity, Severity), (
        f"severity supplied as {severity!r} ({type(severity).__name__}) must "
        f"be coerced to a Severity member; got "
        f"{type(finding.severity).__name__}"
    )
    assert isinstance(finding.account_type, AccountType), (
        f"account_type supplied as {account_type!r} "
        f"({type(account_type).__name__}) must be coerced to an AccountType "
        f"member; got {type(finding.account_type).__name__}"
    )

    # Coercion must land on the member the caller named, not merely on some
    # member: the value round-trips.
    assert finding.status is Status(status)
    assert finding.severity is Severity(severity)
    assert finding.account_type is AccountType(account_type)
