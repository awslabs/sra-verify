"""Unit tests for ``sraverify.core.finding``.

Four behaviors are asserted here, and each one is load-bearing for the
16-column CSV contract the HTML dashboards parse:

  * **``to_row`` key set and order** -- the returned mapping's keys are exactly
    ``Finding.FIELDS`` in ``FIELDS`` order. The dashboards index by position,
    so a dropped, renamed, or reordered key is a downstream break that no
    scanner-side assertion other than this one catches.
  * **Null ``resource_id``** -- the one nullable field renders as ``""``, never
    as the text ``None``. Every other field is a ``str`` or an enum member, so
    nothing else can leak a ``repr`` into a cell.
  * **Frozen-ness** -- assignment to any of the sixteen fields raises
    ``FrozenInstanceError``. This is what lets a returned Finding be handed to
    the CSV writer without a defensive copy, and what guarantees a Finding
    holds no live reference into a check or a ``ScanContext``.
  * **Enum coercion** -- ``status``, ``severity``, and ``account_type`` accept
    a member or that member's exact string value and are stored as the member.
    Anything else raises ``ValueError``. A dataclass annotation performs no
    run-time check, and ``StrEnum`` members are ``str``, so without
    ``__post_init__`` an illegal string would construct happily.

Requirements 1.5, 1.6, 1.9, 1.12, 1.13.
"""
from __future__ import annotations

import dataclasses
from dataclasses import FrozenInstanceError, fields

import pytest

from sraverify.core.enums import AccountType, Severity, Status
from sraverify.core.finding import GLOBAL_REGION, Finding


CHECK_ID = "SRA-GUARDDUTY-01"

#: A fully valid construction. Every test that needs an invalid Finding starts
#: from this and overrides exactly one field, so the assertion is unambiguous
#: about which rule fired.
VALID = {
    "check_id": CHECK_ID,
    "status": Status.PASS,
    "region": "us-east-1",
    "severity": Severity.HIGH,
    "title": f"{CHECK_ID} GuardDuty is enabled",
    "description": "GuardDuty is enabled in the account and region.",
    "resource_id": "12345678901234567890abcdefabcdef",
    "resource_type": "AWS::GuardDuty::Detector",
    "account_id": "111122223333",
    "account_name": "Audit",
    "checked_value": "GuardDuty Configuration",
    "actual_value": "Detector exists and is enabled",
    "remediation": "",
    "service": "GuardDuty",
    "check_logic": "Calls guardduty:ListDetectors for the region.",
    "account_type": AccountType.AUDIT,
}

FIELD_NAMES = tuple(f.name for f in fields(Finding))


def make(**overrides) -> Finding:
    """Build a Finding from the valid baseline with the given overrides."""
    return Finding(**{**VALID, **overrides})


# --------------------------------------------------------------------------
# to_row key set and order (Requirement 1.5)
# --------------------------------------------------------------------------

def test_to_row_keys_equal_fields_in_fields_order():
    assert list(make().to_row()) == list(Finding.FIELDS)


def test_fields_is_the_sixteen_dashboard_columns_in_order():
    assert Finding.FIELDS == (
        "AccountId", "AccountName", "Region", "CheckId", "Status", "Severity",
        "Title", "Description", "ResourceId", "ResourceType", "CheckedValue",
        "ActualValue", "Remediation", "Service", "CheckLogic", "AccountType",
    )
    assert len(Finding.FIELDS) == 16


def test_fields_is_an_immutable_sequence():
    assert isinstance(Finding.FIELDS, tuple)


def test_every_fields_entry_maps_to_a_dataclass_field():
    # Each column name is its field name in lower snake case (Requirement 1.4
    # is the source of the mapping; asserted here because to_row's key set is
    # only meaningful if the two sides cannot drift).
    assert len(FIELD_NAMES) == 16
    for column in Finding.FIELDS:
        snake = "".join(
            f"_{c.lower()}" if c.isupper() and i else c.lower()
            for i, c in enumerate(column)
        )
        assert snake in FIELD_NAMES, column


def test_to_row_carries_every_field_value():
    row = make().to_row()
    assert row["AccountId"] == "111122223333"
    assert row["AccountName"] == "Audit"
    assert row["Region"] == "us-east-1"
    assert row["CheckId"] == CHECK_ID
    assert row["Status"] == "PASS"
    assert row["Severity"] == "HIGH"
    assert row["Title"] == f"{CHECK_ID} GuardDuty is enabled"
    assert row["Description"] == VALID["description"]
    assert row["ResourceId"] == VALID["resource_id"]
    assert row["ResourceType"] == "AWS::GuardDuty::Detector"
    assert row["CheckedValue"] == "GuardDuty Configuration"
    assert row["ActualValue"] == "Detector exists and is enabled"
    assert row["Remediation"] == ""
    assert row["Service"] == "GuardDuty"
    assert row["CheckLogic"] == VALID["check_logic"]
    assert row["AccountType"] == "audit"


def test_to_row_returns_a_fresh_mapping_each_call():
    finding = make()
    first, second = finding.to_row(), finding.to_row()
    assert first == second
    assert first is not second
    # Mutating the returned row cannot reach the Finding.
    first["Status"] = "FAIL"
    assert finding.to_row()["Status"] == "PASS"


# --------------------------------------------------------------------------
# Value rendering, including the nullable field (Requirement 1.6)
# --------------------------------------------------------------------------

def test_null_resource_id_renders_as_the_empty_string():
    row = make(resource_id=None).to_row()
    assert row["ResourceId"] == ""
    assert row["ResourceId"] is not None


def test_null_resource_id_is_stored_as_none_and_only_rendered_as_empty():
    finding = make(resource_id=None)
    assert finding.resource_id is None
    assert finding.to_row()["ResourceId"] == ""


def test_empty_string_resource_id_is_legal_and_renders_unchanged():
    assert make(resource_id="").to_row()["ResourceId"] == ""


def test_every_row_value_is_a_string():
    row = make(resource_id=None).to_row()
    for column, value in row.items():
        assert type(value) is str or isinstance(value, str), column


def test_enum_fields_render_as_the_bare_value_not_the_member_repr():
    row = make(
        status=Status.ERROR,
        severity=Severity.CRITICAL,
        account_type=AccountType.LOG_ARCHIVE,
    ).to_row()
    assert row["Status"] == "ERROR"
    assert row["Severity"] == "CRITICAL"
    assert row["AccountType"] == "log-archive"
    for value in (row["Status"], row["Severity"], row["AccountType"]):
        # No "Status.ERROR" style rendering leaking into a cell.
        assert not value.startswith(("Status", "Severity", "AccountType"))


def test_string_fields_are_returned_unchanged_with_no_coercion():
    # Commas, quotes, and line breaks survive untouched: quoting belongs to the
    # CSV writer, and escaping here would escape twice.
    gnarly = 'a, b "quoted"\r\nsecond line  '
    row = make(actual_value=gnarly, remediation=gnarly).to_row()
    assert row["ActualValue"] == gnarly
    assert row["Remediation"] == gnarly


def test_to_row_leaves_the_receiving_finding_unmodified():
    finding = make()
    before = dataclasses.astuple(finding)
    finding.to_row()
    assert dataclasses.astuple(finding) == before


# --------------------------------------------------------------------------
# Frozen-ness (Requirement 1.9)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("field_name", FIELD_NAMES)
def test_assignment_to_any_field_raises_frozen_instance_error(field_name):
    finding = make()
    with pytest.raises(FrozenInstanceError):
        setattr(finding, field_name, "mutated")


@pytest.mark.parametrize("field_name", FIELD_NAMES)
def test_deleting_any_field_raises_frozen_instance_error(field_name):
    finding = make()
    with pytest.raises(FrozenInstanceError):
        delattr(finding, field_name)


def test_assigning_an_enum_field_a_legal_member_still_raises():
    # Coercion happens once, in __post_init__. It is not a re-opened door.
    finding = make()
    with pytest.raises(FrozenInstanceError):
        finding.status = Status.FAIL
    assert finding.status is Status.PASS


def test_dataclasses_replace_produces_a_new_validated_finding():
    original = make()
    replaced = dataclasses.replace(original, status="FAIL")
    assert original.status is Status.PASS
    assert replaced.status is Status.FAIL
    assert replaced is not original
    # replace re-runs __post_init__, so the title rule still applies.
    with pytest.raises(ValueError):
        dataclasses.replace(original, check_id="SRA-OTHER-01")


# --------------------------------------------------------------------------
# Enum coercion (Requirements 1.6, 1.9 storage guarantee)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("member", list(Status))
def test_status_accepts_a_member_and_stores_the_member(member):
    assert make(status=member).status is member


@pytest.mark.parametrize("member", list(Status))
def test_status_accepts_the_members_value_and_stores_the_member(member):
    assert make(status=member.value).status is member


@pytest.mark.parametrize("member", list(Severity))
def test_severity_accepts_a_member_or_its_value(member):
    assert make(severity=member).severity is member
    assert make(severity=member.value).severity is member


@pytest.mark.parametrize("member", list(AccountType))
def test_account_type_accepts_a_member_or_its_value(member):
    assert make(account_type=member).account_type is member
    assert make(account_type=member.value).account_type is member


@pytest.mark.parametrize(
    "field_name, illegal",
    [
        ("status", "PASSED"),
        ("status", "pass"),
        ("status", "UNKNOWN"),
        ("status", ""),
        # A member of the wrong enum is a string that is not a Status value.
        ("status", Severity.HIGH),
        ("severity", "INFORMATIONAL"),
        ("severity", "high"),
        ("severity", "UNKNOWN"),
        ("severity", ""),
        ("severity", Status.PASS),
        # The illegal value living in services/config/base.py today.
        ("account_type", "account"),
        ("account_type", "log_archive"),
        ("account_type", "Application"),
        ("account_type", "all"),
        ("account_type", ""),
        ("account_type", Status.PASS),
    ],
)
def test_illegal_enum_value_raises_value_error_naming_field_and_value(
    field_name, illegal
):
    with pytest.raises(ValueError) as excinfo:
        make(**{field_name: illegal})
    message = str(excinfo.value)
    assert field_name in message
    assert repr(illegal) in message or str(illegal) in message


@pytest.mark.parametrize("field_name", ["status", "severity", "account_type"])
@pytest.mark.parametrize("illegal", [None, 1, 0, ["PASS"], object()])
def test_non_string_enum_value_is_rejected(field_name, illegal):
    with pytest.raises(ValueError):
        make(**{field_name: illegal})


# --------------------------------------------------------------------------
# Non-string values in the remaining fields (Requirement 1.6's guarantee that
# a repr cannot reach a cell)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "field_name",
    [n for n in FIELD_NAMES
     if n not in ("resource_id", "status", "severity", "account_type")],
)
def test_non_string_field_raises_type_error_naming_the_field(field_name):
    # The string check runs ahead of the title rule, so a non-string check_id
    # or title reports as a TypeError on that field rather than as a title
    # mismatch.
    with pytest.raises(TypeError) as excinfo:
        make(**{field_name: None})
    assert field_name in str(excinfo.value)


def test_non_string_resource_id_raises_type_error():
    with pytest.raises(TypeError) as excinfo:
        make(resource_id=42)
    assert "resource_id" in str(excinfo.value)


def test_omitting_any_field_raises_type_error():
    incomplete = dict(VALID)
    del incomplete["remediation"]
    with pytest.raises(TypeError):
        Finding(**incomplete)


# --------------------------------------------------------------------------
# The title rule (Requirement 1.12)
# --------------------------------------------------------------------------

def test_title_beginning_with_check_id_and_one_space_is_accepted():
    assert make(title=f"{CHECK_ID} A stated fact").title.startswith(CHECK_ID)


@pytest.mark.parametrize(
    "title",
    [
        "GuardDuty is enabled",                     # no check ID at all
        "SRA-GUARDDUTY-02 GuardDuty is enabled",    # a different check's ID
        "SRA-GUARDDUTY-01",                         # ID with no trailing space
        "SRA-GUARDDUTY-01: GuardDuty is enabled",   # colon instead of a space
        "SRA-GUARDDUTY-01\tGuardDuty is enabled",   # tab instead of a space
        " SRA-GUARDDUTY-01 GuardDuty is enabled",   # leading space
        "",                                          # empty
    ],
)
def test_title_not_beginning_with_check_id_and_one_space_raises(title):
    with pytest.raises(ValueError) as excinfo:
        make(title=title)
    message = str(excinfo.value)
    assert repr(title) in message
    assert repr(CHECK_ID) in message


def test_title_of_only_the_check_id_and_a_space_is_accepted():
    # The rule is a prefix rule; a blank remainder is metadata's problem, not
    # the Finding's.
    assert make(title=f"{CHECK_ID} ").title == f"{CHECK_ID} "


# --------------------------------------------------------------------------
# GLOBAL_REGION (Requirement 1.13)
# --------------------------------------------------------------------------

def test_global_region_is_the_string_global():
    assert GLOBAL_REGION == "global"
    assert isinstance(GLOBAL_REGION, str)


def test_global_region_is_usable_as_the_region_of_a_non_regional_finding():
    assert make(region=GLOBAL_REGION).to_row()["Region"] == "global"
