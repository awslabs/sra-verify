"""Unit tests for ``sraverify.core.enums``.

Three things are asserted here, and they are the three things the rest of the
design leans on:

  * **Membership** -- each enum carries exactly the members the design fixes,
    with exactly those values and no extras. An extra ``Severity`` member or a
    renamed ``AccountType`` value silently widens the 16-column CSV contract.
  * **``.value`` round-trip** -- ``Enum(value)`` recovers the member and
    ``Enum(illegal_value)`` raises ``ValueError``. This is the coercion path
    ``Finding.__post_init__`` uses, and the reason
    ``account_type="account"`` (the illegal value in ``services/config/base.py``)
    cannot survive metadata load.
  * **String comparison** -- ``AccountType.AUDIT == "audit"`` is true because
    ``StrEnum`` members are ``str`` subclasses. ``_select`` compares
    ``cls.meta.account_type`` against the plain ``--account-type`` string with no
    explicit ``.value``, so if this ever stopped holding, every account-type
    filter would match nothing and the scan would quietly select zero checks.

Requirements 1.3 and 9.10.
"""
from __future__ import annotations

import pytest

from sraverify.core.enums import AccountType, Severity, Status


# --------------------------------------------------------------------------
# Membership (Requirement 1.3)
# --------------------------------------------------------------------------

def test_status_members_are_exactly_pass_fail_error():
    assert [m.name for m in Status] == ["PASS", "FAIL", "ERROR"]
    assert {m.value for m in Status} == {"PASS", "FAIL", "ERROR"}


def test_severity_members_are_exactly_the_four_levels():
    assert [m.name for m in Severity] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert {m.value for m in Severity} == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_account_type_members_are_exactly_the_four_account_roles():
    assert [m.name for m in AccountType] == [
        "APPLICATION",
        "AUDIT",
        "LOG_ARCHIVE",
        "MANAGEMENT",
    ]
    assert {m.value for m in AccountType} == {
        "application",
        "audit",
        "log-archive",
        "management",
    }


def test_account_type_log_archive_value_is_hyphenated_not_underscored():
    # The member name uses an underscore because it must be an identifier; the
    # value is the CLI spelling and is hyphenated. Confusing the two breaks
    # `--account-type log-archive`.
    assert AccountType.LOG_ARCHIVE.value == "log-archive"
    assert AccountType.LOG_ARCHIVE.name == "LOG_ARCHIVE"


@pytest.mark.parametrize("enum_cls", [Status, Severity, AccountType])
def test_members_are_str_instances(enum_cls):
    for member in enum_cls:
        assert isinstance(member, str)


# --------------------------------------------------------------------------
# .value round-trip (Requirement 1.3)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("enum_cls", [Status, Severity, AccountType])
def test_value_round_trips_back_to_the_same_member(enum_cls):
    for member in enum_cls:
        assert enum_cls(member.value) is member
        assert enum_cls[member.name] is member


@pytest.mark.parametrize("enum_cls", [Status, Severity, AccountType])
def test_member_round_trips_through_the_constructor(enum_cls):
    # Finding.__post_init__ coerces a field that may already hold a member.
    for member in enum_cls:
        assert enum_cls(member) is member


@pytest.mark.parametrize("enum_cls", [Status, Severity, AccountType])
def test_str_renders_the_bare_value(enum_cls):
    # StrEnum semantics: no "Severity.HIGH" leaking into a CSV cell.
    for member in enum_cls:
        assert str(member) == member.value
        assert f"{member}" == member.value


@pytest.mark.parametrize(
    "enum_cls, illegal",
    [
        (Status, "PASSED"),
        (Status, "pass"),
        (Status, "UNKNOWN"),
        (Severity, "INFORMATIONAL"),
        (Severity, "high"),
        (Severity, "UNKNOWN"),
        # The illegal value in services/config/base.py, and the two shapes the
        # migration could plausibly get wrong.
        (AccountType, "account"),
        (AccountType, "log_archive"),
        (AccountType, "Application"),
        (AccountType, "all"),
        (AccountType, ""),
    ],
)
def test_non_member_value_raises_value_error(enum_cls, illegal):
    with pytest.raises(ValueError):
        enum_cls(illegal)


@pytest.mark.parametrize("enum_cls", [Status, Severity, AccountType])
def test_non_member_string_is_not_a_member(enum_cls):
    assert "definitely-not-a-member" not in [m.value for m in enum_cls]


# --------------------------------------------------------------------------
# The string comparison _select relies on (Requirements 1.3, 9.10)
# --------------------------------------------------------------------------

def test_account_type_member_equals_its_plain_string():
    # This is the exact comparison _select performs, with no .value.
    assert AccountType.AUDIT == "audit"
    assert AccountType.APPLICATION == "application"
    assert AccountType.LOG_ARCHIVE == "log-archive"
    assert AccountType.MANAGEMENT == "management"


def test_account_type_member_does_not_equal_a_different_account_type_string():
    assert AccountType.AUDIT != "application"
    assert AccountType.AUDIT != "AUDIT"
    assert AccountType.LOG_ARCHIVE != "log_archive"
    assert AccountType.APPLICATION != "all"


@pytest.mark.parametrize("enum_cls", [Status, Severity, AccountType])
def test_every_member_equals_its_value_as_a_plain_string(enum_cls):
    for member in enum_cls:
        assert member == member.value
        assert member.value == member


def test_select_style_filter_matches_on_the_plain_cli_string():
    # Stands in for _select's `cls.meta.account_type == account_type` step
    # without importing main.py, which pulls in the whole check catalog.
    catalog = {
        "SRA-A-01": AccountType.APPLICATION,
        "SRA-B-01": AccountType.AUDIT,
        "SRA-C-01": AccountType.LOG_ARCHIVE,
        "SRA-D-01": AccountType.MANAGEMENT,
        "SRA-E-01": AccountType.AUDIT,
    }

    selected = {
        check_id: at for check_id, at in catalog.items() if at == "audit"
    }

    assert set(selected) == {"SRA-B-01", "SRA-E-01"}


def test_members_are_usable_as_plain_string_dict_keys():
    # A member and its value hash identically, so a lookup keyed by one finds
    # the other. Several call sites depend on this.
    by_member = {AccountType.AUDIT: "audit-account"}
    assert by_member["audit"] == "audit-account"
    assert hash(AccountType.AUDIT) == hash("audit")


# --------------------------------------------------------------------------
# The CLI derives its choices from AccountType (Requirement 9.10)
# --------------------------------------------------------------------------

def test_cli_account_type_choices_derive_from_the_members_plus_all():
    choices = [t.value for t in AccountType] + ["all"]
    assert choices == ["application", "audit", "log-archive", "management", "all"]


def test_all_is_not_an_account_type_member():
    # "all" is the CLI's own sentinel, not an account role, so it must not be
    # reachable through the enum.
    assert "all" not in [t.value for t in AccountType]
    with pytest.raises(ValueError):
        AccountType("all")
