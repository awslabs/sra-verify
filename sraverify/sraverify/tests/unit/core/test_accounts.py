"""Unit tests for ``sraverify.core.accounts``.

Organizations is retiring the account ``Status`` field in favour of ``State``
(issue #23). Two things are asserted:

  * **The rule** -- ``State`` decides whenever it is present, and ``Status`` is
    read only when ``State`` is absent.
  * **One call site** -- no service module compares an account's ``Status`` to
    ``ACTIVE`` directly, so the rule cannot be bypassed by a check written or
    copied later. When ``Status`` is gone from the API, a direct compare would
    silently see zero active accounts.
"""
from __future__ import annotations

import pathlib
import re

import pytest

from sraverify.core.accounts import ACCOUNT_ACTIVE, is_active_account

SERVICES = pathlib.Path(__file__).resolve().parents[3] / "services"

# Every AccountState value in the botocore model (1.43.105).
ACCOUNT_STATES = ["PENDING_ACTIVATION", "ACTIVE", "SUSPENDED", "PENDING_CLOSURE", "CLOSED"]


def test_active_constant_is_the_api_literal():
    assert ACCOUNT_ACTIVE == "ACTIVE"


@pytest.mark.parametrize("state", ACCOUNT_STATES)
def test_state_alone_decides(state):
    assert is_active_account({"Id": "111122223333", "State": state}) is (state == "ACTIVE")


@pytest.mark.parametrize("state", [s for s in ACCOUNT_STATES if s != "ACTIVE"])
def test_state_wins_over_a_stale_active_status(state):
    # Status has a coarser lifecycle; a non-ACTIVE State is authoritative.
    account = {"Id": "111122223333", "State": state, "Status": "ACTIVE"}
    assert is_active_account(account) is False


def test_active_state_with_a_different_status_is_active():
    account = {"Id": "111122223333", "State": "ACTIVE", "Status": "SUSPENDED"}
    assert is_active_account(account) is True


def test_both_fields_active_is_active():
    # The shape AWS returns today.
    assert is_active_account({"Id": "111122223333", "State": "ACTIVE", "Status": "ACTIVE"}) is True


@pytest.mark.parametrize(
    "status, expected",
    [("ACTIVE", True), ("SUSPENDED", False), ("PENDING_CLOSURE", False)],
)
def test_status_is_the_fallback_when_state_is_absent(status, expected):
    assert is_active_account({"Id": "111122223333", "Status": status}) is expected


def test_neither_field_is_not_active():
    assert is_active_account({"Id": "111122223333"}) is False


def test_comparison_is_case_sensitive():
    assert is_active_account({"State": "active"}) is False
    assert is_active_account({"Status": "Active"}) is False


# An Organizations Account object compared directly on Status. Other services'
# Status fields (GuardDuty features, Security Hub admins) compare against
# ENABLED, not ACTIVE, and are not matched.
DIRECT_STATUS_COMPARE = re.compile(r"""\.get\(\s*['"]Status['"]\s*\)\s*==\s*['"]ACTIVE['"]""")


def test_no_service_module_compares_account_status_directly():
    offenders = sorted(
        str(path.relative_to(SERVICES))
        for path in SERVICES.rglob("*.py")
        if DIRECT_STATUS_COMPARE.search(path.read_text(encoding="utf-8"))
    )
    assert offenders == [], (
        "Use sraverify.core.accounts.is_active_account instead of comparing an "
        f"account's Status to ACTIVE: {offenders}"
    )


def test_the_services_directory_was_found():
    # Guards the static test above against passing vacuously on a wrong path.
    assert (SERVICES / "organizations" / "base.py").is_file()
