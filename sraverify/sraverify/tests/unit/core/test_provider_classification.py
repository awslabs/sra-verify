"""
Property 44: each moved-verdict ledger row reaches the verdict the tables assign.

Task 26 moved every classification of an operation the Organizations provider owns
into ``OrganizationsProvider.NOT_CONFIGURED_ERRORS``. Two entries are new
(``ListDelegatedAdministrators`` and ``ListAccounts`` with
``AWSOrganizationsNotInUseException``) and two are relocations of identical pairs
(``DescribeOrganization``, ``DescribeEffectivePolicy``). The test organization
cannot return ``AWSOrganizationsNotInUseException`` -- every account is a member --
so the live A/B is expected to move zero rows, and this module is what holds each
row offline (Requirement 13.12).

Each case drives one real check with the row's accessor answering the row's
semantic error, every other accessor answering a non-semantic denial, and any
accessor the check must pass first answering a minimal success. It runs the drive
twice:

* under the **committed** tables (Phase 2), and
* under the **Phase 1** tables: the provider table empty and the five entries task
  26 removed from service tables restored. For a "moves" row that is the same as
  patching the provider table empty, because no service table ever declared the
  pair.

A "moves" row must FAIL with the check's existing wording and never PASS under
Phase 2, and must not FAIL under Phase 1. "Does not move" and "stays ERROR" rows
must produce the same statuses under both.

Exports :data:`LEDGER`, which ``test_check_classification_property`` reads to hold
``_PROVIDER_PAIRS_WITHOUT_FAIL_ARM`` to the ledger.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from typing import Any, Iterator, Literal
from unittest.mock import patch

import pytest

from sraverify.core.aws_errors import NotConfigured, error_result
from sraverify.core.enums import Status
from sraverify.core.organization import OrganizationsProvider
from sraverify.core.registry import all_checks
from sraverify.services.config.base import ConfigCheck
from sraverify.services.iam.base import IAMCheck
from sraverify.services.organizations.base import OrganizationsCheck
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.tests.property.test_check_classification_property import (
    _AUDIT_ACCOUNT,
    _prepare,
)

Outcome = Literal["moves", "does not move", "stays ERROR"]

_CODE = "AWSOrganizationsNotInUseException"
_MESSAGE = "Your account isn't a member of an organization."

_NO_ORG = "No AWS Organization exists"

#: One active member account, for the drives that must enumerate accounts first.
_ACCOUNTS_SUCCESS = {"Accounts": [{"Id": "444455556666", "Name": "member", "State": "ACTIVE"}]}


@dataclass(frozen=True)
class LedgerRow:
    """One row of the design's moved-verdict ledger.

    Attributes:
        check_id: The check.
        operation: The provider-owned operation whose entry can move it.
        outcome: ``moves``, ``does not move`` or ``stays ERROR``.
        text: For ``moves``, a substring of the check's existing FAIL wording.
        provider_successes: Provider accessors that must succeed first,
            ``method -> success``.
        accessor_successes: Base accessors that must succeed first,
            ``method -> success``.
    """

    check_id: str
    operation: str
    outcome: Outcome
    text: str = ""
    provider_successes: dict[str, Any] = field(default_factory=dict)
    accessor_successes: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.check_id}-{self.operation}"


def _lda(check_id: str, text: str = _NO_ORG, **kw: Any) -> LedgerRow:
    return LedgerRow(check_id, "ListDelegatedAdministrators", "moves", text, **kw)


def _accounts(check_id: str, text: str = _NO_ORG) -> LedgerRow:
    return LedgerRow(check_id, "ListAccounts", "moves", text)


#: The design's ledger, row by row (design-phase2.md, "The moved-verdict ledger").
LEDGER: tuple[LedgerRow, ...] = (
    # ListDelegatedAdministrators: twelve checks move, SRA-IAM-04 already FAILed.
    _lda("SRA-ACCESSANALYZER-02"),
    _lda("SRA-ACCESSANALYZER-03"),
    _lda("SRA-CLOUDTRAIL-12"),
    _lda("SRA-CLOUDTRAIL-13"),
    _lda("SRA-CONFIG-07"),
    _lda("SRA-CONFIG-08"),
    _lda("SRA-SECURITYHUB-03"),
    _lda(
        "SRA-SECURITYHUB-06",
        accessor_successes={
            "get_organization_admin_accounts": {
                "AdminAccounts": [{"AccountId": _AUDIT_ACCOUNT, "Status": "ENABLED"}]
            }
        },
    ),
    _lda("SRA-SECURITYHUB-07"),
    _lda(
        "SRA-SECURITYINCIDENTRESPONSE-01",
        text="No delegated administrator is configured for Security Incident Response",
    ),
    _lda("SRA-SECURITYLAKE-14"),
    _lda("SRA-SECURITYLAKE-15"),
    LedgerRow("SRA-IAM-04", "ListDelegatedAdministrators", "does not move"),
    # ListAccounts: fourteen checks move, SRA-SECURITYHUB-17 has no FAIL arm.
    _accounts("SRA-INSPECTOR-07"),
    _accounts("SRA-MACIE-07"),
    _accounts("SRA-SECURITYHUB-08"),
    _accounts("SRA-SECURITYLAKE-01"),
    *(_accounts(f"SRA-SECURITYLAKE-{n:02d}") for n in range(6, 14)),
    _accounts(
        "SRA-ORGANIZATIONS-12",
        text=f"AWS Organizations reports the control absent: {_CODE}",
    ),
    _accounts(
        "SRA-SECURITYINCIDENTRESPONSE-04",
        text="This account is not a member of an AWS Organization",
    ),
    LedgerRow("SRA-SECURITYHUB-17", "ListAccounts", "stays ERROR"),
    # DescribeOrganization: a relocation for OrganizationsCheck; no FAIL arm
    # in SRA-IAM-05; SRA-SECURITYINCIDENTRESPONSE-05 does not classify it.
    *(
        LedgerRow(f"SRA-ORGANIZATIONS-{n:02d}", "DescribeOrganization", "does not move")
        for n in (1, 5, 6, 7, 11)
    ),
    LedgerRow("SRA-IAM-05", "DescribeOrganization", "stays ERROR"),
    LedgerRow("SRA-SECURITYINCIDENTRESPONSE-05", "DescribeOrganization", "stays ERROR"),
    # DescribeEffectivePolicy: a relocation for both consumers.
    LedgerRow(
        "SRA-ORGANIZATIONS-12",
        "DescribeEffectivePolicy",
        "does not move",
        provider_successes={"accounts": _ACCOUNTS_SUCCESS},
    ),
    LedgerRow(
        "SRA-SECURITYHUB-17",
        "DescribeEffectivePolicy",
        "does not move",
        provider_successes={"accounts": _ACCOUNTS_SUCCESS},
    ),
)

#: The provider accessors that issue each owned operation in the ledger.
_PROVIDER_METHODS = {
    "ListDelegatedAdministrators": ("delegated_administrators",),
    "ListAccounts": ("accounts",),
    "DescribeOrganization": ("describe", "management_account_id"),
    "DescribeEffectivePolicy": ("effective_policy",),
}

_RESTORED = NotConfigured(evidence="Phase 1 entry, restored for the ledger comparison only")

#: The five service-table entries task 26 removed, keyed by base class.
_PHASE_ONE_SERVICE_ENTRIES: dict[type, dict[str, dict[str, NotConfigured]]] = {
    IAMCheck: {"ListDelegatedAdministrators": {_CODE: _RESTORED}},
    ConfigCheck: {"DescribeOrganization": {_CODE: _RESTORED}},
    OrganizationsCheck: {
        "DescribeOrganization": {_CODE: _RESTORED},
        "DescribeEffectivePolicy": {"EffectivePolicyNotFoundException": _RESTORED},
    },
    SecurityHubCheck: {"DescribeEffectivePolicy": {"EffectivePolicyNotFoundException": _RESTORED}},
}


@contextlib.contextmanager
def _phase_one_tables() -> Iterator[None]:
    """The tables as they stood at f517024: provider empty, five entries restored."""
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(OrganizationsProvider, "NOT_CONFIGURED_ERRORS", {}))
        for base, extra in _PHASE_ONE_SERVICE_ENTRIES.items():
            merged = {**base.NOT_CONFIGURED_ERRORS, **extra}
            stack.enter_context(patch.object(base, "NOT_CONFIGURED_ERRORS", merged))
        yield


def _semantic_error(row: LedgerRow) -> dict:
    code = _CODE if row.operation != "DescribeEffectivePolicy" else "EffectivePolicyNotFoundException"
    return error_result(code=code, message=_MESSAGE, operation=row.operation)


def _drive(row: LedgerRow) -> list[Any]:
    """Run the row's check once with its accessor answering the semantic error."""
    cls = all_checks()[row.check_id]
    check, patchers = _prepare(cls)
    extra = []
    try:
        provider = check._ctx.organization
        failure = _semantic_error(row)
        for method in _PROVIDER_METHODS[row.operation]:
            getattr(provider, method).side_effect = lambda *a, _v=failure, **k: _v
        if row.operation == "DescribeOrganization":
            check._ctx.get_management_account_id.return_value = failure
        for method, value in row.provider_successes.items():
            getattr(provider, method).side_effect = lambda *a, _v=value, **k: _v
        for method, value in row.accessor_successes.items():
            patcher = patch.object(cls, method, lambda self, *a, _v=value, **k: _v)
            patcher.start()
            extra.append(patcher)
        return list(check.execute())
    finally:
        for patcher in reversed(extra):
            patcher.stop()
        for patcher in patchers:
            patcher.stop()


def _statuses(findings: list[Any]) -> list[Status]:
    return sorted((f.status for f in findings), key=lambda s: s.value)


def test_the_ledger_has_the_designs_rows() -> None:
    """Twelve and fourteen moves, three stays-ERROR rows, every check registered."""
    moves = [r for r in LEDGER if r.outcome == "moves"]
    assert sum(r.operation == "ListDelegatedAdministrators" for r in moves) == 12
    assert sum(r.operation == "ListAccounts" for r in moves) == 14
    assert {(r.check_id, r.operation) for r in LEDGER if r.outcome == "stays ERROR"} == {
        ("SRA-SECURITYHUB-17", "ListAccounts"),
        ("SRA-IAM-05", "DescribeOrganization"),
        ("SRA-SECURITYINCIDENTRESPONSE-05", "DescribeOrganization"),
    }
    assert len({r.id for r in LEDGER}) == len(LEDGER)
    registered = all_checks()
    assert all(r.check_id in registered for r in LEDGER)
    assert set(_PROVIDER_METHODS) == set(OrganizationsProvider.NOT_CONFIGURED_ERRORS)


@pytest.mark.parametrize("row", LEDGER, ids=lambda r: r.id)
def test_each_ledger_row_reaches_the_verdict_the_tables_assign(row: LedgerRow) -> None:
    """Property 44, one case per ledger row."""
    after = _drive(row)
    with _phase_one_tables():
        before = _drive(row)

    assert after, f"{row.id}: no row under the committed tables"
    assert before, f"{row.id}: no row under the Phase 1 tables"

    if row.outcome == "moves":
        assert not [f for f in after if f.status is Status.PASS], after
        failing = [f for f in after if f.status is Status.FAIL]
        assert failing, f"{row.id}: no FAIL under the committed tables: {after}"
        assert any(row.text in f.actual_value for f in failing), (
            f"{row.id}: no FAIL carries {row.text!r}: {[f.actual_value for f in failing]}"
        )
        assert not [f for f in before if f.status is Status.FAIL], (
            f"{row.id}: already FAILed under the Phase 1 tables, so the entry is not "
            f"what moves it: {[f.actual_value for f in before]}"
        )
        assert any(
            f.status is Status.ERROR and f.actual_value.startswith(f"{row.operation} failed: {_CODE}")
            for f in before
        ), f"{row.id}: the branch did not ERROR under the Phase 1 tables: {before}"
    else:
        assert _statuses(after) == _statuses(before), (
            f"{row.id} ({row.outcome}): {_statuses(before)} -> {_statuses(after)}"
        )
        if row.outcome == "stays ERROR":
            assert {f.status for f in after} == {Status.ERROR}, after
        assert [f.actual_value for f in after] == [f.actual_value for f in before]
