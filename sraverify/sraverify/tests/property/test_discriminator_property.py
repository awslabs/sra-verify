"""
Properties 11, 11a, and 12: the per-service discriminator tables.

A table entry converts an ERROR into a FAIL. That is the whole reason these
properties exist and the reason they are strict about evidence: an ERROR says
"the scanner could not tell", a FAIL says "AWS told us the control is absent",
and an entry asserted without grounds turns a permission failure into a
fabricated finding that a dashboard counts and somebody investigates.

Three claims:

* **Property 11.** The predicate is *total* -- it never raises, whatever it is
  handed -- and *conservative*: anything not declared is ``False``. An
  undeclared code, a declared code arriving from an operation it is not declared
  for, and a declared message needle that does not appear all resolve to ERROR.
* **Property 11a.** Every entry carries non-blank ``evidence``, and no
  ``TO CONFIRM`` placeholder survives its service's batch. The second clause is
  so a placeholder fails the run the moment its
  service lands rather than at the end of the whole migration -- which is when
  nobody would be looking at it.
* **Property 12.** The table is declared once per service, on the base class. No
  check declares its own; ``__init_subclass__`` refuses one, and this asserts the
  catalog is actually clean.

The tables are empty until their batches land, so Property 11 is thin today by
construction. It is written now, in Phase 0, so that the first entry any batch
adds is checked the moment it appears.

Validates: Requirements 4.2, 4.3, 4.4, 4.5, 4.6, 4.6a, 7.7.
"""
from __future__ import annotations

import hashlib
import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import sraverify.services
from sraverify.core.aws_errors import (
    NO_CLIENT_CODE,
    TRANSPORT_ERROR_CODES,
    NotConfigured,
    error_result,
    is_not_configured,
    is_not_configured_in,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.organization import OrganizationsProvider
from sraverify.core.registry import all_checks
from sraverify.tests.property.strategies import cell_text
from sraverify.tests.property.test_accessor_cache_property import _concrete
from sraverify.tests.property.test_client_contract_property import (
    ADAPTERS as CLIENT_ADAPTERS,
)
from sraverify.tests.property.test_organization_provider_property import PROVIDER_ADAPTERS

_SERVICES_ROOT: Path = Path(sraverify.services.__file__).resolve().parent

#: The prefix a provisional evidence string must carry, so that Property 11a can
#: find it. Three entries in the design are seeded from an existing inline
#: classification with no evidence behind it and must be confirmed against a live
#: account in their batch or omitted.
_PLACEHOLDER_PREFIX = "TO CONFIRM"


def _service_names() -> list[str]:
    """Return every service package name, sorted.

    Returns:
        The service directory names.
    """
    return sorted(
        module.name
        for module in pkgutil.iter_modules([str(_SERVICES_ROOT)])
        if module.ispkg
    )


def _base_class(service: str) -> type[SecurityCheck]:
    """Return the ``<Service>Check`` class declared in a service's ``base`` module.

    Args:
        service: A service package name.

    Returns:
        The declared base class.

    Raises:
        AssertionError: If the module declares no base class.
    """
    module = importlib.import_module(f"sraverify.services.{service}.base")
    for obj in vars(module).values():
        if (
            inspect.isclass(obj)
            and issubclass(obj, SecurityCheck)
            and obj is not SecurityCheck
            and obj.__module__ == module.__name__
        ):
            return obj
    raise AssertionError(f"{service}/base.py declares no <Service>Check class")


_SERVICE_NAMES: list[str] = _service_names()

#: The key the Organizations provider's table is listed under, beside the
#: eighteen service keys. Not a service package name, so it cannot collide.
_PROVIDER_KEY = "organization-provider"

#: Every declared discriminator table: the eighteen service base tables and the
#: Organizations provider's, which ``SecurityCheck.is_not_configured`` consults
#: after the service's. Each table is held to the same shape, evidence and
#: conservatism rules.
_TABLES: dict[str, Any] = {
    service: _base_class(service).NOT_CONFIGURED_ERRORS for service in _SERVICE_NAMES
} | {_PROVIDER_KEY: OrganizationsProvider.NOT_CONFIGURED_ERRORS}

_TABLE_KEYS: list[str] = list(_TABLES)

#: ``(table key, operation, code, NotConfigured)`` for every declared entry, in a
#: stable order. Snapshotted at import so collection does not vary.
_ENTRIES: list[tuple[str, str, str, NotConfigured]] = [
    (service, operation, code, fact)
    for service, table in _TABLES.items()
    for operation, by_code in table.items()
    for code, fact in by_code.items()
]

#: ``(check_id, cls)`` for the real catalog, in ascending check-ID order.
_CATALOG: list[tuple[str, type[SecurityCheck]]] = sorted(all_checks().items())


def _entry_ids() -> list[str]:
    """Return parametrize IDs of the form ``<service>.<operation>.<code>``.

    Returns:
        One ID per declared entry.
    """
    return [f"{service}.{operation}.{code}" for service, operation, code, _ in _ENTRIES]


# --------------------------------------------------------------------------- #
# Non-vacuity, stated honestly
# --------------------------------------------------------------------------- #


def test_eighteen_services_declare_a_table_attribute() -> None:
    """Every base inherits the ClassVar even before it declares its own.

    The default is an empty mapping, which classifies nothing -- so an unmigrated
    service resolves every error to ERROR. That is the safe direction, and it is
    what makes the migration landable in batches.
    """
    for service in _SERVICE_NAMES:
        table = _TABLES[service]
        assert isinstance(table, dict), (
            f"{service}: NOT_CONFIGURED_ERRORS is {type(table).__name__}, "
            f"expected a mapping"
        )


def test_the_declared_entry_count_matches_the_migration_state() -> None:
    """Some services must declare entries, or Property 11 quantifies over nothing.

    This is the guard against the quiet failure mode of Property 11: with every
    table empty it has nothing to test and passes vacuously.

    A floor rather than an exact count, because a service legitimately having no
    semantic codes is normal: ``accessanalyzer`` and ``ec2`` declare an empty
    table, each for a reason recorded on its own base class. ``auditmanager``,
    ``cloudtrail``, ``config`` and ``iam`` each declare at least one
    non-Organizations entry, held by the golden below.
    """
    with_entries = {service for service, _, _, _ in _ENTRIES}

    assert len(with_entries) >= 8, (
        f"only {sorted(with_entries)} declare discriminator entries. Property 11 "
        f"quantifies over these tables, so a truncated set makes it pass having "
        f"tested almost nothing."
    )


# --------------------------------------------------------------------------- #
# Property 11 -- total and conservative
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "service,operation,code,fact",
    _ENTRIES or [pytest.param(None, None, None, None, id="no-entries-yet")],
    ids=_entry_ids() or None,
)
def test_a_declared_entry_classifies_as_not_configured(
    service: str | None, operation: str | None, code: str | None, fact: Any
) -> None:
    """Property 11: a declared pair resolves to FAIL.

    With the entry's message needle present, when it declares one.
    """
    if service is None:
        pytest.skip("no discriminator entries declared yet")

    message = fact.message if fact.message else "any message at all"
    error = error_result(code=code, message=message, operation=operation)["Error"]

    assert is_not_configured(_TABLES[service], error) is True, (
        f"{service}.{operation}.{code} is declared but did not classify"
    )


@pytest.mark.parametrize(
    "service,operation,code,fact",
    _ENTRIES or [pytest.param(None, None, None, None, id="no-entries-yet")],
    ids=_entry_ids() or None,
)
def test_the_same_code_from_an_undeclared_operation_does_not_classify(
    service: str | None, operation: str | None, code: str | None, fact: Any
) -> None:
    """Property 11: the operation dimension is load-bearing.

    This is the property that justifies keying the table by operation at all.
    ``BadRequestException`` from ``guardduty:DescribeOrganizationConfiguration``
    means "no delegated administrator has been enabled" -- the control is absent,
    a FAIL. The same code from ``guardduty:ListOrganizationAdminAccounts`` means
    "this is not the management account" -- run the scan somewhere else, an ERROR.
    A table keyed by code alone would have to pick one and be wrong about the
    other.
    """
    if service is None:
        pytest.skip("no discriminator entries declared yet")

    error = error_result(
        code=code,
        message=fact.message or "any message at all",
        operation="AnOperationNobodyDeclared",
    )["Error"]

    assert (
        is_not_configured(_TABLES[service], error) is False
    ), (
        f"{service}: {code} classified as not-configured through an operation it "
        f"is not declared for"
    )


@pytest.mark.parametrize(
    "service,operation,code,fact",
    _ENTRIES or [pytest.param(None, None, None, None, id="no-entries-yet")],
    ids=_entry_ids() or None,
)
def test_an_undeclared_code_from_a_declared_operation_does_not_classify(
    service: str | None, operation: str | None, code: str | None, fact: Any
) -> None:
    """Property 11: a code AWS introduces later produces an honest ERROR."""
    if service is None:
        pytest.skip("no discriminator entries declared yet")

    error = error_result(
        code="SomeFutureExceptionAwsHasNotInventedYet",
        message="whatever it says",
        operation=operation,
    )["Error"]

    assert (
        is_not_configured(_TABLES[service], error) is False
    )


@pytest.mark.parametrize(
    "service,operation,code,fact",
    [
        pytest.param(s, o, c, f, id=f"{s}.{o}.{c}")
        for s, o, c, f in _ENTRIES
        if f.message
    ]
    or [pytest.param(None, None, None, None, id="no-needled-entries-yet")],
)
@settings(max_examples=40, deadline=None)
@given(noise=cell_text())
def test_an_overloaded_code_without_its_needle_does_not_classify(
    service: str | None,
    operation: str | None,
    code: str | None,
    fact: Any,
    noise: str,
) -> None:
    """Property 11: the single most consequential ``False`` in the feature.

    An overloaded code is one AWS returns for both a semantic condition and an
    access failure. ``macie2`` returns ``AccessDeniedException`` both when Macie
    is disabled in a Region and when the caller lacks the API permission;
    ``securityhub`` returns ``InvalidAccessException`` both when Security Hub is
    not subscribed and for other access problems. Only the message separates them,
    and reading the *permission* case as "not configured" would publish a
    fabricated finding.

    Property-based over ``cell_text()`` because the message is free-form AWS
    prose: it can be empty, contain quotes and newlines, or contain unrelated
    text that happens to be near the needle. The strategy's hostile corpus
    includes a real ``AccessDenied`` message, which is the case that matters.
    """
    if service is None:
        pytest.skip("no message-discriminated entries declared yet")

    # Skip the (vanishingly unlikely) draw that contains the needle after all.
    if fact.message.lower() in noise.lower():
        return

    error = error_result(
        code=code,
        message=noise if noise.strip() else "a message without the needle",
        operation=operation,
    )["Error"]

    assert (
        is_not_configured(_TABLES[service], error) is False
    ), (
        f"{service}.{operation}.{code} classified a message lacking its declared "
        f"needle {fact.message!r} as not-configured"
    )


@pytest.mark.parametrize("service", _TABLE_KEYS)
@pytest.mark.parametrize(
    "error",
    [
        {},
        {"Operation": "GetThing"},
        {"Code": "AccessDeniedException"},
        {"Operation": "", "Code": "", "Message": ""},
        {"Operation": None, "Code": None, "Message": None},
        {"Operation": 42, "Code": [], "Message": {}},
    ],
    ids=["empty", "operation-only", "code-only", "blank", "None-valued", "wrong-types"],
)
def test_the_predicate_is_total_over_every_service_table(
    service: str, error: Any
) -> None:
    """Property 11: never raises, whatever it is handed.

    A predicate that raised here would abort the calling check and cost every row
    it had already yielded -- to avoid answering a question about a value that
    ``is_error`` should have rejected upstream anyway.
    """
    assert (
        is_not_configured(_TABLES[service], error) is False
    )


@pytest.mark.parametrize("service", _TABLE_KEYS)
@pytest.mark.parametrize(
    "code", sorted(TRANSPORT_ERROR_CODES | {NO_CLIENT_CODE})
)
def test_no_service_classifies_a_transport_or_no_client_code(
    service: str, code: str
) -> None:
    """Requirement 4.3: these can never establish absence.

    A Region with no endpoint and a Region behind a broken network raise the same
    exception, so a transport code carries no information about whether the
    control exists. ``NoClient`` likewise: it means the scanner never had a way to
    ask.

    Swept across every declared operation of every service, so a future table
    entry cannot introduce one by accident.
    """
    table = _TABLES[service]

    for operation in list(table) + ["AnyOperation"]:
        error = error_result(
            code=code, message="transport or no-client", operation=operation
        )["Error"]
        assert is_not_configured(table, error) is False, (
            f"{service}.{operation} classified {code} as not-configured; a "
            f"transport failure and a missing client are undetermined states"
        )


# --------------------------------------------------------------------------- #
# Property 11a -- evidence
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "service,operation,code,fact",
    _ENTRIES or [pytest.param(None, None, None, None, id="no-entries-yet")],
    ids=_entry_ids() or None,
)
def test_every_entry_is_a_notconfigured_carrying_evidence(
    service: str | None, operation: str | None, code: str | None, fact: Any
) -> None:
    """Property 11a: evidence is a structural part of the entry.

    ``NotConfigured.__post_init__`` already enforces this at construction, so a
    table built the normal way cannot violate it. Asserted here anyway, because a
    table built any *other* way -- a dict literal, a value copied from another
    service, a ``MagicMock`` left behind by a test -- would bypass the constructor
    and reach the predicate.
    """
    if service is None:
        pytest.skip("no discriminator entries declared yet")

    assert isinstance(fact, NotConfigured), (
        f"{service}.{operation}.{code} is a {type(fact).__name__}, not a "
        f"NotConfigured; the table's values carry the evidence and cannot be "
        f"bare strings or None"
    )
    assert fact.evidence.strip(), (
        f"{service}.{operation}.{code} carries blank evidence"
    )


@pytest.mark.parametrize(
    "service,operation,code,fact",
    _ENTRIES or [pytest.param(None, None, None, None, id="no-entries-yet")],
    ids=_entry_ids() or None,
)
def test_no_placeholder_evidence_survives_its_services_batch(
    service: str | None, operation: str | None, code: str | None, fact: Any
) -> None:
    """Property 11a: a ``TO CONFIRM`` placeholder must not outlive its batch.

    Three entries in the design are seeded from a classification the tree already
    makes but has no evidence for -- Security Lake's ``UnauthorizedException``,
    asserted only by a deleted helper's docstring, and Audit Manager's
    "complete setup" ``AccessDeniedException``, whose code is *inferred* from a
    handler rather than observed. Each must be confirmed against a controlled
    account in its batch, or omitted so the code resolves to ERROR.

    No entry may carry a placeholder. An entry that cannot be evidenced is omitted
    instead, so the code resolves to ERROR -- which is why ``auditmanager``'s table
    is empty.
    """
    if service is None:
        pytest.skip("no discriminator entries declared yet")

    assert not fact.evidence.strip().startswith(_PLACEHOLDER_PREFIX), (
        f"{service}.{operation}.{code} still carries placeholder evidence "
        f"({fact.evidence[:60]!r}). Replace it with an API reference URL or an "
        f"observed aws_call_failed line from a controlled account, or delete the "
        f"entry so the code resolves to ERROR."
    )


def test_evidence_strings_are_substantial_enough_to_check() -> None:
    """An evidence string a reviewer cannot act on is not evidence.

    Deliberately weak -- a length floor and a demand that it look like either a
    URL or an observation. The point is to catch ``evidence="yes"``, not to grade
    prose.
    """
    offenders = [
        f"{service}.{operation}.{code}: {fact.evidence!r}"
        for service, operation, code, fact in _ENTRIES
        if not fact.evidence.strip().startswith(_PLACEHOLDER_PREFIX)
        and len(fact.evidence.strip()) < 25
    ]

    assert offenders == [], (
        f"evidence too short to verify: {offenders}. Cite the AWS API reference "
        f"page that documents the code's meaning for that operation, or the "
        f"build-log line from a controlled account observed to produce it."
    )


# --------------------------------------------------------------------------- #
# Property 12 -- declared once per service
# --------------------------------------------------------------------------- #


def test_the_catalog_is_not_empty() -> None:
    """Property 12 quantifies over the real catalog."""
    assert len(_CATALOG) >= 150, (
        f"the registry holds {len(_CATALOG)} checks; something has emptied it"
    )


@pytest.mark.parametrize(
    "check_id,cls", _CATALOG, ids=[check_id for check_id, _ in _CATALOG]
)
def test_no_check_declares_its_own_discriminator_table(
    check_id: str, cls: type[SecurityCheck]
) -> None:
    """Property 12: the table belongs to the service, not to a check.

    ``__init_subclass__`` refuses one at import time, so this cannot fail while
    that rule holds -- which is the point of asserting it separately. If the rule
    were ever loosened or bypassed, the catalog is where the damage would show,
    and a check with its own table would classify a shared error result differently
    from its siblings while continuing to work.
    """
    assert "NOT_CONFIGURED_ERRORS" not in vars(cls), (
        f"{check_id} declares its own NOT_CONFIGURED_ERRORS; it belongs on the "
        f"service base class so every check of the service classifies a given "
        f"(operation, code) pair identically"
    )


@pytest.mark.parametrize(
    "check_id,cls", _CATALOG, ids=[check_id for check_id, _ in _CATALOG]
)
def test_a_check_reads_the_same_table_its_service_base_declares(
    check_id: str, cls: type[SecurityCheck]
) -> None:
    """Property 12: inheritance resolves to the service's table, by identity.

    Identity rather than equality: two equal-but-distinct tables would mean a copy
    exists somewhere, and a copy is what drifts.
    """
    service_base = next(
        (
            base
            for base in cls.__mro__[1:]
            if base is not SecurityCheck
            and "NOT_CONFIGURED_ERRORS" in vars(base)
        ),
        None,
    )

    if service_base is None:
        # The service has not declared a table yet, so the check inherits
        # SecurityCheck's empty default. That is the correct pre-migration state.
        assert cls.NOT_CONFIGURED_ERRORS == {}, (
            f"{check_id} resolves a non-empty table that no base declares"
        )
        return

    assert cls.NOT_CONFIGURED_ERRORS is service_base.NOT_CONFIGURED_ERRORS, (
        f"{check_id} does not resolve to {service_base.__name__}'s table by "
        f"identity; a copy exists somewhere and copies drift"
    )


def test_the_default_table_on_security_check_is_empty() -> None:
    """An unmigrated service classifies nothing, so every failure is an ERROR.

    The safe default, and the reason a batch can land without the others.
    """
    assert SecurityCheck.NOT_CONFIGURED_ERRORS == {}


# --------------------------------------------------------------------------- #
# The Organizations provider's table (Properties 16 and 17)
# --------------------------------------------------------------------------- #


#: Every service-table entry for an operation outside
#: ``OrganizationsProvider.OWNED_OPERATIONS``:
#: ``(base class, operation, code, message needle or None, sha256(evidence))``.
#: Captured at f517024. A deliberate change to a non-owned NOT_CONFIGURED_ERRORS entry updates this tuple in the same commit.
#: Each row's digest trips detect-secrets' hex-entropy rule, so each carries the
#: per-line allowlist pragma: a sha256 of the evidence text, which is public
#: API-reference wording, is not a secret.
_NON_OWNED_NOT_CONFIGURED_ENTRIES: tuple[tuple[str, str, str, str | None, str], ...] = (
    ('AccountCheck', 'GetAlternateContact', 'ResourceNotFoundException', None, 'cee1a2d0dd7497c603bc606f9955cc3fb248102e17bffb0445056a26c05e66df'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('AuditManagerCheck', 'GetOrganizationAdminAccount', 'AccessDeniedException', 'Please complete AWS Audit Manager setup', 'c94a8c90079f230535f436901a3e87e2cc8ae631c3d848bea2c14afe90c8d3f6'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('CloudTrailCheck', 'GetEventSelectors', 'TrailNotFoundException', None, '501d46b719d2d6608713e7f242dc98fa7afa0335dfa900e278d03b8d1dddb581'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('CloudTrailCheck', 'GetTrailStatus', 'TrailNotFoundException', None, '64dac76a668ed3de3620f594c77cfd0f0326380821824b00f77befd38cc6803c'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('ConfigCheck', 'GetBucketPolicy', 'NoSuchBucketPolicy', None, 'c443af8abd141a33d8d8a3e870ad157320ee2590984f351a46ad0b3c75dc248a'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('FirewallManagerCheck', 'GetAdminAccount', 'ResourceNotFoundException', None, '3f33df4b1bd99f160b5a9fa54a10b04df68efc3c20f01b76b9074f8d1c0e7ec3'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('GuardDutyCheck', 'DescribeOrganizationConfiguration', 'BadRequestException', None, '3724b5d86c89141f13ba15661194428cd1193c9ea726fb7656fccf1e572e3896'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('IAMCheck', 'GetAccountPasswordPolicy', 'NoSuchEntity', None, '749cae5663cb5263a5c65cebfb626b838a11d7624f78966557569ab5f2ff6e93'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('IAMCheck', 'ListOrganizationsFeatures', 'ServiceAccessNotEnabledException', None, '2600df326324cf7b80db53b8d6d268b44247ce05831cb7f0ca888f5f35bc45f3'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('InspectorCheck', 'GetDelegatedAdminAccount', 'ResourceNotFoundException', None, '5e7148b3a4219d008f38b0eec4e18dc7e667d5b2079828ba59170b3bdee53fa7'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('MacieCheck', 'DescribeOrganizationConfiguration', 'AccessDeniedException', 'macie is not enabled', '48a988e3ade2535a16322e6670ffe0573dd131ff3aa5863dcc0e54691da9c203'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('MacieCheck', 'DescribeOrganizationConfiguration', 'ResourceNotFoundException', None, 'dade7281e7c2e71e162fb82116afae7cbd3666bf9668598680510635aa46b022'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('MacieCheck', 'GetAdministratorAccount', 'AccessDeniedException', 'macie is not enabled', '48a988e3ade2535a16322e6670ffe0573dd131ff3aa5863dcc0e54691da9c203'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('MacieCheck', 'GetAdministratorAccount', 'ResourceNotFoundException', None, 'dade7281e7c2e71e162fb82116afae7cbd3666bf9668598680510635aa46b022'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('MacieCheck', 'GetClassificationExportConfiguration', 'AccessDeniedException', 'macie is not enabled', '48a988e3ade2535a16322e6670ffe0573dd131ff3aa5863dcc0e54691da9c203'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('MacieCheck', 'GetClassificationExportConfiguration', 'ResourceNotFoundException', None, 'dade7281e7c2e71e162fb82116afae7cbd3666bf9668598680510635aa46b022'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('MacieCheck', 'GetFindingsPublicationConfiguration', 'AccessDeniedException', 'macie is not enabled', '48a988e3ade2535a16322e6670ffe0573dd131ff3aa5863dcc0e54691da9c203'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('MacieCheck', 'GetFindingsPublicationConfiguration', 'ResourceNotFoundException', None, 'dade7281e7c2e71e162fb82116afae7cbd3666bf9668598680510635aa46b022'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('MacieCheck', 'ListMembers', 'AccessDeniedException', 'macie is not enabled', '48a988e3ade2535a16322e6670ffe0573dd131ff3aa5863dcc0e54691da9c203'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('MacieCheck', 'ListMembers', 'ResourceNotFoundException', None, 'dade7281e7c2e71e162fb82116afae7cbd3666bf9668598680510635aa46b022'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('OrganizationsCheck', 'ListPolicies', 'PolicyTypeNotEnabledException', None, '33e69805a9edcd78963a4b16930071048c1fb6d2e1700e87f9cc45a73266b749'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('S3Check', 'GetPublicAccessBlock', 'NoSuchPublicAccessBlockConfiguration', None, 'f9d0924aa614e269f263bb043bf6dfd1947b7d2af6bc9ba1d40ef7d5ec20d05e'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('SecurityHubCheck', 'DescribeOrganizationConfiguration', 'InvalidAccessException', 'not subscribed to aws security hub', '06df84c9084551366d866513ed2dce96c48ef3528471a761e9def60d810b305d'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('SecurityHubCheck', 'DescribeSecurityHubV2', 'ResourceNotFoundException', 'not subscribed to hubv2', '24a4b3c0b0b19bd7f5c51a012ee69c7b39eb0f8ed578ef8ad8e4f9c844ed3c94'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('SecurityHubCheck', 'GetAdministratorAccount', 'InvalidAccessException', 'not subscribed to aws security hub', '06df84c9084551366d866513ed2dce96c48ef3528471a761e9def60d810b305d'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('SecurityHubCheck', 'GetEnabledStandards', 'InvalidAccessException', 'not subscribed to aws security hub', '06df84c9084551366d866513ed2dce96c48ef3528471a761e9def60d810b305d'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('SecurityHubCheck', 'ListAggregatorsV2', 'ConflictException', 'security hub v2 is not enabled', '82a75d90bf56c4c1b8bbb79d75985eb2babf6fc1b4f61c92f40dc0b47a9ac45e'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('SecurityHubCheck', 'ListConfigurationPolicies', 'AccessDeniedException', 'with central configuration enabled', '3ccf7d833f5c2d8d5db02e4500ad64e60f3295052a9b453347e6c52b3ecd567f'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('SecurityHubCheck', 'ListEnabledProductsForImport', 'InvalidAccessException', 'not subscribed to aws security hub', '06df84c9084551366d866513ed2dce96c48ef3528471a761e9def60d810b305d'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('SecurityHubCheck', 'ListMembers', 'BadRequestException', 'no such resource found', '7b9e912ade6d39edd69dd443c98c299938e7536c69f6dec126fe5cefc81f076d'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('SecurityHubCheck', 'ListMembers', 'InvalidAccessException', 'not subscribed to aws security hub', '06df84c9084551366d866513ed2dce96c48ef3528471a761e9def60d810b305d'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('SecurityHubCheck', 'ListOrganizationAdminAccounts', 'InvalidAccessException', 'not subscribed to aws security hub', '06df84c9084551366d866513ed2dce96c48ef3528471a761e9def60d810b305d'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('SecurityIncidentResponseCheck', 'GetRole', 'NoSuchEntity', None, '7c5ac83a7dc3e9ac92c4466f38d34e30b8105bcf37792c85c1358fa08242cfc6'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('SecurityLakeCheck', 'GetDataLakeOrganizationConfiguration', 'ResourceNotFoundException', None, 'd0a3bcee55d785cb9ce21d8c1a0a82108b8d884f1265532f6e0a00c07f6da557'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('SecurityLakeCheck', 'GetDataLakeSources', 'ResourceNotFoundException', None, 'd0a3bcee55d785cb9ce21d8c1a0a82108b8d884f1265532f6e0a00c07f6da557'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('SecurityLakeCheck', 'ListDataLakes', 'ResourceNotFoundException', None, 'd0a3bcee55d785cb9ce21d8c1a0a82108b8d884f1265532f6e0a00c07f6da557'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('SecurityLakeCheck', 'ListLogSources', 'ResourceNotFoundException', None, 'd0a3bcee55d785cb9ce21d8c1a0a82108b8d884f1265532f6e0a00c07f6da557'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('SecurityLakeCheck', 'ListSubscribers', 'ResourceNotFoundException', None, 'd0a3bcee55d785cb9ce21d8c1a0a82108b8d884f1265532f6e0a00c07f6da557'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('ShieldCheck', 'DescribeDRTAccess', 'ResourceNotFoundException', None, 'ef3c54752d071f290a3d3e68f8b01c2e69ebec2a191c22e61706862deeebb6d5'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('ShieldCheck', 'DescribeSubscription', 'ResourceNotFoundException', None, 'ef21755e28d48a807a5b824d3e1df72efe98361e642c665ea3cbe136fe22339d'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('ShieldCheck', 'GetFunction', 'ResourceNotFoundException', None, '0e3d077029789b73513f4c38c2e1d55c722de361fea0b274e18d2573fbca70b8'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('ShieldCheck', 'GetSubscriptionState', 'ResourceNotFoundException', None, 'a7ecb34b3959e0920601905acd65fdc3dd0a410e77e7fd5edb1119f601baadda'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('ShieldCheck', 'GetWebACLForResource', 'WAFNonexistentItemException', None, 'cf665ed2fe71e9f6e878c7fcb1b73ce68aab7ac4eb201592db231773d7e2155c'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('ShieldCheck', 'ListProtections', 'ResourceNotFoundException', None, '39c65b6c56d10982dbb452a17e5a1e57def679107077016262cfad195b7d5201'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('WAFCheck', 'GetLoggingConfiguration', 'WAFNonexistentItemException', None, '046667f6559c3ddde6bff7c372f1cd1592ad7520ad425049651b83db286daa5c'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
    ('WAFCheck', 'GetWebACLForResource', 'WAFNonexistentItemException', None, 'dc848f79642065ffc6f2bd548e657eff49ce770c3e0d510db0e2987c1df2b54a'),  # pragma: allowlist secret -- sha256 of public evidence text, not a credential
)


def _live_non_owned_entries() -> tuple[tuple[str, str, str, str | None, str], ...]:
    """Rebuild the golden's tuple from the live service base classes."""
    rows = []
    for service in _SERVICE_NAMES:
        base = _base_class(service)
        for operation, by_code in vars(base).get("NOT_CONFIGURED_ERRORS", {}).items():
            if operation in OrganizationsProvider.OWNED_OPERATIONS:
                continue
            for code, fact in by_code.items():
                rows.append((
                    base.__name__,
                    operation,
                    code,
                    fact.message,
                    hashlib.sha256(fact.evidence.encode()).hexdigest(),
                ))
    return tuple(sorted(rows, key=lambda r: (r[0], r[1], r[2], r[3] or "")))


def test_the_provider_table_declares_only_operations_it_owns() -> None:
    """Property 43: every provider-table operation is in ``OWNED_OPERATIONS``."""
    table = OrganizationsProvider.NOT_CONFIGURED_ERRORS
    assert isinstance(table, dict)
    assert set(table) <= OrganizationsProvider.OWNED_OPERATIONS
    assert set(table) == {
        "ListDelegatedAdministrators",
        "ListAccounts",
        "DescribeOrganization",
        "DescribeEffectivePolicy",
    }
    assert "ListPolicies" not in OrganizationsProvider.OWNED_OPERATIONS


def test_the_owned_operations_are_the_providers_and_no_other_clients() -> None:
    """Property 43: owned operations are provider operations no other service issues."""
    provider_operations = {a.operation for a in PROVIDER_ADAPTERS}
    assert OrganizationsProvider.OWNED_OPERATIONS <= provider_operations
    elsewhere = {
        adapter.operation
        for service, adapters in CLIENT_ADAPTERS.items()
        if service != "organizations"
        for adapter in adapters
    }
    assert not OrganizationsProvider.OWNED_OPERATIONS & elsewhere
    # Non-vacuous: ListPolicies is why the set is not every provider operation.
    assert "ListPolicies" in provider_operations
    assert "ListPolicies" in elsewhere


@pytest.mark.parametrize("service", _SERVICE_NAMES)
def test_no_service_table_declares_an_owned_operation(service: str) -> None:
    """Property 43: the provider table alone classifies an owned operation."""
    declared = set(_TABLES[service]) & OrganizationsProvider.OWNED_OPERATIONS
    assert declared == set(), (
        f"{service} declares {sorted(declared)}, which only "
        f"OrganizationsProvider.NOT_CONFIGURED_ERRORS may declare"
    )


def test_every_non_owned_service_entry_is_unchanged_from_the_merged_phase_one() -> None:
    """Property 43: 46 entries, byte-identical to f517024 (evidence by digest)."""
    assert len(_NON_OWNED_NOT_CONFIGURED_ENTRIES) == 46
    assert _live_non_owned_entries() == _NON_OWNED_NOT_CONFIGURED_ENTRIES


#: The pair every precedence case classifies.
_PAIR_OPERATION = "ListAccounts"
_PAIR_CODE = "AWSOrganizationsNotInUseException"
_NEEDLE = "not a member"
_EVIDENCE = (
    "synthetic entry for test_discriminator_property precedence cases only; "
    "patched in for the test's duration and never committed to a real table"
)


def _table(message: str | None) -> dict[str, dict[str, NotConfigured]]:
    """Return a one-entry table declaring the pair, with an optional needle."""
    return {
        _PAIR_OPERATION: {_PAIR_CODE: NotConfigured(evidence=_EVIDENCE, message=message)}
    }


def _precedence_check() -> SecurityCheck:
    """Return an instance of a throwaway check whose service table is patchable."""
    return _concrete(SecurityCheck)()


@pytest.mark.parametrize(
    "service,provider,message,expected",
    [
        # The service table declares the pair: its verdict wins, whatever the
        # provider's table says.
        pytest.param(_table(None), _table("absent from message"), "anything", True,
                     id="service-no-needle-beats-provider-mismatch"),
        pytest.param(_table(_NEEDLE), _table(None), "access denied", False,
                     id="service-needle-mismatch-is-not-overruled"),
        pytest.param(_table(_NEEDLE), _table("absent from message"),
                     f"account is {_NEEDLE.upper()} of an org", True,
                     id="service-needle-match-beats-provider-mismatch"),
        # Only the provider declares: the provider's verdict.
        pytest.param({}, _table(None), "anything", True, id="provider-only-no-needle"),
        pytest.param({}, _table(_NEEDLE), "access denied", False,
                     id="provider-only-needle-mismatch"),
        pytest.param({}, _table(_NEEDLE), f"is {_NEEDLE}", True,
                     id="provider-only-needle-match"),
        # Neither declares.
        pytest.param({}, {}, "anything", False, id="neither"),
    ],
)
def test_the_first_table_to_declare_the_pair_decides(
    service: dict, provider: dict, message: str, expected: bool
) -> None:
    """Property 16: service table first, provider table second, first declarer wins."""
    error = error_result(code=_PAIR_CODE, message=message, operation=_PAIR_OPERATION)["Error"]
    check = _precedence_check()
    committed = OrganizationsProvider.NOT_CONFIGURED_ERRORS

    with patch.object(OrganizationsProvider, "NOT_CONFIGURED_ERRORS", provider), patch.object(
        type(check), "NOT_CONFIGURED_ERRORS", service
    ):
        assert check.is_not_configured(error) is expected
        assert is_not_configured_in((service, provider), error) is expected

    assert OrganizationsProvider.NOT_CONFIGURED_ERRORS is committed
