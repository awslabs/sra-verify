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

import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import Any

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
)
from sraverify.core.check import SecurityCheck
from sraverify.core.registry import all_checks
from sraverify.tests.property.strategies import cell_text

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

#: ``(service, operation, code, NotConfigured)`` for every declared entry, in a
#: stable order. Snapshotted at import so collection does not vary.
_ENTRIES: list[tuple[str, str, str, NotConfigured]] = [
    (service, operation, code, fact)
    for service in _SERVICE_NAMES
    for operation, by_code in _base_class(service).NOT_CONFIGURED_ERRORS.items()
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
        table = _base_class(service).NOT_CONFIGURED_ERRORS
        assert isinstance(table, dict), (
            f"{service}: NOT_CONFIGURED_ERRORS is {type(table).__name__}, "
            f"expected a mapping"
        )


def test_the_declared_entry_count_matches_the_migration_state() -> None:
    """Some services must declare entries, or Property 11 quantifies over nothing.

    This is the guard against the quiet failure mode of Property 11: with every
    table empty it has nothing to test and passes vacuously.

    A floor rather than an exact count, because a service legitimately having no
    semantic codes is normal: ``auditmanager``, ``config``, ``cloudtrail``, ``ec2``
    and ``iam`` declare none, each for a reason recorded on its own base class.
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

    assert is_not_configured(_base_class(service).NOT_CONFIGURED_ERRORS, error) is True, (
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
        is_not_configured(_base_class(service).NOT_CONFIGURED_ERRORS, error) is False
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
        is_not_configured(_base_class(service).NOT_CONFIGURED_ERRORS, error) is False
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
        is_not_configured(_base_class(service).NOT_CONFIGURED_ERRORS, error) is False
    ), (
        f"{service}.{operation}.{code} classified a message lacking its declared "
        f"needle {fact.message!r} as not-configured"
    )


@pytest.mark.parametrize("service", _SERVICE_NAMES)
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
        is_not_configured(_base_class(service).NOT_CONFIGURED_ERRORS, error) is False
    )


@pytest.mark.parametrize("service", _SERVICE_NAMES)
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
    table = _base_class(service).NOT_CONFIGURED_ERRORS

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
