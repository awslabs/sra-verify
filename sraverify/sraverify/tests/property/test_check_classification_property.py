"""
Properties 14, 14a, and 14b: what a check *does* with an error result.

The other modules hold the plumbing -- clients return the right shape, accessors
refuse to cache a failure, the discriminator is conservative. This one holds the
thing a consumer of the report actually experiences: when the scanner could not
evaluate a control, the row says ERROR.

**Property 14 is catalog-wide, over all 158 checks, by reflection.** Not a
sample. The first draft of the design proposed one check per batch, which cannot
establish Requirement 4.1 for the catalog -- and the catalog is where the defect
lives: 100 erasing handlers feed 158 checks, and which branch a given check lands
on depends on its own control flow, not on its client's. It also needs no
consumer manifest: patch every accessor on the check's service base to return a
error_result, run ``execute()``, and the check's own branching does the rest.

**Property 14a** is the other direction: a *declared semantic* error result must
reach ``failed()``. Without it, a check could satisfy Property 14 by yielding
ERROR unconditionally and the discriminator would be dead code.

**Property 14b** covers the availability guard: in a Region the service does not
serve, a check yields no row and issues no call.

Validates: Requirements 4.1, 4.2, 4.3, 4.8, 4.9, 4.12, 5.5, 5.6, 7.5a.
"""
from __future__ import annotations

import re
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from sraverify.core.aws_errors import NotConfigured, error_result
from sraverify.core.check import SecurityCheck
from sraverify.core.enums import Status
from sraverify.core.finding import Finding
from sraverify.core.registry import all_checks
from sraverify.core.scan_context import ScanContext
from sraverify.tests.property.test_accessor_cache_property import (
    _ADAPTERS,
    _global_client_attributes,
)
from sraverify.tests.property.test_client_contract_property import (
    ADAPTERS as _CLIENT_ADAPTERS,
)

_TEST_REGION = "us-east-1"
_TEST_ACCOUNT = "111122223333"
_AUDIT_ACCOUNT = "222233334444"
_LOG_ARCHIVE_ACCOUNT = "444455556666"

#: The code the harness makes every accessor return. Chosen so no discriminator
#: table declares it, which is what makes the expected verdict ERROR.
_DENIED_CODE = "TestDenied"

#: Requirement 4.8's shape for an ERROR row built from an error result:
#: ``{Operation} failed: {Code}: {Message}``. This is what lets a reader tell a
#: permission gap from an unreachable endpoint without opening the build log.
_ERROR_VALUE_RE = re.compile(rf"^\S+ failed: {_DENIED_CODE}: ")

#: ``(check_id, cls)`` for the real catalog, ascending. Snapshotted at import.
_CATALOG: list[tuple[str, type[SecurityCheck]]] = sorted(all_checks().items())


def _service_of(cls: type[SecurityCheck]) -> str:
    """Return the service package name from a check class's module path.

    ``cls.__module__`` is ``sraverify.services.<svc>.checks.sra_<svc>_NN``, and
    ``__init_subclass__`` has already cross-checked that the segment agrees with
    the file stem -- so this is reliable rather than a guess.

    Args:
        cls: A registered check class.

    Returns:
        The service directory name.
    """
    return cls.__module__.split(".")[-3]


def _accessor_names(service: str) -> tuple[str, ...]:
    """Return the ``accessor``-kind method names for a service.

    Read from the accessor module's adapter tables, which Property 3a proves
    complete and exact against the real base classes. Reusing them here rather
    than re-deriving means the two modules cannot disagree about what an accessor
    is -- and the classification already distinguishes an accessor from a derived
    value, a pure helper, and a client lookup, which a source-text rule cannot.

    Args:
        service: A service package name.

    Returns:
        The names of every method that hands a check a value it must test for
        ``"Error"``. That is broader than the ``accessor`` kind: it includes the
        uncached accessors, and it includes ``securityincidentresponse``'s six
        public methods, which are classified ``derived`` for caching purposes -- they
        route through ``_sir_client`` rather than ``self._clients`` -- but still
        return the client's dict straight to a check. It excludes the derived
        *predicates* that return a ``bool`` by design, because feeding one a
        error result would simulate something that cannot happen.
    """
    return tuple(
        adapter.method
        for adapter in _ADAPTERS.get(service, ())
        if adapter.bears_error()
    )


def _make_context() -> MagicMock:
    """Return a mock ``ScanContext`` warm enough for ``execute()`` to run.

    Both account lists are non-empty on purpose. Six checks used to report an
    absent ``--audit-account`` as FAIL, and a harness that left the lists empty
    would drive those checks down their missing-input branch instead of down the
    error result branch this property is about -- and would then "fail" for the wrong
    reason.

    Returns:
        The mock context.
    """
    ctx = MagicMock(spec=ScanContext)
    ctx.regions = [_TEST_REGION]
    ctx.audit_accounts = [_AUDIT_ACCOUNT]
    ctx.log_archive_accounts = [_LOG_ARCHIVE_ACCOUNT]
    ctx.get_account_info.return_value = {
        "account_id": _TEST_ACCOUNT,
        "account_name": "probe-account",
    }
    ctx.get_management_account_id.return_value = _TEST_ACCOUNT
    ctx.get_enabled_regions.return_value = [_TEST_REGION]
    ctx._has.return_value = False
    ctx._get.return_value = None
    return ctx


def _prepare(
    cls: type[SecurityCheck], *, returns: Any = None, record: list[str] | None = None
) -> tuple[SecurityCheck, list[Any]]:
    """Build a check whose every accessor is patched, and return the patchers.

    ``_setup_clients`` is bypassed: the accessors are patched wholesale, so no
    client wrapper is needed and constructing real ones would reach for a session.

    Args:
        cls: The check class.
        returns: What each patched accessor returns. Defaults to a non-semantic
            error result naming the accessor as its operation.
        record: When given, each accessor call appends its name here.

    Returns:
        ``(check, patchers)``. The caller stops the patchers.
    """
    service = _service_of(cls)
    check = cls()
    check._ctx = _make_context()

    # A global service's base pins its client on a named attribute; give it
    # something non-None so a truthiness guard does not divert control flow before
    # the patched accessor is reached.
    for attribute in _global_client_attributes(cls):
        setattr(check, attribute, MagicMock(name=attribute))
    check._clients[_TEST_REGION] = MagicMock(name=f"{service}Client")

    patchers: list[Any] = []
    for name in _accessor_names(service):
        if not hasattr(cls, name):
            continue

        def _make(accessor_name: str) -> Any:
            def _stub(*args: Any, **kwargs: Any) -> Any:
                if record is not None:
                    record.append(accessor_name)
                if returns is not None:
                    return returns
                return error_result(
                    code=_DENIED_CODE,
                    message="simulated denial for the classification property",
                    operation=accessor_name,
                )

            return _stub

        patcher = patch.object(cls, name, _make(name))
        patcher.start()
        patchers.append(patcher)

    return check, patchers


def _catalog_params(property_key: str) -> list[Any]:
    """Return parametrize values over the catalog, one per registered check.

    ``property_key`` is retained and unused; see the note on
    ``test_accessor_cache_property._params``. All 158 checks are asserted
    unconditionally against all three properties.

    Args:
        property_key: Which property this parametrization drives. Unused.

    Returns:
        ``pytest.param`` values, one per registered check.
    """
    return [pytest.param(check_id, cls, id=check_id) for check_id, cls in _CATALOG]


# --------------------------------------------------------------------------- #
# Non-vacuity
# --------------------------------------------------------------------------- #


def test_the_catalog_is_complete() -> None:
    """158 checks, so this is quantifying over the real thing."""
    assert len(_CATALOG) >= 150, (
        f"the registry holds {len(_CATALOG)} checks; Property 14 is catalog-wide "
        f"and something has emptied or truncated it"
    )


def test_every_check_belongs_to_a_service_with_a_known_accessor_set() -> None:
    """Every check's service has an adapter table, so nothing is silently skipped.

    Without this, a check whose service was missing from ``_ADAPTERS`` would have
    zero accessors patched, ``execute()`` would run against ``MagicMock``
    attributes, and the property would pass having tested nothing.
    """
    missing = sorted(
        {
            _service_of(cls)
            for _, cls in _CATALOG
            if _service_of(cls) not in _ADAPTERS
        }
    )
    assert missing == [], (
        f"these services have registered checks but no accessor adapter table: "
        f"{missing}"
    )


@pytest.mark.parametrize(
    "check_id,cls", _CATALOG, ids=[check_id for check_id, _ in _CATALOG]
)
def test_every_check_has_at_least_one_accessor_to_patch(
    check_id: str, cls: type[SecurityCheck]
) -> None:
    """A check whose service exposes no accessor cannot be driven by Property 14.

    Reported rather than assumed: if a service legitimately had none, Property 14
    would pass vacuously for all of its checks and nobody would know.
    """
    accessors = _accessor_names(_service_of(cls))
    assert accessors, (
        f"{check_id}: service {_service_of(cls)!r} declares no accessor adapters, "
        f"so Property 14 cannot drive this check"
    )


# --------------------------------------------------------------------------- #
# Property 14 -- only ERROR when nothing can be evaluated
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("check_id,cls", _catalog_params("property_14"), ids=None)
def test_a_check_yields_only_error_when_every_accessor_fails(
    check_id: str, cls: type[SecurityCheck]
) -> None:
    """Property 14: no PASS, no FAIL, at least one row, each naming the failure.

    The behavioural form of Requirement 4.1, and the property that would have
    caught all 120 wrong rows in the baseline. Every accessor returns a
    non-semantic error_result, so nothing about any control has been established --
    and therefore every row must be an ERROR that says which operation failed and
    with what code.

    A FAIL here is the defect this whole feature exists to remove: the check
    landed on a branch written for "no data" and published an undetermined state
    as an established negative. A PASS is worse.
    """
    check, patchers = _prepare(cls)
    try:
        findings = list(check.execute())
    finally:
        for patcher in patchers:
            patcher.stop()

    assert findings, (
        f"{check_id} yielded no rows at all when every accessor failed. The "
        f"scanner ran the check and produced nothing, so the report is silent "
        f"about a control it could not evaluate."
    )

    wrong = [
        f"{finding.status.value}: {finding.actual_value[:90]!r}"
        for finding in findings
        if finding.status is not Status.ERROR
    ]
    assert wrong == [], (
        f"{check_id} yielded a non-ERROR row when every accessor failed:\n  "
        + "\n  ".join(wrong)
        + "\nNothing was established about this control, so every row must be an "
        "ERROR."
    )

    unnamed = [
        finding.actual_value[:90]
        for finding in findings
        if not _ERROR_VALUE_RE.match(finding.actual_value)
    ]
    assert unnamed == [], (
        f"{check_id} yielded an ERROR row whose ActualValue does not name the "
        f"failed operation and code (Requirement 4.8):\n  "
        + "\n  ".join(repr(v) for v in unnamed)
        + f"\nExpected the shape {_ERROR_VALUE_RE.pattern!r}."
    )


@pytest.mark.parametrize(
    "check_id,cls", _catalog_params("property_14_remediation"), ids=None
)
def test_every_error_row_carries_scan_environment_remediation(
    check_id: str, cls: type[SecurityCheck]
) -> None:
    """An ERROR row's remediation addresses the scan, not the control.

    ``error()`` already refuses a blank remediation, so the interesting failure is
    the *wrong* one: falling back to ``meta.remediation.text``, which is the advice
    for a FAIL. "Enable GuardDuty in every enabled Region" against an
    ``AccessDeniedException`` is confidently wrong, and confidently wrong is worse
    than vague.
    """
    check, patchers = _prepare(cls)
    try:
        findings = list(check.execute())
    finally:
        for patcher in patchers:
            patcher.stop()

    control_advice = cls.meta.remediation.text
    offenders = [
        finding.remediation[:90]
        for finding in findings
        if finding.status is Status.ERROR and finding.remediation == control_advice
    ]

    assert offenders == [], (
        f"{check_id} gave an ERROR row the control-level remediation "
        f"{control_advice[:60]!r}. An ERROR means the control was not evaluated, "
        f"so the remediation should address the scan environment -- pass "
        f"self._remediation_for(error)."
    )


@pytest.mark.parametrize(
    "check_id,cls", _catalog_params("property_14_no_raise"), ids=None
)
def test_no_check_raises_when_every_accessor_fails(
    check_id: str, cls: type[SecurityCheck]
) -> None:
    """Requirement 2.5: an error result must not become a synthetic ERROR row.

    If ``execute()`` raises here, the orchestrator would convert the whole check
    into one synthetic row -- discarding every row it had already yielded for
    other Regions. After this feature a synthetic row means a programming defect,
    so it must not be reachable by feeding a check the error result its accessors are
    contracted to return.

    Separated from Property 14 so the two failure modes are distinguishable in the
    report: "yielded a FAIL" and "raised a KeyError" need different fixes.
    """
    check, patchers = _prepare(cls)
    try:
        list(check.execute())
    except Exception as exc:  # noqa: BLE001 - the failure is the point
        pytest.fail(
            f"{check_id} raised {type(exc).__name__}: {exc} when every accessor "
            f"returned an error result. The orchestrator would turn this into one "
            f"synthetic ERROR row and discard the check's other rows."
        )
    finally:
        for patcher in patchers:
            patcher.stop()


# --------------------------------------------------------------------------- #
# Property 14a -- a declared semantic error result reaches failed()
# --------------------------------------------------------------------------- #


#: accessor method name -> the botocore operation it ultimately issues.
#:
#: Joined from the two adapter tables: the accessor table names the client method
#: each accessor delegates to, and the client-contract table names the operation
#: each client method issues. Property 3a proves both tables complete and exact
#: against the real classes, so this join is derived from the tree rather than
#: asserted about it.
#:
#: ``securityincidentresponse``'s six public methods are classified ``derived``
#: and declare no ``client_method``, because they route through a private helper
#: rather than through ``self._clients`` -- but their names are the client method
#: names, so ``client_method or method`` resolves them.
_OPERATION_OF_ACCESSOR: dict[tuple[str, str], str] = {
    (service, accessor.method): client.operation
    for service, accessors in _ADAPTERS.items()
    for accessor in accessors
    for client in _CLIENT_ADAPTERS.get(service, ())
    if (accessor.client_method or accessor.method) == client.method
}


def _semantic_targets() -> list[Any]:
    """Return one param per (check, declared pair) over the whole catalog.

    Every declared pair, not just the service's first. The earlier version took
    ``next(iter(table.items()))``, which meant a service declaring four pairs had
    three of them untested -- ``shield`` declares ``GetSubscriptionState``,
    ``GetFunction`` and ``GetWebACLForResource`` alongside
    ``DescribeSubscription``, and only the first was ever exercised.

    Returns:
        ``pytest.param`` values of ``(check_id, cls, operation, code, fact)``.
    """
    out = []
    for check_id, cls in _CATALOG:
        for operation, by_code in cls.NOT_CONFIGURED_ERRORS.items():
            for code, fact in by_code.items():
                out.append(
                    pytest.param(
                        check_id,
                        cls,
                        operation,
                        code,
                        fact,
                        id=f"{check_id}-{operation}-{code}",
                    )
                )
    return out


@pytest.mark.parametrize(
    "check_id,cls,operation,code,fact",
    _semantic_targets() or [pytest.param(None, None, None, None, None, id="no-tables-yet")],
)
def test_a_declared_semantic_error_result_reaches_failed(
    check_id: str | None,
    cls: type[SecurityCheck] | None,
    operation: str | None,
    code: str | None,
    fact: NotConfigured | None,
) -> None:
    """Property 14a: the discriminator's ``True`` actually changes the verdict.

    Without this, a check could satisfy Property 14 by yielding ERROR
    unconditionally, and the whole discriminator table would be dead code that
    reads as protection.

    Asserts only that a FAIL is reached and that nothing PASSes -- not the FAIL's
    wording, which is a per-check judgement and is reviewed against a live scan
    rather than pinned here.

    **Skipped where the check's verdict is settled before the declared operation
    is reached.** The harness makes *every* accessor return the error result, so a
    check whose first accessor issues a different operation resolves at that first
    branch and returns -- and its handling of the declared pair is simply not
    observable this way. ``SRA-WAF-02`` is the clearest case: it calls
    ``DescribeLoadBalancers`` to enumerate load balancers, then
    ``GetWebACLForResource`` per load balancer. With the enumeration failing there
    are no load balancers to loop over, so the per-resource FAIL branch cannot be
    reached no matter how the check is written.

    The skip is narrow on purpose: it fires only when the *first* accessor the
    check consults does not issue the declared operation, which is a structural
    fact about the check read from the two adapter tables, not a judgement.

    **What the skip costs, stated plainly.** Twelve of the eighteen declared pairs
    are reached only *after* a successful enumeration -- ``GetTrailStatus`` per
    trail, ``GetWebACLForResource`` per protected resource,
    ``GetLoggingConfiguration`` per Web ACL -- so no check has one of them as its
    first operation and this property does not observe them. Reaching them would
    mean feeding every *other* accessor a plausible success, which needs a success
    shape per **accessor** rather than per client method: the two differ wherever a
    base class reshapes a response, as ``ShieldCheck.get_cloudwatch_alarms_for_resource``
    turns ``MetricAlarms`` into ``DDoSDetectedAlarms``. That table does not exist,
    and inventing it would put the harness's fixtures in the position of deciding
    what a check sees.

    What the skip must **not** become is a way to make the property vacuous by
    dropping a FAIL arm. Do not add one to a check whose no-resources-found case is
    a PASS -- ``waf``, and ``SRA-FIREWALLMANAGER-08``/``-09``/``-10`` -- because
    there a FAIL arm would contradict the check's own verdict on a successful empty
    response.
    """
    if check_id is None:
        pytest.skip("no service declares a discriminator table yet")

    service = _service_of(cls)
    result = error_result(
        code=code,
        message=fact.message or "the control is not configured",
        operation=operation,
    )

    calls: list[str] = []
    check, patchers = _prepare(cls, returns=result, record=calls)
    try:
        findings = list(check.execute())
    finally:
        for patcher in patchers:
            patcher.stop()

    if not calls:
        pytest.skip(f"{check_id} consulted no accessor for this error result")

    first_operation = _OPERATION_OF_ACCESSOR.get((service, calls[0]))
    if first_operation != operation:
        pytest.skip(
            f"{check_id} resolves on {calls[0]} ({first_operation or 'unmapped'}) "
            f"before reaching {operation}; the pair is not observable from this "
            f"check with every accessor failing"
        )

    if not findings:
        pytest.skip(f"{check_id} yields no row for this operation's error result")

    passed = [f.actual_value[:80] for f in findings if f.status is Status.PASS]
    assert passed == [], (
        f"{check_id} PASSed on a semantic error result: {passed}. A declared "
        f"'not configured' code means AWS reported the control absent."
    )
    assert any(f.status is Status.FAIL for f in findings), (
        f"{check_id} never reached failed() for the declared semantic pair "
        f"{operation}/{code}; every row was "
        f"{sorted({f.status.value for f in findings})}. The discriminator's True "
        f"is not changing the verdict."
    )


# --------------------------------------------------------------------------- #
# Property 14b -- an unsupported Region yields no row and no call
# --------------------------------------------------------------------------- #


def _availability_guarded_checks() -> list[Any]:
    """Return checks whose module consults the availability lookup.

    Returns:
        ``pytest.param`` values, one per guarded check.
    """
    import inspect as _inspect
    from pathlib import Path

    out = []
    for check_id, cls in _CATALOG:
        module = __import__(cls.__module__, fromlist=["*"])
        try:
            source = Path(_inspect.getfile(module)).read_text(encoding="utf-8")
        except OSError:  # pragma: no cover
            continue
        if (
            "service_available_in_region" in source
            or "region_supports_service" in source
        ):
            out.append(pytest.param(check_id, cls, id=check_id))
    return out


@pytest.mark.parametrize(
    "check_id,cls",
    _availability_guarded_checks() or [pytest.param(None, None, id="no-guards-yet")],
)
def test_an_unsupported_region_yields_no_row_and_issues_no_call(
    check_id: str | None, cls: type[SecurityCheck] | None
) -> None:
    """Property 14b: silence, and no wasted call.

    Both halves. No row, because the absence of a service in a Region is not a
    finding and the ERROR column should carry only conditions worth acting on. And
    no call, because the guard exists precisely to avoid an AWS call whose result
    cannot change the outcome -- and because a call to a Region with no endpoint
    costs 30 seconds or more against the bounded retry config before it fails.
    """
    if check_id is None:
        pytest.skip("no check consults the availability lookup yet")

    called: list[str] = []
    check, patchers = _prepare(cls, record=called)

    # Patch both spellings: the shared core function and the WAF delegate that
    # Batch 6 removes.
    with patch(
        "sraverify.core.availability.service_available_in_region", return_value=False
    ), patch.object(
        type(check), "region_supports_service", lambda self, s, r: False, create=True
    ):
        # Also patch the name as imported into the check's own module namespace,
        # since `from ... import service_available_in_region` binds a local alias.
        module = __import__(cls.__module__, fromlist=["*"])
        had_alias = hasattr(module, "service_available_in_region")
        if had_alias:
            original = module.service_available_in_region
            module.service_available_in_region = lambda s, r: False
        try:
            findings = list(check.execute())
        finally:
            if had_alias:
                module.service_available_in_region = original
            for patcher in patchers:
                patcher.stop()

    assert findings == [], (
        f"{check_id} yielded {len(findings)} row(s) for a Region its service does "
        f"not serve: "
        f"{[(f.region, f.status.value, f.actual_value[:50]) for f in findings]}"
    )
    assert called == [], (
        f"{check_id} called {sorted(set(called))} in a Region its service does not "
        f"serve; the availability guard belongs ahead of the call"
    )
