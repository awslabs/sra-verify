"""
The Organizations provider: ``ctx.organization`` and ``self.organization``.

Six service base classes need every account in the organization. On ``main`` they
carried their own copies of ``organizations:ListAccounts``: three regional copies
(Macie, Security Hub, Security Lake) that keyed their cache slot on the Region and
so issued the same organization-wide sweep once per Region, one copy that was
never cached (Security Incident Response), and one that read the first page only
(Inspector, so an organization of more than 20 accounts was silently truncated).
:class:`OrganizationsProvider` replaced all of them. It is reached through the
scan context rather than inherited, so no service base carries an Organizations
accessor at all.

This module holds the provider's contract:

* every page is merged, whichever service's check asks;
* one sweep serves the whole (sequential) scan, across services and Regions, on the one
  Organizations client the scan derives;
* a failure is returned unchanged, never cached, and re-issued on retry;
* the Security Lake log-source primer reads the provider, seeds nothing on a
  failure, and issues no second sweep on the guarded path;
* the provider's public surface is exactly ``accounts()``, its log records have a
  fixed shape, and it is freed by refcount the moment its context is.

It also exports :data:`PROVIDER_ADAPTERS` and :func:`stub_organization`, the
single table and stub the catalog-wide harnesses patch the provider from, so an
accessor added to the provider later is stubbed everywhere or fails a named test.

A real ``ScanContext`` is used, over a mock session, so the cache being shared is
the real two-level cache rather than a stand-in for it.
"""
from __future__ import annotations

import ast
import gc
import inspect
import logging
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

import sraverify.core.organization as organization_module
from sraverify.core.aws_errors import error_result, is_error
from sraverify.core.organization import ACCOUNTS_KEY, NAMESPACE, OrganizationsProvider
from sraverify.core.organizations_client import OrganizationsClient, scan_region
from sraverify.core.scan_context import ScanContext
from sraverify.services.inspector.base import InspectorCheck
from sraverify.services.macie.base import MacieCheck
from sraverify.services.organizations.base import OrganizationsCheck
from sraverify.services.securityhub.base import SecurityHubCheck
from sraverify.services.securityincidentresponse.base import (
    SecurityIncidentResponseCheck,
)
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.tests.property.test_accessor_cache_property import _concrete

_REGIONS = ["us-east-1", "us-west-2", "eu-central-1"]

#: The six bases whose checks read organization accounts.
_BASES: tuple[type, ...] = (
    InspectorCheck,
    MacieCheck,
    OrganizationsCheck,
    SecurityHubCheck,
    SecurityIncidentResponseCheck,
    SecurityLakeCheck,
)

_PAGES = (
    {"Accounts": [{"Id": f"1111222233{n:02d}", "Status": "ACTIVE"} for n in range(20)]},
    {"Accounts": [{"Id": "999988887777", "Status": "ACTIVE"}]},
)

_ORG_IDS = [a["Id"] for page in _PAGES for a in page["Accounts"]]


# --------------------------------------------------------------------------- #
# The adapter table and the shared stub (Property 26)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ProviderAdapter:
    """One public provider accessor and the operation its failure names."""

    method: str
    operation: str
    args: tuple = ()


#: Every public accessor on :class:`OrganizationsProvider`. Prescriptive, like the
#: client and accessor adapter tables: an accessor missing here fails
#: :func:`test_the_provider_adapter_table_is_complete_and_exact`, so the catalog
#: harnesses cannot run one unpatched.
PROVIDER_ADAPTERS: tuple[ProviderAdapter, ...] = (ProviderAdapter("accounts", "ListAccounts"),)


def test_the_provider_adapter_table_is_complete_and_exact() -> None:
    """The table names exactly the provider's public methods."""
    public = {
        n
        for n, o in vars(OrganizationsProvider).items()
        if not n.startswith("_") and inspect.isfunction(o)
    }
    assert public == {a.method for a in PROVIDER_ADAPTERS}


def stub_organization(
    ctx: MagicMock, *, returns: Any = None, record: list[str] | None = None
) -> MagicMock:
    """Replace ``ctx.organization`` on a mock context with a stubbed provider.

    Without it, a ``MagicMock(spec=ScanContext)`` answers ``ctx.organization``
    with an auto-specced mock whose ``accounts()`` returns a truthy, iterable,
    non-error ``MagicMock`` -- the "empty success" a harness simulating failure
    exists to rule out.

    Args:
        ctx: A mock ``ScanContext``.
        returns: What every provider accessor returns. Defaults to a non-semantic
            error result naming the accessor's operation.
        record: When given, each call appends ``organization.<method>`` here.

    Returns:
        The stub provider, also assigned to ``ctx.organization``.
    """
    provider = MagicMock(name="OrganizationsProvider", spec=OrganizationsProvider)
    for adapter in PROVIDER_ADAPTERS:

        def _stub(*a: Any, _adapter: ProviderAdapter = adapter, **k: Any) -> Any:
            if record is not None:
                record.append(f"organization.{_adapter.method}")
            if returns is not None:
                return returns
            return error_result(
                code="TestDenied",
                message="simulated denial for the classification property",
                operation=_adapter.operation,
            )

        getattr(provider, adapter.method).side_effect = _stub
    ctx.organization = provider
    return provider


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #


class _Session:
    """A stand-in ``boto3.Session`` handing out one mock client per key.

    Distinct mocks per ``(service, region)`` let a test count calls on the one
    client the provider should use, without the per-Region wrappers built by
    ``_setup_clients`` muddying the count.
    """

    def __init__(self, region_name: Any = None) -> None:
        self.region_name = region_name
        self.clients: dict[tuple[str, Any], MagicMock] = {}

    def client(self, service_name: str, region_name: Any = None, config: Any = None) -> MagicMock:
        """Return the mock for ``(service_name, region_name)``, creating it once."""
        key = (service_name, region_name)
        if key not in self.clients:
            self.clients[key] = MagicMock(name=f"{service_name}@{region_name}")
        return self.clients[key]

    def org(self) -> MagicMock:
        """Return the Organizations mock for the Region the scan derives."""
        return self.client("organizations", _REGIONS[0])


def _arm_pages(org: MagicMock, *pages: dict) -> None:
    """Make ``get_paginator('list_accounts').paginate()`` yield ``pages``."""
    org.get_paginator.return_value.paginate.side_effect = lambda **_: iter(pages)


def _client_error() -> ClientError:
    """A denied ``ListAccounts``, as AWS would answer it."""
    return ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "not allowed"}},
        "ListAccounts",
    )


def _transport_error() -> EndpointConnectionError:
    """A request that never completed."""
    return EndpointConnectionError(endpoint_url="https://organizations.example")


#: ``(exception factory, expected Operation, expected Code)``.
_FAILURES = (
    pytest.param(_client_error, "ListAccounts", "AccessDeniedException", id="ClientError"),
    pytest.param(_transport_error, "Request", "EndpointConnectionError", id="BotoCoreError"),
)


def _arm_failure(org: MagicMock, make: Any = _client_error) -> None:
    """Make the sweep fail on its first page."""
    org.get_paginator.return_value.paginate.side_effect = make()


def _sweeps(org: MagicMock) -> int:
    """Return how many ``ListAccounts`` sweeps were started."""
    return org.get_paginator.return_value.paginate.call_count


def _scan() -> tuple[ScanContext, _Session]:
    """Return a real per-scan context over a mock session."""
    session = _Session()
    return ScanContext(session=session, regions=list(_REGIONS)), session  # type: ignore[arg-type]


def _check(base: type, ctx: ScanContext) -> Any:
    """Return an initialized throwaway check built on ``base``."""
    check = _concrete(base)()
    check.initialize(ctx)
    return check


def _stub_account(ctx: ScanContext, account_id: str) -> None:
    """Answer ``get_account_info`` without STS, on this context only."""
    info = {"account_id": account_id, "account_name": "probe"}
    ctx.get_account_info = lambda: info  # type: ignore[method-assign]


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    """Capture records from the ``sraverify`` logger at ``DEBUG``.

    ``caplog`` is not used: the suite runs with ``-p no:logging``, and the
    library's records are emitted at ``debug``.
    """
    captured: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    handler = _Collector()
    target = logging.getLogger("sraverify")
    previous = target.level
    target.setLevel(logging.DEBUG)
    target.addHandler(handler)
    try:
        yield captured
    finally:
        target.removeHandler(handler)
        target.setLevel(previous)


def _messages(captured: list[logging.LogRecord], needle: str) -> list[logging.LogRecord]:
    """Return the records whose message contains ``needle``."""
    return [r for r in captured if needle in r.getMessage()]


# --------------------------------------------------------------------------- #
# Every page, one sweep (Properties 1 and 2)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("base", _BASES, ids=lambda b: b.__name__)
def test_every_page_is_merged(base: type) -> None:
    """21 accounts over two pages arrive as 21, whichever service's check asks.

    Inspector's former copy read one page, so account 21 was invisible to
    SRA-INSPECTOR-07.
    """
    ctx, session = _scan()
    _arm_pages(session.org(), *_PAGES)

    result = _check(base, ctx).organization.accounts()

    assert not is_error(result)
    assert [a["Id"] for a in result["Accounts"]] == _ORG_IDS
    session.org().get_paginator.assert_called_with("list_accounts")


def test_one_sweep_serves_every_service_and_region_in_the_scan() -> None:
    """Six services asking in three Regions cost one ``ListAccounts`` sweep.

    Sequential execution, as ``run_checks`` runs: the cache is not single-flight,
    so concurrent first callers could each sweep (per-key in-flight coordination
    is Phase 2). On ``main`` the regional copies keyed their slot on the Region,
    so this loop issued several regional sweeps plus one per uncached call.
    """
    ctx, session = _scan()
    _arm_pages(session.org(), *_PAGES)

    results = [
        _check(base, ctx).organization.accounts()
        for _ in _REGIONS
        for base in _BASES
    ]

    assert _sweeps(session.org()) == 1
    assert all(result is results[0] for result in results)
    assert ctx._get(NAMESPACE, ACCOUNTS_KEY) is results[0]

    derived = scan_region(ctx)
    assert derived == _REGIONS[0]
    for key, client in session.clients.items():
        if key[0] == "organizations" and key[1] != derived:
            client.get_paginator.assert_not_called()
            client.list_accounts.assert_not_called()


def test_a_value_cached_through_one_base_is_what_another_bases_check_reads() -> None:
    """The slot is the one ``OrganizationsCheck``'s namespace names."""
    ctx, session = _scan()
    _arm_pages(session.org(), *_PAGES)

    first = _check(SecurityLakeCheck, ctx).organization.accounts()
    second = _check(OrganizationsCheck, ctx).organization.accounts()

    assert second is first
    assert ctx._get(NAMESPACE, ACCOUNTS_KEY) is first
    assert _sweeps(session.org()) == 1
    assert NAMESPACE == OrganizationsCheck.NAMESPACE


# --------------------------------------------------------------------------- #
# Never cache a failure (Property 3)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("make,operation,code", _FAILURES)
@pytest.mark.parametrize("base", _BASES, ids=lambda b: b.__name__)
def test_a_failure_is_returned_unchanged_and_not_cached(
    base: type, make: Any, operation: str, code: str
) -> None:
    """The error result names the operation, and the slot stays empty."""
    ctx, session = _scan()
    _arm_failure(session.org(), make)

    result = _check(base, ctx).organization.accounts()

    assert is_error(result)
    assert result["Error"]["Operation"] == operation
    assert result["Error"]["Code"] == code
    assert not ctx._has(NAMESPACE, ACCOUNTS_KEY)


@pytest.mark.parametrize("make,operation,code", _FAILURES)
def test_a_failure_is_re_issued_and_a_later_success_is_cached(
    make: Any, operation: str, code: str
) -> None:
    """Six services after one failure: each retries until one succeeds, then none.

    The slot is shared by six services, so a cached failure would be replayed to
    every later check in the scan.
    """
    ctx, session = _scan()
    org = session.org()
    _arm_failure(org, make)

    for base in _BASES:
        result = _check(base, ctx).organization.accounts()
        assert is_error(result)
        assert result["Error"]["Operation"] == operation
    assert _sweeps(org) == len(_BASES)

    _arm_pages(org, *_PAGES)
    after = [_check(base, ctx).organization.accounts() for base in _BASES]

    assert _sweeps(org) == len(_BASES) + 1
    assert all(not is_error(r) and r is after[0] for r in after)


# --------------------------------------------------------------------------- #
# The Security Lake primer (Properties 19, 20 and 21)
# --------------------------------------------------------------------------- #


def _arm_log_sources(session: _Session, member: str) -> MagicMock:
    """Make ``ListLogSources`` in us-east-1 return one ROUTE53 entry for ``member``."""
    lake = session.client("securitylake", "us-east-1")
    lake.list_log_sources.return_value = {
        "sources": [
            {
                "account": member,
                "region": "us-east-1",
                "sources": [{"awsLogSource": {"sourceName": "ROUTE53", "sourceVersion": "2.0"}}],
            }
        ]
    }
    return lake


def _log_source_slots(ctx: ScanContext, region: str) -> set[str]:
    """Return the account IDs holding a primed log-source slot for ``region``."""
    keys = ctx._cache.get(SecurityLakeCheck.NAMESPACE, {})
    out = set()
    for key in keys:
        if key.startswith("list_log_sources:") and key.endswith(f":{region}"):
            out.add(key.split(":")[1])
    return out


def test_security_lake_primes_log_sources_for_every_member_account() -> None:
    """``_prime_region_log_sources`` seeds a slot for every organization account.

    When the primer read a retired per-Region slot it found nothing, seeded only
    the scanned account, and every member account's log source read as "not
    configured" -- 176 PASS rows turned FAIL in the live A/B scan that caught it.
    """
    ctx, session = _scan()
    _arm_pages(session.org(), *_PAGES)
    member = _PAGES[1]["Accounts"][0]["Id"]
    _arm_log_sources(session, member)
    _stub_account(ctx, "000011112222")
    check = _check(SecurityLakeCheck, ctx)

    assert not is_error(check.organization.accounts())
    assert check.check_log_source_configured("us-east-1", "ROUTE53", member, "2.0")


def test_the_guarded_primer_issues_no_second_sweep() -> None:
    """Property 19: after ``accounts()``, priming reads the cache and issues nothing."""
    ctx, session = _scan()
    org = session.org()
    _arm_pages(org, *_PAGES)
    member = _PAGES[1]["Accounts"][0]["Id"]
    _arm_log_sources(session, member)
    _stub_account(ctx, _ORG_IDS[0])
    check = _check(SecurityLakeCheck, ctx)

    assert not is_error(check.organization.accounts())
    assert check.check_log_source_configured("us-east-1", "ROUTE53", member, "2.0")

    assert _sweeps(org) == 1
    assert _log_source_slots(ctx, "us-east-1") == set(_ORG_IDS)


def test_an_unguarded_primer_seeds_nothing_when_the_sweep_fails(
    records: list[logging.LogRecord],
) -> None:
    """Property 21: a failed sweep seeds no slot -- not ``[]``, not the scanned account."""
    ctx, session = _scan()
    _arm_failure(session.org())
    _arm_log_sources(session, _ORG_IDS[0])
    _stub_account(ctx, _ORG_IDS[0])
    check = _check(SecurityLakeCheck, ctx)

    returned = check._prime_region_log_sources("us-east-1")

    assert returned is None
    assert _log_source_slots(ctx, "us-east-1") == set()
    primer = [
        r
        for r in _messages(records, "could not list organization accounts")
        if r.levelno == logging.DEBUG
    ]
    assert len(primer) == 1
    assert "AccessDeniedException" in primer[0].getMessage()


# --------------------------------------------------------------------------- #
# Identity and surface (Property 4)
# --------------------------------------------------------------------------- #


def test_accounts_returns_the_clients_response_by_identity() -> None:
    """The provider hands back the client's dict unchanged, then the cached one."""
    ctx, _ = _scan()
    org_response = {"Accounts": [{"Id": _ORG_IDS[0], "Status": "ACTIVE"}]}
    with patch.object(OrganizationsClient, "list_accounts", return_value=org_response):
        assert ctx.organization.accounts() is org_response
        assert ctx.organization.accounts() is org_response


def test_the_provider_surface_is_exactly_accounts() -> None:
    """One public accessor, and three public module-level names."""
    public = {
        n
        for n, o in vars(OrganizationsProvider).items()
        if not n.startswith("_") and inspect.isfunction(o)
    }
    assert public == {"accounts"}

    tree = ast.parse(Path(organization_module.__file__).read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    assert {n for n in names if not n.startswith("_")} == {
        "OrganizationsProvider",
        "NAMESPACE",
        "ACCOUNTS_KEY",
    }


def test_reading_before_initialize_names_the_property() -> None:
    """The clean ``_require_ctx`` error, not a ``None`` dereference (Property 13)."""
    check = _concrete(InspectorCheck)()
    with pytest.raises(RuntimeError, match=r"\.organization was read before"):
        check.organization  # noqa: B018 -- the read is the test


# --------------------------------------------------------------------------- #
# Log shape (Property 29)
# --------------------------------------------------------------------------- #


def test_a_success_logs_one_fetch_one_cache_and_a_hit_per_later_read(
    records: list[logging.LogRecord],
) -> None:
    """One fetch, one cached record naming N, n hits, and no ``aws_call_failed``."""
    ctx, session = _scan()
    _arm_pages(session.org(), *_PAGES)
    later = 4

    for _ in range(1 + later):
        ctx.organization.accounts()

    assert len(_messages(records, "Organizations: Fetching organization accounts")) == 1
    cached = _messages(records, "Organizations: Cached ")
    assert [r.getMessage() for r in cached] == [
        f"Organizations: Cached {len(_ORG_IDS)} organization accounts"
    ]
    assert len(_messages(records, "Organizations: Using cached organization accounts")) == later
    assert _messages(records, "aws_call_failed") == []


@pytest.mark.parametrize("make,operation,code", _FAILURES)
def test_a_failure_logs_exactly_one_aws_call_failed_line(
    records: list[logging.LogRecord], make: Any, operation: str, code: str
) -> None:
    """One failure is one ``aws_call_failed`` line, from ``aws_error``."""
    ctx, session = _scan()
    _arm_failure(session.org(), make)

    ctx.organization.accounts()

    failed = _messages(records, "aws_call_failed")
    assert len(failed) == 1
    assert failed[0].funcName == "aws_error"
    assert f"operation={operation} " in failed[0].getMessage()
    assert _messages(records, "Organizations: Cached ") == []


# --------------------------------------------------------------------------- #
# Collectible deterministically (Property 28)
# --------------------------------------------------------------------------- #


def test_the_provider_is_freed_by_refcount_with_its_context() -> None:
    """``del ctx`` frees the provider immediately, with the cyclic collector off.

    The call goes through the context directly, not through a check, whose
    ``_ctx`` would be a second strong reference to the context.
    """
    session = _Session()
    _arm_pages(session.org(), *_PAGES)
    ctx = ScanContext(session=session, regions=["us-east-1"])  # type: ignore[arg-type]
    assert not is_error(ctx.organization.accounts())
    ref = weakref.ref(ctx.organization)
    assert ctx.organization._ctx_ref() is ctx

    gc.disable()
    try:
        del ctx
        assert ref() is None
    finally:
        gc.enable()
