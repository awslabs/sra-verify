"""Shared ``ScanContext`` lookups under concurrent callers.

A second caller for the same key waits for the first instead of repeating the
AWS call, a failure is never shared, other keys are not blocked, and boto3
clients are built one at a time. ``GRACE`` is how long a second caller is
given to wrongly start the same call; it never decides a passing run.
"""
from __future__ import annotations

import threading
from typing import Any, Callable
from unittest.mock import MagicMock

import pytest

from sraverify.core.aws_errors import is_error
from sraverify.core.organizations_client import OrganizationsClient
from sraverify.core.scan_context import ScanContext
from sraverify.tests.unit.core.test_scan_context import _client_error, _ServiceSession

TIMEOUT = 5.0
GRACE = 0.5


class _Gate:
    """A call whose first invocation blocks until released."""

    def __init__(self, outcomes: list[Any]) -> None:
        self.outcomes = outcomes
        self.calls = 0
        self.first_entered = threading.Event()
        self.second_entered = threading.Event()
        self.release = threading.Event()
        self._lock = threading.Lock()

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            self.calls += 1
            number = self.calls
        if number == 1:
            self.first_entered.set()
            assert self.release.wait(TIMEOUT)
        else:
            self.second_entered.set()
        outcome = self.outcomes[min(number, len(self.outcomes)) - 1]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _run(target: Callable[[], Any], results: dict[str, Any], name: str) -> threading.Thread:
    thread = threading.Thread(target=lambda: results.__setitem__(name, target()))
    thread.start()
    return thread


def _race(call: Callable[[], Any], gate: _Gate) -> tuple[bool, dict[str, Any]]:
    results: dict[str, Any] = {}
    first = _run(call, results, "first")
    assert gate.first_entered.wait(TIMEOUT)
    second = _run(call, results, "second")
    overlapped = gate.second_entered.wait(GRACE)
    gate.release.set()
    for thread in (first, second):
        thread.join(TIMEOUT)
        assert not thread.is_alive()
    return overlapped, results


_IDENTITY = {"Account": "111122223333"}
_REGIONS = {"Regions": [{"RegionName": "us-east-1"}, {"RegionName": "eu-west-1"}]}

_LOOKUPS = [
    pytest.param("get_account_info", "sts", "get_caller_identity", _IDENTITY,
                 "GetCallerIdentity", ["us-east-1"], id="identity"),
    pytest.param("get_enabled_regions", "ec2", "describe_regions", _REGIONS,
                 "DescribeRegions", None, id="regions"),
]


def _context(service: str, method: str, gate: _Gate, regions: list[str] | None) -> ScanContext:
    session = _ServiceSession()
    session.client("account").get_account_information.return_value = {"AccountName": "probe"}
    getattr(session.client(service), method).side_effect = gate
    return ScanContext(session=session, regions=regions)  # type: ignore[arg-type]


@pytest.mark.parametrize("lookup,service,method,response,operation,regions", _LOOKUPS)
def test_concurrent_callers_share_one_successful_lookup(
    lookup: str, service: str, method: str, response: Any, operation: str, regions: list[str] | None
) -> None:
    gate = _Gate([response])
    ctx = _context(service, method, gate, regions)

    overlapped, results = _race(getattr(ctx, lookup), gate)

    assert not overlapped
    assert gate.calls == 1
    assert not is_error(results["first"])
    assert results["second"] is results["first"]


@pytest.mark.parametrize("lookup,service,method,response,operation,regions", _LOOKUPS)
def test_a_failed_lookup_is_not_shared_and_the_waiting_caller_retries(
    lookup: str, service: str, method: str, response: Any, operation: str, regions: list[str] | None
) -> None:
    gate = _Gate([_client_error(operation), response])
    ctx = _context(service, method, gate, regions)

    overlapped, results = _race(getattr(ctx, lookup), gate)

    assert not overlapped
    assert gate.calls == 2
    assert is_error(results["first"])
    assert not is_error(results["second"])
    assert getattr(ctx, lookup)() is results["second"]
    assert gate.calls == 2


_PROVIDER_KEYS = [
    pytest.param("roots", "list_roots", {"Roots": [{"Id": "r-1"}]}, id="roots"),
    pytest.param("accounts", "list_accounts", {"Accounts": [{"Id": "111122223333"}]}, id="accounts"),
]


def _org_context(paginators: dict[str, MagicMock]) -> ScanContext:
    session = _ServiceSession()
    session.client("organizations").get_paginator.side_effect = lambda name: paginators[name]
    return ScanContext(session=session, regions=["us-east-1"])  # type: ignore[arg-type]


@pytest.mark.parametrize("accessor,operation,page", _PROVIDER_KEYS)
def test_concurrent_provider_callers_paginate_once(accessor: str, operation: str, page: Any) -> None:
    gate = _Gate([[page]])
    paginator = MagicMock(name=operation)
    paginator.paginate.side_effect = gate
    ctx = _org_context({operation: paginator})

    overlapped, results = _race(getattr(ctx.organization, accessor), gate)

    assert not overlapped
    assert gate.calls == 1
    assert results["first"] == page
    assert results["second"] is results["first"]


@pytest.mark.parametrize("accessor,operation,page", _PROVIDER_KEYS)
def test_a_failed_provider_fetch_is_not_shared_and_the_waiting_caller_retries(
    accessor: str, operation: str, page: Any
) -> None:
    gate = _Gate([_client_error(operation), [page]])
    paginator = MagicMock(name=operation)
    paginator.paginate.side_effect = gate
    ctx = _org_context({operation: paginator})

    overlapped, results = _race(getattr(ctx.organization, accessor), gate)

    assert not overlapped
    assert gate.calls == 2
    assert is_error(results["first"])
    assert results["second"] == page
    assert getattr(ctx.organization, accessor)() is results["second"]
    assert gate.calls == 2


def test_a_blocked_lookup_does_not_block_other_keys() -> None:
    roots_gate = _Gate([[{"Roots": [{"Id": "r-1"}]}]])
    roots = MagicMock(name="list_roots")
    roots.paginate.side_effect = roots_gate
    accounts = MagicMock(name="list_accounts")
    accounts.paginate.return_value = [{"Accounts": [{"Id": "111122223333"}]}]
    ctx = _org_context({"list_roots": roots, "list_accounts": accounts})
    sts = ctx.session.client("sts")
    sts.get_caller_identity.return_value = _IDENTITY

    results: dict[str, Any] = {}
    blocked = _run(ctx.organization.roots, results, "roots")
    assert roots_gate.first_entered.wait(TIMEOUT)

    def others() -> Any:
        ctx._set("probe", "key", "value")
        return (ctx.organization.accounts(), ctx.get_account_info(), ctx._get("probe", "key"))

    other = _run(others, results, "others")
    other.join(TIMEOUT)
    finished_while_blocked = not other.is_alive()
    roots_gate.release.set()
    blocked.join(TIMEOUT)

    assert finished_while_blocked
    accounts_answer, identity, cached = results["others"]
    assert accounts_answer == {"Accounts": [{"Id": "111122223333"}]}
    assert identity["account_id"] == "111122223333"
    assert cached == "value"
    assert results["roots"] == {"Roots": [{"Id": "r-1"}]}


class _GatedSession:
    region_name = "us-east-1"

    def __init__(self, gate: _Gate) -> None:
        self.gate = gate

    def client(self, service_name: str, region_name: Any = None, config: Any = None) -> Any:
        self.gate()
        return MagicMock(name=f"{service_name}:{region_name}")


@pytest.mark.parametrize(
    "first,second",
    [
        pytest.param("s3", "iam", id="different-keys"),
        pytest.param("s3", "s3", id="same-key"),
    ],
)
def test_clients_are_built_one_at_a_time(first: str, second: str) -> None:
    gate = _Gate([None])
    ctx = ScanContext(session=_GatedSession(gate), regions=["us-east-1"])  # type: ignore[arg-type]

    results: dict[str, Any] = {}
    one = _run(lambda: ctx.get_client(first), results, "first")
    assert gate.first_entered.wait(TIMEOUT)
    two = _run(lambda: ctx.get_client(second), results, "second")
    overlapped = gate.second_entered.wait(GRACE)
    gate.release.set()
    for thread in (one, two):
        thread.join(TIMEOUT)
        assert not thread.is_alive()

    assert not overlapped
    assert gate.calls == len({first, second})
    assert results["first"] is ctx.get_client(first)
    assert results["second"] is ctx.get_client(second)
    assert gate.calls == len({first, second})


class _CountingSession:
    def __init__(self, region: str) -> None:
        self._region = region
        self.region_reads = 0

    @property
    def region_name(self) -> str:
        self.region_reads += 1
        return self._region

    def client(self, service_name: str, region_name: Any = None, config: Any = None) -> Any:
        return MagicMock(name=f"{service_name}:{region_name}")


def test_the_organizations_client_reads_the_scan_region_not_the_session() -> None:
    session = _CountingSession("us-gov-west-1")
    ctx = ScanContext(session=session, regions=None)  # type: ignore[arg-type]
    reads_at_construction = session.region_reads

    client = OrganizationsClient(ctx)

    assert session.region_reads == reads_at_construction
    assert client.region == "us-gov-west-1"
