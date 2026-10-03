"""
``ScanContext`` construction, the scan Region, and the Organizations Region
derivation.

* Property 5 -- constructing a context binds no boto3 client, and its
  ``organization`` is an :class:`OrganizationsProvider`.
* Property 6 -- the Organizations client's Region is the first explicit
  ``--regions`` value, else the session's Region; with neither, constructing
  the context raises ``PartitionUndeterminedError``. It is never resolved
  through ``get_enabled_regions``.
* Property 7 -- ``IAM_Client`` binds no Organizations client at all.
* Property 32 (context half) -- ``ctx.scan_region`` is computed once, is
  read-only, survives the caller mutating its list, and is the Region every
  ``core`` binding and every Region-less ``get_client`` uses.
* Property 40 (tail) -- ``ctx.get_management_account_id()`` and
  ``check.get_management_accountId()`` equal the provider's answer.
* Property 46 -- the three lookups return an error result for an AWS failure,
  log it once at ``debug``, never cache it, and let a defect or a
  client-construction failure propagate unchanged.

No AWS call is issued: the session is a stand-in and ``get_client`` is replaced
on the instance where a call would otherwise be made.
"""
from __future__ import annotations

import logging
from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError, PartialCredentialsError

from sraverify.core.aws_errors import is_error
from sraverify.core.errors import PartitionUndeterminedError
from sraverify.core.organization import OrganizationsProvider
from sraverify.core.organizations_client import OrganizationsClient, scan_region
from sraverify.core.scan_context import ScanContext
from sraverify.services.iam.client import IAM_Client
from sraverify.services.organizations.base import OrganizationsCheck
from sraverify.tests.property.test_accessor_cache_property import _concrete


class _BareSession:
    """A session stand-in with no ``region_name`` attribute at all."""

    def __init__(self) -> None:
        self.client_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def client(self, *args: Any, **kwargs: Any) -> MagicMock:
        """Record the call and hand out a mock client."""
        self.client_calls.append((args, kwargs))
        return MagicMock(name="client")


class _RecordingSession:
    """A session stand-in with a Region that records every ``client`` build."""

    def __init__(self, region_name: str | None) -> None:
        self.region_name = region_name
        self.client_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def client(self, *args: Any, **kwargs: Any) -> MagicMock:
        """Record the call and hand out a fresh mock client."""
        self.client_calls.append((args, kwargs))
        return MagicMock(name=f"client:{args[0] if args else '?'}")


def _instrument(ctx: ScanContext) -> MagicMock:
    """Replace ``get_client`` and ``get_enabled_regions`` on this instance.

    Returns:
        The ``get_client`` mock.
    """
    ctx.get_client = MagicMock(name="get_client")  # type: ignore[method-assign]
    ctx.get_enabled_regions = MagicMock(  # type: ignore[method-assign]
        name="get_enabled_regions",
        side_effect=AssertionError("scan_region must not resolve enabled Regions"),
    )
    return ctx.get_client


# --------------------------------------------------------------------------- #
# Property 5 -- construction is silent
# --------------------------------------------------------------------------- #


def test_constructing_a_context_binds_no_client() -> None:
    """``ScanContext(...)`` calls ``session.client`` zero times."""
    session = MagicMock(name="session")

    ctx = ScanContext(session=session, regions=["us-east-1"])

    session.client.assert_not_called()
    assert isinstance(ctx.organization, OrganizationsProvider)
    assert ctx.organization is ctx.organization


def test_the_organization_property_has_no_setter() -> None:
    """Assigning ``ctx.organization`` raises."""
    ctx = ScanContext(session=MagicMock(name="session"), regions=["us-east-1"])
    with pytest.raises(AttributeError):
        ctx.organization = None  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# Property 6 -- the Region is derived from the scan
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "regions,session_region,expected",
    [
        pytest.param(["us-gov-west-1", "us-gov-east-1"], "us-east-1", "us-gov-west-1",
                     id="explicit-govcloud"),
        pytest.param(["eu-west-1"], None, "eu-west-1", id="explicit-commercial"),
        pytest.param(None, "us-gov-west-1", "us-gov-west-1", id="session-region"),
    ],
)
def test_the_organizations_client_region_is_derived_from_the_scan(
    regions: list[str] | None, session_region: str | None, expected: str
) -> None:
    """First explicit Region, else the session's."""
    session = MagicMock(name="session")
    session.region_name = session_region
    ctx = ScanContext(session=session, regions=regions)
    get_client = _instrument(ctx)

    client = OrganizationsClient(ctx)

    assert scan_region(ctx) == expected
    get_client.assert_called_once_with("organizations", region=expected)
    assert client.region == expected
    ctx.get_enabled_regions.assert_not_called()


def test_a_context_with_no_determinable_region_raises() -> None:
    """No explicit Region and a session Region of ``None``: construction raises."""
    session = MagicMock(name="session")
    session.region_name = None

    with pytest.raises(PartitionUndeterminedError) as info:
        ScanContext(session=session, regions=None)

    assert info.value.reason == "absent"
    session.client.assert_not_called()


def test_a_session_without_a_region_attribute_raises_and_builds_no_client() -> None:
    """A session stand-in lacking ``region_name`` cannot start a scan."""
    session = _BareSession()

    with pytest.raises(PartitionUndeterminedError):
        ScanContext(session=session)  # type: ignore[arg-type]

    assert session.client_calls == []


# --------------------------------------------------------------------------- #
# Property 7 -- IAM binds no Organizations client at all
# --------------------------------------------------------------------------- #


def test_the_iam_client_requests_no_organizations_client() -> None:
    """``IAM_Client(ctx)`` binds ``iam`` only.

    Its delegated administrator and organization are read through the scan's
    Organizations provider (``IAMCheck`` delegates to ``self.organization``), so
    the client has no Organizations binding whose Region could be wrong.
    """
    session = MagicMock(name="session")
    session.region_name = "us-gov-west-1"
    ctx = ScanContext(session=session, regions=None)
    get_client = _instrument(ctx)

    IAM_Client(ctx)

    services = [c.args[0] for c in get_client.call_args_list]
    assert "organizations" not in services
    assert services == ["iam"]
    ctx.get_enabled_regions.assert_not_called()


# --------------------------------------------------------------------------- #
# Property 32 (context half) -- ctx.scan_region
# --------------------------------------------------------------------------- #


def test_scan_region_is_single_valued_read_only_and_survives_caller_mutation() -> None:
    """``scan_region(ctx) == ctx.scan_region``; no setter; the caller's list is copied."""
    regions = ["us-gov-west-1", "us-gov-east-1"]
    ctx = ScanContext(session=_RecordingSession("us-east-1"), regions=regions)  # type: ignore[arg-type]

    assert ctx.scan_region == "us-gov-west-1"
    assert scan_region(ctx) == ctx.scan_region
    with pytest.raises(AttributeError):
        ctx.scan_region = "eu-west-1"  # type: ignore[misc]

    regions[0] = "eu-west-1"

    assert ctx.regions[0] == "us-gov-west-1"
    assert scan_region(ctx) == "us-gov-west-1"
    assert ctx.scan_region == "us-gov-west-1"


def test_get_enabled_regions_asks_the_scan_region() -> None:
    """Region discovery binds ``ec2`` to the scan Region, never ``us-east-1``."""
    ctx = ScanContext(session=_RecordingSession("us-gov-west-1"), regions=None)  # type: ignore[arg-type]
    ec2 = MagicMock(name="ec2")
    ec2.describe_regions.return_value = {
        "Regions": [{"RegionName": "us-gov-west-1"}, {"RegionName": "us-gov-east-1"}]
    }
    ctx.get_client = MagicMock(name="get_client", return_value=ec2)  # type: ignore[method-assign]

    assert ctx.get_enabled_regions() == ["us-gov-west-1", "us-gov-east-1"]

    ctx.get_client.assert_called_once_with("ec2", region="us-gov-west-1")
    for call in ctx.get_client.call_args_list:
        assert "us-east-1" not in call.args
        assert "us-east-1" not in call.kwargs.values()


def test_the_core_lookups_bind_the_scan_region() -> None:
    """``sts``, ``account`` and ``organizations`` are each requested with the scan Region."""
    ctx = ScanContext(session=_RecordingSession("us-east-1"), regions=["us-gov-west-1"])  # type: ignore[arg-type]
    stub = MagicMock(name="stub")
    stub.get_caller_identity.return_value = {"Account": "999988887777"}
    stub.get_account_information.return_value = {"AccountName": "example"}
    stub.describe_organization.return_value = {
        "Organization": {"MasterAccountId": "000011112222"}
    }
    ctx.get_client = MagicMock(name="get_client", return_value=stub)  # type: ignore[method-assign]

    ctx.get_account_info()
    ctx.get_management_account_id()

    assert [c.args for c in ctx.get_client.call_args_list] == [
        ("sts",), ("account",), ("organizations",)
    ]
    for call in ctx.get_client.call_args_list:
        assert call.kwargs == {"region": ctx.scan_region}


def test_a_regionless_get_client_is_the_scan_region_client() -> None:
    """``get_client(svc)`` and ``get_client(svc, region=scan_region)`` share one client."""
    session = _RecordingSession("us-gov-west-1")
    ctx = ScanContext(session=session, regions=None)  # type: ignore[arg-type]

    implicit = ctx.get_client("sts")
    explicit = ctx.get_client("sts", region=ctx.scan_region)

    assert implicit is explicit
    assert len(session.client_calls) == 1
    assert session.client_calls[0][1]["region_name"] == "us-gov-west-1"
    assert all(kw.get("region_name") is not None for _, kw in session.client_calls)


def test_the_management_lookup_reads_the_provider() -> None:
    """Property 40 (tail): the context and the check agree with the provider."""
    session = _RecordingSession("us-east-1")
    ctx = ScanContext(session=session, regions=["us-gov-west-1"])  # type: ignore[arg-type]
    org = OrganizationsClient(ctx)
    org.client.describe_organization.return_value = {
        "Organization": {"MasterAccountId": "000011112222"}
    }
    check = _concrete(OrganizationsCheck)()
    check.initialize(ctx)

    expected = ctx.organization.management_account_id()
    assert expected == "000011112222"
    assert ctx.get_management_account_id() == expected
    assert check.get_management_accountId() == expected
    assert check.get_management_accountId(MagicMock(name="ignored-session")) == expected
    assert org.client.describe_organization.call_count == 1


def test_the_management_lookup_and_the_organizations_client_share_one_client() -> None:
    """``get_management_account_id`` and ``OrganizationsClient`` hit one cache key."""
    session = _RecordingSession("us-east-1")
    ctx = ScanContext(session=session, regions=["us-gov-west-1"])  # type: ignore[arg-type]

    org = OrganizationsClient(ctx)
    org.client.describe_organization.return_value = {
        "Organization": {"MasterAccountId": "000011112222"}
    }

    assert ctx.get_management_account_id() == "000011112222"
    org_builds = [kw for args, kw in session.client_calls if args[:1] == ("organizations",)]
    assert len(org_builds) == 1
    assert org_builds[0]["region_name"] == "us-gov-west-1"
    assert all(kw.get("region_name") is not None for _, kw in session.client_calls)


# --------------------------------------------------------------------------- #
# Property 46 -- the lookups never raise for an AWS outcome, never cache a failure
# --------------------------------------------------------------------------- #


class _ServiceSession:
    """A session handing out one mock per service, optionally failing construction."""

    def __init__(self, region_name: str = "us-east-1", fail: dict[str, Exception] | None = None):
        self.region_name = region_name
        self.mocks: dict[str, MagicMock] = {}
        self.fail = fail or {}
        self.client_calls: list[str] = []

    def client(self, service_name: str, region_name: Any = None, config: Any = None) -> MagicMock:
        """Return the service's mock, or raise the configured construction error."""
        self.client_calls.append(service_name)
        if service_name in self.fail:
            raise self.fail[service_name]
        return self.mocks.setdefault(service_name, MagicMock(name=service_name))


@pytest.fixture
def records() -> Any:
    """Capture every ``sraverify`` record at ``DEBUG`` (the suite runs ``-p no:logging``)."""
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


def _aws_call_failed(captured: list[logging.LogRecord]) -> list[logging.LogRecord]:
    return [r for r in captured if r.getMessage().startswith("aws_call_failed ")]


def _error_records(captured: list[logging.LogRecord]) -> list[logging.LogRecord]:
    return [r for r in captured if r.levelno >= logging.ERROR]


def _client_error(operation: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "not allowed"}}, operation
    )


def _transport_error() -> EndpointConnectionError:
    return EndpointConnectionError(endpoint_url="https://example.invalid")


#: ``(lookup id, service, boto3 method, operation, ctx regions)``.
_LOOKUPS = [
    pytest.param("get_account_info", "sts", "get_caller_identity", "GetCallerIdentity",
                 ["us-east-1"], id="sts"),
    pytest.param("get_enabled_regions", "ec2", "describe_regions", "DescribeRegions",
                 None, id="ec2"),
    pytest.param("get_management_account_id", "organizations", "describe_organization",
                 "DescribeOrganization", ["us-east-1"], id="organizations"),
]


@pytest.mark.parametrize("kind", ["ClientError", "BotoCoreError"])
@pytest.mark.parametrize("lookup,service,method,operation,regions", _LOOKUPS)
def test_a_failed_lookup_is_an_error_result_logged_once_and_never_cached(
    records: list[logging.LogRecord],
    lookup: str,
    service: str,
    method: str,
    operation: str,
    regions: list[str] | None,
    kind: str,
) -> None:
    """One ``aws_call_failed``, no ``error`` record, nothing cached, a re-call re-issues."""
    session = _ServiceSession()
    ctx = ScanContext(session=session, regions=regions)  # type: ignore[arg-type]
    boto = session.client(service)
    exc = _client_error(operation) if kind == "ClientError" else _transport_error()
    getattr(boto, method).side_effect = exc

    result = getattr(ctx, lookup)()

    assert is_error(result)
    assert result["Error"]["Operation"] == (operation if kind == "ClientError" else "Request")
    assert result["Error"]["Code"] == (
        "AccessDeniedException" if kind == "ClientError" else "EndpointConnectionError"
    )
    assert len(_aws_call_failed(records)) == 1
    assert _error_records(records) == []
    assert ctx._account_info is None
    assert ctx._resolved_regions is None
    assert not ctx._has("organizations", "organization")

    again = getattr(ctx, lookup)()
    assert is_error(again)
    assert getattr(boto, method).call_count == 2


@pytest.mark.parametrize(
    "account_outcome",
    [
        pytest.param(_client_error("GetAccountInformation"), id="ClientError"),
        pytest.param(_transport_error(), id="BotoCoreError"),
        pytest.param({}, id="no-AccountName"),
    ],
)
def test_the_account_name_is_best_effort(
    records: list[logging.LogRecord], account_outcome: Any
) -> None:
    """A failed Account call, or no ``AccountName``, gives ``""`` with identity cached."""
    session = _ServiceSession()
    ctx = ScanContext(session=session, regions=["us-east-1"])  # type: ignore[arg-type]
    session.client("sts").get_caller_identity.return_value = {"Account": "111122223333"}
    account = session.client("account")
    if isinstance(account_outcome, Exception):
        account.get_account_information.side_effect = account_outcome
    else:
        account.get_account_information.return_value = account_outcome

    info = ctx.get_account_info()

    assert info == {"account_id": "111122223333", "account_name": ""}
    assert ctx.get_account_info() is info
    assert session.client("sts").get_caller_identity.call_count == 1
    expected_failed = 1 if isinstance(account_outcome, Exception) else 0
    assert len(_aws_call_failed(records)) == expected_failed
    assert _error_records(records) == []


@pytest.mark.parametrize(
    "lookup,service,method,regions",
    [
        pytest.param("get_account_info", "sts", "get_caller_identity", ["us-east-1"], id="sts"),
        pytest.param("get_account_info", "account", "get_account_information", ["us-east-1"],
                     id="account"),
        pytest.param("get_enabled_regions", "ec2", "describe_regions", None, id="ec2"),
    ],
)
def test_a_non_aws_exception_propagates_unchanged(
    records: list[logging.LogRecord],
    lookup: str,
    service: str,
    method: str,
    regions: list[str] | None,
) -> None:
    """A defect is not an AWS outcome: it is neither wrapped nor turned into a result."""
    session = _ServiceSession()
    ctx = ScanContext(session=session, regions=regions)  # type: ignore[arg-type]
    session.client("sts").get_caller_identity.return_value = {"Account": "111122223333"}
    defect = RuntimeError("a programming defect")
    getattr(session.client(service), method).side_effect = defect

    with pytest.raises(RuntimeError) as info:
        getattr(ctx, lookup)()

    assert info.value is defect
    assert _aws_call_failed(records) == []
    assert ctx._account_info is None
    assert ctx._resolved_regions is None


@pytest.mark.parametrize(
    "lookup,service,regions",
    [
        pytest.param("get_enabled_regions", "ec2", None, id="ec2"),
        pytest.param("get_account_info", "sts", ["us-east-1"], id="sts"),
    ],
)
def test_a_client_construction_failure_propagates_unwrapped(
    records: list[logging.LogRecord], lookup: str, service: str, regions: list[str] | None
) -> None:
    """``PartialCredentialsError`` from ``session.client()`` is raised as the same object.

    No error result, no ``aws_call_failed`` record, nothing cached: the client is
    acquired before the lookup's ``try``, so a construction failure never
    becomes an error result describing a call that was never made.
    """
    partial = PartialCredentialsError(provider="env", cred_var="AWS_SECRET_ACCESS_KEY")
    session = _ServiceSession(fail={service: partial})
    ctx = ScanContext(session=session, regions=regions)  # type: ignore[arg-type]

    with pytest.raises(PartialCredentialsError) as info:
        getattr(ctx, lookup)()

    assert info.value is partial
    assert _aws_call_failed(records) == []
    assert ctx._account_info is None
    assert ctx._resolved_regions is None
