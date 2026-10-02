"""
``ScanContext`` construction, the scan Region, and the Organizations Region
derivation.

* Property 5 -- constructing a context binds no boto3 client, and its
  ``organization`` is an :class:`OrganizationsProvider`.
* Property 6 -- the Organizations client's Region is the first explicit
  ``--regions`` value, else the session's Region; with neither, constructing
  the context raises ``PartitionUndeterminedError``. It is never resolved
  through ``get_enabled_regions``.
* Property 7 -- ``IAM_Client`` binds its Organizations client the same way.
* Property 32 (context half) -- ``ctx.scan_region`` is computed once, is
  read-only, survives the caller mutating its list, and is the Region every
  ``core`` binding and every Region-less ``get_client`` uses.

No AWS call is issued: the session is a stand-in and ``get_client`` is replaced
on the instance where a call would otherwise be made.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

import sraverify.services.iam.client as iam_client_module
from sraverify.core.errors import PartitionUndeterminedError
from sraverify.core.organization import OrganizationsProvider
from sraverify.core.organizations_client import OrganizationsClient, scan_region
from sraverify.core.scan_context import ScanContext
from sraverify.services.iam.client import IAM_Client


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
# Property 7 -- IAM's Organizations binding follows the same rule
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "regions,session_region",
    [
        pytest.param(["us-gov-west-1"], "us-east-1", id="explicit"),
        pytest.param(None, "cn-north-1", id="session"),
    ],
)
def test_the_iam_client_binds_organizations_through_scan_region(
    regions: list[str] | None, session_region: str | None
) -> None:
    """``IAM_Client(ctx)`` requests ``("organizations", scan_region(ctx))``."""
    session = MagicMock(name="session")
    session.region_name = session_region
    ctx = ScanContext(session=session, regions=regions)
    get_client = _instrument(ctx)

    IAM_Client(ctx)

    org_calls = [c for c in get_client.call_args_list if c.args[:1] == ("organizations",)]
    assert len(org_calls) == 1
    assert org_calls[0].kwargs == {"region": scan_region(ctx)}
    ctx.get_enabled_regions.assert_not_called()


def test_the_iam_client_cannot_be_built_without_a_scan_region() -> None:
    """With neither Region source, the context -- and so the IAM client -- cannot exist."""
    session = MagicMock(name="session")
    session.region_name = None

    with pytest.raises(PartitionUndeterminedError):
        IAM_Client(ScanContext(session=session, regions=None))

    session.client.assert_not_called()


def test_the_iam_client_source_pins_no_organizations_region() -> None:
    """No ``get_client('organizations', region='us-east-1')`` survives in the source."""
    path = Path(iam_client_module.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    pinned = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr != "get_client" or not node.args:
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant) and first.value == "organizations"):
            continue
        for kw in node.keywords:
            if kw.arg == "region" and isinstance(kw.value, ast.Constant):
                pinned.append(node.lineno)
    assert pinned == [], f"services/iam/client.py pins an Organizations Region at {pinned}"


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
