"""
``SecurityHubCheck.get_organization()`` derives its Organizations Region from
the scan (Requirement 6.5, merge blocker 3 of the !55 review).

The method has no production call site today -- no ``securityhub`` check calls
it -- so the change moves no row; these tests hold the binding so a future
caller cannot inherit a commercial-partition pin.
"""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock

import sraverify.services.securityhub.base as securityhub_base
from sraverify.core.scan_context import ScanContext
from sraverify.services.securityhub.base import SecurityHubCheck


class _Probe(SecurityHubCheck):
    """Concrete, unregistered (the module stem is not ``sra_*``) Security Hub check."""

    def execute(self):
        return []


def _check_over(ctx: MagicMock) -> SecurityHubCheck:
    """A Security Hub check bound to ``ctx`` without running ``_setup_clients``."""
    check = _Probe()
    check._ctx = ctx
    return check


def test_get_organization_binds_the_scan_region() -> None:
    """A GovCloud scan requests ``("organizations", region="us-gov-west-1")``."""
    ctx = MagicMock(spec=ScanContext)
    ctx.regions = ["us-gov-west-1", "us-gov-east-1"]
    ctx.session = MagicMock(name="session")
    ctx.session.region_name = "us-east-1"
    ctx._has.return_value = False
    org = MagicMock(name="organizations")
    org.describe_organization.return_value = {"Organization": {"Id": "o-example"}}
    ctx.get_client.return_value = org

    response = _check_over(ctx).get_organization()

    assert response == {"Organization": {"Id": "o-example"}}
    ctx.get_client.assert_called_once_with("organizations", region="us-gov-west-1")


def test_the_module_pins_no_organizations_region() -> None:
    """No ``get_client('organizations', region=<literal>)`` survives in the source."""
    tree = ast.parse(Path(securityhub_base.__file__).read_text(encoding="utf-8"))
    pinned = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get_client"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "organizations"
        and any(kw.arg == "region" and isinstance(kw.value, ast.Constant) for kw in node.keywords)
    ]
    assert pinned == [], f"securityhub/base.py pins an Organizations Region at {pinned}"
