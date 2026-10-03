"""
``SecurityHubCheck.get_organization()`` delegates to the scan's Organizations
provider (Requirement 13.2, task 24.2).

The method has no production call site today -- no ``securityhub`` check calls
it -- so the change moves no row. It used to issue its own boto3 call and write
the ``organizations`` namespace by key; these tests hold that it now returns
``self.organization.describe()``'s answer by identity and binds no client.
"""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock

import sraverify.services.securityhub.base as securityhub_base
from sraverify.core.aws_errors import error_result
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


def test_get_organization_returns_the_providers_answer_by_identity() -> None:
    """A success and a failure both come back as the provider's own object."""
    ctx = MagicMock(spec=ScanContext)
    success = {"Organization": {"Id": "o-example", "MasterAccountId": "111122223333"}}
    failure = error_result(
        code="AccessDeniedException", message="no", operation="DescribeOrganization"
    )

    for answer in (success, failure):
        ctx.organization = MagicMock(name="OrganizationsProvider")
        ctx.organization.describe.return_value = answer

        assert _check_over(ctx).get_organization() is answer
        ctx.organization.describe.assert_called_once_with()

    ctx.get_client.assert_not_called()
    ctx._has.assert_not_called()
    ctx._set.assert_not_called()


def test_the_module_binds_no_organizations_client() -> None:
    """No ``get_client('organizations', ...)`` survives in the source."""
    tree = ast.parse(Path(securityhub_base.__file__).read_text(encoding="utf-8"))
    bound = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get_client"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "organizations"
    ]
    assert bound == [], f"securityhub/base.py binds an Organizations client at {bound}"
