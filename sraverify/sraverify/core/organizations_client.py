"""
Organizations client.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

Organizations is partition-global: there is one endpoint per partition, and the
wrapper takes no Region. The Region the boto3 client is built for is derived from
the scan by :func:`scan_region` rather than pinned to ``us-east-1``, which is a
correct pin only in the ``aws`` partition -- in GovCloud or China it would build a
client for the wrong partition's endpoint.

This module lives under ``core/`` because the Organizations provider
(``core/organization.py``) uses it, and ``core/`` never imports from
``services/``. ``OrganizationsCheck`` imports it from here too.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.regions import resolve_scan_region

if TYPE_CHECKING:
    from sraverify.core.scan_context import ScanContext


def scan_region(ctx: ScanContext) -> str:
    """Return the Region an Organizations boto3 client should be built for.

    The scan Region: the first explicit ``--regions`` value, else the session's
    Region. Never ``None``. Applies ``resolve_scan_region`` to ``ctx.regions``
    and ``ctx.session`` -- the same pure rule ``ScanContext`` used to compute
    ``ctx.scan_region``, over the same inputs -- and never calls
    ``ctx.get_enabled_regions()``, so deriving the Region issues no AWS call.

    It reads the inputs rather than ``ctx.scan_region`` deliberately: the
    catalog-wide harnesses hand clients a ``MagicMock`` context with a
    non-empty ``regions``, on which ``ctx.scan_region`` would be a mock.

    Args:
        ctx: ScanContext for the current scan.

    Returns:
        A Region name.

    Raises:
        PartitionUndeterminedError: Neither input supplies a Region. A real
            ``ScanContext`` cannot reach this, because its constructor raised
            first; only a hand-built context can, and that is a programming
            defect. Raised rather than asserted, because ``python -O`` strips
            an ``assert`` and would restore the commercial ``aws-global``
            fallback this function exists to remove.
    """
    return resolve_scan_region(ctx.regions, ctx.session)


class OrganizationsClient(AWSClient):
    """Client for interacting with AWS Organizations."""

    def __init__(self, ctx: ScanContext) -> None:
        """
        Initialize the Organizations client.

        Organizations is partition-global; the boto3 client is built for the
        Region :func:`scan_region` derives, so it reaches the scan's partition.

        Args:
            ctx: ScanContext for the current scan.
        """
        region = scan_region(ctx)
        super().__init__(region, ctx)
        self.client = ctx.get_client('organizations', region=region)

    def describe_organization(self) -> Mapping[str, Any]:
        """
        Describe the organization.

        Returns:
            The ``DescribeOrganization`` response on success, or the error result.

            ``AWSOrganizationsNotInUseException`` means no organization exists,
            which is a real answer and is declared in
            ``OrganizationsCheck.NOT_CONFIGURED_ERRORS``.
        """
        try:
            return self.client.describe_organization()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_roots(self) -> Mapping[str, Any]:
        """
        List the organization roots.

        Returns:
            ``{"Roots": [...]}`` with every page merged, on success, or the error
            result.
        """
        try:
            roots = []
            for page in self.client.get_paginator('list_roots').paginate():
                roots.extend(page.get('Roots', []))
            return {"Roots": roots}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_organizational_units_for_parent(
        self, parent_id: str
    ) -> Mapping[str, Any]:
        """
        List the organizational units under a parent.

        Args:
            parent_id: Root or OU ID.

        Returns:
            ``{"OrganizationalUnits": [...]}`` with every page merged, on success,
            or the error result.
        """
        try:
            ous = []
            paginator = self.client.get_paginator(
                'list_organizational_units_for_parent'
            )
            for page in paginator.paginate(ParentId=parent_id):
                ous.extend(page.get('OrganizationalUnits', []))
            return {"OrganizationalUnits": ous}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_policies(
        self, policy_type: str = "SERVICE_CONTROL_POLICY"
    ) -> Mapping[str, Any]:
        """
        List the organization policies of a type.

        Args:
            policy_type: e.g. ``"SERVICE_CONTROL_POLICY"``.

        Returns:
            ``{"Policies": [...]}`` with every page merged, on success, or the
            error result.

            ``PolicyTypeNotEnabledException`` means the policy type is not enabled
            for the organization, which is a real answer and is declared in the
            discriminator table.
        """
        try:
            policies = []
            for page in self.client.get_paginator('list_policies').paginate(
                Filter=policy_type
            ):
                policies.extend(page.get('Policies', []))
            return {"Policies": policies}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_accounts(self) -> Mapping[str, Any]:
        """
        List every account in the organization.

        Returns:
            ``{"Accounts": [...]}`` with every page merged, on success, or the
            error result.

            The whole paginator loop sits inside the ``try`` deliberately: a
            failure on page three has to arrive as an error result, because a
            short list is indistinguishable from a smaller organization.
        """
        try:
            accounts = []
            for page in self.client.get_paginator('list_accounts').paginate():
                accounts.extend(page.get('Accounts', []))
            return {"Accounts": accounts}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_effective_policy(
        self, policy_type: str, target_id: str
    ) -> Mapping[str, Any]:
        """
        Describe the effective management policy for a target.

        Args:
            policy_type: A management policy type, e.g. ``"BEDROCK_POLICY"``.
            target_id: An account ID. A root or OU is **not** supported and
                answers ``InvalidInputException`` (verified 2026-09-16), so
                callers must iterate accounts.

        Returns:
            ``{"EffectivePolicy": {...}}`` on success, or the error result.

            ``EffectivePolicyNotFoundException`` means no policy of that type
            reaches the target, which is a real answer and is declared in
            ``OrganizationsCheck.NOT_CONFIGURED_ERRORS``.
        """
        try:
            return self.client.describe_effective_policy(
                PolicyType=policy_type, TargetId=target_id
            )
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_accounts_for_parent(self, parent_id: str) -> Mapping[str, Any]:
        """
        List the accounts directly under a parent.

        Args:
            parent_id: Root or OU ID.

        Returns:
            ``{"Accounts": [...]}`` with every page merged, on success, or the
            error result.
        """
        try:
            accounts = []
            paginator = self.client.get_paginator('list_accounts_for_parent')
            for page in paginator.paginate(ParentId=parent_id):
                accounts.extend(page.get('Accounts', []))
            return {"Accounts": accounts}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
