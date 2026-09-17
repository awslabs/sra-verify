"""
Organizations client.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

Organizations is a global service, so the client is pinned to ``us-east-1`` and the
wrapper takes no region.
"""
from typing import Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class OrganizationsClient(AWSClient):
    """Client for interacting with AWS Organizations."""

    def __init__(self, ctx: ScanContext):
        """
        Initialize the Organizations client.

        Organizations is a global service; the boto3 client is pinned to
        ``us-east-1`` so every code path shares one cached instance.

        Args:
            ctx: ScanContext for the current scan.
        """
        super().__init__("us-east-1", ctx)
        self.client = ctx.get_client('organizations', region='us-east-1')

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
