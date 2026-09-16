"""
Inspector client (``inspector2``).

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

``list_organization_accounts`` reads only the **first page** of ``ListAccounts``,
so it caps at 20 accounts. Paginating would change which accounts the callers see
and therefore move verdicts, so it is a recorded deferred correction rather than
part of the error contract.
"""
from typing import Any, List, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class InspectorClient(AWSClient):
    """Client for interacting with AWS Inspector."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize Inspector client for a specific region.

        Args:
            region: AWS region name
            ctx: ScanContext for the current scan; the underlying boto3 clients
                are obtained via ``ctx.get_client(...)`` so the per-scan client
                cache and bounded ``Client_Config`` are applied.
        """
        super().__init__(region, ctx)
        self.client = ctx.get_client('inspector2', region=region)
        self.org_client = ctx.get_client('organizations', region=region)

    def batch_get_account_status(
        self, account_ids: List[str]
    ) -> Mapping[str, Any]:
        """
        Get the Inspector status for a batch of accounts.

        Args:
            account_ids: Account IDs to query.

        Returns:
            The ``BatchGetAccountStatus`` response on success, i.e.
            ``{"accounts": [...]}``, or the error result.
        """
        try:
            return self.client.batch_get_account_status(accountIds=account_ids)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_delegated_admin_account(self) -> Mapping[str, Any]:
        """
        Get the Inspector delegated administrator account.

        Returns:
            The ``GetDelegatedAdminAccount`` response on success, or the error
            result.
        """
        try:
            return self.client.get_delegated_admin_account()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_organization_configuration(self) -> Mapping[str, Any]:
        """
        Describe the Inspector organization configuration.

        Returns:
            The ``DescribeOrganizationConfiguration`` response on success, or the
            error result.
        """
        try:
            return self.client.describe_organization_configuration()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_organization_accounts(self) -> Mapping[str, Any]:
        """
        List accounts in the AWS Organization.

        Returns:
            ``{"Accounts": [...]}`` on success, or the error result.

            **First page only.** ``ListAccounts`` returns at most 20 accounts per
            page and this makes one call, so an organization larger than 20
            accounts is silently truncated. Left as-is on purpose: pagination
            would change which accounts the dependent checks see and therefore
            their verdicts, which is out of scope for an error-contract migration.
        """
        try:
            return self.org_client.list_accounts()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
