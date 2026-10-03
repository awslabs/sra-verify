"""
IAM client.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

IAM is a global service, so the boto3 client is requested with ``region=None``,
which the context binds to the scan Region; IAM is partition-global, so the
Region selects only the partition. The IAM delegated administrator and the
organization are read through the scan's Organizations provider
(``self.organization`` on ``IAMCheck``), not through this client.
"""
from typing import Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class IAM_Client(AWSClient):
    """Client for interacting with AWS IAM."""

    def __init__(self, ctx: ScanContext):
        """
        Initialize the IAM client.

        Args:
            ctx: ScanContext for the current scan.
        """
        super().__init__("us-east-1", ctx)
        # IAM is a global service; requested with region=None, which the
        # context binds to the scan Region. IAM is partition-global, so the
        # Region selects only the partition.
        self.client = ctx.get_client('iam', region=None)

    def list_users(self) -> Mapping[str, Any]:
        """
        List the IAM users in the account.

        Returns:
            ``{"Users": [...]}`` with every page merged, on success, or the error
            result.
        """
        try:
            users = []
            for page in self.client.get_paginator('list_users').paginate():
                users.extend(page.get('Users', []))
            return {"Users": users}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_organizations_features(self) -> Mapping[str, Any]:
        """
        List the centralized root access features enabled for the organization.

        Callable only from the management account or the IAM delegated
        administrator.

        Returns:
            ``{"OrganizationId": ..., "EnabledFeatures": [...]}`` on success, or
            the error result. ``EnabledFeatures`` may be empty.
        """
        try:
            return self.client.list_organizations_features()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_account_summary(self) -> Mapping[str, Any]:
        """
        Get the IAM account summary, which includes the root user credential keys.

        Returns:
            ``{"SummaryMap": {...}}`` on success, or the error result.
        """
        try:
            return self.client.get_account_summary()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_account_password_policy(self) -> Mapping[str, Any]:
        """
        Get the account's custom IAM password policy.

        Returns:
            ``{"PasswordPolicy": {...}}`` on success, or the error result.
            ``NoSuchEntity`` means the account has no custom policy.
        """
        try:
            return self.client.get_account_password_policy()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
