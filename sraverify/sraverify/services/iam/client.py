"""
IAM client.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

IAM is a global service, so the boto3 client is requested with ``region=None`` and
the context caches it under the ``"__global__"`` sentinel key. The Organizations
client, used for the IAM delegated administrator and the management account ID,
is pinned to ``us-east-1`` like ``OrganizationsClient``.
"""
from typing import Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext

#: The service principal the IAM delegated administrator is registered under,
#: for centralized root access management.
IAM_SERVICE_PRINCIPAL = "iam.amazonaws.com"


class IAM_Client(AWSClient):
    """Client for interacting with AWS IAM."""

    def __init__(self, ctx: ScanContext):
        """
        Initialize the IAM client.

        Args:
            ctx: ScanContext for the current scan.
        """
        super().__init__("us-east-1", ctx)
        # IAM is a global service; request the client without a region so the
        # context caches it under the "__global__" sentinel.
        self.client = ctx.get_client('iam', region=None)
        self.org_client = ctx.get_client('organizations', region='us-east-1')

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

    def list_delegated_administrators(self) -> Mapping[str, Any]:
        """
        List the delegated administrators for IAM (``iam.amazonaws.com``).

        Returns:
            ``{"DelegatedAdministrators": [...]}`` with every page merged, on
            success, or the error result.
        """
        try:
            admins = []
            paginator = self.org_client.get_paginator('list_delegated_administrators')
            for page in paginator.paginate(ServicePrincipal=IAM_SERVICE_PRINCIPAL):
                admins.extend(page.get('DelegatedAdministrators', []))
            return {"DelegatedAdministrators": admins}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def describe_organization(self) -> Mapping[str, Any]:
        """
        Describe the organization the account belongs to.

        Returns:
            ``{"Organization": {...}}`` on success, or the error result.
        """
        try:
            return self.org_client.describe_organization()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
