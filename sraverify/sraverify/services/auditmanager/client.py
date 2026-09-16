"""
Audit Manager client.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

``AccessDeniedException`` from ``GetOrganizationAdminAccount`` is deliberately
**not** declared semantic. It is returned for the "Please complete AWS Audit
Manager setup" condition as well as for a genuine permission failure, and that
first case has not been observed against a not-yet-set-up account -- so
``AuditManagerCheck.NOT_CONFIGURED_ERRORS`` is empty and the code resolves to an
honest ERROR.
"""
from typing import Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class AuditManagerClient(AWSClient):
    """Client for interacting with AWS Audit Manager."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize Audit Manager client for a specific region.

        Args:
            region: AWS region name
            ctx: ScanContext for the current scan.
        """
        super().__init__(region, ctx)
        self.client = ctx.get_client('auditmanager', region=region)

    def get_account_status(self) -> Mapping[str, Any]:
        """
        Get the Audit Manager registration status for this account.

        Returns:
            The ``GetAccountStatus`` response on success, i.e.
            ``{"status": ...}``, or the error result.
        """
        try:
            return self.client.get_account_status()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def get_organization_admin_account(self) -> Mapping[str, Any]:
        """
        Get the Audit Manager delegated administrator.

        Returns:
            The ``GetOrganizationAdminAccount`` response on success, or the error
            result.
        """
        try:
            return self.client.get_organization_admin_account()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
