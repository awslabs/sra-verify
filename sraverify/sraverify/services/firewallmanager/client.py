"""
Firewall Manager client.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

``ResourceNotFoundException`` from ``GetAdminAccount`` means no administrator
account has been set for the organization. That is declared in
``FirewallManagerCheck.NOT_CONFIGURED_ERRORS`` rather than translated into prose
here: classifying an error is the check's decision, and it needs the operation
context to make it.
"""
from typing import Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class FirewallManagerClient(AWSClient):
    """Client for interacting with AWS Firewall Manager."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize Firewall Manager client for a specific region.

        Args:
            region: AWS region name
            ctx: ScanContext for the current scan.
        """
        super().__init__(region, ctx)
        self.client = ctx.get_client('fms', region=region)

    def get_admin_account(self) -> Mapping[str, Any]:
        """
        Get the Firewall Manager administrator account.

        Returns:
            The ``GetAdminAccount`` response on success, or the error result.

            ``ResourceNotFoundException`` means no administrator account is
            configured. That is a real answer, and it is declared in the
            discriminator table rather than translated into prose here.
        """
        try:
            return self.client.get_admin_account()
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)

    def list_policies(self) -> Mapping[str, Any]:
        """
        List the Firewall Manager policies.

        Returns:
            ``{"PolicyList": [...]}`` with every page merged, on success, or the
            error result.
        """
        try:
            policies = []
            for page in self.client.get_paginator('list_policies').paginate():
                policies.extend(page.get('PolicyList', []))
            return {"PolicyList": policies}
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
