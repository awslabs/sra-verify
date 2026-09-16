"""
IAM client.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

IAM is a global service, so the boto3 client is requested with ``region=None`` and
the context caches it under the ``"__global__"`` sentinel key.
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
        # IAM is a global service; request the client without a region so the
        # context caches it under the "__global__" sentinel.
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
