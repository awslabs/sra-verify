"""
S3 client, for the account-level public access block.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

``s3control`` answers ``GetPublicAccessBlock`` two ways that must not be confused:
``NoSuchPublicAccessBlockConfiguration`` when no configuration exists, which is
the control genuinely being absent, and ``AccessDenied`` when the caller lacks
``s3:GetAccountPublicAccessBlock``, which is an inability to determine. Both reach
the check intact and ``S3Check.NOT_CONFIGURED_ERRORS`` declares which is which.

The method returns the whole response rather than the extracted
``PublicAccessBlockConfiguration`` sub-dict, so an empty configuration stays
distinguishable from a failure.
"""
from typing import Any, Mapping

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class S3Client(AWSClient):
    """Client for interacting with the S3 account-level public access block."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize S3 client for a specific region.

        Args:
            region: AWS region name
            ctx: ScanContext for the current scan; the underlying boto3 clients
                are obtained via ``ctx.get_client(...)`` so the per-scan client
                cache and bounded ``Client_Config`` are applied.
        """
        super().__init__(region, ctx)
        self.client = ctx.get_client('s3', region=region)
        self.s3control_client = ctx.get_client('s3control', region=region)

    def get_public_access_block(self, account_id: str) -> Mapping[str, Any]:
        """
        Get the account-level public access block configuration.

        Args:
            account_id: The account whose configuration to read.

        Returns:
            The ``GetPublicAccessBlock`` response on success, i.e.
            ``{"PublicAccessBlockConfiguration": {...}}``, or the error result.

            The whole response rather than the extracted sub-dict, so that an
            account with an empty configuration stays distinguishable from a call
            that failed.
        """
        try:
            return self.s3control_client.get_public_access_block(
                AccountId=account_id
            )
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
