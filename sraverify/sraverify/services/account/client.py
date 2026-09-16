"""
Account client, for the alternate-contact settings.

Every method returns a dict: the boto3 response on success, or the error result
built by ``AWSClient.aws_error``. Each method catches exactly ``AWS_EXCEPTIONS``
and hands the exception over; anything else raised is a programming defect and
propagates to the orchestrator's guard.

``ResourceNotFoundException`` means the alternate contact of that type is not
set, which is what the three Account checks test for, and is declared in
``AccountCheck.NOT_CONFIGURED_ERRORS``.
"""
from typing import Any, Mapping, Optional

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.scan_context import ScanContext


class AccountClient(AWSClient):
    """Client for interacting with the AWS Account service."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize Account client for a specific region.

        Args:
            region: AWS region name
            ctx: ScanContext for the current scan.
        """
        super().__init__(region, ctx)
        self.client = ctx.get_client('account', region=region)

    def get_alternate_contact(
        self, contact_type: str, account_id: Optional[str] = None
    ) -> Mapping[str, Any]:
        """
        Get an alternate contact.

        Args:
            contact_type: ``"SECURITY"``, ``"BILLING"`` or ``"OPERATIONS"``.
            account_id: The account to read, for a management-account caller.

        Returns:
            The ``GetAlternateContact`` response on success, or the error result.
        """
        try:
            params: dict[str, Any] = {"AlternateContactType": contact_type}
            if account_id:
                params["AccountId"] = account_id
            return self.client.get_alternate_contact(**params)
        except AWS_EXCEPTIONS as e:
            return self.aws_error(e)
