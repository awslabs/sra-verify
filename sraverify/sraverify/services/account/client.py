"""
Account client for interacting with AWS Account Management service.
"""
from typing import Dict, Optional, Any
from botocore.exceptions import ClientError
from sraverify.core.logging import logger
from sraverify.core.scan_context import ScanContext


class AccountClient:
    """Client for interacting with AWS Account Management service."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize Account client for a specific region.

        Args:
            region: AWS region name
            ctx: The per-scan ``ScanContext`` used to obtain the underlying
                boto3 client. The client is fetched via
                ``ctx.get_client('account', region=region)`` so it picks up
                the scan's bounded ``Client_Config`` and is shared across
                checks in the same scan.
        """
        self.region = region
        self.ctx = ctx
        self.client = ctx.get_client('account', region=region)

    def get_alternate_contact(self, contact_type: str, account_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get alternate contact information for the specified type.

        Args:
            contact_type: Type of contact (BILLING, OPERATIONS, or SECURITY)
            account_id: Optional account ID (defaults to current account)

        Returns:
            Dictionary containing contact details or error information
        """
        try:
            params = {"AlternateContactType": contact_type}
            if account_id:
                params["AccountId"] = account_id

            return self.client.get_alternate_contact(**params)
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = str(e)
            logger.debug(f"Error getting {contact_type} alternate contact in {self.region}: {error_message}")
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }
