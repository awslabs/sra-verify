"""
Audit Manager client for interacting with AWS Audit Manager service.
"""
from typing import Dict, Any
from botocore.exceptions import ClientError
from sraverify.core.logging import logger


class AuditManagerClient:
    """Client for interacting with AWS Audit Manager service."""

    def __init__(self, region: str, ctx):
        """
        Initialize Audit Manager client for a specific region.

        Args:
            region: AWS region name
            ctx: ScanContext for the current scan; the underlying boto3 client
                is obtained via ``ctx.get_client(...)`` so the per-scan client
                cache and bounded ``Client_Config`` are applied.
        """
        self.region = region
        self.ctx = ctx
        self.client = ctx.get_client('auditmanager', region=region)

    def get_account_status(self) -> Dict[str, Any]:
        """
        Get the registration status of the account in Audit Manager.

        Returns:
            Dictionary containing status or error information
        """
        try:
            response = self.client.get_account_status()
            return response
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = str(e)
            logger.error(f"Error getting account status in {self.region}: {error_message}")

    def get_organization_admin_account(self) -> Dict[str, Any]:
        """
        Get the delegated administrator account for the organization.

        Returns:
            Dictionary containing admin account info or error information
        """
        try:
            response = self.client.get_organization_admin_account()
            return response
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = str(e)

            # Don't log setup required errors as they're handled as FAIL in the check
            if "Please complete AWS Audit Manager setup" not in error_message:
                logger.error(f"Error getting organization admin account in {self.region}: {error_message}")

            return {"Error": {"Code": error_code, "Message": error_message}}
