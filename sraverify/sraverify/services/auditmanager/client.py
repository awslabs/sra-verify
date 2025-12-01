"""
Audit Manager client for interacting with AWS Audit Manager service.
"""
from typing import Dict, Optional, Any
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger


class AuditManagerClient:
    """Client for interacting with AWS Audit Manager service."""

    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        """
        Initialize Audit Manager client for a specific region.

        Args:
            region: AWS region name
            session: AWS session to use (if None, a new session will be created)
        """
        self.region = region
        self.session = session or boto3.Session()
        self.client = self.session.client('auditmanager', region_name=region)

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
