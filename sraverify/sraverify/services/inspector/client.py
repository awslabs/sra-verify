"""
Inspector client for interacting with AWS Inspector service.
"""
from typing import Dict, List, Any
from botocore.exceptions import ClientError
from sraverify.core.logging import logger
from sraverify.core.scan_context import ScanContext


class InspectorClient:
    """Client for interacting with AWS Inspector service."""

    def __init__(self, region: str, ctx: ScanContext):
        """
        Initialize Inspector client for a specific region.

        Args:
            region: AWS region name
            ctx: The ``ScanContext`` whose per-scan boto3 client cache and
                ``Client_Config`` back every underlying boto3 client this
                wrapper uses. Underlying boto3 clients are obtained via
                ``ctx.get_client`` so they are cached for the lifetime of the
                scan and pick up the bounded timeouts/retries from the
                context's ``Client_Config``.
        """
        self.region = region
        self.ctx = ctx
        # Inspector v2 uses the boto3 service name ``inspector2``.
        self.client = ctx.get_client('inspector2', region=region)
        self.org_client = ctx.get_client('organizations', region=region)

    def batch_get_account_status(self, account_ids: List[str]) -> Dict[str, Any]:
        """
        Get the Inspector account status for specified accounts.

        Args:
            account_ids: List of AWS account IDs

        Returns:
            Dictionary containing account status information
        """
        try:
            logger.debug(f"Getting Inspector account status for accounts {account_ids} in {self.region}")
            response = self.client.batch_get_account_status(accountIds=account_ids)
            return response
        except ClientError as e:
            logger.debug(f"Error getting Inspector account status in {self.region}: {e}")
            return {}
        except Exception as e:
            logger.debug(f"Unexpected error getting Inspector account status in {self.region}: {e}")
            return {}

    def get_delegated_admin_account(self) -> Dict[str, Any]:
        """
        Get the delegated administrator account for Inspector.

        Returns:
            Dictionary containing delegated admin account information
        """
        try:
            logger.debug(f"Getting Inspector delegated admin account in {self.region}")
            response = self.client.get_delegated_admin_account()
            return response
        except ClientError as e:
            logger.debug(f"Error getting Inspector delegated admin account in {self.region}: {e}")
            return {}
        except Exception as e:
            logger.debug(f"Unexpected error getting Inspector delegated admin account in {self.region}: {e}")
            return {}

    def describe_organization_configuration(self) -> Dict[str, Any]:
        """
        Describe Inspector organization configuration.

        Returns:
            Dictionary containing organization configuration
        """
        try:
            logger.debug(f"Describing Inspector organization configuration in {self.region}")
            response = self.client.describe_organization_configuration()
            return response
        except ClientError as e:
            logger.debug(f"Error describing Inspector organization configuration in {self.region}: {e}")
            return {}
        except Exception as e:
            logger.debug(f"Unexpected error describing Inspector organization configuration in {self.region}: {e}")
            return {}

    def list_organization_accounts(self) -> List[Dict[str, Any]]:
        """
        List all accounts in the AWS Organization.

        Returns:
            List of organization accounts
        """
        try:
            logger.debug(f"Listing organization accounts in {self.region}")
            response = self.org_client.list_accounts()
            return response.get('Accounts', [])
        except ClientError as e:
            logger.debug(f"Error listing organization accounts in {self.region}: {e}")
            return []
        except Exception as e:
            logger.debug(f"Unexpected error listing organization accounts in {self.region}: {e}")
            return []
