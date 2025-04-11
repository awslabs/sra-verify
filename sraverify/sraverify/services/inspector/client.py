"""
Inspector client for interacting with AWS Inspector service.
"""
from typing import Dict, List, Optional, Any
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger


class InspectorClient:
    """Client for interacting with AWS Inspector service."""
    
    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        """
        Initialize Inspector client for a specific region.
        
        Args:
            region: AWS region name
            session: AWS session to use (if None, a new session will be created)
        """
        self.region = region
        self.session = session or boto3.Session()
        self.client = self.session.client('inspector2', region_name=region)
        self.org_client = self.session.client('organizations', region_name=region)

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
