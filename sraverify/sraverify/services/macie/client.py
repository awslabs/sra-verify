"""
Macie client for interacting with AWS Macie service.
"""
from typing import Dict, List, Optional, Any
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger


class MacieClient:
    """Client for interacting with AWS Macie service."""
    
    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        """
        Initialize Macie client for a specific region.
        
        Args:
            region: AWS region name
            session: AWS session to use (if None, a new session will be created)
        """
        self.region = region
        self.session = session or boto3.Session()
        self.client = self.session.client('macie2', region_name=region)
        self.org_client = self.session.client('organizations', region_name=region)

    def get_findings_publication_configuration(self) -> Dict[str, Any]:
        """
        Get the findings publication configuration for Macie.
        
        Returns:
            Dictionary containing findings publication configuration
        """
        try:
            logger.debug(f"Getting Macie findings publication configuration in {self.region}")
            response = self.client.get_findings_publication_configuration()
            logger.debug(f"Macie findings publication configuration in {self.region}: {response}")
            return response
        except ClientError as e:
            error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', '')
            error_message = str(e)
            if error_code == 'AccessDeniedException' or 'Macie is not enabled' in error_message:
                # If we get an access denied exception, it might be because Macie is not enabled
                # in this region for this account
                logger.debug(f"Access denied when getting Macie findings publication configuration in {self.region}. Macie might not be enabled in this region.")
            else:
                logger.debug(f"Error getting Macie findings publication configuration in {self.region}: {e}")
            return {}
        except Exception as e:
            logger.debug(f"Unexpected error getting Macie findings publication configuration in {self.region}: {e}")
            return {}
    
    def get_classification_export_configuration(self) -> Dict[str, Any]:
        """
        Get the classification export configuration for Macie.
        
        Returns:
            Dictionary containing classification export configuration
        """
        try:
            logger.debug(f"Getting Macie classification export configuration in {self.region}")
            response = self.client.get_classification_export_configuration()
            logger.debug(f"Macie classification export configuration in {self.region}: {response}")
            return response
        except ClientError as e:
            error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', '')
            error_message = str(e)
            if error_code == 'AccessDeniedException' or 'Macie is not enabled' in error_message:
                logger.debug(f"Access denied when getting Macie classification export configuration in {self.region}. Macie might not be enabled in this region.")
            else:
                logger.debug(f"Error getting Macie classification export configuration in {self.region}: {e}")
            return {}
        except Exception as e:
            logger.debug(f"Unexpected error getting Macie classification export configuration in {self.region}: {e}")
            return {}
    
    def list_delegated_administrators(self, service_principal: str = "macie.amazonaws.com") -> List[Dict[str, Any]]:
        """
        List delegated administrators for Macie.
        
        Args:
            service_principal: Service principal to check for delegated administrators
            
        Returns:
            List of delegated administrators
        """
        try:
            logger.debug(f"Listing delegated administrators for {service_principal} in {self.region}")
            response = self.org_client.list_delegated_administrators(ServicePrincipal=service_principal)
            delegated_admins = response.get('DelegatedAdministrators', [])
            logger.debug(f"Found {len(delegated_admins)} delegated administrators for {service_principal}")
            for admin in delegated_admins:
                logger.debug(f"Delegated admin: {admin.get('Id')} - {admin.get('Name')}")
            return delegated_admins
        except ClientError as e:
            logger.error(f"Error listing delegated administrators for {service_principal}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing delegated administrators: {e}")
            return []
    
    def list_members(self) -> List[Dict[str, Any]]:
        """
        List Macie members.
        
        Returns:
            List of Macie members
        """
        try:
            logger.debug(f"Listing Macie members in {self.region}")
            members = []
            paginator = self.client.get_paginator('list_members')
            
            for page in paginator.paginate():
                members.extend(page.get('members', []))
            
            logger.debug(f"Found {len(members)} Macie members in {self.region}")
            return members
        except ClientError as e:
            error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', '')
            error_message = str(e)
            if error_code == 'AccessDeniedException' or 'Macie is not enabled' in error_message:
                logger.debug(f"Access denied when listing Macie members in {self.region}. This is expected if the account is not a Macie admin account or Macie is not enabled.")
            else:
                logger.debug(f"Error listing Macie members in {self.region}: {e}")
            return []
        except Exception as e:
            logger.debug(f"Unexpected error listing Macie members in {self.region}: {e}")
            return []
    
    def list_organization_accounts(self) -> List[Dict[str, Any]]:
        """
        List all accounts in the AWS Organization.
        
        Returns:
            List of accounts in the AWS Organization
        """
        try:
            logger.debug(f"Listing AWS Organization accounts in {self.region}")
            accounts = []
            paginator = self.org_client.get_paginator('list_accounts')
            
            for page in paginator.paginate():
                accounts.extend(page.get('Accounts', []))
            
            logger.debug(f"Found {len(accounts)} AWS Organization accounts")
            return accounts
        except ClientError as e:
            logger.error(f"Error listing AWS Organization accounts: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing AWS Organization accounts: {e}")
            return []
    
    def describe_organization_configuration(self) -> Dict[str, Any]:
        """
        Describe the Macie organization configuration.
        
        Returns:
            Dictionary containing Macie organization configuration
        """
        try:
            logger.debug(f"Describing Macie organization configuration in {self.region}")
            response = self.client.describe_organization_configuration()
            logger.debug(f"Macie organization configuration in {self.region}: {response}")
            return response
        except ClientError as e:
            error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', '')
            error_message = str(e)
            if error_code == 'AccessDeniedException' or 'Macie is not enabled' in error_message or 'must be the Macie administrator' in error_message:
                logger.debug(f"Access denied when describing Macie organization configuration in {self.region}. This is expected if the account is not a Macie admin account or Macie is not enabled.")
            else:
                logger.debug(f"Error describing Macie organization configuration in {self.region}: {e}")
            return {}
        except Exception as e:
            logger.debug(f"Unexpected error describing Macie organization configuration in {self.region}: {e}")
            return {}
    
    def get_account_id(self) -> Optional[str]:
        """
        Get the current account ID.
        
        Returns:
            Current account ID or None if not available
        """
        try:
            logger.debug(f"Getting current account ID in {self.region}")
            sts_client = self.session.client("sts")
            response = sts_client.get_caller_identity()
            account_id = response["Account"]
            logger.debug(f"Current account ID: {account_id}")
            return account_id
        except ClientError as e:
            logger.error(f"Error getting current account ID: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting current account ID: {e}")
            return None
    def get_administrator_account(self) -> Dict[str, Any]:
        """
        Get the Macie administrator account.
        
        Returns:
            Dictionary containing Macie administrator account information
        """
        try:
            logger.debug(f"Getting Macie administrator account in {self.region}")
            response = self.client.get_administrator_account()
            logger.debug(f"Macie administrator account in {self.region}: {response}")
            return response
        except ClientError as e:
            error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', '')
            error_message = str(e)
            if error_code == 'AccessDeniedException' or 'Macie is not enabled' in error_message:
                logger.debug(f"Access denied when getting Macie administrator account in {self.region}. Macie might not be enabled in this region.")
            else:
                logger.debug(f"Error getting Macie administrator account in {self.region}: {e}")
            return {}
        except Exception as e:
            logger.debug(f"Unexpected error getting Macie administrator account in {self.region}: {e}")
            return {}
