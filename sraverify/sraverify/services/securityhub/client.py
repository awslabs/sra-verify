"""
SecurityHub client for interacting with AWS SecurityHub service.
"""
from typing import Dict, List, Optional, Any
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger


class SecurityHubClient:
    """Client for interacting with AWS SecurityHub service."""
    
    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        """
        Initialize SecurityHub client for a specific region.
        
        Args:
            region: AWS region name
            session: AWS session to use (if None, a new session will be created)
        """
        self.region = region
        self.session = session or boto3.Session()
        self.client = self.session.client('securityhub', region_name=region)
        self.org_client = self.session.client('organizations', region_name=region)

    def get_enabled_standards(self) -> List[Dict[str, Any]]:
        """
        Get all enabled Security Hub standards.
        
        Returns:
            List of enabled standards or None if Security Hub is not enabled
        """
        try:
            logger.debug(f"Getting enabled standards in {self.region}")
            response = self.client.get_enabled_standards()
            standards = response.get('StandardsSubscriptions', [])
            
            # Handle pagination
            while response.get('NextToken'):
                response = self.client.get_enabled_standards(NextToken=response['NextToken'])
                standards.extend(response.get('StandardsSubscriptions', []))
                
            logger.debug(f"Found {len(standards)} enabled standards in {self.region}")
            return standards
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', '')
            
            # Check if this is the "not subscribed to AWS Security Hub" error
            if error_code == 'InvalidAccessException' and 'not subscribed to AWS Security Hub' in error_message:
                # Return None specifically for this error to indicate Security Hub is not enabled
                # Don't log this as an error since it's an expected condition we want to check for
                logger.debug(f"Security Hub is not enabled in {self.region}")
                return None
                
            # For other errors, log a warning instead of an error
            logger.warning(f"Error getting enabled standards in {self.region}: {e}")
            return []
        except Exception as e:
            logger.warning(f"Unexpected error getting enabled standards in {self.region}: {e}")
            return []
    
    def list_organization_admin_accounts(self) -> List[Dict[str, Any]]:
        """
        List Security Hub administrator accounts for the organization.
        
        Returns:
            List of administrator accounts
        """
        try:
            logger.debug(f"Listing organization admin accounts in {self.region}")
            response = self.client.list_organization_admin_accounts()
            admin_accounts = response.get('AdminAccounts', [])
            
            # Handle pagination
            while response.get('NextToken'):
                response = self.client.list_organization_admin_accounts(NextToken=response['NextToken'])
                admin_accounts.extend(response.get('AdminAccounts', []))
                
            logger.debug(f"Found {len(admin_accounts)} organization admin accounts in {self.region}")
            return admin_accounts
        except ClientError as e:
            logger.error(f"Error listing organization admin accounts in {self.region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing organization admin accounts in {self.region}: {e}")
            return []
    
    def get_administrator_account(self) -> Dict[str, Any]:
        """
        Get the Security Hub administrator account for the current account.
        
        Returns:
            Administrator account information
        """
        try:
            logger.debug(f"Getting administrator account in {self.region}")
            response = self.client.get_administrator_account()
            logger.debug(f"Administrator account: {response}")
            return response
        except ClientError as e:
            logger.error(f"Error getting administrator account in {self.region}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error getting administrator account in {self.region}: {e}")
            return {}
    
    def describe_organization_configuration(self) -> Dict[str, Any]:
        """
        Describe the Security Hub organization configuration.
        
        Returns:
            Organization configuration
        """
        try:
            logger.debug(f"Describing organization configuration in {self.region}")
            response = self.client.describe_organization_configuration()
            logger.debug(f"Organization configuration: {response}")
            return response
        except ClientError as e:
            # Don't log the error here, let the check handle it
            return {}
        except Exception as e:
            # Only log unexpected errors
            logger.error(f"Unexpected error describing organization configuration in {self.region}: {e}")
            return {}
    
    
    def list_enabled_products_for_import(self) -> Optional[List[str]]:
        """
        List enabled products for import into Security Hub.
        
        Returns:
            List of enabled product ARNs, or None if Security Hub is not enabled
        """
        try:
            logger.debug(f"Listing enabled products for import in {self.region}")
            response = self.client.list_enabled_products_for_import()
            product_subscriptions = response.get('ProductSubscriptions', [])
            
            # Handle pagination
            while response.get('NextToken'):
                response = self.client.list_enabled_products_for_import(NextToken=response['NextToken'])
                product_subscriptions.extend(response.get('ProductSubscriptions', []))
                
            logger.debug(f"Found {len(product_subscriptions)} enabled products in {self.region}")
            return product_subscriptions
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', '')
            
            # Check if this is the "not subscribed to AWS Security Hub" error
            if error_code == 'InvalidAccessException' and 'not subscribed to AWS Security Hub' in error_message:
                # Return None specifically for this error to indicate Security Hub is not enabled
                logger.debug(f"Security Hub is not enabled in {self.region}")
                return None
                
            # For other errors, log as error and return empty list
            logger.error(f"Error listing enabled products in {self.region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing enabled products in {self.region}: {e}")
            return []
    
    def list_delegated_administrators(self, service_principal: str = "securityhub.amazonaws.com") -> List[Dict[str, Any]]:
        """
        List delegated administrators for SecurityHub.
        
        Args:
            service_principal: Service principal to check for delegated administrators
            
        Returns:
            List of delegated administrators
        """
        try:
            logger.debug(f"Listing delegated administrators for {service_principal} in {self.region}")
            response = self.org_client.list_delegated_administrators(ServicePrincipal=service_principal)
            delegated_admins = response.get('DelegatedAdministrators', [])
            
            # Handle pagination
            while response.get('NextToken'):
                response = self.org_client.list_delegated_administrators(
                    ServicePrincipal=service_principal,
                    NextToken=response['NextToken']
                )
                delegated_admins.extend(response.get('DelegatedAdministrators', []))
                
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
        List Security Hub member accounts.
        
        Returns:
            List of member accounts
        """
        try:
            logger.debug(f"Listing Security Hub members in {self.region}")
            response = self.client.list_members()
            members = response.get('Members', [])
            
            # Handle pagination
            while response.get('NextToken'):
                response = self.client.list_members(NextToken=response['NextToken'])
                members.extend(response.get('Members', []))
                
            logger.debug(f"Found {len(members)} Security Hub members in {self.region}")
            return members
        except ClientError as e:
            logger.error(f"Error listing Security Hub members in {self.region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing Security Hub members in {self.region}: {e}")
            return []
    
    def list_organization_accounts(self) -> List[Dict[str, Any]]:
        """
        List all accounts in the organization.
        
        Returns:
            List of organization accounts
        """
        try:
            logger.debug(f"Listing organization accounts in {self.region}")
            response = self.org_client.list_accounts()
            accounts = response.get('Accounts', [])
            
            # Handle pagination
            while response.get('NextToken'):
                response = self.org_client.list_accounts(NextToken=response['NextToken'])
                accounts.extend(response.get('Accounts', []))
                
            logger.debug(f"Found {len(accounts)} organization accounts")
            return accounts
        except ClientError as e:
            logger.error(f"Error listing organization accounts: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing organization accounts: {e}")
            return []
