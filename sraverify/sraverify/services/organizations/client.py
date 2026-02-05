"""
Organizations client for interacting with AWS Organizations service.
"""
from typing import Dict, List, Optional, Any
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger


class OrganizationsClient:
    """Client for interacting with AWS Organizations service."""
    
    def __init__(self, session: Optional[boto3.Session] = None):
        """
        Initialize Organizations client.
        
        Args:
            session: AWS session to use (if None, a new session will be created)
        """
        self.session = session or boto3.Session()
        # Organizations is a global service, always use us-east-1
        self.client = self.session.client('organizations', region_name='us-east-1')
    
    def describe_organization(self) -> Dict[str, Any]:
        """
        Get organization details.
        
        Returns:
            Dictionary with Organization key containing organization details,
            or Error key if an error occurred.
        """
        try:
            response = self.client.describe_organization()
            return response
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            logger.error(f"Error describing organization: {error_message}")
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }

    def list_roots(self) -> Dict[str, Any]:
        """
        List organization roots with pagination support.
        
        Returns:
            Dictionary with Roots key containing list of roots,
            or Error key if an error occurred.
        """
        try:
            roots = []
            paginator = self.client.get_paginator('list_roots')
            for page in paginator.paginate():
                roots.extend(page.get('Roots', []))
            return {"Roots": roots}
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            logger.error(f"Error listing roots: {error_message}")
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }
    
    def list_organizational_units_for_parent(self, parent_id: str) -> Dict[str, Any]:
        """
        List organizational units under a parent with pagination support.
        
        Args:
            parent_id: The ID of the parent root or OU
            
        Returns:
            Dictionary with OrganizationalUnits key containing list of OUs,
            or Error key if an error occurred.
        """
        try:
            ous = []
            paginator = self.client.get_paginator('list_organizational_units_for_parent')
            for page in paginator.paginate(ParentId=parent_id):
                ous.extend(page.get('OrganizationalUnits', []))
            return {"OrganizationalUnits": ous}
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            logger.error(f"Error listing OUs for parent {parent_id}: {error_message}")
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }
    
    def list_policies(self, policy_type: str = "SERVICE_CONTROL_POLICY") -> Dict[str, Any]:
        """
        List policies by type with pagination support.
        
        Args:
            policy_type: Type of policy to list (default: SERVICE_CONTROL_POLICY)
            
        Returns:
            Dictionary with Policies key containing list of policies,
            or Error key if an error occurred.
        """
        try:
            policies = []
            paginator = self.client.get_paginator('list_policies')
            for page in paginator.paginate(Filter=policy_type):
                policies.extend(page.get('Policies', []))
            return {"Policies": policies}
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            logger.error(f"Error listing policies of type {policy_type}: {error_message}")
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }

    def list_accounts_for_parent(self, parent_id: str) -> Dict[str, Any]:
        """
        List accounts under a parent (root or OU) with pagination support.
        
        Args:
            parent_id: The ID of the parent root or OU
            
        Returns:
            Dictionary with Accounts key containing list of accounts,
            or Error key if an error occurred.
        """
        try:
            accounts = []
            paginator = self.client.get_paginator('list_accounts_for_parent')
            for page in paginator.paginate(ParentId=parent_id):
                accounts.extend(page.get('Accounts', []))
            return {"Accounts": accounts}
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            logger.error(f"Error listing accounts for parent {parent_id}: {error_message}")
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }
