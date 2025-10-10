"""
Account client for interacting with AWS Account Management service.
"""
from typing import Dict, Optional, Any
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger


class AccountClient:
    """Client for interacting with AWS Account Management service."""
    
    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        """
        Initialize Account client for a specific region.
        
        Args:
            region: AWS region name
            session: AWS session to use (if None, a new session will be created)
        """
        self.region = region
        self.session = session or boto3.Session()
        self.client = self.session.client('account', region_name=region)
    
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
