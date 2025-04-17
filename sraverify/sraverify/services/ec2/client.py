"""
EC2 client for interacting with AWS EC2 service.
"""
from typing import Dict, List, Optional, Any
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger


class EC2Client:
    """Client for interacting with AWS EC2 service."""
    
    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        """
        Initialize EC2 client for a specific region.
        
        Args:
            region: AWS region name
            session: AWS session to use (if None, a new session will be created)
        """
        self.region = region
        self.session = session or boto3.Session()
        self.client = self.session.client('ec2', region_name=region)

    def get_ebs_encryption_by_default(self) -> Dict[str, Any]:
        """
        Get the EBS encryption by default status for the account in the region.
        
        Returns:
            Dictionary containing EBS encryption by default status
        """
        try:
            logger.debug(f"Getting EBS encryption by default status in {self.region}")
            response = self.client.get_ebs_encryption_by_default()
            logger.debug(f"EBS encryption by default status in {self.region}: {response}")
            return response
        except ClientError as e:
            logger.error(f"Error getting EBS encryption by default status in {self.region}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error getting EBS encryption by default status in {self.region}: {e}")
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
