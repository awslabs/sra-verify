"""
S3 client for interacting with AWS S3 service.
"""
from typing import Dict, List, Optional, Any
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger


class S3Client:
    """Client for interacting with AWS S3 service."""
    
    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        """
        Initialize S3 client for a specific region.
        
        Args:
            region: AWS region name
            session: AWS session to use (if None, a new session will be created)
        """
        self.region = region
        self.session = session or boto3.Session()
        self.client = self.session.client('s3', region_name=region)
        self.s3control_client = self.session.client('s3control', region_name=region)
        
    def get_public_access_block(self, account_id: str) -> Dict[str, Any]:
        """
        Get the public access block configuration for an account.
        
        Args:
            account_id: AWS account ID
            
        Returns:
            Public access block configuration
        """
        try:
            logger.debug(f"Getting public access block configuration for account {account_id} in {self.region}")
            response = self.s3control_client.get_public_access_block(
                AccountId=account_id
            )
            return response.get('PublicAccessBlockConfiguration', {})
        except ClientError as e:
            if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                logger.warning(f"No public access block configuration found for account {account_id} in {self.region}")
                return {}
            logger.error(f"Error getting public access block configuration for account {account_id} in {self.region}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error getting public access block configuration for account {account_id} in {self.region}: {e}")
            return {}
