"""
CloudTrail client for interacting with AWS CloudTrail service.
"""
from typing import Dict, List, Optional, Any
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger


class CloudTrailClient:
    """Client for interacting with AWS CloudTrail service."""
    
    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        """
        Initialize CloudTrail client for a specific region.
        
        Args:
            region: AWS region name
            session: AWS session to use (if None, a new session will be created)
        """
        self.region = region
        self.session = session or boto3.Session()
        self.client = self.session.client('cloudtrail', region_name=region)

    def list_trails(self) -> List[Dict[str, Any]]:
        """
        List all trails in the current region.
        
        Returns:
            List of trails
        """
        try:
            logger.debug(f"Listing trails in {self.region}")
            response = self.client.list_trails()
            return response.get('Trails', [])
        except ClientError as e:
            logger.error(f"Error listing trails in {self.region}: {e}")
            return []
    
    def describe_trails(self, trail_name_list: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Describe one or more trails.
        
        Args:
            trail_name_list: List of trail names to describe (if None, all trails are described)
            
        Returns:
            List of trail descriptions
        """
        try:
            if trail_name_list:
                logger.debug(f"Describing specific trails in {self.region}: {trail_name_list}")
                response = self.client.describe_trails(trailNameList=trail_name_list)
            else:
                logger.debug(f"Describing all trails in {self.region}")
                response = self.client.describe_trails()
            return response.get('trailList', [])
        except ClientError as e:
            logger.error(f"Error describing trails in {self.region}: {e}")
            return []
