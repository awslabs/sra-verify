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
        self.org_client = self.session.client('organizations', region_name=region)

    def describe_trails(self, trail_name_list: Optional[List[str]] = None, include_shadow_trails: bool = True) -> List[Dict[str, Any]]:
        """
        Describe one or more trails.
        
        Args:
            trail_name_list: List of trail names to describe (if None, all trails are described)
            include_shadow_trails: Include shadow trails in the response
            
        Returns:
            List of trail descriptions
        """
        try:
            params = {}
            if trail_name_list:
                params['trailNameList'] = trail_name_list
            params['includeShadowTrails'] = include_shadow_trails
            
            logger.debug(f"Describing trails in {self.region} with params: {params}")
            response = self.client.describe_trails(**params)
            return response.get('trailList', [])
        except ClientError as e:
            logger.error(f"Error describing trails in {self.region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error describing trails in {self.region}: {e}")
            return []
    
    def get_trail_status(self, trail_arn: str) -> Dict[str, Any]:
        """
        Get the status of a trail.
        
        Args:
            trail_arn: ARN of the trail
            
        Returns:
            Trail status
        """
        try:
            logger.debug(f"Getting status for trail {trail_arn} in {self.region}")
            response = self.client.get_trail_status(Name=trail_arn)
            return response
        except ClientError as e:
            logger.error(f"Error getting trail status for {trail_arn} in {self.region}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error getting trail status for {trail_arn} in {self.region}: {e}")
            return {}
    
    def list_delegated_administrators(self, service_principal: str = "cloudtrail.amazonaws.com") -> List[Dict[str, Any]]:
        """
        List delegated administrators for CloudTrail.
        
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
