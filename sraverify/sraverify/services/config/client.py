"""
AWS Config client for interacting with AWS Config service.
"""
from typing import Dict, List, Optional, Any
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger


class ConfigClient:
    """Client for interacting with AWS Config service."""
    
    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        """
        Initialize Config client for a specific region.
        
        Args:
            region: AWS region name
            session: AWS session to use (if None, a new session will be created)
        """
        self.region = region
        self.session = session or boto3.Session()
        self.client = self.session.client('config', region_name=region)
        self.org_client = self.session.client('organizations', region_name=region)

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
    
    def get_management_account_id(self) -> Optional[str]:
        """
        Get the management account ID for the organization.
        
        Returns:
            Management account ID or None if not available
        """
        try:
            logger.debug(f"Getting management account ID in {self.region}")
            response = self.org_client.describe_organization()
            management_account_id = response["Organization"]["MasterAccountId"]
            logger.debug(f"Management account ID: {management_account_id}")
            return management_account_id
        except ClientError as e:
            logger.error(f"Error getting management account ID: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting management account ID: {e}")
            return None

    def describe_configuration_recorders(self) -> List[Dict[str, Any]]:
        """
        Describe configuration recorders in the current region.
        
        Returns:
            List of configuration recorders
        """
        try:
            logger.debug(f"Describing configuration recorders in {self.region}")
            response = self.client.describe_configuration_recorders()
            recorders = response.get('ConfigurationRecorders', [])
            logger.debug(f"Found {len(recorders)} configuration recorders in {self.region}")
            return recorders
        except ClientError as e:
            logger.error(f"Error describing configuration recorders in {self.region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error describing configuration recorders in {self.region}: {e}")
            return []
    
    def describe_configuration_recorder_status(self) -> List[Dict[str, Any]]:
        """
        Describe configuration recorder status in the current region.
        
        Returns:
            List of configuration recorder statuses
        """
        try:
            logger.debug(f"Describing configuration recorder status in {self.region}")
            response = self.client.describe_configuration_recorder_status()
            statuses = response.get('ConfigurationRecordersStatus', [])
            logger.debug(f"Found {len(statuses)} configuration recorder statuses in {self.region}")
            return statuses
        except ClientError as e:
            logger.error(f"Error describing configuration recorder status in {self.region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error describing configuration recorder status in {self.region}: {e}")
            return []
    
    def describe_delivery_channels(self) -> List[Dict[str, Any]]:
        """
        Describe delivery channels in the current region.
        
        Returns:
            List of delivery channels
        """
        try:
            logger.debug(f"Describing delivery channels in {self.region}")
            response = self.client.describe_delivery_channels()
            channels = response.get('DeliveryChannels', [])
            logger.debug(f"Found {len(channels)} delivery channels in {self.region}")
            return channels
        except ClientError as e:
            logger.error(f"Error describing delivery channels in {self.region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error describing delivery channels in {self.region}: {e}")
            return []
    
    def describe_delivery_channel_status(self) -> List[Dict[str, Any]]:
        """
        Describe delivery channel status in the current region.
        
        Returns:
            List of delivery channel statuses
        """
        try:
            logger.debug(f"Describing delivery channel status in {self.region}")
            response = self.client.describe_delivery_channel_status()
            statuses = response.get('DeliveryChannelsStatus', [])
            logger.debug(f"Found {len(statuses)} delivery channel statuses in {self.region}")
            return statuses
        except ClientError as e:
            logger.error(f"Error describing delivery channel status in {self.region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error describing delivery channel status in {self.region}: {e}")
            return []
