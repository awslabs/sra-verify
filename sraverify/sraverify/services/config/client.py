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
        self.s3_client = self.session.client('s3', region_name=region)

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
            
    def describe_configuration_aggregators(self) -> List[Dict[str, Any]]:
        """
        Describe configuration aggregators in the current region.
        
        Returns:
            List of configuration aggregators
        """
        try:
            logger.debug(f"Describing configuration aggregators in {self.region}")
            response = self.client.describe_configuration_aggregators()
            aggregators = response.get('ConfigurationAggregators', [])
            logger.debug(f"Found {len(aggregators)} configuration aggregators in {self.region}")
            return aggregators
        except ClientError as e:
            logger.error(f"Error describing configuration aggregators in {self.region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error describing configuration aggregators in {self.region}: {e}")
            return []
            
    def describe_configuration_aggregator_sources_status(self, aggregator_name: str) -> List[Dict[str, Any]]:
        """
        Describe configuration aggregator sources status in the current region.
        
        Args:
            aggregator_name: Name of the configuration aggregator
            
        Returns:
            List of configuration aggregator sources statuses
        """
        try:
            logger.debug(f"Describing configuration aggregator sources status for {aggregator_name} in {self.region}")
            response = self.client.describe_configuration_aggregator_sources_status(
                ConfigurationAggregatorName=aggregator_name
            )
            source_statuses = response.get('AggregatedSourceStatusList', [])
            logger.debug(f"Found {len(source_statuses)} source statuses for aggregator {aggregator_name} in {self.region}")
            return source_statuses
        except ClientError as e:
            logger.error(f"Error describing configuration aggregator sources status in {self.region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error describing configuration aggregator sources status in {self.region}: {e}")
            return []
            
    def get_bucket_location(self, bucket_name: str) -> Optional[str]:
        """
        Get the location of an S3 bucket.
        
        Args:
            bucket_name: Name of the S3 bucket
            
        Returns:
            Region of the S3 bucket or None if not available
        """
        try:
            logger.debug(f"Getting location for bucket {bucket_name}")
            response = self.s3_client.get_bucket_location(Bucket=bucket_name)
            location = response.get('LocationConstraint')
            # If location is None, the bucket is in us-east-1
            bucket_region = location if location else 'us-east-1'
            logger.debug(f"Bucket {bucket_name} is in region {bucket_region}")
            return bucket_region
        except ClientError as e:
            logger.error(f"Error getting bucket location for {bucket_name}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting bucket location for {bucket_name}: {e}")
            return None
            
    def get_bucket_policy(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """
        Get the policy of an S3 bucket.
        
        Args:
            bucket_name: Name of the S3 bucket
            
        Returns:
            Policy of the S3 bucket or None if not available
        """
        try:
            logger.debug(f"Getting policy for bucket {bucket_name}")
            response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = response.get('Policy')
            logger.debug(f"Got policy for bucket {bucket_name}")
            return policy
        except ClientError as e:
            logger.error(f"Error getting bucket policy for {bucket_name}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting bucket policy for {bucket_name}: {e}")
            return None
            
    def list_delegated_administrators(self, service_principal: str = "config.amazonaws.com") -> List[Dict[str, Any]]:
        """
        List delegated administrators for a specific service principal.
        
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
