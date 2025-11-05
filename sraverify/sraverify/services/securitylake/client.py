"""Security Lake client for interacting with AWS Security Lake service."""

from typing import Dict, List, Optional, Any
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger


class SecurityLakeClient:
    """Client for interacting with AWS Security Lake service."""

    def __init__(self, region: str, session: Optional[boto3.Session] = None):
        """
        Initialize Security Lake client.

        Args:
            region: AWS region name
            session: Optional boto3 session
        """
        self.region = region
        self.session = session or boto3.Session()
        self.client = self.session.client('securitylake', region_name=region)
        self.org_client = self.session.client('organizations', region_name=region)

    def is_security_lake_enabled(self):
        """
        Check if Security Lake is enabled in the region.

        Returns:
            True if enabled, False otherwise
        """
        try:
            response = self.client.list_data_lakes(regions=[self.region])
            data_lakes = response.get('dataLakes', [])
            return len(data_lakes) > 0
        except ClientError as e:
            logger.debug(f"Error checking Security Lake status in {self.region}: {e}")
            return False

    def get_organization_configuration(self):
        """
        Get Security Lake organization configuration.

        Returns:
            Organization configuration or empty dict if error
        """
        try:
            response = self.client.get_data_lake_organization_configuration()
            return response
        except self.client.exceptions.ResourceNotFoundException:
            logger.debug(f"No organization configuration found in region {self.region}")
            return {}
        except ClientError as e:
            logger.error(f"Error getting organization configuration in {self.region}: {e}")
            return {}

    def list_data_lakes(self):
        """
        List Security Lake data lakes.

        Returns:
            List of data lakes or empty list if error
        """
        try:
            response = self.client.list_data_lakes(regions=[self.region])
            return response.get("dataLakes", [])
        except self.client.exceptions.ResourceNotFoundException:
            logger.debug(f"No data lakes found in region {self.region}")
            return []
        except ClientError as e:
            logger.error(f"Error listing data lakes in {self.region}: {e}")
            return []

    def list_log_sources(self, regions=None, accounts=None):
        """
        List enabled log sources with pagination support.

        Args:
            regions: List of regions to filter (optional)
            accounts: List of account IDs to filter (optional)

        Returns:
            List of log sources or empty list if error
        """
        try:
            params = {}
            if regions:
                params['regions'] = regions
            if accounts:
                params['accounts'] = accounts
                
            response = self.client.list_log_sources(**params)
            log_sources = response.get("sources", [])

            # Handle pagination
            while response.get('nextToken'):
                params['nextToken'] = response['nextToken']
                response = self.client.list_log_sources(**params)
                log_sources.extend(response.get("sources", []))

            return log_sources
        except self.client.exceptions.ResourceNotFoundException:
            logger.debug(f"No log sources found in region {self.region}")
            return []
        except ClientError as e:
            logger.error(f"Error listing log sources in {self.region}: {e}")
            return []

    def list_subscribers(self):
        """
        List Security Lake subscribers with pagination support.

        Returns:
            List of subscribers or empty list if error
        """
        try:
            response = self.client.list_subscribers()
            subscribers = response.get("subscribers", [])

            # Handle pagination
            while response.get('nextToken'):
                response = self.client.list_subscribers(nextToken=response['nextToken'])
                subscribers.extend(response.get("subscribers", []))

            return subscribers
        except self.client.exceptions.ResourceNotFoundException:
            logger.debug(f"No subscribers found in region {self.region}")
            return []
        except ClientError as e:
            logger.error(f"Error listing subscribers in {self.region}: {e}")
            return []

    def get_delegated_admin(self):
        """
        Get Security Lake delegated admin account.

        Returns:
            Delegated admin info or None if error
        """
        try:
            response = self.org_client.list_delegated_administrators(ServicePrincipal="securitylake.amazonaws.com")
            admins = response.get("DelegatedAdministrators", [])
            return admins[0] if admins else None
        except ClientError as e:
            logger.error(f"Error getting delegated admin: {e}")
            return None

    def list_delegated_administrators(self, service_principal: str = "securitylake.amazonaws.com") -> List[Dict[str, Any]]:
        """
        List delegated administrators for SecurityLake.

        Args:
            service_principal: Service principal to check for delegated administrators

        Returns:
            List of delegated administrators or empty list if error
        """
        try:
            response = self.org_client.list_delegated_administrators(ServicePrincipal=service_principal)
            delegated_admins = response.get("DelegatedAdministrators", [])

            logger.debug(f"Found {len(delegated_admins)} delegated administrators for {service_principal}")
            for admin in delegated_admins:
                logger.debug(f"Delegated admin: {admin.get('Id')} - {admin.get('Name')}")
            return delegated_admins
        except ClientError as e:
            logger.error(f"Error listing delegated administrators for {service_principal}: {e}")
            return []

    def get_sqs_queue_encryption(self, queue_url):
        """
        Get SQS queue encryption settings.

        Args:
            queue_url: SQS queue URL

        Returns:
            KMS key ID or None if error
        """
        try:
            sqs = self.session.client('sqs', region_name=self.region)
            response = sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=["KmsMasterKeyId"]
            )
            return response.get("Attributes", {}).get("KmsMasterKeyId")
        except ClientError as e:
            logger.error(f"Error getting SQS queue encryption for {queue_url}: {e}")
            return None

    def list_organization_accounts(self) -> List[Dict[str, Any]]:
        """
        List all accounts in the organization.

        Returns:
            List of organization accounts or empty list if error
        """
        try:
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

    def get_data_lake_sources(self, account_id: str = None):
        """
        Get data lake sources for a specific account.
        
        Args:
            account_id: AWS account ID string to check sources for
            
        Returns:
            List of data lake sources or empty list if error
        """
        try:
            request_body = {}
            if account_id:
                # Ensure account_id is a string (extract ID if it's a dict like SecurityHub pattern)
                if isinstance(account_id, dict):
                    if 'Id' in account_id:
                        account_id = account_id['Id']
                    else:
                        logger.error(f"Cannot extract account ID from dict: {account_id}")
                        return []
                        
                request_body["accounts"] = [account_id]
                
            response = self.client.get_data_lake_sources(**request_body)
            return response.get("dataLakeSources", [])
        except self.client.exceptions.ResourceNotFoundException:
            logger.debug(f"No data lake sources found in region {self.region}")
            return []
        except ClientError as e:
            # Use debug level for UnauthorizedException as it's expected when Security Lake isn't enabled
            if e.response.get('Error', {}).get('Code') == 'UnauthorizedException':
                logger.debug(f"Security Lake not enabled in {self.region}: {e}")
            else:
                logger.error(f"Error getting data lake sources in {self.region}: {e}")
            return []
