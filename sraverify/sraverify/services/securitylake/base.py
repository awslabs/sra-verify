"""Security Lake service module."""

from typing import List, Dict, Any, Optional
from sraverify.core.check import SecurityCheck
from sraverify.services.securitylake.client import SecurityLakeClient
from sraverify.core.logging import logger


class SecurityLakeCheck(SecurityCheck):
    """Security Lake service class with integrated check functionality."""

    # Class-level caches shared across all instances
    _subscribers_cache = {}
    _security_lake_status_cache = {}
    _organization_configuration_cache = {}
    _delegated_admin_cache = {}
    _organization_accounts_cache = {}
    _log_sources_cache = {}
    _sqs_encryption_cache = {}

    def __init__(self):
        """Initialize Security Lake service."""
        super().__init__(
            account_type="log-archive",
            service="SecurityLake",
            resource_type="AWS::SecurityLake::SecurityLake"
        )
        # Initialize log archive account attribute
        self._log_archive_accounts = None

    def _setup_clients(self):
        """Set up Security Lake clients for each region."""
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = SecurityLakeClient(region, session=self.session)

    def get_client(self, region: str) -> Optional[SecurityLakeClient]:
        """
        Get Security Lake client for a specific region.

        Args:
            region: AWS region name

        Returns:
            SecurityLakeClient for the region or None if not available
        """
        client = self._clients.get(region)
        if not client:
            logger.debug(f"No Security Lake client available for region {region}")
        return client

    def get_subscribers(self, region: str) -> List[Dict[str, Any]]:
        """
        Get Security Lake subscribers with caching.

        Args:
            region: AWS region name

        Returns:
            List of subscribers
        """
        if not self.account_id:
            logger.debug("Could not determine account ID")
            return []

        # Check cache first
        cache_key = f"{self.account_id}:{region}"
        if cache_key in self.__class__._subscribers_cache:
            logger.debug(f"Using cached subscribers for {cache_key}")
            return self.__class__._subscribers_cache[cache_key]

        client = self.get_client(region)
        if not client:
            return []

        try:
            # Get subscribers from client
            subscribers = client.list_subscribers()

            # Cache the results
            self.__class__._subscribers_cache[cache_key] = subscribers
            logger.debug(f"Cached {len(subscribers)} subscribers for {cache_key}")

            return subscribers
        except Exception as e:
            logger.debug(f"Error getting subscribers in {region}: {e}")
            return []

    def is_security_lake_enabled(self, region: str) -> bool:
        """
        Check if Security Lake is enabled with caching.

        Args:
            region: AWS region name

        Returns:
            True if Security Lake is enabled, False otherwise
        """
        if not self.account_id:
            logger.debug("Could not determine account ID")
            return False

        # Check cache first
        cache_key = f"{self.account_id}:{region}"
        if cache_key in self.__class__._security_lake_status_cache:
            logger.debug(f"Using cached Security Lake status for {cache_key}")
            return self.__class__._security_lake_status_cache[cache_key]

        client = self.get_client(region)
        if not client:
            return False

        try:
            # Check if Security Lake is enabled
            is_enabled = client.is_security_lake_enabled()

            # Cache the results
            self.__class__._security_lake_status_cache[cache_key] = is_enabled
            logger.debug(f"Cached Security Lake status for {cache_key}: {is_enabled}")

            return is_enabled
        except Exception as e:
            logger.debug(f"Error checking Security Lake status in {region}: {e}")
            self.__class__._security_lake_status_cache[cache_key] = False
            return False

    def get_organization_configuration(self, region: str) -> Dict[str, Any]:
        """
        Get Security Lake organization configuration with caching.

        Args:
            region: AWS region name

        Returns:
            Organization configuration
        """
        if not self.account_id:
            logger.debug("Could not determine account ID")
            return {}

        # Check cache first
        cache_key = f"{self.account_id}:{region}"
        if cache_key in self.__class__._organization_configuration_cache:
            logger.debug(f"Using cached organization configuration for {cache_key}")
            return self.__class__._organization_configuration_cache[cache_key]

        client = self.get_client(region)
        if not client:
            return {}

        try:
            # Get organization configuration from client
            org_config = client.get_organization_configuration()

            # Cache the results
            self.__class__._organization_configuration_cache[cache_key] = org_config
            logger.debug(f"Cached organization configuration for {cache_key}")

            return org_config
        except Exception as e:
            logger.debug(f"Error getting organization configuration in {region}: {e}")
            self.__class__._organization_configuration_cache[cache_key] = {}
            return {}

    def get_log_source_status(self, region: str, source_name: str) -> bool:
        """
        Check if a specific log source is enabled in a region.

        Args:
            region: AWS region name
            source_name: Name of the log source to check (e.g., 'ROUTE53', 'VPC_FLOW')

        Returns:
            True if the log source is enabled, False otherwise
        """
        if not self.account_id:
            logger.debug("Could not determine account ID")
            return False

        # Check cache first
        cache_key = f"{self.account_id}:{region}"
        if cache_key not in self.__class__._log_sources_cache:
            client = self.get_client(region)
            if not client:
                return False

            # Get log sources from client and cache them
            log_sources = client.list_log_sources()
            self.__class__._log_sources_cache[cache_key] = log_sources
            logger.debug(f"Cached {len(log_sources)} log source entries for {cache_key}")
        else:
            log_sources = self.__class__._log_sources_cache[cache_key]
            logger.debug(f"Using cached log sources for {cache_key}")

        # Navigate the nested structure to find the source
        # Structure: sources[].sources[].awsLogSource.sourceName
        for log_source_entry in log_sources:
            for source in log_source_entry.get("sources", []):
                aws_log_source = source.get("awsLogSource", {})
                if aws_log_source.get("sourceName") == source_name:
                    # Check if source is collecting
                    source_status = source.get("sourceStatus", [])
                    for status in source_status:
                        if status.get("status") == "COLLECTING":
                            return True
                    return False

        return False

    def get_delegated_administrators(self, region: str) -> List[Dict[str, Any]]:
        """
        Get Security Lake delegated administrators with caching.

        Args:
            region: AWS region name

        Returns:
            List of delegated administrators
        """
        if not self.account_id:
            logger.debug("Could not determine account ID")
            return []

        # Check cache first
        cache_key = f"{self.account_id}:{region}"
        if cache_key in self.__class__._delegated_admin_cache:
            logger.debug(f"Using cached delegated administrators for {cache_key}")
            return self.__class__._delegated_admin_cache[cache_key]

        client = self.get_client(region)
        if not client:
            return []

        try:
            # Get delegated administrators from client
            delegated_admins = client.list_delegated_administrators()

            # Cache the results
            self.__class__._delegated_admin_cache[cache_key] = delegated_admins
            logger.debug(f"Cached {len(delegated_admins)} delegated administrators for {cache_key}")

            return delegated_admins
        except Exception as e:
            logger.debug(f"Error getting delegated administrators in {region}: {e}")
            return []

    def get_organization_accounts(self, region: str) -> List[Dict[str, Any]]:
        """
        Get all organization accounts with caching.

        Args:
            region: AWS region name

        Returns:
            List of organization accounts
        """
        if not self.account_id:
            logger.debug("Could not determine account ID")
            return []

        # Check cache first
        cache_key = f"{self.account_id}:{region}"
        if cache_key in self.__class__._organization_accounts_cache:
            logger.debug(f"Using cached organization accounts for {cache_key}")
            return self.__class__._organization_accounts_cache[cache_key]

        client = self.get_client(region)
        if not client:
            return []

        try:
            # Get organization accounts from client
            accounts = client.list_organization_accounts()

            # Cache the results
            self.__class__._organization_accounts_cache[cache_key] = accounts
            logger.debug(f"Cached {len(accounts)} organization accounts for {cache_key}")

            return accounts
        except Exception as e:
            logger.debug(f"Error getting organization accounts in {region}: {e}")
            return []
            
    def get_sqs_queue_encryption(self, region: str, queue_url: str) -> Optional[str]:
        """
        Get SQS queue encryption key with caching.
        
        Args:
            region: AWS region name
            queue_url: SQS queue URL
            
        Returns:
            KMS key ID or None if not encrypted/error
        """
        cache_key = f"{self.account_id}:{region}:{queue_url}"
        if cache_key in self.__class__._sqs_encryption_cache:
            logger.debug(f"Using cached SQS encryption for {queue_url}")
            return self.__class__._sqs_encryption_cache[cache_key]
            
        client = self.get_client(region)
        if not client:
            logger.debug(f"No client available for region {region}")
            self.__class__._sqs_encryption_cache[cache_key] = None
            return None
            
        try:
            kms_key = client.get_sqs_queue_encryption(queue_url)
            self.__class__._sqs_encryption_cache[cache_key] = kms_key
            logger.debug(f"SQS queue {queue_url} encryption: {kms_key}")
            return kms_key
        except Exception as e:
            logger.error(f"Error getting SQS encryption for {queue_url} in {region}: {e}")
            self.__class__._sqs_encryption_cache[cache_key] = None
            return None

    def get_enabled_regions(self) -> List[str]:
        """
        Get list of regions where Security Lake is enabled.

        Returns:
            List of region names where Security Lake is enabled
        """
        enabled_regions = []

        for region in self.regions:
            if self.is_security_lake_enabled(region):
                logger.debug(f"Security Lake is enabled in {region}")
                enabled_regions.append(region)
            else:
                logger.debug(f"Security Lake is not enabled in {region}")

        return enabled_regions

    def get_account_log_source_status(self, region: str, source_name: str) -> bool:
        """
        Check if a specific log source is enabled for the current account in a region.
        Uses get_data_lake_sources API for account-specific status.

        Args:
            region: AWS region name
            source_name: Name of the log source to check (e.g., 'ROUTE53', 'VPC_FLOW')

        Returns:
            True if the log source is enabled for this account, False otherwise
        """
        if not self.account_id:
            logger.debug("Could not determine account ID")
            return False

        # Check cache first
        cache_key = f"account_sources:{self.account_id}:{region}"
        if cache_key not in self.__class__._log_sources_cache:
            client = self.get_client(region)
            if not client:
                return False

            # Get account-specific data lake sources and cache them
            # Pass the account ID as a string (not the full account object)
            data_lake_sources = client.get_data_lake_sources(self.account_id)
            self.__class__._log_sources_cache[cache_key] = data_lake_sources
            logger.debug(f"Cached {len(data_lake_sources)} account data lake sources for {cache_key}")
        else:
            data_lake_sources = self.__class__._log_sources_cache[cache_key]
            logger.debug(f"Using cached account data lake sources for {cache_key}")

        # Check if the source is enabled for this account
        for source_entry in data_lake_sources:
            if source_entry.get("account") == self.account_id and source_entry.get("sourceName") == source_name:
                return True

        return False

    def check_log_source_configured(self, region: str, source_name: str, account_id: str = None, 
                                     required_version: str = "2.0") -> bool:
        """
        Check if a log source is configured using list-log-sources API.
        This checks configuration, not collection status.

        Args:
            region: AWS region name
            source_name: Name of the log source (e.g., 'ROUTE53', 'VPC_FLOW')
            account_id: Account ID to check (defaults to current account)
            required_version: Required source version (default: "2.0")

        Returns:
            True if source is configured with correct version, False otherwise
        """
        target_account = account_id or self.account_id
        if not target_account:
            logger.debug("Could not determine account ID")
            return False

        # Check cache first
        cache_key = f"list_sources:{target_account}:{region}"
        if cache_key not in self.__class__._log_sources_cache:
            client = self.get_client(region)
            if not client:
                return False

            # Get configured log sources and cache them
            try:
                log_sources = client.list_log_sources(regions=[region], accounts=[target_account])
                self.__class__._log_sources_cache[cache_key] = log_sources
                logger.debug(f"Cached log sources for {cache_key}")
            except Exception as e:
                logger.error(f"Error listing log sources: {e}")
                return False
        else:
            log_sources = self.__class__._log_sources_cache[cache_key]
            logger.debug(f"Using cached log sources for {cache_key}")

        # Check if the source is configured with correct version
        for source_entry in log_sources:
            if source_entry.get("account") == target_account and source_entry.get("region") == region:
                for source in source_entry.get("sources", []):
                    aws_log_source = source.get("awsLogSource", {})
                    if (aws_log_source.get("sourceName") == source_name and 
                        aws_log_source.get("sourceVersion") == required_version):
                        return True

        return False
