"""
Base class for AWS Config security checks.
"""
from typing import List, Optional, Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.config.client import ConfigClient
from sraverify.core.logging import logger


class ConfigCheck(SecurityCheck):
    """Base class for all AWS Config security checks.

    Cached AWS responses are stored on the per-scan ``ScanContext`` under the
    ``"config"`` namespace via ``self._ctx._has`` / ``_get`` / ``_set``.
    Class-level cache dicts have been removed (Requirements 5.4, 5.18).
    """

    # Service namespace used by ``ScanContext`` cache primitives.
    NAMESPACE = "config"

    # Config service principals
    CONFIG_SERVICE_PRINCIPALS = [
        "config.amazonaws.com",
        "config-multiaccountsetup.amazonaws.com"
    ]

    def __init__(self):
        """Initialize Config base check."""
        super().__init__(
            account_type="account",  # Default to account, can be overridden in child classes
            service="Config",
            resource_type="AWS::Config::ConfigurationRecorder"
        )

    def _setup_clients(self):
        """Set up Config clients for each region."""
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = ConfigClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[ConfigClient]:
        """
        Get Config client for a specific region.

        Args:
            region: AWS region name

        Returns:
            ConfigClient for the region or None if not available
        """
        return self._clients.get(region)

    def get_configuration_recorders(self, region: str) -> List[Dict[str, Any]]:
        """
        Get configuration recorders for a specific region.

        Args:
            region: AWS region name

        Returns:
            List of configuration recorders
        """
        # Get client for the region
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Config client available for region {region}")
            return []

        # Get configuration recorders from client
        recorders = client.describe_configuration_recorders()
        logger.debug(f"Found {len(recorders)} configuration recorders for {region}")

        return recorders

    def get_configuration_recorder_status(self, region: str) -> List[Dict[str, Any]]:
        """
        Get configuration recorder status for a specific region with caching.

        Args:
            region: AWS region name

        Returns:
            List of configuration recorder statuses
        """
        # Check cache first
        cache_key = f"recorder_status:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached configuration recorder status for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        # Get client for the region
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Config client available for region {region}")
            return []

        # Get configuration recorder status from client
        statuses = client.describe_configuration_recorder_status()

        # Cache the results - store the complete response
        self._ctx._set(self.NAMESPACE, cache_key, statuses)
        logger.debug(f"Cached {len(statuses)} configuration recorder statuses for {region}")

        return statuses

    def get_delivery_channels(self, region: str) -> List[Dict[str, Any]]:
        """
        Get delivery channels for a specific region.

        Args:
            region: AWS region name

        Returns:
            List of delivery channels
        """
        # Check cache first
        cache_key = f"delivery_channels:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached delivery channels for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        # Get client for the region
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Config client available for region {region}")
            return []

        # Get delivery channels from client
        channels = client.describe_delivery_channels()

        # Cache the results
        self._ctx._set(self.NAMESPACE, cache_key, channels)
        logger.debug(f"Cached {len(channels)} delivery channels for {region}")

        return channels

    def get_delivery_channel_status(self, region: str) -> List[Dict[str, Any]]:
        """
        Get delivery channel status for a specific region with caching.

        Args:
            region: AWS region name

        Returns:
            List of delivery channel statuses
        """
        # Check cache first
        cache_key = f"delivery_channel_status:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached delivery channel status for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        # Get client for the region
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Config client available for region {region}")
            return []

        # Get delivery channel status from client
        statuses = client.describe_delivery_channel_status()

        # Cache the results - store the complete response
        self._ctx._set(self.NAMESPACE, cache_key, statuses)
        logger.debug(f"Cached {len(statuses)} delivery channel statuses for {region}")

        return statuses

    def get_configuration_aggregators(self, region: str) -> List[Dict[str, Any]]:
        """
        Get configuration aggregators for a specific region with caching.

        Args:
            region: AWS region name

        Returns:
            List of configuration aggregators
        """
        # Check cache first
        cache_key = f"configuration_aggregators:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached configuration aggregators for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        # Get client for the region
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Config client available for region {region}")
            return []

        # Get configuration aggregators from client
        aggregators = client.describe_configuration_aggregators()

        # Cache the results
        self._ctx._set(self.NAMESPACE, cache_key, aggregators)
        logger.debug(f"Cached {len(aggregators)} configuration aggregators for {region}")

        return aggregators

    def get_delegated_administrators(self, service_principal=None) -> List[Dict[str, Any]]:
        """
        Get Config delegated administrators with caching.

        Args:
            service_principal: Optional specific service principal to check

        Returns:
            List of delegated administrators
        """
        if not self.regions:
            logger.warning("No regions specified")
            return []

        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return []

        # If a specific service principal is provided, only check that one
        service_principals = [service_principal] if service_principal else self.CONFIG_SERVICE_PRINCIPALS

        all_delegated_admins = []

        for sp in service_principals:
            # Check cache first
            cache_key = f"delegated_admin:{account_id}:{sp}"
            if self._ctx._has(self.NAMESPACE, cache_key):
                logger.debug(f"Using cached delegated administrators for {cache_key}")
                admins = self._ctx._get(self.NAMESPACE, cache_key)
                all_delegated_admins.extend(admins)
                continue

            # Use any region to get delegated administrators
            client = self.get_client(self.regions[0])
            if not client:
                logger.warning("No Config client available")
                continue

            # Get delegated administrators from client
            delegated_admins = client.list_delegated_administrators(sp)

            # Cache the results
            self._ctx._set(self.NAMESPACE, cache_key, delegated_admins)
            logger.debug(f"Cached {len(delegated_admins)} delegated administrators for {cache_key}")

            all_delegated_admins.extend(delegated_admins)

        return all_delegated_admins
