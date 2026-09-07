"""
Base class for GuardDuty security checks.

As of the scan-context-refactor (task 8.1), GuardDuty's four previously
class-level caches (``_detector_details_cache``, ``_detector_ids_cache``,
``_org_config_cache``, ``_admin_accounts_cache``) have been replaced with
calls to the per-scan :class:`ScanContext` namespaced primitives under the
``"guardduty"`` namespace. The session-region-name prefix that used to be
baked into every cache key (e.g., ``f"{self.session.region_name}:{region}"``)
is dropped here because the per-scan context already scopes the cache to a
single session.
"""
from typing import List, Optional, Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.guardduty.client import GuardDutyClient
from sraverify.core.logging import logger


class GuardDutyCheck(SecurityCheck):
    """Base class for all GuardDuty security checks."""

    # All cached AWS-API responses for GuardDuty are stored under this
    # namespace on the per-scan ``ScanContext``. Cache keys are simple
    # service-internal strings (e.g., ``"detector_id:us-east-1"``) since the
    # ``ScanContext`` itself is per-scan and per-session, so there is no
    # need to disambiguate by session region anymore.
    NAMESPACE = "guardduty"

    def __init__(self):
        """Initialize GuardDuty base check."""
        super().__init__(
            account_type="application",
            service="GuardDuty",
            resource_type="AWS::GuardDuty::Detector"
        )

    def _setup_clients(self):
        """Set up GuardDuty clients for each region.

        The underlying boto3 clients held by :class:`GuardDutyClient` are
        obtained from ``self._ctx.get_client(...)`` so they share the
        per-scan bounded ``Client_Config`` and the ``(service, region)``
        client cache.
        """
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = GuardDutyClient(region, ctx=self._ctx)

    def get_detector_id(self, region: str) -> Optional[str]:
        """
        Get detector ID for a specific region with caching.

        Args:
            region: AWS region name

        Returns:
            Detector ID if available, None otherwise
        """
        cache_key = f"detector_id:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"GuardDuty: Using cached detector ID for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        # Get client
        client = self.get_client(region)
        if not client:
            logger.warning(f"GuardDuty: No GuardDuty client available for region {region}")
            return None

        # Get detector ID
        logger.debug(f"GuardDuty: Fetching detector ID for {region}")
        detector_id = client.get_detector_id()

        # Check if detector_id contains an error
        if detector_id and isinstance(detector_id, str) and detector_id.startswith("ERROR:"):
            _, error_code, error_message = detector_id.split(":", 2)
            logger.warning(f"GuardDuty: Error accessing GuardDuty in {region}: {error_code}")
            self._ctx._set(self.NAMESPACE, cache_key, None)
            return None

        # Cache the detector ID (preserves pre-refactor behaviour: only cache
        # truthy detector IDs; an empty/None response is left uncached so a
        # later call can retry).
        if detector_id:
            logger.debug(f"GuardDuty: Found detector ID {detector_id} for {region}")
            self._ctx._set(self.NAMESPACE, cache_key, detector_id)
        else:
            logger.debug(f"GuardDuty: No detector ID found for {region}")

        return detector_id

    def get_detector_details(self, region: str) -> Dict[str, Any]:
        """
        Get detector details for a specific region.

        Args:
            region: AWS region name

        Returns:
            Dictionary containing detector details or empty dict if not available
        """
        cache_key = f"detector_details:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"GuardDuty: Using cached detector details for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        # Get detector ID
        detector_id = self.get_detector_id(region)
        if not detector_id:
            logger.debug(f"GuardDuty: No detector ID found for region {region}")
            return {}

        # Get client
        client = self.get_client(region)
        if not client:
            logger.warning(f"GuardDuty: No GuardDuty client available for region {region}")
            return {}

        # Get detector details
        logger.debug(f"GuardDuty: Getting detector details for {detector_id} in {region}")
        details = client.get_detector_details(detector_id)

        # Cache the details under the per-scan namespace.
        self._ctx._set(self.NAMESPACE, cache_key, details)
        logger.debug(f"GuardDuty: Cached detector details for {region}")

        return details

    def get_organization_configuration(self, region: str) -> Dict[str, Any]:
        """
        Get organization configuration for a specific region.

        Args:
            region: AWS region name

        Returns:
            Dictionary containing organization configuration details or empty dict if not available
        """
        cache_key = f"org_config:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"GuardDuty: Using cached organization configuration for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        # Get detector ID
        detector_id = self.get_detector_id(region)
        if not detector_id:
            logger.debug(f"GuardDuty: No detector ID found for region {region}")
            return {}

        # Get client
        client = self.get_client(region)
        if not client:
            logger.warning(f"GuardDuty: No GuardDuty client available for region {region}")
            return {}

        # Get organization configuration
        logger.debug(f"GuardDuty: Getting organization configuration for {detector_id} in {region}")
        org_config = client.describe_organization_configuration(detector_id)

        # Cache the org config under the per-scan namespace.
        self._ctx._set(self.NAMESPACE, cache_key, org_config)
        logger.debug(f"GuardDuty: Cached organization configuration for {region}")

        return org_config

    def list_organization_admin_accounts(self, region: str) -> Dict[str, Any]:
        """
        List organization admin accounts for GuardDuty.

        Args:
            region: AWS region name

        Returns:
            Dictionary containing organization admin accounts details or empty dict if not available
        """
        cache_key = f"admin_accounts:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"GuardDuty: Using cached organization admin accounts for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        # Get client
        client = self.get_client(region)
        if not client:
            logger.warning(f"GuardDuty: No GuardDuty client available for region {region}")
            return {}

        # List organization admin accounts
        logger.debug(f"GuardDuty: Listing organization admin accounts in {region}")
        admin_accounts = client.list_organization_admin_accounts()

        # Cache the admin accounts under the per-scan namespace.
        self._ctx._set(self.NAMESPACE, cache_key, admin_accounts)
        logger.debug(f"GuardDuty: Cached organization admin accounts for {region}")

        return admin_accounts

    def get_enabled_regions(self) -> List[str]:
        """
        Get list of regions where GuardDuty is enabled.

        Returns:
            List of region names where GuardDuty is enabled
        """
        # Walk every region in scope and resolve a detector ID for it. Each
        # ``get_detector_id`` call is cache-aware so subsequent passes don't
        # re-issue any AWS calls.
        for region in self.regions:
            self.get_detector_id(region)

        # Read each region's cached detector ID back out of the per-scan
        # namespace; only regions whose cached detector ID is truthy count
        # as "GuardDuty enabled".
        enabled_regions = []
        for region in self.regions:
            cache_key = f"detector_id:{region}"
            if self._ctx._has(self.NAMESPACE, cache_key):
                detector_id = self._ctx._get(self.NAMESPACE, cache_key)
                if detector_id:
                    enabled_regions.append(region)

        return enabled_regions
