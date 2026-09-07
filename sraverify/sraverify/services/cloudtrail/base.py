"""
Base class for CloudTrail security checks.

As of the scan-context-refactor (task 8.2), CloudTrail's three previously
class-level caches (``_describe_trails_cache``, ``_trail_status_cache``,
``_delegated_admin_account_id_cache``) have been replaced with calls to the
per-scan :class:`ScanContext` namespaced primitives under the ``"cloudtrail"``
namespace. The session-region-name prefix that used to be baked into every
cache key (e.g., ``f"{self.session.region_name}:{region}"``) is dropped here
because the per-scan context already scopes the cache to a single session.
"""
from typing import List, Optional, Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.cloudtrail.client import CloudTrailClient
from sraverify.core.logging import logger


class CloudTrailCheck(SecurityCheck):
    """Base class for all CloudTrail security checks."""

    # All cached AWS-API responses for CloudTrail are stored under this
    # namespace on the per-scan ``ScanContext``. Cache keys are simple
    # service-internal strings (e.g., ``"describe_trails:True"``) since the
    # ``ScanContext`` itself is per-scan and per-session, so there is no
    # need to disambiguate by session region anymore.
    NAMESPACE = "cloudtrail"

    def __init__(self):
        """Initialize CloudTrail base check."""
        super().__init__(
            account_type="management",
            service="CloudTrail",
            resource_type="AWS::CloudTrail::Trail"
        )

    def _setup_clients(self):
        """Set up CloudTrail clients for each region.

        The underlying boto3 clients held by :class:`CloudTrailClient` are
        obtained from ``self._ctx.get_client(...)`` so they share the per-scan
        bounded ``Client_Config`` and the ``(service, region)`` client cache.
        """
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = CloudTrailClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[CloudTrailClient]:
        """
        Get CloudTrail client for a specific region.

        Args:
            region: AWS region name

        Returns:
            CloudTrailClient for the region or None if not available
        """
        return self._clients.get(region)

    def describe_trails(self, include_shadow_trails: bool = True) -> List[Dict[str, Any]]:
        """
        Get all CloudTrail trails across all regions using the client with caching.

        Args:
            include_shadow_trails: Include shadow trails in the response

        Returns:
            List of all trails
        """
        if not self.regions:
            logger.warning("No regions specified")
            return []

        # Cache key only needs to disambiguate by the boolean flag; the
        # per-scan ctx already scopes by session.
        cache_key = f"describe_trails:{include_shadow_trails}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached trails for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        # Use any region to get all trails
        client = self.get_client(self.regions[0])
        if not client:
            logger.warning("No CloudTrail client available")
            return []

        # Get all trails using the client
        trails = client.describe_trails(include_shadow_trails=include_shadow_trails)

        # Cache the results
        self._ctx._set(self.NAMESPACE, cache_key, trails)
        logger.debug(f"Cached {len(trails)} trails for {cache_key}")

        return trails

    def get_organization_trails(self) -> List[Dict[str, Any]]:
        """
        Get all organization CloudTrail trails.

        Returns:
            List of organization trails
        """
        # Get all trails first
        all_trails = self.describe_trails()

        # Filter for organization trails
        org_trails = [
            trail for trail in all_trails
            if trail.get('IsOrganizationTrail', False)
        ]

        logger.debug(f"Found {len(org_trails)} organization trails")
        return org_trails

    def get_trail_status(self, region: str, trail_arn: str) -> Dict[str, Any]:
        """
        Get status of a specific CloudTrail trail using the client with caching.

        Args:
            region: AWS region name
            trail_arn: ARN of the trail

        Returns:
            Dictionary containing trail status
        """
        # Cache key includes both the trail ARN and the region the call was
        # issued from. The ARN alone is unique, but the region is included to
        # match the pre-refactor key shape.
        cache_key = f"trail_status:{trail_arn}:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached trail status for {trail_arn} in {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No CloudTrail client available for region {region}")
            return {}

        # Get trail status from client
        status = client.get_trail_status(trail_arn)

        # Cache the result
        self._ctx._set(self.NAMESPACE, cache_key, status)
        logger.debug(f"Cached trail status for {trail_arn} in {region}")

        return status

    def get_delegated_administrators(self) -> List[Dict[str, Any]]:
        """
        Get CloudTrail delegated administrators with caching.

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

        # Cache key is keyed only on the account ID; the session-region prefix
        # that the pre-refactor implementation used is dropped because the
        # per-scan ctx already scopes the cache to a single session.
        cache_key = f"delegated_admins:{account_id}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached delegated administrators for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        # Use any region to get delegated administrators
        client = self.get_client(self.regions[0])
        if not client:
            logger.warning("No CloudTrail client available")
            return []

        # Get delegated administrators from client
        delegated_admins = client.list_delegated_administrators()

        # Cache the results
        self._ctx._set(self.NAMESPACE, cache_key, delegated_admins)
        logger.debug(f"Cached {len(delegated_admins)} delegated administrators for {cache_key}")

        return delegated_admins
