"""
Base class for IAM Access Analyzer security checks.

As of the scan-context-refactor (task 8.3), Access Analyzer's two previously
class-level caches (``_delegated_admin_cache``, ``_analyzer_cache``) have
been replaced with calls to the per-scan :class:`ScanContext` namespaced
primitives under the ``"accessanalyzer"`` namespace. The session-region-name
prefix that used to be baked into the per-region cache key
(e.g., ``f"{self.session.region_name}:{region}"``) is dropped here because
the per-scan context already scopes the cache to a single session.
"""
from typing import List, Optional, Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.accessanalyzer.client import AccessAnalyzerClient
from sraverify.core.logging import logger


class AccessAnalyzerCheck(SecurityCheck):
    """Base class for all IAM Access Analyzer security checks."""

    # All cached AWS-API responses for Access Analyzer are stored under this
    # namespace on the per-scan ``ScanContext``. Cache keys are simple
    # service-internal strings (e.g., ``"analyzers:us-east-1"``) since the
    # ``ScanContext`` itself is per-scan and per-session, so there is no
    # need to disambiguate by session region anymore.
    NAMESPACE = "accessanalyzer"

    def __init__(self):
        """Initialize IAM Access Analyzer base check."""
        super().__init__(
            account_type="application",
            service="IAM Access Analyzer",
            resource_type="AWS::AccessAnalyzer::Analyzer"
        )

    def _setup_clients(self):
        """Set up AccessAnalyzer clients for enabled regions.

        The underlying boto3 clients held by :class:`AccessAnalyzerClient`
        are obtained from ``self._ctx.get_client(...)`` so they share the
        per-scan bounded ``Client_Config`` and the ``(service, region)``
        client cache.
        """
        # Clear existing clients
        self._clients.clear()

        if self._ctx is None:
            logger.debug("No ScanContext available, skipping Access Analyzer client setup")
            return

        # For organization checks, we need to check all specified regions
        for region in self.regions:
            try:
                client = AccessAnalyzerClient(region, ctx=self._ctx)
                if client.is_access_analyzer_available():
                    self._clients[region] = client
                    logger.debug(f"Access Analyzer client set up for region {region}")
                else:
                    logger.debug(f"Access Analyzer not available in region {region}")
            except Exception as e:
                # Skip regions where client creation fails
                logger.warning(f"Failed to create Access Analyzer client for region {region}: {e}")
                continue

    def get_client(self, region: str) -> Optional[AccessAnalyzerClient]:
        """
        Get Access Analyzer client for a region.

        Args:
            region: AWS region name

        Returns:
            AccessAnalyzerClient for the region or None if not available
        """
        return self._clients.get(region)

    def get_analyzers(self, region: str) -> List[Dict[str, Any]]:
        """
        Get analyzers for a specific region with caching.

        Args:
            region: AWS region name

        Returns:
            List of analyzers in the region
        """
        # Cache key is keyed only on the region; the session-region prefix
        # that the pre-refactor implementation used is dropped because the
        # per-scan ctx already scopes the cache to a single session.
        cache_key = f"analyzers:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached analyzers for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        # Get client
        client = self.get_client(region)
        if not client:
            logger.warning(f"No Access Analyzer client available for region {region}")
            return []

        # Get analyzers
        logger.debug(f"Fetching analyzers for {region}")
        analyzers = client.list_analyzers()

        # Cache the analyzers under the per-scan namespace.
        self._ctx._set(self.NAMESPACE, cache_key, analyzers)
        logger.debug(f"Cached {len(analyzers)} analyzers for {region}")

        return analyzers

    def get_delegated_admin(self) -> Dict[str, Any]:
        """
        Get the delegated administrator for IAM Access Analyzer with caching.

        Returns:
            Dictionary containing delegated administrator details or empty dict if none
        """
        account_id = self.account_id

        # Cache key is keyed only on the account ID; the per-scan ctx already
        # scopes the cache to a single session.
        cache_key = f"delegated_admin:{account_id}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached delegated admin for account {account_id}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        # If not in cache, get it from the client
        # Use the first available region to make the API call
        if not self._clients:
            logger.warning("No Access Analyzer clients available")
            return {}

        # Use the first available region's client
        region = next(iter(self._clients))
        client = self._clients[region]

        # Get delegated admin from client
        delegated_admin = client.get_delegated_admin()

        # Cache the result under the per-scan namespace.
        self._ctx._set(self.NAMESPACE, cache_key, delegated_admin)

        return delegated_admin
