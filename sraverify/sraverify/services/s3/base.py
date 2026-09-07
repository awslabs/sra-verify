"""
Base class for S3 security checks.

Migrated to the per-scan :class:`ScanContext` model in task 8.6 of the
scan-context-refactor spec: the previously class-level
``_public_access_cache`` dict has been removed and the cached
``get_public_access`` result now lives in the ``"s3"`` namespace on the
attached ``ScanContext`` (Requirements 5.6, 5.18).
"""
from typing import Any, Dict

from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.s3.client import S3Client


class S3Check(SecurityCheck):
    """Base class for all S3 security checks."""

    #: Namespace used for all ``ctx._get`` / ``ctx._set`` / ``ctx._has``
    #: calls made from this base class. Matches Requirement 5.6.
    NAMESPACE = "s3"

    def __init__(self):
        """Initialize S3 base check."""
        super().__init__(
            account_type="application",
            service="S3",
            resource_type="AWS::S3::AccountPublicAccessBlock"
        )

    def _setup_clients(self):
        """Set up S3 client wrappers for each region.

        Each :class:`S3Client` obtains its underlying boto3 ``s3`` and
        ``s3control`` clients through ``ctx.get_client(...)`` so the bounded
        ``Client_Config`` is applied and the same boto3 client instance is
        shared across all wrappers in this scan.
        """
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = S3Client(region, ctx=self._ctx)

    def get_public_access(self) -> Dict[str, Any]:
        """
        Get the public access block configuration for the account with caching.

        The result is cached for the lifetime of the current scan in the
        ``"s3"`` namespace on the attached :class:`ScanContext`. The cache
        key includes the account ID; the previously-used session-region
        prefix has been dropped because the per-scan context already scopes
        the cache to one session (per the design's "Cache key conventions"
        section).

        Returns:
            Public access block configuration dictionary, or ``{}`` when no
            regions are available, no account ID can be determined, or no
            S3 client is available.
        """
        if not self.regions:
            logger.warning("No regions specified")
            return {}

        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return {}

        cache_key = f"public_access:{account_id}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached public access block configuration for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        # Use any region to get public access block configuration. S3 is a
        # global service, but the s3control endpoint is regional, so we
        # arbitrarily use the first region in the scan's region list.
        client = self._clients.get(self.regions[0])
        if not client:
            logger.warning("No S3 client available")
            return {}

        # Get public access block configuration from client
        public_access_config = client.get_public_access_block(account_id)

        # Cache the result on the ScanContext
        self._ctx._set(self.NAMESPACE, cache_key, public_access_config)
        logger.debug(f"Cached public access block configuration for {cache_key}")

        return public_access_config
