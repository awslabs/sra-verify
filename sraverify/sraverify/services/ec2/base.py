"""
Base class for EC2 security checks.

As of the scan-context-refactor (task 8.8), per-scan cached AWS responses
live on the attached :class:`~sraverify.core.scan_context.ScanContext` under
the ``"ec2"`` namespace. The previous class-level
``_ebs_encryption_default_cache`` dict has been removed; reads and writes
go through ``self._ctx._has`` / ``self._ctx._get`` / ``self._ctx._set``,
which keeps the cache scoped to one ``run_checks`` invocation and makes
the cache eligible for garbage collection when the scan ends.
"""
from typing import Dict, Optional, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.ec2.client import EC2Client
from sraverify.core.logging import logger


class EC2Check(SecurityCheck):
    """Base class for all EC2 security checks."""

    #: Namespace string used for ``ScanContext`` cache reads/writes
    #: (Requirement 5.8).
    NAMESPACE = "ec2"

    def __init__(self):
        """Initialize EC2 base check."""
        super().__init__(
            account_type="application",
            service="EC2",
            resource_type="AWS::EC2::Instance"
        )

    def _setup_clients(self):
        """Set up EC2 clients for each region.

        The underlying boto3 ``ec2`` clients are obtained via
        ``self._ctx.get_client(...)`` inside :class:`EC2Client`, so they
        share the bounded ``Client_Config`` and de-duplicate across
        service base classes that need an EC2 client in the same region.
        """
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = EC2Client(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[EC2Client]:
        """
        Get EC2 client for a specific region.

        Args:
            region: AWS region name

        Returns:
            EC2Client for the region or None if not available
        """
        return self._clients.get(region)

    def get_ebs_encryption_by_default(self, region: str) -> Dict[str, Any]:
        """
        Get the EBS encryption by default status for the account in the region with caching.

        Reads from / writes to the ``ScanContext``'s ``"ec2"`` namespace, so
        the cache is per-scan rather than process-wide.

        Args:
            region: AWS region name

        Returns:
            Dictionary containing EBS encryption by default status
        """
        cache_key = f"ebs_encryption_default:{region}"

        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached EBS encryption by default status for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No EC2 client available for region {region}")
            return {}

        # Get EBS encryption by default status from client
        encryption_status = client.get_ebs_encryption_by_default()

        # Cache the result on the ScanContext under the "ec2" namespace.
        self._ctx._set(self.NAMESPACE, cache_key, encryption_status)
        logger.debug(f"Cached EBS encryption by default status for {region}")

        return encryption_status
