"""
Base class for EC2 security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"ec2"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

One accessor, reading the account-level default EBS encryption setting per Region.
"""
from typing import Any, ClassVar, Mapping, Optional

from sraverify.core.aws_errors import (
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.ec2.client import EC2Client


class EC2Check(SecurityCheck):
    """Base class for all EC2 security checks."""

    NAMESPACE = "ec2"

    #: Empty, deliberately. ``GetEbsEncryptionByDefault`` answers a **boolean** --
    #: an account with default encryption switched off is a successful response
    #: carrying ``EbsEncryptionByDefault: False``, not an error. So there is no
    #: code from this operation that means "not configured", and every error is an
    #: inability to determine.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}

    def _setup_clients(self):
        """Set up EC2 clients for each region.

        Each wrapper obtains its underlying boto3 ``ec2`` and ``sts`` clients from
        ``self._ctx.get_client(...)``.
        """
        self._clients.clear()
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

    def get_ebs_encryption_by_default(self, region: str) -> Mapping[str, Any]:
        """
        Get the account's default EBS encryption setting for a Region, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"EbsEncryptionByDefault": bool}``, or an error result.
        """
        cache_key = f"ebs_encryption_default:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"EC2: Using cached {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if client is None:
            logger.warning(f"EC2: No client available for region {region}")
            return no_client_result(service="EC2", region=region)

        result = client.get_ebs_encryption_by_default()
        if is_error(result):
            # Never cached: a retry has to be able to re-issue the call.
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result
