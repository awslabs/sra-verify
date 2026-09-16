"""
Base class for S3 security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"s3"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

One accessor. Its table entry separates the two codes ``s3control`` overloads onto
``GetPublicAccessBlock``: ``NoSuchPublicAccessBlockConfiguration``, which is the
control genuinely being absent, from ``AccessDenied``, which is an inability to
determine.
"""
from typing import Any, ClassVar, Mapping, Optional

from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.s3.client import S3Client


class S3Check(SecurityCheck):
    """Base class for all S3 security checks."""

    NAMESPACE = "s3"

    #: The one pair that means "the control is not configured" for S3.
    #:
    #: ``s3control`` returns exactly two codes here and they mean opposite things:
    #: ``NoSuchPublicAccessBlockConfiguration`` is the control being absent, and
    #: ``AccessDenied`` is the scan being unable to look. Only the first is
    #: declared.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "GetPublicAccessBlock": {
            "NoSuchPublicAccessBlockConfiguration": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/AmazonS3/latest/API/"
                    "API_control_GetPublicAccessBlock.html -- "
                    "NoSuchPublicAccessBlockConfiguration is returned when the "
                    "specified account has no public access block configuration, "
                    "which is exactly the control this check tests for. The "
                    "sibling code AccessDenied is deliberately not declared: it "
                    "means the member role lacks "
                    "s3:GetAccountPublicAccessBlock, so the control could not be "
                    "evaluated. Declaring both would make SRA-S3-01..-04 report "
                    "a denied permission as a finding."
                ),
            ),
        },
    }

    def _setup_clients(self):
        """Set up S3 clients for each region.

        Each wrapper obtains its underlying boto3 ``s3`` and ``s3control``
        clients from ``self._ctx.get_client(...)``.
        """
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = S3Client(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[S3Client]:
        """
        Get S3 client for a specific region.

        Args:
            region: AWS region name

        Returns:
            S3Client for the region or None if not available
        """
        return self._clients.get(region)

    def get_public_access(self) -> Mapping[str, Any]:
        """
        Get the account-level public access block configuration, with caching.

        The public access block is an account-wide setting, but the ``s3control``
        endpoint is regional, so the first Region in the scan's list is used to
        reach it. The cache key is the account ID alone for the same reason.

        Returns:
            The ``GetPublicAccessBlock`` response on success, i.e.
            ``{"PublicAccessBlockConfiguration": {...}}``, or an error result.

            The whole response, not the extracted sub-dict, so an account with
            an empty configuration stays distinguishable from a failed call.
        """
        account_id = self.account_id
        cache_key = f"public_access:{account_id}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"S3: Using cached public access block for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        if not self.regions:
            logger.warning("S3: No regions specified")
            return no_client_result(service="S3", region="global")

        region = self.regions[0]
        client = self.get_client(region)
        if client is None:
            logger.warning(f"S3: No client available for region {region}")
            return no_client_result(service="S3", region=region)

        logger.debug(f"S3: Fetching public access block for {account_id}")
        result = client.get_public_access_block(account_id)

        if is_error(result):
            # Never cached: a retry has to be able to re-issue the call.
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result
