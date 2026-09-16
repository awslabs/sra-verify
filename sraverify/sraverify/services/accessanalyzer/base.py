"""
Base class for IAM Access Analyzer security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"accessanalyzer"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

``_setup_clients`` registers a wrapper for every Region unconditionally.
``accessanalyzer`` has an endpoint in all 34 commercial Regions, so there is
nothing to gate on; where a genuine availability question arises,
``core/availability.py`` answers it offline and without an API call.
"""
from typing import Any, ClassVar, List, Mapping, Optional

from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.accessanalyzer.client import AccessAnalyzerClient


class AccessAnalyzerCheck(SecurityCheck):
    """Base class for all IAM Access Analyzer security checks."""

    NAMESPACE = "accessanalyzer"

    #: The ``(operation, code)`` pairs that mean "the control is not configured"
    #: for Access Analyzer.
    #:
    #: Empty, and deliberately so. An account with no analyzer is a *successful*
    #: ``ListAnalyzers`` returning an empty list, not an error -- so every error
    #: from these operations is an inability to determine, and declaring one would
    #: turn a permission failure into a fabricated finding.
    #:
    #: ``ValidationException`` from ``GetAnalyzer`` is not declared either: it
    #: means the ARN was malformed, which is a defect in the caller.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}

    def _setup_clients(self):
        """Set up Access Analyzer clients for each region.

        One wrapper per Region, unconditionally. Access Analyzer has an endpoint in
        every commercial Region, so there is nothing to gate on.
        """
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = AccessAnalyzerClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[AccessAnalyzerClient]:
        """
        Get Access Analyzer client for a specific region.

        Args:
            region: AWS region name

        Returns:
            AccessAnalyzerClient for the region or None if not available
        """
        return self._clients.get(region)

    def get_analyzers(self, region: str) -> Mapping[str, Any]:
        """
        Get the analyzers in a Region, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"analyzers": [...]}`` on success, or an error result.

            An empty ``analyzers`` list is a real answer: there is no analyzer
            in this Region.
        """
        cache_key = f"analyzers:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"AccessAnalyzer: Using cached analyzers for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if client is None:
            logger.warning(
                f"AccessAnalyzer: No client available for region {region}"
            )
            return no_client_result(service="IAM Access Analyzer", region=region)

        logger.debug(f"AccessAnalyzer: Fetching analyzers for {region}")
        result = client.list_analyzers()

        if is_error(result):
            # Never cached: a retry has to be able to re-issue the call.
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result

    def get_delegated_admin(self) -> Mapping[str, Any]:
        """
        Get the Organizations delegated administrator, with caching.

        Organization-wide, so the first registered client is used to reach
        ``organizations`` and the cache key is the account ID alone.

        Returns:
            ``{"DelegatedAdministrators": [...]}`` on success, or an error
            result. Read element ``[0]`` after the error test.
        """
        account_id = self.account_id
        cache_key = f"delegated_admin:{account_id}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(
                f"AccessAnalyzer: Using cached delegated admin for {account_id}"
            )
            return self._ctx._get(self.NAMESPACE, cache_key)

        if not self._clients:
            logger.warning("AccessAnalyzer: No clients available")
            return no_client_result(
                service="IAM Access Analyzer", region="global"
            )

        region = next(iter(self._clients))
        result = self._clients[region].get_delegated_admin()

        if is_error(result):
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result
