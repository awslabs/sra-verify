"""
Base class for Shield security checks.

As of the scan-context-refactor (task 8.10), per-scan cached AWS responses
live on the attached :class:`~sraverify.core.scan_context.ScanContext` under
the ``"shield"`` namespace. The previous class-level ``_subscription_cache``
dict has been removed; reads and writes go through ``self._ctx._has`` /
``self._ctx._get`` / ``self._ctx._set``, which keeps the cache scoped to one
``run_checks`` invocation and makes the cache eligible for garbage
collection when the scan ends.

Shield is a global service: every concrete Shield check passes
``"us-east-1"`` to the typed methods below. ``_setup_clients`` still
constructs one ``ShieldClient`` per region from ``self.regions`` so this
class doesn't need to know which region the checks will pin to; the wrapper
itself keeps the region passthrough behavior described in
:class:`~sraverify.services.shield.client.ShieldClient`.
"""
from typing import Dict, Any, Optional
from sraverify.core.check import SecurityCheck
from sraverify.services.shield.client import ShieldClient
from sraverify.core.logging import logger


class ShieldCheck(SecurityCheck):
    """Base class for all Shield security checks."""

    #: Namespace string used for ``ScanContext`` cache reads/writes
    #: (Requirement 5.10).
    NAMESPACE = "shield"

    def __init__(self):
        """Initialize Shield base check."""
        super().__init__(
            account_type="application",
            service="Shield",
            resource_type="AWS::Shield::Subscription"
        )

    def _setup_clients(self):
        """Set up Shield clients for each region.

        The underlying boto3 ``shield`` clients (and the auxiliary
        ``lambda``/``wafv2``/``cloudwatch``/``cloudfront`` clients used by
        helper methods) are obtained via ``self._ctx.get_client(...)``
        inside :class:`ShieldClient`, so they share the bounded
        ``Client_Config`` and de-duplicate across service base classes
        that need the same client in the same region.
        """
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = ShieldClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[ShieldClient]:
        """
        Get Shield client for a specific region.

        Args:
            region: AWS region name

        Returns:
            ShieldClient for the region or None if not available
        """
        return self._clients.get(region)

    def get_subscription_state(self, region: str) -> Dict[str, Any]:
        """
        Get Shield Advanced subscription state with caching.

        Reads from / writes to the ``ScanContext``'s ``"shield"`` namespace,
        so the cache is per-scan rather than process-wide.

        Args:
            region: AWS region name

        Returns:
            Dictionary containing subscription details or empty dict if not available
        """
        cache_key = f"subscription_state:{region}"

        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Shield: Using cached subscription state for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return {}

        logger.debug(f"Shield: Fetching subscription state for {region}")
        subscription = client.get_subscription_state()

        self._ctx._set(self.NAMESPACE, cache_key, subscription)
        logger.debug(f"Shield: Cached subscription state for {region}")

        return subscription

    def get_subscription_status(self, region: str) -> Dict[str, Any]:
        """
        Get Shield Advanced subscription status (ACTIVE/INACTIVE) with caching.

        Reads from / writes to the ``ScanContext``'s ``"shield"`` namespace,
        so the cache is per-scan rather than process-wide.

        Args:
            region: AWS region name

        Returns:
            Dictionary containing subscription status or empty dict if not available
        """
        cache_key = f"subscription_status:{region}"

        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Shield: Using cached subscription status for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return {}

        logger.debug(f"Shield: Fetching subscription status for {region}")
        status = client.get_subscription_status()

        self._ctx._set(self.NAMESPACE, cache_key, status)
        logger.debug(f"Shield: Cached subscription status for {region}")

        return status

    def list_protections(self, region: str, resource_type: str = None) -> Dict[str, Any]:
        """
        List Shield Advanced protections with caching.

        Reads from / writes to the ``ScanContext``'s ``"shield"`` namespace,
        so the cache is per-scan rather than process-wide.

        Args:
            region: AWS region name
            resource_type: Optional resource type filter

        Returns:
            Dictionary containing protections list or empty dict if not available
        """
        cache_key = f"protections:{region}:{resource_type or 'all'}"

        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Shield: Using cached protections for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return {}

        logger.debug(f"Shield: Listing protections for {region}")
        protections = client.list_protections(resource_type)

        self._ctx._set(self.NAMESPACE, cache_key, protections)
        logger.debug(f"Shield: Cached protections for {region}")

        return protections

    def describe_drt_access(self, region: str) -> Dict[str, Any]:
        """
        Describe Shield Response Team (SRT) access configuration with caching.

        Reads from / writes to the ``ScanContext``'s ``"shield"`` namespace,
        so the cache is per-scan rather than process-wide.

        Args:
            region: AWS region name

        Returns:
            Dictionary containing DRT access details or empty dict if not available
        """
        cache_key = f"drt_access:{region}"

        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Shield: Using cached DRT access for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return {}

        logger.debug(f"Shield: Describing DRT access for {region}")
        drt_access = client.describe_drt_access()

        self._ctx._set(self.NAMESPACE, cache_key, drt_access)
        logger.debug(f"Shield: Cached DRT access for {region}")

        return drt_access

    def get_lambda_function(self, region: str, function_name: str) -> Dict[str, Any]:
        """
        Get Lambda function details.

        This helper is intentionally uncached: the underlying boto3 client
        is reused per-scan via the ``ScanContext``, but the response itself
        varies per ``function_name`` and is not worth caching at this layer.

        Args:
            region: AWS region name
            function_name: Name of the Lambda function

        Returns:
            Dictionary containing function details or empty dict if not available
        """
        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return {}

        logger.debug(f"Shield: Getting Lambda function {function_name} for {region}")
        return client.get_lambda_function(function_name)

    def get_web_acl_for_resource(self, region: str, resource_arn: str) -> Dict[str, Any]:
        """
        Get WAF web ACL associated with a resource.

        This helper is intentionally uncached: the underlying boto3 client
        is reused per-scan via the ``ScanContext``, but the response itself
        varies per ``resource_arn`` and is not worth caching at this layer.

        Args:
            region: AWS region name
            resource_arn: ARN of the resource

        Returns:
            Dictionary containing web ACL details or empty dict if not available
        """
        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return {}

        logger.debug(f"Shield: Getting web ACL for resource {resource_arn} in {region}")
        return client.get_web_acl_for_resource(resource_arn)

    def get_cloudwatch_alarms_for_resource(self, region: str, resource_arn: str) -> Dict[str, Any]:
        """
        Get CloudWatch alarms for Shield Advanced DDoS metrics for a resource.

        This helper is intentionally uncached: the underlying boto3 client
        is reused per-scan via the ``ScanContext``, but the response itself
        varies per ``resource_arn`` and is not worth caching at this layer.

        Args:
            region: AWS region name
            resource_arn: ARN of the resource

        Returns:
            Dictionary containing alarm details or empty dict if not available
        """
        client = self.get_client(region)
        if not client:
            logger.warning(f"Shield: No Shield client available for region {region}")
            return {}

        logger.debug(f"Shield: Getting CloudWatch alarms for resource {resource_arn} in {region}")
        return client.get_cloudwatch_alarms_for_resource(resource_arn)
