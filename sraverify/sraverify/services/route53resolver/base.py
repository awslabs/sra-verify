"""
Base class for Route 53 Resolver security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"route53resolver"`` namespace. Every accessor returns the client's response dict
unchanged, or an error result, and none caches a failure.

Two accessors, per Region: the VPC inventory (``ec2:DescribeVpcs``, issued from
this package rather than borrowed from ``EC2Check``) and the query logging
configuration associations.
"""
from typing import Any, ClassVar, Mapping, Optional

from sraverify.core.aws_errors import (
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.route53resolver.client import Route53ResolverClient


class Route53ResolverCheck(SecurityCheck):
    """Base class for all Route 53 Resolver security checks."""

    NAMESPACE = "route53resolver"

    #: Empty, deliberately. ``ListResolverQueryLogConfigAssociations`` and
    #: ``DescribeVpcs`` answer an empty list for "nothing here", so the absent
    #: control never arrives as an error code. ``UnrecognizedClientException``
    #: ("The security token included in the request is invalid") was observed only
    #: in a Region not enabled for the account; a scan covers enabled Regions, and
    #: anywhere else that code means a credential problem, so it is not declared.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {}

    def _setup_clients(self):
        """Set up Route 53 Resolver clients for each region.

        Each wrapper obtains its underlying boto3 ``route53resolver`` and ``ec2``
        clients from ``self._ctx.get_client(...)``.
        """
        self._clients.clear()
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = Route53ResolverClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[Route53ResolverClient]:
        """
        Get Route 53 Resolver client for a specific region.

        Args:
            region: AWS region name

        Returns:
            Route53ResolverClient for the region or None if not available
        """
        return self._clients.get(region)

    def get_vpcs(self, region: str) -> Mapping[str, Any]:
        """
        Get every VPC visible to the account in a Region, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"Vpcs": [...]}``, or an error result.
        """
        cache_key = f"vpcs:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Route53Resolver: Using cached {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if client is None:
            logger.warning(f"Route53Resolver: No client available for region {region}")
            return no_client_result(service="Route 53 Resolver", region=region)

        result = client.describe_vpcs()
        if is_error(result):
            # Never cached: a retry has to be able to re-issue the call.
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result

    def get_query_log_config_associations(self, region: str) -> Mapping[str, Any]:
        """
        Get every Resolver query logging configuration association in a Region,
        with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"ResolverQueryLogConfigAssociations": [...]}``, or an error result.
        """
        cache_key = f"query_log_config_associations:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Route53Resolver: Using cached {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if client is None:
            logger.warning(f"Route53Resolver: No client available for region {region}")
            return no_client_result(service="Route 53 Resolver", region=region)

        result = client.list_resolver_query_log_config_associations()
        if is_error(result):
            # Never cached: a retry has to be able to re-issue the call.
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result
