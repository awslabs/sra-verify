"""
Base class for WAF security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"waf"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

``_setup_clients`` always builds a ``us-east-1`` wrapper, because WAF for
CloudFront is global and must be queried there, and additionally builds one per
scan Region for ALB, API Gateway, AppSync, Cognito, App Runner, Verified Access,
Amplify and regional Web ACLs.

The :meth:`get_web_acls` cache key embeds the scope as ``f"{region}_{scope}"`` so
REGIONAL and CLOUDFRONT lookups in the same Region do not collide.

Three accessors are **uncached** -- :meth:`get_stages`,
:meth:`get_web_acl_for_resource` and :meth:`get_logging_configuration` -- because
each is parameterized on a resource identifier.
"""
from typing import Any, ClassVar, Dict

from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.services.waf.client import WAFClient
from sraverify.core.logging import logger


class WAFCheck(SecurityCheck):
    """Base class for all WAF security checks."""

    #: Namespace string used for ``ScanContext`` cache reads/writes
    #: (Requirement 5.17).
    NAMESPACE = "waf"

    #: The two pairs that mean "the control is not configured".
    #:
    #: One declaration decides it for the five checks that read
    #: ``GetWebACLForResource``, rather than each judging the code itself.
    #:
    #: Nothing is declared for the nine resource-enumeration operations
    #: (``ListDistributions``, ``DescribeLoadBalancers``, ``GetRestApis``,
    #: ``GetStages``, ``ListGraphqlApis``, ``ListUserPools``, ``ListServices``,
    #: ``DescribeVerifiedAccessInstances``, ``ListApps``, ``ListWebACLs``): "no
    #: resources" arrives from each of those as a successful response with an
    #: empty list, so any error from one is an inability to determine.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "GetWebACLForResource": {
            "WAFNonexistentItemException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/waf/latest/APIReference/"
                    "API_GetWebACLForResource.html -- WAFNonexistentItemException "
                    "is returned when AWS WAF could not find the referenced "
                    "resource, which for this call means the resource has no "
                    "associated web ACL. That is exactly what these five checks "
                    "test for, and the client already reached the same conclusion "
                    "by substituting {'WebACL': None} for the error."
                ),
            ),
        },
        "GetLoggingConfiguration": {
            "WAFNonexistentItemException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/waf/latest/APIReference/"
                    "API_GetLoggingConfiguration.html -- the same code, returned "
                    "when the web ACL has no logging configuration. SRA-WAF-09 "
                    "asks whether logging is enabled, so its absence is the "
                    "control being absent; the client already substituted "
                    "{'LoggingConfiguration': None} for it."
                ),
            ),
        },
    }

    def _setup_clients(self):
        """Set up WAF clients per region.

        Always constructs a ``us-east-1`` client because WAF for CloudFront
        is a global service that must be queried from ``us-east-1``. For
        ALB, API Gateway, AppSync, Cognito, App Runner, Verified Access,
        Amplify, and regional Web ACLs, an additional client is constructed
        per scan region. The underlying boto3 clients held by each
        :class:`WAFClient` are obtained from ``self._ctx.get_client(...)``
        so they share the per-scan bounded ``Client_Config`` and the
        ``(service, region)`` client cache.
        """
        self._clients.clear()
        # WAF for CloudFront is global; pin to us-east-1.
        self._clients['us-east-1'] = WAFClient('us-east-1', ctx=self._ctx)
        # For ALB, API Gateway, AppSync, Cognito, App Runner, Verified
        # Access, Amplify, and regional Web ACLs, create clients for all
        # scan regions.
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                if region not in self._clients:
                    self._clients[region] = WAFClient(region, ctx=self._ctx)

    def get_distributions(self) -> Dict[str, Any]:
        """
        Get CloudFront distributions for the account with caching.

        CloudFront is a global service, so the lookup is always issued from
        the ``us-east-1`` :class:`WAFClient`. Reads from / writes to the
        ``ScanContext``'s ``"waf"`` namespace.
        """
        cache_key = "distributions"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug("WAF: Using cached CloudFront distributions")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client('us-east-1')
        if not client:
            logger.warning("WAF: No WAF client available for us-east-1")
            return no_client_result(service="WAF", region="us-east-1")

        distributions = client.list_distributions()
        if is_error(distributions):
            # Never cached: a retry has to be able to re-issue the call.
            return distributions

        self._ctx._set(self.NAMESPACE, cache_key, distributions)
        logger.debug("WAF: Cached CloudFront distributions")
        return distributions

    def get_load_balancers(self, region: str) -> Dict[str, Any]:
        """
        Get ALB load balancers for ``region`` with caching.

        Reads from / writes to the ``ScanContext``'s ``"waf"`` namespace.
        """
        cache_key = f"load_balancers:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"WAF: Using cached load balancers for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"WAF: No WAF client available for region {region}")
            return no_client_result(service="WAF", region=region)

        load_balancers = client.describe_load_balancers()
        if is_error(load_balancers):
            # Never cached: a retry has to be able to re-issue the call.
            return load_balancers

        self._ctx._set(self.NAMESPACE, cache_key, load_balancers)
        logger.debug(f"WAF: Cached load balancers for {region}")
        return load_balancers

    def get_rest_apis(self, region: str) -> Dict[str, Any]:
        """
        Get API Gateway REST APIs for ``region`` with caching.

        Reads from / writes to the ``ScanContext``'s ``"waf"`` namespace.
        """
        cache_key = f"rest_apis:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"WAF: Using cached REST APIs for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"WAF: No WAF client available for region {region}")
            return no_client_result(service="WAF", region=region)

        rest_apis = client.get_rest_apis()
        if is_error(rest_apis):
            # Never cached: a retry has to be able to re-issue the call.
            return rest_apis

        self._ctx._set(self.NAMESPACE, cache_key, rest_apis)
        logger.debug(f"WAF: Cached REST APIs for {region}")
        return rest_apis

    def get_stages(self, region: str, rest_api_id: str) -> Dict[str, Any]:
        """
        Get API Gateway stages for a REST API in ``region``.

        Uncached: parameterized on ``rest_api_id``, so there is nothing to share
        between two checks asking about different APIs.
        """
        client = self.get_client(region)
        if not client:
            # Was a hand-built {"Error": {"Message": "No client available"}} with
            # no Code and no Operation, so is_error rejected it and a check could
            # read the message but had nothing to classify on.
            return no_client_result(service="WAF", region=region)
        return client.get_stages(rest_api_id)

    def get_graphql_apis(self, region: str) -> Dict[str, Any]:
        """
        Get AppSync GraphQL APIs for ``region`` with caching.

        Reads from / writes to the ``ScanContext``'s ``"waf"`` namespace.
        """
        cache_key = f"graphql_apis:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"WAF: Using cached GraphQL APIs for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"WAF: No WAF client available for region {region}")
            return no_client_result(service="WAF", region=region)

        graphql_apis = client.list_graphql_apis()
        if is_error(graphql_apis):
            # Never cached: a retry has to be able to re-issue the call.
            return graphql_apis

        self._ctx._set(self.NAMESPACE, cache_key, graphql_apis)
        logger.debug(f"WAF: Cached GraphQL APIs for {region}")
        return graphql_apis

    def get_user_pools(self, region: str) -> Dict[str, Any]:
        """
        Get Cognito user pools for ``region`` with caching.

        Reads from / writes to the ``ScanContext``'s ``"waf"`` namespace.
        """
        cache_key = f"user_pools:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"WAF: Using cached user pools for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"WAF: No WAF client available for region {region}")
            return no_client_result(service="WAF", region=region)

        user_pools = client.list_user_pools()
        if is_error(user_pools):
            # Never cached: a retry has to be able to re-issue the call.
            return user_pools

        self._ctx._set(self.NAMESPACE, cache_key, user_pools)
        logger.debug(f"WAF: Cached user pools for {region}")
        return user_pools

    def get_apprunner_services(self, region: str) -> Dict[str, Any]:
        """
        Get App Runner services for ``region`` with caching.

        Reads from / writes to the ``ScanContext``'s ``"waf"`` namespace.
        """
        cache_key = f"apprunner_services:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"WAF: Using cached App Runner services for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"WAF: No WAF client available for region {region}")
            return no_client_result(service="WAF", region=region)

        services = client.list_services()

        if is_error(services):
            # Never cached: a retry has to be able to re-issue the call.
            return services

        self._ctx._set(self.NAMESPACE, cache_key, services)
        logger.debug(f"WAF: Cached App Runner services for {region}")
        return services

    def get_verified_access_instances(self, region: str) -> Dict[str, Any]:
        """
        Get Verified Access instances for ``region`` with caching.

        Reads from / writes to the ``ScanContext``'s ``"waf"`` namespace.
        """
        cache_key = f"verified_access_instances:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"WAF: Using cached Verified Access instances for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"WAF: No WAF client available for region {region}")
            return no_client_result(service="WAF", region=region)

        instances = client.describe_verified_access_instances()
        if is_error(instances):
            # Never cached: a retry has to be able to re-issue the call.
            return instances

        self._ctx._set(self.NAMESPACE, cache_key, instances)
        logger.debug(f"WAF: Cached Verified Access instances for {region}")
        return instances

    def get_amplify_apps(self, region: str) -> Dict[str, Any]:
        """
        Get Amplify apps for ``region`` with caching.

        Reads from / writes to the ``ScanContext``'s ``"waf"`` namespace.
        """
        cache_key = f"amplify_apps:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"WAF: Using cached Amplify apps for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"WAF: No WAF client available for region {region}")
            return no_client_result(service="WAF", region=region)

        apps = client.list_apps()
        if is_error(apps):
            # Never cached: a retry has to be able to re-issue the call.
            return apps

        self._ctx._set(self.NAMESPACE, cache_key, apps)
        logger.debug(f"WAF: Cached Amplify apps for {region}")
        return apps

    def get_web_acl_for_resource(self, region: str, resource_arn: str) -> Dict[str, Any]:
        """
        Get the Web ACL associated with one resource.

        Uncached: parameterized on ``resource_arn``, so there is nothing to share
        between two checks asking about different resources.

        Args:
            region: AWS region name.
            resource_arn: ARN of the protected resource.

        Returns:
            The ``GetWebACLForResource`` response on success, or an error result.
            ``WAFNonexistentItemException`` is declared in
            :data:`NOT_CONFIGURED_ERRORS`, so a check routes it to FAIL through
            ``is_not_configured``.
        """
        client = self.get_client(region)
        if not client:
            logger.warning(f"WAF: No WAF client available for region {region}")
            return no_client_result(service="WAF", region=region)
        return client.get_web_acl_for_resource(resource_arn)

    def get_logging_configuration(self, region: str, resource_arn: str) -> Dict[str, Any]:
        """
        Get the logging configuration of one Web ACL.

        Uncached, for the same reason as :meth:`get_web_acl_for_resource`.

        Args:
            region: AWS region name.
            resource_arn: ARN of the Web ACL.

        Returns:
            The ``GetLoggingConfiguration`` response on success, or an error
            result. ``WAFNonexistentItemException`` is declared in
            :data:`NOT_CONFIGURED_ERRORS`.
        """
        client = self.get_client(region)
        if not client:
            logger.warning(f"WAF: No WAF client available for region {region}")
            return no_client_result(service="WAF", region=region)
        return client.get_logging_configuration(resource_arn)

    def get_web_acls(self, region: str, scope: str = "REGIONAL") -> Dict[str, Any]:
        """
        Get WAFv2 Web ACLs for ``(region, scope)`` with caching.

        The cache key embeds ``scope`` (``"REGIONAL"`` vs ``"CLOUDFRONT"``) so
        REGIONAL and CLOUDFRONT lookups in the same region don't collide.

        Reads from / writes to the ``ScanContext``'s ``"waf"`` namespace.
        """
        cache_key = f"web_acls:{region}_{scope}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"WAF: Using cached Web ACLs for {region}_{scope}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"WAF: No WAF client available for region {region}")
            return no_client_result(service="WAF", region=region)

        web_acls = client.list_web_acls(scope)
        if is_error(web_acls):
            # Never cached: a retry has to be able to re-issue the call.
            return web_acls

        self._ctx._set(self.NAMESPACE, cache_key, web_acls)
        logger.debug(f"WAF: Cached Web ACLs for {region}_{scope}")
        return web_acls
