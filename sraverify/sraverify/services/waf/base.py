"""
Base class for WAF security checks.

As of the scan-context-refactor (task 8.17), WAF's nine previously
*instance-level* caches (``_distributions_cache``, ``_load_balancers_cache``,
``_rest_apis_cache``, ``_graphql_apis_cache``, ``_user_pools_cache``,
``_apprunner_services_cache``, ``_verified_access_instances_cache``,
``_amplify_apps_cache``, ``_web_acls_cache``) have been replaced with calls
to the per-scan :class:`ScanContext` namespaced primitives under the
``"waf"`` namespace. WAF was the only service whose caches lived on the
instance (assigned in ``__init__``) rather than the class; the migration
removes all 9 ``__init__`` assignments. Cache reads and writes now flow
through ``self._ctx._has`` / ``self._ctx._get`` / ``self._ctx._set``, which
keeps them scoped to a single ``run_checks`` invocation and lets the cached
data be garbage collected when the scan ends.

The "WAF for CloudFront is global, use us-east-1" behavior is preserved in
``_setup_clients``: an additional :class:`WAFClient` is always constructed
for ``us-east-1`` so the CloudFront-scoped Web ACL and distribution lookups
work even when the scan was constrained to other regions. The
``get_web_acls`` cache key continues to embed scope as ``f"{region}_{scope}"``
so REGIONAL and CLOUDFRONT lookups in the same region don't collide.
"""
from typing import Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.waf.client import WAFClient
from sraverify.core.logging import logger


class WAFCheck(SecurityCheck):
    """Base class for all WAF security checks."""

    #: Namespace string used for ``ScanContext`` cache reads/writes
    #: (Requirement 5.17).
    NAMESPACE = "waf"

    def __init__(self):
        """Initialize WAF base check.

        The 9 instance-level cache dicts that the pre-refactor
        ``__init__`` assigned (``_distributions_cache``,
        ``_load_balancers_cache``, ``_rest_apis_cache``,
        ``_graphql_apis_cache``, ``_user_pools_cache``,
        ``_apprunner_services_cache``,
        ``_verified_access_instances_cache``, ``_amplify_apps_cache``,
        ``_web_acls_cache``) are gone; cached AWS responses now live on
        the per-scan ``ScanContext`` under the ``"waf"`` namespace.
        """
        super().__init__(
            account_type="application",
            service="WAF",
            resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer"
        )

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
            return {}

        distributions = client.list_distributions()
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
            return {}

        load_balancers = client.describe_load_balancers()
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
            return {}

        rest_apis = client.get_rest_apis()
        self._ctx._set(self.NAMESPACE, cache_key, rest_apis)
        logger.debug(f"WAF: Cached REST APIs for {region}")
        return rest_apis

    def get_stages(self, region: str, rest_api_id: str) -> Dict[str, Any]:
        """
        Get API Gateway stages for a REST API in ``region``.

        ``get_stages`` is intentionally not cached: it is parameterized on
        ``rest_api_id`` and the pre-refactor implementation didn't cache
        either. This method is preserved unchanged across the migration.
        """
        client = self.get_client(region)
        if client:
            return client.get_stages(rest_api_id)
        return {"Error": {"Message": "No client available"}}

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
            return {}

        graphql_apis = client.list_graphql_apis()
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
            return {}

        user_pools = client.list_user_pools()
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
            return {}

        services = client.list_services()
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
            return {}

        instances = client.describe_verified_access_instances()
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
            return {}

        apps = client.list_apps()
        self._ctx._set(self.NAMESPACE, cache_key, apps)
        logger.debug(f"WAF: Cached Amplify apps for {region}")
        return apps

    def get_web_acls(self, region: str, scope: str = "REGIONAL") -> Dict[str, Any]:
        """
        Get WAFv2 Web ACLs for ``(region, scope)`` with caching.

        The cache key embeds ``scope`` (``"REGIONAL"`` vs ``"CLOUDFRONT"``)
        so REGIONAL and CLOUDFRONT lookups in the same region don't
        collide. The shape ``f"{region}_{scope}"`` is preserved from the
        pre-refactor instance-level cache key.

        Reads from / writes to the ``ScanContext``'s ``"waf"`` namespace.
        """
        cache_key = f"web_acls:{region}_{scope}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"WAF: Using cached Web ACLs for {region}_{scope}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"WAF: No WAF client available for region {region}")
            return {}

        web_acls = client.list_web_acls(scope)
        self._ctx._set(self.NAMESPACE, cache_key, web_acls)
        logger.debug(f"WAF: Cached Web ACLs for {region}_{scope}")
        return web_acls
