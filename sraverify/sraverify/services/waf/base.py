from typing import Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.waf.client import WAFClient

class WAFCheck(SecurityCheck):
    def __init__(self):
        super().__init__(
            account_type="application",
            service="WAF",
            resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer"
        )
        self._distributions_cache = {}
        self._load_balancers_cache = {}
        self._rest_apis_cache = {}
        self._graphql_apis_cache = {}
        self._user_pools_cache = {}
        self._apprunner_services_cache = {}
        self._verified_access_instances_cache = {}
        self._amplify_apps_cache = {}
        self._web_acls_cache = {}

    def _setup_clients(self):
        self._clients.clear()
        # WAF for CloudFront is global, use us-east-1
        self._clients['us-east-1'] = WAFClient('us-east-1', session=self.session)
        # For ALB, API Gateway, AppSync, Cognito, App Runner, Verified Access, Amplify, and Web ACLs, create clients for all regions
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                if region not in self._clients:
                    self._clients[region] = WAFClient(region, session=self.session)

    def get_distributions(self) -> Dict[str, Any]:
        if not self._distributions_cache:
            client = self.get_client('us-east-1')
            if client:
                self._distributions_cache = client.list_distributions()
        return self._distributions_cache

    def get_load_balancers(self, region: str) -> Dict[str, Any]:
        if region not in self._load_balancers_cache:
            client = self.get_client(region)
            if client:
                self._load_balancers_cache[region] = client.describe_load_balancers()
        return self._load_balancers_cache.get(region, {})

    def get_rest_apis(self, region: str) -> Dict[str, Any]:
        if region not in self._rest_apis_cache:
            client = self.get_client(region)
            if client:
                self._rest_apis_cache[region] = client.get_rest_apis()
        return self._rest_apis_cache.get(region, {})

    def get_graphql_apis(self, region: str) -> Dict[str, Any]:
        if region not in self._graphql_apis_cache:
            client = self.get_client(region)
            if client:
                self._graphql_apis_cache[region] = client.list_graphql_apis()
        return self._graphql_apis_cache.get(region, {})

    def get_user_pools(self, region: str) -> Dict[str, Any]:
        if region not in self._user_pools_cache:
            client = self.get_client(region)
            if client:
                self._user_pools_cache[region] = client.list_user_pools()
        return self._user_pools_cache.get(region, {})

    def get_apprunner_services(self, region: str) -> Dict[str, Any]:
        if region not in self._apprunner_services_cache:
            client = self.get_client(region)
            if client:
                self._apprunner_services_cache[region] = client.list_services()
        return self._apprunner_services_cache.get(region, {})

    def get_verified_access_instances(self, region: str) -> Dict[str, Any]:
        if region not in self._verified_access_instances_cache:
            client = self.get_client(region)
            if client:
                self._verified_access_instances_cache[region] = client.describe_verified_access_instances()
        return self._verified_access_instances_cache.get(region, {})

    def get_amplify_apps(self, region: str) -> Dict[str, Any]:
        if region not in self._amplify_apps_cache:
            client = self.get_client(region)
            if client:
                self._amplify_apps_cache[region] = client.list_apps()
        return self._amplify_apps_cache.get(region, {})

    def get_web_acls(self, region: str, scope: str = "REGIONAL") -> Dict[str, Any]:
        cache_key = f"{region}_{scope}"
        if cache_key not in self._web_acls_cache:
            client = self.get_client(region)
            if client:
                self._web_acls_cache[cache_key] = client.list_web_acls(scope)
        return self._web_acls_cache.get(cache_key, {})
