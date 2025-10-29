from typing import Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.firewallmanager.client import FirewallManagerClient
from sraverify.core.logging import logger

class FirewallManagerCheck(SecurityCheck):
    # Class-level caches shared across all instances
    _admin_account_cache = None
    _policies_cache = {}

    def __init__(self):
        super().__init__(
            account_type="audit",
            service="FirewallManager",
            resource_type="AWS::FMS::Policy"
        )

    def _setup_clients(self):
        self._clients.clear()
        # Firewall Manager admin APIs are global (us-east-1)
        self._clients['us-east-1'] = FirewallManagerClient('us-east-1', session=self.session)
        # For regional policy checks, create clients for all regions
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                if region not in self._clients:
                    self._clients[region] = FirewallManagerClient(region, session=self.session)

    def get_admin_account(self) -> Dict[str, Any]:
        if FirewallManagerCheck._admin_account_cache is None:
            logger.debug("FirewallManager: Fetching admin account")
            client = self.get_client('us-east-1')
            if client:
                FirewallManagerCheck._admin_account_cache = client.get_admin_account()
                logger.debug("FirewallManager: Cached admin account")
        else:
            logger.debug("FirewallManager: Using cached admin account")
        return FirewallManagerCheck._admin_account_cache or {}

    def list_policies(self, region: str) -> Dict[str, Any]:
        if region not in FirewallManagerCheck._policies_cache:
            logger.debug(f"FirewallManager: Fetching policies for {region}")
            client = self.get_client(region)
            if client:
                FirewallManagerCheck._policies_cache[region] = client.list_policies()
                logger.debug(f"FirewallManager: Cached policies for {region}")
        else:
            logger.debug(f"FirewallManager: Using cached policies for {region}")
        return FirewallManagerCheck._policies_cache.get(region, {})
