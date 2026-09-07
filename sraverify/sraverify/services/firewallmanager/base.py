"""
Base class for FirewallManager security checks.

Migrated to the per-scan ``ScanContext`` (task 8.13 of scan-context-refactor):

* The two class-level cache attributes (``_admin_account_cache`` and
  ``_policies_cache``) are removed. Cached AWS responses live on
  ``self._ctx`` under the ``"firewallmanager"`` namespace via the
  namespaced primitives ``_has`` / ``_get`` / ``_set`` (Requirements 5.13,
  5.18).
* ``_setup_clients`` constructs ``FirewallManagerClient(region,
  ctx=self._ctx)``. The ``us-east-1`` pin is preserved because Firewall
  Manager admin APIs (``get_admin_account``) are global and only respond
  there; regional clients are still built for ``list_policies``. Each
  wrapper obtains its underlying boto3 ``fms`` client from
  ``ctx.get_client(...)`` so the bounded ``Client_Config`` is applied and
  the same ``(service, region)`` boto3 instance is reused across the scan.

Requirements: 5.13, 5.18.
"""
from typing import Dict, Any

from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.firewallmanager.client import FirewallManagerClient


class FirewallManagerCheck(SecurityCheck):
    """Base class for all Firewall Manager security checks.

    Per-scan cached AWS responses live on the attached :class:`ScanContext`
    under the ``"firewallmanager"`` namespace. Individual Firewall Manager
    check classes never touch the namespaced primitives directly: they call
    the typed methods on this base class, which is the only thing that
    reaches into ``self._ctx._has`` / ``_get`` / ``_set`` (Requirement 6.3).
    """

    #: Namespace used for all ``ctx._get`` / ``ctx._set`` / ``ctx._has``
    #: calls made from this base class. Matches Requirement 5.13.
    NAMESPACE = "firewallmanager"

    def __init__(self):
        """Initialize Firewall Manager base check."""
        super().__init__(
            account_type="audit",
            service="FirewallManager",
            resource_type="AWS::FMS::Policy"
        )

    def _setup_clients(self):
        """Set up Firewall Manager client wrappers.

        Firewall Manager admin APIs (``get_admin_account``) are global and
        only respond in ``us-east-1``; that wrapper is always constructed.
        Regional policy APIs (``list_policies``) accept any enabled region,
        so additional wrappers are constructed for every region in
        ``self.regions`` that is not already pinned to ``us-east-1``.

        Each :class:`FirewallManagerClient` obtains its underlying boto3
        ``fms`` client through ``ctx.get_client(...)`` so the bounded
        ``Client_Config`` is applied and the same boto3 client instance is
        shared across all wrappers in this scan.
        """
        # Clear existing clients
        self._clients.clear()
        # Firewall Manager admin APIs are global (us-east-1)
        self._clients['us-east-1'] = FirewallManagerClient('us-east-1', ctx=self._ctx)
        # For regional policy checks, create clients for all other regions
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                if region not in self._clients:
                    self._clients[region] = FirewallManagerClient(region, ctx=self._ctx)

    def get_admin_account(self) -> Dict[str, Any]:
        """
        Get the Firewall Manager administrator account, cached for the scan.

        The result is cached on the attached :class:`ScanContext` under the
        ``"firewallmanager"`` namespace. The previous global cache lived on
        the class itself and persisted across scans; the migrated path
        scopes the cache to the current scan only.

        Returns:
            ``get_admin_account`` response dict, or ``{}`` when no
            ``us-east-1`` Firewall Manager client is available or when the
            cached response is falsy (preserves the pre-refactor behavior
            of returning ``{}`` when the service has no admin configured).
        """
        cache_key = "admin_account"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug("FirewallManager: Using cached admin account")
            return self._ctx._get(self.NAMESPACE, cache_key) or {}

        logger.debug("FirewallManager: Fetching admin account")
        client = self.get_client('us-east-1')
        if not client:
            return {}

        admin_account = client.get_admin_account()
        self._ctx._set(self.NAMESPACE, cache_key, admin_account)
        logger.debug("FirewallManager: Cached admin account")
        return admin_account or {}

    def list_policies(self, region: str) -> Dict[str, Any]:
        """
        List Firewall Manager policies for a region, cached per region.

        The result is cached on the attached :class:`ScanContext` under the
        ``"firewallmanager"`` namespace, keyed by region. The previous
        cache key was just the region; the migrated key keeps the region
        but partitions it under the typed-method shape used by the rest of
        the migrated services (``"policies:{region}"``).

        Args:
            region: AWS region name.

        Returns:
            ``list_policies`` response dict, or ``{}`` when no Firewall
            Manager client is available for the region.
        """
        cache_key = f"policies:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"FirewallManager: Using cached policies for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key) or {}

        logger.debug(f"FirewallManager: Fetching policies for {region}")
        client = self.get_client(region)
        if not client:
            return {}

        policies = client.list_policies()
        self._ctx._set(self.NAMESPACE, cache_key, policies)
        logger.debug(f"FirewallManager: Cached policies for {region}")
        return policies or {}
