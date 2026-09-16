"""
Base class for Firewall Manager security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"firewallmanager"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

``_setup_clients`` always builds a ``us-east-1`` wrapper, because the Firewall
Manager admin API (``GetAdminAccount``) is global and answers only there, and
additionally builds one per scan Region for the regional ``ListPolicies``.
"""
from typing import ClassVar, Dict, Any

from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    is_error,
    no_client_result,
)
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

    #: The one pair that means "the control is not configured".
    #:
    #: Declared here rather than translated into prose by the client, so that a
    #: *different* error cannot arrive wearing the same sentence.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "GetAdminAccount": {
            "ResourceNotFoundException": NotConfigured(
                evidence=(
                    "https://docs.aws.amazon.com/fms/2018-01-01/APIReference/"
                    "API_GetAdminAccount.html -- returned when no Firewall Manager "
                    "administrator account has been set for the organization, which "
                    "is exactly what these checks test for. product.md already "
                    "lists fms:GetAdminAccount/ResourceNotFoundException among the "
                    "codes classified this way somewhere in the tree."
                ),
            ),
        },
    }

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
        ``"firewallmanager"`` namespace, so it is scoped to a single scan.

        Returns:
            The ``GetAdminAccount`` response on success, or an error result.
            ``ResourceNotFoundException`` is declared in
            :data:`NOT_CONFIGURED_ERRORS`, so the absent-administrator case
            arrives as an error result the check routes to FAIL and every other
            failure as one it routes to ERROR.
        """
        cache_key = "admin_account"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug("FirewallManager: Using cached admin account")
            return self._ctx._get(self.NAMESPACE, cache_key)

        logger.debug("FirewallManager: Fetching admin account")
        # Firewall Manager's admin API answers only in us-east-1, so this
        # accessor is not parameterised by Region and the no-client result names
        # the Region the wrapper would have been built for.
        client = self.get_client('us-east-1')
        if not client:
            return no_client_result(service="FirewallManager", region="us-east-1")

        admin_account = client.get_admin_account()
        if is_error(admin_account):
            # Never cached: a retry has to be able to re-issue the call.
            return admin_account

        self._ctx._set(self.NAMESPACE, cache_key, admin_account)
        logger.debug("FirewallManager: Cached admin account")
        return admin_account

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
            The ``ListPolicies`` response on success, or an error result. It used
            to answer ``{}`` on the no-client path, which a check read as "no
            policies exist" -- an established negative built out of never having
            asked.
        """
        cache_key = f"policies:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"FirewallManager: Using cached policies for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        logger.debug(f"FirewallManager: Fetching policies for {region}")
        client = self.get_client(region)
        if not client:
            return no_client_result(service="FirewallManager", region=region)

        policies = client.list_policies()
        if is_error(policies):
            # Never cached: a retry has to be able to re-issue the call.
            return policies

        self._ctx._set(self.NAMESPACE, cache_key, policies)
        logger.debug(f"FirewallManager: Cached policies for {region}")
        return policies
