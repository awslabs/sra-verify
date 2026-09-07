"""
Base class for AWS Organizations security checks.

As of the scan-context-refactor (task 8.15), Organizations' five previously
class-level caches (``_organization_cache``, ``_roots_cache``, ``_ous_cache``,
``_policies_cache``, ``_accounts_cache``) have been replaced with calls to
the per-scan :class:`ScanContext` namespaced primitives under the
``"organizations"`` namespace. The ``account_id`` prefix that used to be
baked into every cache key is dropped here because the per-scan context is
already scoped to a single account scan, so there is no need to disambiguate
by account inside the cache key.
"""
from typing import Any, Dict

from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.organizations.client import OrganizationsClient


class OrganizationsCheck(SecurityCheck):
    """Base class for all AWS Organizations security checks.

    Organizations is a global AWS service, so a single
    :class:`OrganizationsClient` (pinned to ``us-east-1`` inside the client
    itself) is constructed per check instance. All cached AWS-API responses
    live on the per-scan :class:`ScanContext` under the ``"organizations"``
    namespace; nothing is stored at class or instance level.
    """

    # All cached AWS-API responses for Organizations are stored under this
    # namespace on the per-scan ``ScanContext``. Cache keys are simple
    # service-internal strings (e.g., ``"ous:{parent_id}"``) since the
    # ``ScanContext`` itself is per-scan and per-account, so there is no
    # need to disambiguate by account anymore.
    NAMESPACE = "organizations"

    def __init__(self, resource_type: str = "AWS::Organizations::Organization"):
        """
        Initialize Organizations base check.

        Args:
            resource_type: AWS resource type for findings (default: Organization)
        """
        super().__init__(
            account_type="management",
            service="Organizations",
            resource_type=resource_type
        )
        self._org_client = None

    def _setup_clients(self):
        """Set up Organizations client (global service, no per-region clients needed).

        The underlying boto3 client held by :class:`OrganizationsClient` is
        obtained from ``self._ctx.get_client(...)`` so it picks up the
        per-scan bounded ``Client_Config`` and the ``(service, region)``
        client cache.
        """
        # Organizations is a global service: one client pinned to us-east-1
        # inside the wrapper is enough.
        self._org_client = OrganizationsClient(ctx=self._ctx)
        # Clear inherited per-region clients dict since Organizations
        # doesn't use it.
        self._clients.clear()

    def get_org_client(self) -> OrganizationsClient:
        """
        Get the Organizations client.

        Returns:
            OrganizationsClient instance
        """
        return self._org_client

    def get_organization(self) -> Dict[str, Any]:
        """
        Get organization details with caching.

        Returns:
            Dictionary containing organization details or Error key if failed.
        """
        cache_key = "organization"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug("Organizations: Using cached organization details")
            return self._ctx._get(self.NAMESPACE, cache_key)

        logger.debug("Organizations: Fetching organization details")
        response = self._org_client.describe_organization()

        self._ctx._set(self.NAMESPACE, cache_key, response)
        logger.debug("Organizations: Cached organization details")

        return response

    def get_roots(self) -> Dict[str, Any]:
        """
        Get organization roots with caching.

        Returns:
            Dictionary with Roots key containing list of roots,
            or Error key if failed.
        """
        cache_key = "roots"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug("Organizations: Using cached roots")
            return self._ctx._get(self.NAMESPACE, cache_key)

        logger.debug("Organizations: Fetching organization roots")
        response = self._org_client.list_roots()

        self._ctx._set(self.NAMESPACE, cache_key, response)
        logger.debug("Organizations: Cached roots")

        return response

    def get_ous_for_parent(self, parent_id: str) -> Dict[str, Any]:
        """
        Get organizational units for a parent with caching.

        Args:
            parent_id: The ID of the parent root or OU

        Returns:
            Dictionary with OrganizationalUnits key containing list of OUs,
            or Error key if failed.
        """
        cache_key = f"ous:{parent_id}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Organizations: Using cached OUs for parent {parent_id}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        logger.debug(f"Organizations: Fetching OUs for parent {parent_id}")
        response = self._org_client.list_organizational_units_for_parent(parent_id)

        self._ctx._set(self.NAMESPACE, cache_key, response)
        logger.debug(f"Organizations: Cached OUs for parent {parent_id}")

        return response

    def list_policies(self, policy_type: str = "SERVICE_CONTROL_POLICY") -> Dict[str, Any]:
        """
        List policies by type with caching.

        Args:
            policy_type: Type of policy to list (default: SERVICE_CONTROL_POLICY)

        Returns:
            Dictionary with Policies key containing list of policies,
            or Error key if failed.
        """
        cache_key = f"policies:{policy_type}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Organizations: Using cached policies of type {policy_type}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        logger.debug(f"Organizations: Fetching policies of type {policy_type}")
        response = self._org_client.list_policies(policy_type)

        self._ctx._set(self.NAMESPACE, cache_key, response)
        logger.debug(f"Organizations: Cached policies of type {policy_type}")

        return response

    def get_accounts_for_parent(self, parent_id: str) -> Dict[str, Any]:
        """
        Get accounts for a parent (root or OU) with caching.

        Args:
            parent_id: The ID of the parent root or OU

        Returns:
            Dictionary with Accounts key containing list of accounts,
            or Error key if failed.
        """
        cache_key = f"accounts:{parent_id}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Organizations: Using cached accounts for parent {parent_id}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        logger.debug(f"Organizations: Fetching accounts for parent {parent_id}")
        response = self._org_client.list_accounts_for_parent(parent_id)

        self._ctx._set(self.NAMESPACE, cache_key, response)
        logger.debug(f"Organizations: Cached accounts for parent {parent_id}")

        return response
