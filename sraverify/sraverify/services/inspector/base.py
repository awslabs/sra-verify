"""
Base class for Inspector security checks.
"""
from typing import List, Optional, Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.inspector.client import InspectorClient
from sraverify.core.logging import logger


class InspectorCheck(SecurityCheck):
    """Base class for all Inspector security checks.

    Per-scan AWS-API responses (account status, batch account status,
    delegated admin, organization configuration, organization members) live
    in the attached :class:`ScanContext`'s namespaced cache under the
    ``"inspector"`` namespace rather than on class-level dicts. This lets a
    fresh ``ScanContext`` per :meth:`SRAVerify.run_checks` invocation start
    with an empty cache (Requirement 7.5) and ensures cached data does not
    leak between consecutive scans (Requirement 5.7, 5.18).
    """

    #: Namespace key for this service's entries in ``ctx._cache``.
    NAMESPACE = "inspector"

    def __init__(self):
        """Initialize Inspector base check."""
        super().__init__(
            account_type="application",  # Default, can be overridden in subclasses
            service="Inspector",
            resource_type="AWS::Inspector::Assessment"
        )

    def _setup_clients(self):
        """Set up Inspector clients for each region.

        Each per-region :class:`InspectorClient` wrapper is constructed with
        the attached :class:`ScanContext` so its underlying boto3 clients
        come from ``ctx.get_client(...)`` and pick up the bounded
        ``Client_Config`` (timeouts, retries, pool size).
        """
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = InspectorClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[InspectorClient]:
        """
        Get Inspector client for a specific region.

        Args:
            region: AWS region name

        Returns:
            InspectorClient for the region or None if not available
        """
        return self._clients.get(region)

    def get_account_status(self, region: str) -> Dict[str, Any]:
        """
        Get Inspector account status with caching.

        Args:
            region: AWS region name

        Returns:
            Dictionary containing account status
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return {}

        # Check the per-scan namespaced cache first.
        cache_key = f"account_status:{account_id}:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached Inspector account status for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No Inspector client available for region {region}")
            return {}

        # Get account status from client
        response = client.batch_get_account_status(account_ids=[account_id])

        # Extract the account status for the current account
        account_status: Dict[str, Any] = {}
        for status in response.get('accounts', []):
            if status.get('accountId') == account_id:
                # Restructure the account status to make it easier to access
                account_status = {
                    'accountId': status.get('accountId'),
                    'state': status.get('state', {}),
                    # Extract resource states to top level for easier access in checks
                    'ec2': status.get('resourceState', {}).get('ec2', {}),
                    'ecr': status.get('resourceState', {}).get('ecr', {}),
                    'lambda': status.get('resourceState', {}).get('lambda', {}),
                    'lambdaCode': status.get('resourceState', {}).get('lambdaCode', {})
                }
                break

        # Cache the result in the per-scan namespaced cache.
        self._ctx._set(self.NAMESPACE, cache_key, account_status)
        logger.debug(f"Cached Inspector account status for {cache_key}")

        return account_status

    def get_delegated_admin(self, region: str) -> Dict[str, Any]:
        """
        Get Inspector delegated admin with caching.

        Args:
            region: AWS region name

        Returns:
            Dictionary containing delegated admin information
        """
        cache_key = f"delegated_admin:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached Inspector delegated admin for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No Inspector client available for region {region}")
            return {}

        # Get delegated admin from client
        response = client.get_delegated_admin_account()

        # Cache the result
        self._ctx._set(self.NAMESPACE, cache_key, response)
        logger.debug(f"Cached Inspector delegated admin for {cache_key}")

        return response

    def get_organization_members(self, region: str) -> List[Dict[str, Any]]:
        """
        Get all AWS Organization member accounts with caching.

        Args:
            region: AWS region name (not used for Organizations API call)

        Returns:
            List of organization member accounts
        """
        # Use the current session region for Organizations API call.
        current_region = self.session.region_name

        # The Organizations call is global per scan; a single namespaced key
        # is enough now that the cache is already scoped to the session via
        # the per-scan ScanContext.
        cache_key = "organization_members"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached organization members for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        # Use the client for the current region
        client = self.get_client(current_region)
        if not client:
            logger.warning(f"No Inspector client available for region {current_region}")
            return []

        # Get organization members from client
        accounts = client.list_organization_accounts()

        # Cache the result
        self._ctx._set(self.NAMESPACE, cache_key, accounts)
        logger.debug(
            f"Cached {len(accounts)} organization members for {cache_key} "
            f"(using current region {current_region})"
        )

        return accounts

    def batch_get_account_status(self, region: str, account_ids: List[str]) -> Dict[str, Dict]:
        """
        Get Inspector account status for multiple accounts with caching.

        Args:
            region: AWS region name
            account_ids: List of account IDs to check

        Returns:
            Dictionary mapping account IDs to their status
        """
        cache_key = f"batch_status:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached Inspector batch account status for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No Inspector client available for region {region}")
            return {}

        # Process accounts in batches of 10 (API limit)
        result: Dict[str, Dict] = {}
        for i in range(0, len(account_ids), 10):
            batch = account_ids[i:i + 10]
            try:
                response = client.batch_get_account_status(batch)
                for account in response.get('accounts', []):
                    acc_id = account.get('accountId')
                    if acc_id:
                        result[acc_id] = account
            except Exception as e:
                logger.debug(f"Error getting batch account status in {region}: {e}")

        # Cache the result
        self._ctx._set(self.NAMESPACE, cache_key, result)
        logger.debug(
            f"Cached Inspector batch account status for {len(result)} accounts in {region}"
        )

        return result

    def get_organization_configuration(self, region: str) -> Dict[str, Any]:
        """
        Get Inspector organization configuration with caching.

        Args:
            region: AWS region name

        Returns:
            Dictionary containing organization configuration
        """
        cache_key = f"organization_configuration:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached Inspector organization configuration for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No Inspector client available for region {region}")
            return {}

        # Get organization configuration from client
        response = client.describe_organization_configuration()

        # Cache the result
        self._ctx._set(self.NAMESPACE, cache_key, response)
        logger.debug(f"Cached Inspector organization configuration for {cache_key}")

        return response
