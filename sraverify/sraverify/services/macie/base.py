"""
Base class for Macie security checks.

Migrated to the per-scan ``ScanContext`` (task 8.9 of scan-context-refactor):

* The six class-level cache dicts (``_findings_publication_cache``,
  ``_export_configuration_cache``, ``_macie_delegated_admin_cache``,
  ``_macie_members_cache``, ``_org_members_cache``, ``_auto_enable_cache``)
  are removed. Cached AWS responses live on ``self._ctx`` under the
  ``"macie"`` namespace via the namespaced primitives ``_has`` / ``_get`` /
  ``_set`` (Requirements 5.9, 5.18).
* ``_setup_clients`` constructs ``MacieClient(region, ctx=self._ctx)`` per
  region; the underlying boto3 clients are obtained from
  ``ctx.get_client(...)`` so the bounded ``Client_Config`` is applied and
  the same ``(service, region)`` boto3 instance is reused across the scan.
* Cache keys are scoped to the typed method that wrote them (e.g.
  ``"findings_publication:{region}"``). Today's
  ``_macie_delegated_admin_cache`` is shared between
  ``get_macie_delegated_admin`` and ``get_macie_administrator_account``,
  which means the second call to land overwrites the first's entry. The
  migration splits them into ``"delegated_admin:{region}"`` and
  ``"administrator_account:{region}"`` so the two no longer collide.
* The pre-refactor cache key prefix of ``f"{self.account_id}:{region}"``
  is dropped: the per-scan ``ScanContext`` already scopes cached values to
  a single account/session, so the region alone is sufficient.

Requirements: 5.9, 5.18.
"""
from typing import List, Optional, Dict, Any
from sraverify.core.check import SecurityCheck
from sraverify.services.macie.client import MacieClient
from sraverify.core.logging import logger


class MacieCheck(SecurityCheck):
    """Base class for all Macie security checks.

    Per-scan cached AWS responses live on the attached :class:`ScanContext`
    under the ``"macie"`` namespace. Individual Macie check classes never
    see the namespaced primitives directly: they call the typed methods on
    this base class, which is the only thing that touches
    ``self._ctx._has`` / ``_get`` / ``_set`` (Requirement 6.3).
    """

    # All cached AWS-API responses for Macie are stored under this namespace
    # on the per-scan ``ScanContext``. Cache keys are simple service-internal
    # strings (e.g., ``"findings_publication:us-east-1"``) since the
    # ``ScanContext`` itself is per-scan and per-session, so there is no
    # need to disambiguate by account ID or session region anymore.
    NAMESPACE = "macie"

    def __init__(self):
        """Initialize Macie base check."""
        super().__init__(
            account_type="application",  # Default, can be overridden in subclasses
            service="Macie",
            resource_type="AWS::Macie::Session"
        )

    def _setup_clients(self):
        """Set up Macie clients for each region.

        Constructs one ``MacieClient`` wrapper per region in ``self.regions``.
        Each wrapper obtains its underlying boto3 ``macie2`` and
        ``organizations`` clients from ``self._ctx.get_client(...)``, so the
        per-scan ``Client_Config`` and per-scan boto3 client cache are
        applied.
        """
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = MacieClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[MacieClient]:
        """
        Get Macie client for a specific region.

        Args:
            region: AWS region name

        Returns:
            MacieClient for the region or None if not available
        """
        return self._clients.get(region)

    def get_findings_publication_configuration(self, region: str) -> Dict[str, Any]:
        """
        Get the findings publication configuration for Macie with caching.

        Args:
            region: AWS region name

        Returns:
            Dictionary containing findings publication configuration
        """
        cache_key = f"findings_publication:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached Macie findings publication configuration for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No Macie client available for region {region}")
            return {}

        # Get findings publication configuration from client
        config = client.get_findings_publication_configuration()

        # Cache the result under the macie namespace.
        self._ctx._set(self.NAMESPACE, cache_key, config)
        logger.debug(f"Cached Macie findings publication configuration for {region}")

        return config

    def get_classification_export_configuration(self, region: str) -> Dict[str, Any]:
        """
        Get the classification export configuration for Macie with caching.

        Args:
            region: AWS region name

        Returns:
            Dictionary containing classification export configuration
        """
        cache_key = f"export_configuration:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached Macie classification export configuration for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No Macie client available for region {region}")
            return {}

        # Get classification export configuration from client
        config = client.get_classification_export_configuration()

        # Cache the result under the macie namespace.
        self._ctx._set(self.NAMESPACE, cache_key, config)
        logger.debug(f"Cached Macie classification export configuration for {region}")

        return config

    def get_macie_delegated_admin(self, region: str) -> List[Dict[str, Any]]:
        """
        Get the Macie delegated administrator with caching.

        Args:
            region: AWS region name

        Returns:
            List of delegated administrators
        """
        cache_key = f"delegated_admin:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached Macie delegated administrator for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No Macie client available for region {region}")
            return []

        # Get delegated administrator from client
        delegated_admin = client.list_delegated_administrators()

        # Cache the result under the macie namespace.
        self._ctx._set(self.NAMESPACE, cache_key, delegated_admin)
        logger.debug(f"Cached Macie delegated administrator for {region}")

        return delegated_admin

    def get_macie_members(self, region: str) -> List[Dict[str, Any]]:
        """
        Get Macie members with caching.

        Args:
            region: AWS region name

        Returns:
            List of Macie members
        """
        cache_key = f"members:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached Macie members for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No Macie client available for region {region}")
            return []

        # Get members from client
        members = client.list_members()

        # Cache the result under the macie namespace.
        self._ctx._set(self.NAMESPACE, cache_key, members)
        logger.debug(f"Cached {len(members)} Macie members for {region}")

        return members

    def get_organization_members(self, region: str) -> List[Dict[str, Any]]:
        """
        Get AWS Organization members with caching.

        Args:
            region: AWS region name

        Returns:
            List of AWS Organization members
        """
        cache_key = f"organization_members:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached AWS Organization members for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No Macie client available for region {region}")
            return []

        # Get organization members from client
        members = client.list_organization_accounts()

        # Cache the result under the macie namespace.
        self._ctx._set(self.NAMESPACE, cache_key, members)
        logger.debug(f"Cached {len(members)} AWS Organization members for {region}")

        return members

    def get_organization_configuration(self, region: str) -> Dict[str, Any]:
        """
        Get Macie organization configuration with caching.

        Args:
            region: AWS region name

        Returns:
            Dictionary containing Macie organization configuration
        """
        cache_key = f"organization_configuration:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached Macie organization configuration for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No Macie client available for region {region}")
            return {}

        # Get organization configuration from client
        config = client.describe_organization_configuration()

        # Cache the result under the macie namespace.
        self._ctx._set(self.NAMESPACE, cache_key, config)
        logger.debug(f"Cached Macie organization configuration for {region}")

        return config

    def get_macie_administrator_account(self, region: str) -> Dict[str, Any]:
        """
        Get the Macie administrator account with caching.

        Pre-refactor this method shared ``_macie_delegated_admin_cache``
        with :meth:`get_macie_delegated_admin`, which meant the two methods
        clobbered each other's cache entries. The migration splits them
        into separate cache keys (``administrator_account`` vs.
        ``delegated_admin``) so each method's response is cached
        independently.

        Args:
            region: AWS region name

        Returns:
            Dictionary containing Macie administrator account information
        """
        cache_key = f"administrator_account:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached Macie administrator account for {region}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No Macie client available for region {region}")
            return {}

        # Get administrator account from client
        admin_account = client.get_administrator_account()

        # Cache the result under the macie namespace.
        self._ctx._set(self.NAMESPACE, cache_key, admin_account)
        logger.debug(f"Cached Macie administrator account for {region}")

        return admin_account
