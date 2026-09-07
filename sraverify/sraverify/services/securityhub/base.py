"""
Base class for SecurityHub security checks.

Migrated to the per-scan ``ScanContext`` (task 8.5 of scan-context-refactor):

* The seven class-level cache dicts (``_enabled_standards_cache``,
  ``_admin_account_cache``, ``_organization_configuration_cache``,
  ``_product_integrations_cache``, ``_delegated_admin_cache``,
  ``_organization_accounts_cache``, ``_securityhub_members_cache``) are
  removed. Cached AWS responses live on ``self._ctx`` under the
  ``"securityhub"`` namespace via the namespaced primitives
  ``_has`` / ``_get`` / ``_set`` (Requirement 5.5, 5.18).
* ``_setup_clients`` constructs ``SecurityHubClient(region, ctx=self._ctx)``
  per region; the underlying boto3 clients are obtained from
  ``ctx.get_client(...)`` so the bounded ``Client_Config`` is applied and
  the same ``(service, region)`` boto3 instance is reused across the scan.
* Cache keys are scoped to the typed method that wrote them (e.g.
  ``"enabled_standards:{region}"``) so the two methods that historically
  shared ``_admin_account_cache`` (``get_administrator_account`` and
  ``get_organization_admin_accounts``) no longer collide.
* Today's session-region prefix on the cache key (e.g.
  ``f"{self.session.region_name}:..."``) is dropped per the design's
  "Cache key conventions": the per-scan ctx already scopes the cache to a
  single session.

Cross-service cache sharing (task 9.1 of scan-context-refactor):

* :meth:`SecurityHubCheck.get_organization` reads from and writes to the
  ``"organizations"`` namespace under the cache key ``"organization"`` —
  the same key shape ``OrganizationsCheck.get_organization`` uses — so a
  later ``OrganizationsCheck`` call in the same scan picks up the value
  without re-issuing ``organizations:DescribeOrganization``, and
  vice-versa (Requirements 6.1, 6.2). Individual SecurityHub check classes
  call this typed method rather than touching the namespaced primitives
  directly (Requirement 6.3).

Requirements: 5.5, 5.18, 6.1, 6.2, 6.3.
"""
from typing import List, Optional, Dict, Any

from botocore.exceptions import ClientError

from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.securityhub.client import SecurityHubClient


class SecurityHubCheck(SecurityCheck):
    """Base class for all SecurityHub security checks.

    Per-scan cached AWS responses live on the attached :class:`ScanContext`
    under the ``"securityhub"`` namespace. Individual SecurityHub check
    classes never see the namespaced primitives directly: they call the
    typed methods on this base class, which is the only thing that touches
    ``self._ctx._has`` / ``_get`` / ``_set`` (Requirement 6.3).
    """

    NAMESPACE = "securityhub"

    def __init__(self):
        """Initialize SecurityHub base check."""
        super().__init__(
            account_type="audit",  # Default to audit, can be overridden in child classes
            service="SecurityHub",
            resource_type="AWS::SecurityHub::Hub"
        )

    def _setup_clients(self):
        """Set up SecurityHub clients for each region.

        Constructs one ``SecurityHubClient`` wrapper per region in
        ``self.regions``. Each wrapper obtains its underlying boto3
        ``securityhub`` and ``organizations`` clients from
        ``self._ctx.get_client(...)``, so the per-scan ``Client_Config``
        and per-scan boto3 client cache are applied.
        """
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = SecurityHubClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[SecurityHubClient]:
        """
        Get SecurityHub client for a specific region.

        Args:
            region: AWS region name

        Returns:
            SecurityHubClient for the region or None if not available
        """
        return self._clients.get(region)

    def get_enabled_standards(self, region: str) -> Optional[List[Dict[str, Any]]]:
        """
        Get enabled Security Hub standards for a region with caching.

        Args:
            region: AWS region name

        Returns:
            List of enabled standards, or ``None`` when Security Hub is not
            enabled in the given region (preserves the pre-refactor
            behavior used by callers to detect the disabled state).
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return []

        # Check ctx-backed cache first (securityhub namespace).
        cache_key = f"enabled_standards:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached enabled standards for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No SecurityHub client available for region {region}")
            return []

        try:
            # Get enabled standards from client
            standards = client.get_enabled_standards()

            # If standards is None (Security Hub not enabled), don't cache
            # the negative — preserves today's behavior of letting callers
            # observe the not-enabled state on every call.
            if standards is None:
                logger.debug(f"Security Hub is not enabled in region {region}")
                return None

            # Cache the results under the securityhub namespace.
            self._ctx._set(self.NAMESPACE, cache_key, standards)
            logger.debug(f"Cached {len(standards)} enabled standards for {cache_key}")

            return standards
        except Exception as e:
            # Check if this is the "not subscribed to AWS Security Hub" error
            if hasattr(e, 'response') and isinstance(e.response, dict):
                error = e.response.get('Error', {})
                if error.get('Code') == 'InvalidAccessException' and 'not subscribed to AWS Security Hub' in error.get('Message', ''):
                    # Return None specifically for this error to indicate Security Hub is not enabled
                    # Don't log this as an error since it's an expected condition we want to check for
                    logger.debug(f"Security Hub is not enabled in region {region}")
                    return None

            # For other errors, log a warning instead of an error to avoid cluttering the build logs
            logger.warning(f"Error getting enabled standards in {region}: {e}")
            return []

    def get_administrator_account(self, region: str) -> Dict[str, Any]:
        """
        Get Security Hub administrator account with caching.

        Args:
            region: AWS region name

        Returns:
            Administrator account information
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return {}

        # Check ctx-backed cache first (securityhub namespace).
        cache_key = f"administrator_account:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached administrator account for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No SecurityHub client available for region {region}")
            return {}

        # Get administrator account from client
        admin_account = client.get_administrator_account()

        # Cache the results
        self._ctx._set(self.NAMESPACE, cache_key, admin_account)
        logger.debug(f"Cached administrator account for {cache_key}")

        return admin_account

    def get_organization_configuration(self, region: str) -> Dict[str, Any]:
        """
        Get Security Hub organization configuration with caching.

        Args:
            region: AWS region name

        Returns:
            Organization configuration
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return {}

        # Check ctx-backed cache first (securityhub namespace).
        cache_key = f"organization_configuration:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached organization configuration for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No SecurityHub client available for region {region}")
            return {}

        # Get organization configuration from client
        org_config = client.describe_organization_configuration()

        # Cache the results
        self._ctx._set(self.NAMESPACE, cache_key, org_config)
        logger.debug(f"Cached organization configuration for {cache_key}")

        return org_config

    def get_enabled_products_for_import(self, region: str) -> Optional[List[str]]:
        """
        Get enabled products for import with caching.

        Args:
            region: AWS region name

        Returns:
            List of enabled product ARNs, or ``None`` if Security Hub is
            not enabled in the given region.
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return []

        # Check ctx-backed cache first (securityhub namespace).
        cache_key = f"product_integrations:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached product integrations for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No SecurityHub client available for region {region}")
            return []

        # Get enabled products from client
        products = client.list_enabled_products_for_import()

        # Only cache if we got a valid response (not None) — preserves
        # today's behavior of not caching the not-enabled signal.
        if products is not None:
            self._ctx._set(self.NAMESPACE, cache_key, products)
            logger.debug(f"Cached {len(products)} product integrations for {cache_key}")

        return products

    def get_delegated_administrators(self, region: str) -> List[Dict[str, Any]]:
        """
        Get SecurityHub delegated administrators with caching.

        Args:
            region: AWS region name

        Returns:
            List of delegated administrators
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return []

        # Check ctx-backed cache first (securityhub namespace).
        cache_key = f"delegated_admin:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached delegated administrators for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No SecurityHub client available for region {region}")
            return []

        # Get delegated administrators from client
        delegated_admins = client.list_delegated_administrators()

        # Cache the results
        self._ctx._set(self.NAMESPACE, cache_key, delegated_admins)
        logger.debug(f"Cached {len(delegated_admins)} delegated administrators for {cache_key}")

        return delegated_admins

    def get_organization_admin_accounts(self, region: str) -> List[Dict[str, Any]]:
        """
        Get Security Hub organization admin accounts with caching.

        Args:
            region: AWS region name

        Returns:
            List of organization admin accounts
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return []

        # Check ctx-backed cache first (securityhub namespace). This used to
        # share ``_admin_account_cache`` with ``get_administrator_account``,
        # which was a latent collision; the migration uses a distinct cache
        # key to avoid that.
        cache_key = f"organization_admin_accounts:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached organization admin accounts for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No SecurityHub client available for region {region}")
            return []

        # Get organization admin accounts from client
        admin_accounts = client.list_organization_admin_accounts()

        # Cache the results
        self._ctx._set(self.NAMESPACE, cache_key, admin_accounts)
        logger.debug(f"Cached {len(admin_accounts)} organization admin accounts for {cache_key}")

        return admin_accounts

    def get_organization_accounts(self, region: str) -> List[Dict[str, Any]]:
        """
        Get all organization accounts with caching.

        Args:
            region: AWS region name

        Returns:
            List of organization accounts
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return []

        # Check ctx-backed cache first (securityhub namespace).
        cache_key = f"organization_accounts:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached organization accounts for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No SecurityHub client available for region {region}")
            return []

        # Get organization accounts from client
        accounts = client.list_organization_accounts()

        # Cache the results
        self._ctx._set(self.NAMESPACE, cache_key, accounts)
        logger.debug(f"Cached {len(accounts)} organization accounts for {cache_key}")

        return accounts

    def get_security_hub_members(self, region: str) -> List[Dict[str, Any]]:
        """
        Get Security Hub member accounts with caching.

        Args:
            region: AWS region name

        Returns:
            List of Security Hub member accounts
        """
        account_id = self.account_id
        if not account_id:
            logger.warning("Could not determine account ID")
            return []

        # Check ctx-backed cache first (securityhub namespace).
        cache_key = f"securityhub_members:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached Security Hub members for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.warning(f"No SecurityHub client available for region {region}")
            return []

        # Get Security Hub members from client
        members = client.list_members()

        # Cache the results
        self._ctx._set(self.NAMESPACE, cache_key, members)
        logger.debug(f"Cached {len(members)} Security Hub members for {cache_key}")

        return members

    # ------------------------------------------------------------------ #
    # Cross-service cache sharing.
    #
    # The Organizations ``DescribeOrganization`` response is useful to
    # several SecurityHub checks (e.g., to determine whether the current
    # account is the organization management account). Rather than
    # re-fetching it independently, SecurityHub reads from and writes to
    # the same cache slot that ``OrganizationsCheck.get_organization``
    # uses: namespace ``"organizations"``, cache key ``"organization"``.
    # Whichever service base class runs first populates the cache, and
    # the other reads the value back without issuing a second AWS call.
    # ------------------------------------------------------------------ #

    # Namespace and cache key shape used by ``OrganizationsCheck`` for
    # ``DescribeOrganization``. Kept as constants here so the cross-service
    # contract is explicit and grep-able.
    _ORGANIZATIONS_NAMESPACE = "organizations"
    _ORGANIZATION_CACHE_KEY = "organization"

    def get_organization(self) -> Dict[str, Any]:
        """Return the AWS Organizations ``DescribeOrganization`` response.

        Reads from and writes to the ``"organizations"`` namespace under
        the cache key ``"organization"`` — the same key shape
        :meth:`sraverify.services.organizations.base.OrganizationsCheck.get_organization`
        uses — so a later ``OrganizationsCheck`` call in the same scan
        picks up the value without re-issuing
        ``organizations:DescribeOrganization``, and vice-versa
        (Requirements 6.1, 6.2).

        On a cache miss, the underlying boto3 ``organizations`` client is
        obtained from ``self._ctx.get_client('organizations', region='us-east-1')``
        — Organizations is a global service and ``OrganizationsClient``
        also pins to ``us-east-1``, so both code paths populate the cache
        with a value produced by the same boto3 client instance. The
        return shape mirrors ``OrganizationsClient.describe_organization``:
        the raw ``describe_organization`` response on success, or a dict
        with an ``Error`` key (``Code``, ``Message``) on failure.

        Returns:
            Dictionary containing organization details, or a dict with an
            ``Error`` key if the AWS call failed.
        """
        if self._ctx._has(self._ORGANIZATIONS_NAMESPACE, self._ORGANIZATION_CACHE_KEY):
            logger.debug(
                "SecurityHub: Using cached organization details from "
                "'organizations' namespace"
            )
            return self._ctx._get(
                self._ORGANIZATIONS_NAMESPACE, self._ORGANIZATION_CACHE_KEY
            )

        logger.debug(
            "SecurityHub: Fetching organization details and writing to "
            "shared 'organizations' namespace"
        )

        # Organizations is a global service; pin to us-east-1 to match
        # ``OrganizationsClient`` so both paths populate the same cache
        # with a value produced by the same underlying boto3 client.
        org_client = self._ctx.get_client('organizations', region='us-east-1')
        try:
            response = org_client.describe_organization()
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            logger.error(
                f"SecurityHub: Error describing organization: {error_message}"
            )
            response = {
                "Error": {
                    "Code": error_code,
                    "Message": error_message,
                }
            }

        self._ctx._set(
            self._ORGANIZATIONS_NAMESPACE, self._ORGANIZATION_CACHE_KEY, response
        )
        logger.debug(
            "SecurityHub: Cached organization details under shared "
            "'organizations' namespace"
        )
        return response
