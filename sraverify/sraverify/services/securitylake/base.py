"""
Base class for Security Lake security checks.

Migrated to the per-scan ``ScanContext`` (task 8.14 of scan-context-refactor):

* The seven class-level cache dicts (``_subscribers_cache``,
  ``_security_lake_status_cache``, ``_organization_configuration_cache``,
  ``_delegated_admin_cache``, ``_organization_accounts_cache``,
  ``_log_sources_cache``, ``_sqs_encryption_cache``) are removed. Cached
  AWS responses live on ``self._ctx`` under the ``"securitylake"`` namespace
  via the namespaced primitives ``_has`` / ``_get`` / ``_set``
  (Requirements 5.14, 5.18).
* ``_setup_clients`` constructs ``SecurityLakeClient(region, ctx=self._ctx)``
  per region; the underlying boto3 clients are obtained from
  ``ctx.get_client(...)`` so the bounded ``Client_Config`` is applied and
  the same ``(service, region)`` boto3 instance is reused across the scan.
* Cache keys are scoped to the typed method that wrote them (e.g.
  ``"subscribers:{region}"``, ``"data_lake_sources:{region}:{account_id}"``)
  so the four methods that historically shared ``_log_sources_cache``
  (``get_log_source_status``, ``get_data_lake_sources``,
  ``get_account_log_source_status``, ``check_log_source_configured``) no
  longer collide on a single dict.
* Today's ``self.account_id`` prefix on cache keys is dropped per the
  design's "Cache key conventions": the per-scan ctx is already scoped to
  one session/account so the prefix added no information. Cache keys that
  vary by *target* account (e.g., when ``check_log_source_configured`` is
  asked to look at a different organization member) keep that account in
  the key because it disambiguates.

Requirements: 5.14, 5.18.
"""

from typing import List, Dict, Any, Optional
from sraverify.core.check import SecurityCheck
from sraverify.services.securitylake.client import SecurityLakeClient
from sraverify.core.logging import logger


class SecurityLakeCheck(SecurityCheck):
    """Security Lake service class with integrated check functionality.

    Per-scan cached AWS responses live on the attached :class:`ScanContext`
    under the ``"securitylake"`` namespace. Individual Security Lake check
    classes never see the namespaced primitives directly: they call the
    typed methods on this base class, which is the only thing that touches
    ``self._ctx._has`` / ``_get`` / ``_set`` (Requirement 6.3).
    """

    NAMESPACE = "securitylake"

    def __init__(self):
        """Initialize Security Lake service."""
        super().__init__(
            account_type="log-archive",
            service="SecurityLake",
            resource_type="AWS::SecurityLake::SecurityLake"
        )
        # Initialize log archive account attribute
        self._log_archive_accounts = None

    def _setup_clients(self):
        """Set up Security Lake clients for each region.

        Constructs one ``SecurityLakeClient`` wrapper per region in
        ``self.regions``. Each wrapper obtains its underlying boto3
        ``securitylake`` and ``organizations`` clients from
        ``self._ctx.get_client(...)``, so the per-scan ``Client_Config``
        and per-scan boto3 client cache are applied.
        """
        # Clear existing clients
        self._clients.clear()
        # Set up new clients only if regions are initialized
        if hasattr(self, 'regions') and self.regions:
            for region in self.regions:
                self._clients[region] = SecurityLakeClient(region, ctx=self._ctx)

    def get_client(self, region: str) -> Optional[SecurityLakeClient]:
        """
        Get Security Lake client for a specific region.

        Args:
            region: AWS region name

        Returns:
            SecurityLakeClient for the region or None if not available
        """
        client = self._clients.get(region)
        if not client:
            logger.debug(f"No Security Lake client available for region {region}")
        return client

    def get_subscribers(self, region: str) -> List[Dict[str, Any]]:
        """
        Get Security Lake subscribers with caching.

        Args:
            region: AWS region name

        Returns:
            List of subscribers
        """
        if not self.account_id:
            logger.debug("Could not determine account ID")
            return []

        # Check ctx-backed cache first (securitylake namespace).
        cache_key = f"subscribers:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached subscribers for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            # Cache the empty result so subsequent checks in the same
            # region don't re-resolve a missing client.
            self._ctx._set(self.NAMESPACE, cache_key, [])
            return []

        try:
            # Get subscribers from client
            subscribers = client.list_subscribers()

            # Cache the results
            self._ctx._set(self.NAMESPACE, cache_key, subscribers)
            logger.debug(f"Cached {len(subscribers)} subscribers for {cache_key}")

            return subscribers
        except Exception as e:
            # The wrapper already classifies opt-in / unreachable region
            # errors at debug level; if anything propagates this far it's
            # unexpected, so log at debug here too and cache the empty
            # result so dependent checks (SECURITYLAKE-02, -03) don't each
            # repeat the whole multi-region sweep.
            logger.debug(f"Error getting subscribers in {region}: {e}")
            self._ctx._set(self.NAMESPACE, cache_key, [])
            return []

    def is_security_lake_enabled(self, region: str) -> bool:
        """
        Check if Security Lake is enabled with caching.

        Args:
            region: AWS region name

        Returns:
            True if Security Lake is enabled, False otherwise
        """
        if not self.account_id:
            logger.debug("Could not determine account ID")
            return False

        # Check ctx-backed cache first (securitylake namespace).
        cache_key = f"security_lake_status:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached Security Lake status for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            return False

        try:
            # Check if Security Lake is enabled
            is_enabled = client.is_security_lake_enabled()

            # Cache the results
            self._ctx._set(self.NAMESPACE, cache_key, is_enabled)
            logger.debug(f"Cached Security Lake status for {cache_key}: {is_enabled}")

            return is_enabled
        except Exception as e:
            logger.debug(f"Error checking Security Lake status in {region}: {e}")
            # Preserve pre-refactor behavior: cache False on error so we
            # don't keep retrying within the same scan.
            self._ctx._set(self.NAMESPACE, cache_key, False)
            return False

    def get_organization_configuration(self, region: str) -> Dict[str, Any]:
        """
        Get Security Lake organization configuration with caching.

        Args:
            region: AWS region name

        Returns:
            Organization configuration
        """
        if not self.account_id:
            logger.debug("Could not determine account ID")
            return {}

        # Check ctx-backed cache first (securitylake namespace).
        cache_key = f"organization_configuration:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached organization configuration for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            return {}

        try:
            # Get organization configuration from client
            org_config = client.get_organization_configuration()

            # Cache the results
            self._ctx._set(self.NAMESPACE, cache_key, org_config)
            logger.debug(f"Cached organization configuration for {cache_key}")

            return org_config
        except Exception as e:
            logger.debug(f"Error getting organization configuration in {region}: {e}")
            # Preserve pre-refactor behavior: cache empty dict on error.
            self._ctx._set(self.NAMESPACE, cache_key, {})
            return {}

    def get_log_source_status(self, region: str, source_name: str) -> bool:
        """
        Check if a specific log source is enabled in a region.

        Args:
            region: AWS region name
            source_name: Name of the log source to check (e.g., 'ROUTE53', 'VPC_FLOW')

        Returns:
            True if the log source is enabled, False otherwise
        """
        if not self.account_id:
            logger.debug("Could not determine account ID")
            return False

        # Check ctx-backed cache first (securitylake namespace). This used
        # to share ``_log_sources_cache`` with three other methods; the
        # migration uses a distinct cache key shape so they no longer
        # collide.
        cache_key = f"log_sources_list:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            log_sources = self._ctx._get(self.NAMESPACE, cache_key)
            logger.debug(f"Using cached log sources for {cache_key}")
        else:
            client = self.get_client(region)
            if not client:
                return False

            # Get log sources from client and cache them
            log_sources = client.list_log_sources()
            self._ctx._set(self.NAMESPACE, cache_key, log_sources)
            logger.debug(f"Cached {len(log_sources)} log source entries for {cache_key}")

        # Navigate the nested structure to find the source
        # Structure: sources[].sources[].awsLogSource.sourceName
        for log_source_entry in log_sources:
            for source in log_source_entry.get("sources", []):
                aws_log_source = source.get("awsLogSource", {})
                if aws_log_source.get("sourceName") == source_name:
                    # Check if source is collecting
                    source_status = source.get("sourceStatus", [])
                    for status in source_status:
                        if status.get("status") == "COLLECTING":
                            return True
                    return False

        return False

    def get_delegated_administrators(self, region: str) -> List[Dict[str, Any]]:
        """
        Get Security Lake delegated administrators with caching.

        Args:
            region: AWS region name

        Returns:
            List of delegated administrators
        """
        if not self.account_id:
            logger.debug("Could not determine account ID")
            return []

        # Check ctx-backed cache first (securitylake namespace).
        cache_key = f"delegated_administrators:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached delegated administrators for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            return []

        try:
            # Get delegated administrators from client
            delegated_admins = client.list_delegated_administrators()

            # Cache the results
            self._ctx._set(self.NAMESPACE, cache_key, delegated_admins)
            logger.debug(f"Cached {len(delegated_admins)} delegated administrators for {cache_key}")

            return delegated_admins
        except Exception as e:
            logger.debug(f"Error getting delegated administrators in {region}: {e}")
            return []

    def get_organization_accounts(self, region: str) -> List[Dict[str, Any]]:
        """
        Get all organization accounts with caching.

        Args:
            region: AWS region name

        Returns:
            List of organization accounts
        """
        if not self.account_id:
            logger.debug("Could not determine account ID")
            return []

        # Check ctx-backed cache first (securitylake namespace).
        cache_key = f"organization_accounts:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached organization accounts for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            return []

        try:
            # Get organization accounts from client
            accounts = client.list_organization_accounts()

            # Cache the results
            self._ctx._set(self.NAMESPACE, cache_key, accounts)
            logger.debug(f"Cached {len(accounts)} organization accounts for {cache_key}")

            return accounts
        except Exception as e:
            logger.debug(f"Error getting organization accounts in {region}: {e}")
            return []

    def get_sqs_queue_encryption(self, region: str, queue_url: str) -> Optional[str]:
        """
        Get SQS queue encryption key with caching.

        Args:
            region: AWS region name
            queue_url: SQS queue URL

        Returns:
            KMS key ID or None if not encrypted/error
        """
        # Check ctx-backed cache first (securitylake namespace). The
        # ``queue_url`` is part of the cache key because a single region
        # may be asked about multiple queues.
        cache_key = f"sqs_encryption:{region}:{queue_url}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached SQS encryption for {queue_url}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.debug(f"No client available for region {region}")
            self._ctx._set(self.NAMESPACE, cache_key, None)
            return None

        try:
            kms_key = client.get_sqs_queue_encryption(queue_url)
            self._ctx._set(self.NAMESPACE, cache_key, kms_key)
            logger.debug(f"SQS queue {queue_url} encryption: {kms_key}")
            return kms_key
        except Exception as e:
            logger.error(f"Error getting SQS encryption for {queue_url} in {region}: {e}")
            self._ctx._set(self.NAMESPACE, cache_key, None)
            return None

    def get_data_lake_sources(self, region: str, account_id: str = None) -> List[Dict[str, Any]]:
        """
        Get Security Lake data lake sources with caching.

        Args:
            region: AWS region name
            account_id: Optional account ID. If None, gets all accounts.

        Returns:
            List of data lake sources
        """
        # The ``account_id`` (or ``"all"``) is part of the cache key because
        # callers can ask about different organization members within a
        # single scan; the per-target value must be independently cached.
        cache_key = f"data_lake_sources:{region}:{account_id or 'all'}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"Using cached data lake sources for {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if not client:
            logger.debug(f"No client available for region {region}")
            self._ctx._set(self.NAMESPACE, cache_key, [])
            return []

        try:
            # Call with or without account_id based on parameter
            data_lake_sources = client.get_data_lake_sources(account_id)
            self._ctx._set(self.NAMESPACE, cache_key, data_lake_sources)
            logger.debug(f"Cached {len(data_lake_sources)} data lake sources for {cache_key}")
            return data_lake_sources
        except Exception as e:
            # Use debug level for UnauthorizedException as it's expected when Security Lake isn't enabled
            if "UnauthorizedException" in str(e) or "Unauthorized" in str(e):
                logger.debug(f"Security Lake not enabled in {region}: {e}")
            else:
                logger.error(f"Error getting data lake sources in {region}: {e}")
            self._ctx._set(self.NAMESPACE, cache_key, [])
            return []

    def get_enabled_regions(self) -> List[str]:
        """
        Get list of regions where Security Lake is enabled.

        Returns:
            List of region names where Security Lake is enabled
        """
        enabled_regions = []

        for region in self.regions:
            if self.is_security_lake_enabled(region):
                logger.debug(f"Security Lake is enabled in {region}")
                enabled_regions.append(region)
            else:
                logger.debug(f"Security Lake is not enabled in {region}")

        return enabled_regions

    def get_account_log_source_status(self, region: str, source_name: str) -> bool:
        """
        Check if a specific log source is enabled for the current account in a region.
        Uses get_data_lake_sources API for account-specific status.

        Args:
            region: AWS region name
            source_name: Name of the log source to check (e.g., 'ROUTE53', 'VPC_FLOW')

        Returns:
            True if the log source is enabled for this account, False otherwise
        """
        if not self.account_id:
            logger.debug("Could not determine account ID")
            return False

        # Check ctx-backed cache first (securitylake namespace). Distinct
        # cache key from the cluster-wide ``log_sources_list`` and from the
        # parameterised ``data_lake_sources`` shapes so the three methods
        # don't trample one another.
        cache_key = f"account_data_lake_sources:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            data_lake_sources = self._ctx._get(self.NAMESPACE, cache_key)
            logger.debug(f"Using cached account data lake sources for {cache_key}")
        else:
            client = self.get_client(region)
            if not client:
                return False

            # Get account-specific data lake sources and cache them
            # Pass the account ID as a string (not the full account object)
            data_lake_sources = client.get_data_lake_sources(self.account_id)
            self._ctx._set(self.NAMESPACE, cache_key, data_lake_sources)
            logger.debug(f"Cached {len(data_lake_sources)} account data lake sources for {cache_key}")

        # Check if the source is enabled for this account
        for source_entry in data_lake_sources:
            if source_entry.get("account") == self.account_id and source_entry.get("sourceName") == source_name:
                return True

        return False

    def check_log_source_configured(self, region: str, source_name: str, account_id: str = None,
                                     required_version: str = "2.0") -> bool:
        """
        Check if a log source is configured using list-log-sources API.
        This checks configuration, not collection status.

        Args:
            region: AWS region name
            source_name: Name of the log source (e.g., 'ROUTE53', 'VPC_FLOW')
            account_id: Account ID to check (defaults to current account)
            required_version: Required source version (default: "2.0")

        Returns:
            True if source is configured with correct version, False otherwise
        """
        target_account = account_id or self.account_id
        if not target_account:
            logger.debug("Could not determine account ID")
            return False

        # Check ctx-backed cache first (securitylake namespace). The
        # ``target_account`` stays in the key because callers may pass an
        # explicit account that differs from ``self.account_id`` and the
        # underlying ``list_log_sources`` response is account-specific.
        cache_key = f"list_log_sources:{target_account}:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            log_sources = self._ctx._get(self.NAMESPACE, cache_key)
            logger.debug(f"Using cached log sources for {cache_key}")
        else:
            # First-time miss for this region: prime the cache for *every*
            # account in scope with a single ``list_log_sources(regions=[region])``
            # call (no ``accounts`` filter) and split the response by
            # account into per-account cache slots. This collapses what
            # used to be ``N_accounts * N_regions`` API calls (e.g.,
            # 13 * 17 = 221) into ``N_regions`` (17). Subsequent
            # ``check_log_source_configured`` calls for any account in the
            # same region — including the cross-check pattern in
            # SRA-SECURITYLAKE-07..-13 — hit the cache.
            self._prime_region_log_sources(region)

            # The prime call writes per-account cache entries. Re-read.
            if self._ctx._has(self.NAMESPACE, cache_key):
                log_sources = self._ctx._get(self.NAMESPACE, cache_key)
            else:
                # Either the priming call failed (already cached `[]` for
                # the region) or the target account had no entries in the
                # response. Treat as empty.
                log_sources = []

        # Check if the source is configured with correct version
        for source_entry in log_sources:
            if source_entry.get("account") == target_account and source_entry.get("region") == region:
                for source in source_entry.get("sources", []):
                    aws_log_source = source.get("awsLogSource", {})
                    if (aws_log_source.get("sourceName") == source_name and
                        aws_log_source.get("sourceVersion") == required_version):
                        return True

        return False
    def _prime_region_log_sources(self, region: str) -> None:
        """Populate the per-account log-source cache for ``region`` with one API call.

        The Security Lake ``list_log_sources`` API accepts an optional
        ``accounts`` filter; without it, a single regional call returns
        entries for every account configured in that region. We exploit
        that here: instead of paying ``N_accounts * N_regions``
        ``list_log_sources`` calls (e.g., 13 accounts * 17 regions = 221),
        we make ``N_regions`` calls and bucket the response by account
        into the same per-account cache key shape that
        :meth:`check_log_source_configured` already uses
        (``list_log_sources:{account_id}:{region}``).

        On a successful call the per-account slots for *every* organization
        account in scope are populated — accounts present in the response
        get their actual entries; accounts absent from the response get an
        empty list so subsequent queries are still cache hits.

        On any failure (no client, opt-in / unreachable region, AWS error)
        every per-account slot in scope is set to ``[]`` so dependent
        checks in the same region don't repeat the failed call.
        """
        client = self.get_client(region)

        # Determine the set of accounts to populate. Prefer the cached
        # organization-accounts list (typically already populated by
        # SRA-SECURITYLAKE-01) so we avoid an extra Organizations call;
        # fall back to ``[self.account_id]`` if that's all we have.
        org_accounts = self._ctx._get(
            self.NAMESPACE, f"organization_accounts:{region}"
        ) or []
        account_ids = [
            a.get("Id") if isinstance(a, dict) else a
            for a in org_accounts
            if (a.get("Id") if isinstance(a, dict) else a)
        ]
        if self.account_id and self.account_id not in account_ids:
            account_ids.append(self.account_id)

        def _seed_empty() -> None:
            for acct in account_ids:
                self._ctx._set(
                    self.NAMESPACE, f"list_log_sources:{acct}:{region}", []
                )

        if not client:
            logger.debug(
                f"No Security Lake client for {region}; seeding empty log "
                f"sources for {len(account_ids)} accounts"
            )
            _seed_empty()
            return

        try:
            # No ``accounts`` filter: returns entries for every account
            # configured in this region. The wrapper already demotes
            # opt-in / unreachable regions to debug and returns ``[]``.
            response = client.list_log_sources(regions=[region])
        except Exception as e:
            logger.debug(
                f"Error priming log sources in {region}: {e}; "
                f"seeding empty for {len(account_ids)} accounts"
            )
            _seed_empty()
            return

        # Bucket response entries by account. ``check_log_source_configured``
        # already filters its cached list by ``account == target_account``
        # and ``region == region``, so we hand each account exactly the
        # entries that match it.
        per_account: Dict[str, List[Dict[str, Any]]] = {}
        for entry in response:
            acct = entry.get("account")
            if not acct:
                continue
            per_account.setdefault(acct, []).append(entry)

        # Write a cache slot for every account in scope. Accounts present
        # in the response get their actual entries; accounts absent from
        # the response get ``[]`` so subsequent reads are still cache hits.
        for acct in account_ids:
            self._ctx._set(
                self.NAMESPACE,
                f"list_log_sources:{acct}:{region}",
                per_account.get(acct, []),
            )
        logger.debug(
            f"Primed log sources cache for {region}: "
            f"{len(per_account)} accounts with entries, "
            f"{len(account_ids) - len(per_account)} empty, "
            f"{len(account_ids)} total"
        )
