"""
Per-scan state container for a single SRAVerify.run_checks invocation.

A fresh ``ScanContext`` is constructed at the start of every scan and goes out
of scope when the scan finishes. It owns the boto3 ``Session``, the region list,
audit and log-archive account lists, the ``botocore.config.Config`` applied to
every boto3 client built during the scan, the per-scan boto3 client cache, and
the namespaced AWS-API response cache used by service base classes.

This module implements task 2.1 of the scan-context-refactor spec: the class
skeleton (constructor, default ``Client_Config`` factory, override precedence,
private state initialization, and typed read-only properties). Subsequent tasks
add the namespaced cache primitives (2.2), ``get_client`` (2.3), and the lazy
typed accessors ``get_account_info`` / ``get_management_account_id`` /
``get_enabled_regions`` (2.4) to this same class.
"""
from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional, Tuple

import boto3
import botocore.config

from sraverify.core.aws_client import AWS_EXCEPTIONS, AWSClient
from sraverify.core.aws_errors import ErrorResult, is_error
from sraverify.core.logging import logger
from sraverify.core.organization import OrganizationsProvider
from sraverify.core.regions import resolve_scan_region


# Documented defaults for the ``Client_Config`` (Requirement 2.2). Pulled out as
# module constants so unit tests and downstream callers can reference them
# without re-typing magic numbers.
DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_READ_TIMEOUT = 30
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_RETRY_MODE = "standard"
DEFAULT_MAX_POOL_CONNECTIONS = 50


def _build_default_client_config(
    connect_timeout: Optional[float] = None,
    read_timeout: Optional[float] = None,
    max_attempts: Optional[int] = None,
    max_pool_connections: Optional[int] = None,
) -> botocore.config.Config:
    """Return the default ``botocore.config.Config`` with optional overrides.

    Each non-``None`` override replaces the corresponding default field; ``None``
    overrides leave the default in place. This is the factory used when no
    explicit ``client_config`` is supplied to ``ScanContext.__init__``.
    """
    return botocore.config.Config(
        connect_timeout=(
            connect_timeout if connect_timeout is not None else DEFAULT_CONNECT_TIMEOUT
        ),
        read_timeout=(
            read_timeout if read_timeout is not None else DEFAULT_READ_TIMEOUT
        ),
        retries={
            "max_attempts": (
                max_attempts if max_attempts is not None else DEFAULT_MAX_ATTEMPTS
            ),
            "mode": DEFAULT_RETRY_MODE,
        },
        max_pool_connections=(
            max_pool_connections
            if max_pool_connections is not None
            else DEFAULT_MAX_POOL_CONNECTIONS
        ),
    )


class ScanContext:
    """Owns all per-scan state for a single ``SRAVerify.run_checks`` call.

    A fresh ``ScanContext`` is constructed per scan and goes out of scope when
    the scan finishes. Cached AWS API responses, cached boto3 clients, and the
    bounded ``Client_Config`` all live here. The context is designed to be safe
    to share across threads; the namespaced cache primitives, the client cache,
    and the lazy typed accessors all serialize their critical sections through
    a single ``threading.Lock``.

    Construction-time overrides for the ``Client_Config`` follow this
    precedence (Requirements 2.4, 2.5):

    1. An explicit ``client_config`` parameter is used as-is. Individual
       override parameters supplied alongside it are ignored, and a debug-level
       message is logged so the discrepancy is visible during troubleshooting.
    2. Otherwise, the default ``Config`` is built and any of
       ``connect_timeout`` / ``read_timeout`` / ``max_attempts`` /
       ``max_pool_connections`` that are not ``None`` override the
       corresponding default field.
    3. With no overrides, the documented defaults apply (10s connect, 30s read,
       3 retry attempts in standard mode, 50 pool connections).
    """

    def __init__(
        self,
        session: boto3.Session,
        regions: Optional[List[str]] = None,
        audit_accounts: Optional[List[str]] = None,
        log_archive_accounts: Optional[List[str]] = None,
        client_config: Optional[botocore.config.Config] = None,
        connect_timeout: Optional[float] = None,
        read_timeout: Optional[float] = None,
        max_attempts: Optional[int] = None,
        max_pool_connections: Optional[int] = None,
    ) -> None:
        # Per-scan immutable inputs (Requirements 1.6, 1.7, 1.8, 1.9). The
        # explicit Region list is copied, so a caller mutating its own list
        # mid-scan cannot make ``scan_region(ctx)`` and ``ctx.scan_region``
        # disagree.
        self._session: boto3.Session = session
        self._explicit_regions: Optional[List[str]] = (
            list(regions) if regions is not None else None
        )
        # The scan Region, which selects the partition. Raises
        # ``PartitionUndeterminedError`` here -- before the lock, caches and
        # provider exist -- when neither an explicit Region nor the session
        # supplies one. ``SRAVerify`` refuses such a scan earlier; this is the
        # backstop for a library caller that builds a context directly.
        self._scan_region: str = resolve_scan_region(self._explicit_regions, session)
        self._resolved_regions: Optional[List[str]] = None
        self._audit_accounts: List[str] = (
            audit_accounts if audit_accounts is not None else []
        )
        self._log_archive_accounts: List[str] = (
            log_archive_accounts if log_archive_accounts is not None else []
        )

        # Resolve the Client_Config per the documented precedence
        # (Requirements 2.1, 2.2, 2.3, 2.4, 2.5).
        if client_config is not None:
            individual_overrides_supplied = any(
                value is not None
                for value in (
                    connect_timeout,
                    read_timeout,
                    max_attempts,
                    max_pool_connections,
                )
            )
            if individual_overrides_supplied:
                logger.debug(
                    "ScanContext received an explicit client_config along with "
                    "individual override parameters (connect_timeout, "
                    "read_timeout, max_attempts, max_pool_connections); the "
                    "explicit client_config takes precedence and the "
                    "individual overrides are ignored."
                )
            self._client_config: botocore.config.Config = client_config
        else:
            self._client_config = _build_default_client_config(
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
                max_attempts=max_attempts,
                max_pool_connections=max_pool_connections,
            )

        # Per-scan mutable state (Requirement 1.10: empty cache on construction).
        # Subsequent tasks (2.2, 2.3, 2.4) populate these structures via the
        # namespaced primitives, ``get_client``, and the lazy typed accessors.
        self._clients: Dict[Tuple[str, str], Any] = {}
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._account_info: Optional[Dict[str, str]] = None

        # Single lock guards all mutable state above so the future Phase 3.1
        # concurrent-execution work does not need a second refactor
        # (Requirement 1.11).
        self._lock: threading.Lock = threading.Lock()

        # The Organizations provider, reached as ``ctx.organization`` and from a
        # check as ``self.organization``. Last, because it holds this context
        # (weakly). Constructing it issues no AWS call and binds no boto3 client.
        self._organization: OrganizationsProvider = OrganizationsProvider(self)

    # ------------------------------------------------------------------ #
    # Typed read-only properties (public API).
    # ------------------------------------------------------------------ #

    @property
    def session(self) -> boto3.Session:
        """The boto3 ``Session`` for this scan."""
        return self._session

    @property
    def regions(self) -> List[str]:
        """Explicit region list passed in at construction, or ``[]`` if none.

        This property does not trigger AWS region discovery. Callers that need
        the lazily resolved enabled-regions list (when no explicit regions were
        supplied) should use ``get_enabled_regions()`` instead, which is added
        in task 2.4.
        """
        if self._explicit_regions is None:
            return []
        return self._explicit_regions

    @property
    def scan_region(self) -> str:
        """The scan Region: the first explicit Region, else the session's.

        Computed once at construction by ``resolve_scan_region`` and never
        ``None``. It selects the partition for every client this context builds
        without an explicit Region. Read-only; no setter.
        """
        return self._scan_region

    @property
    def audit_accounts(self) -> List[str]:
        """Audit account IDs for the scan; ``[]`` when none were supplied."""
        return self._audit_accounts

    @property
    def log_archive_accounts(self) -> List[str]:
        """Log-archive account IDs for the scan; ``[]`` when none were supplied."""
        return self._log_archive_accounts

    @property
    def organization(self) -> OrganizationsProvider:
        """The Organizations provider for this scan. Read-only; no setter."""
        return self._organization

    @property
    def client_config(self) -> botocore.config.Config:
        """The ``botocore.config.Config`` applied to every boto3 client in this scan."""
        return self._client_config

    # ------------------------------------------------------------------ #
    # Private namespaced cache primitives (service base classes only).
    # ------------------------------------------------------------------ #
    #
    # These three methods are the storage layer for cached AWS-API responses.
    # They are deliberately underscore-prefixed and not part of the public API:
    # service base classes (e.g., ``GuardDutyCheck``, ``SecurityHubCheck``) call
    # them from inside their typed accessor methods, but individual check
    # classes never touch them directly (Requirements 1.5, 6.1, 6.3).
    #
    # The ``_cache`` structure is a two-level dict:
    # ``Dict[namespace, Dict[key, value]]``. The outer dict is keyed by the
    # service namespace (e.g., ``"guardduty"``); the inner dict holds whatever
    # cache keys that service has chosen (e.g., ``"detector_id:us-east-1"``).
    # The inner dict is created lazily on the first ``_set`` for a given
    # namespace so reads against an empty namespace stay cheap.
    #
    # Thread-safety: every operation acquires ``self._lock`` for the dict
    # access (Requirement 1.11). The critical section is a handful of dict
    # lookups, so the lock is held for microseconds. Boto3 calls on cache miss
    # happen outside this lock; the typed accessors that combine a miss with an
    # AWS API call (``get_account_info``, ``get_management_account_id``,
    # ``get_enabled_regions``, ``get_client``) implement their own
    # double-checked locking on top of these primitives.

    def _get(self, namespace: str, key: str, default: Any = None) -> Any:
        """Return the cached value for ``(namespace, key)`` or ``default``.

        Intended for use by service base classes only. Acquires ``self._lock``
        for the dict access; never issues an AWS call.
        """
        with self._lock:
            namespace_cache = self._cache.get(namespace)
            if namespace_cache is None:
                return default
            return namespace_cache.get(key, default)

    def _set(self, namespace: str, key: str, value: Any) -> None:
        """Store ``value`` for ``(namespace, key)``, last-writer-wins.

        Intended for use by service base classes only. Lazily creates the inner
        namespace dict on the first write to a previously unseen namespace.
        Acquires ``self._lock`` for the dict access.

        **Refuses an error result.** A failure written here is replayed to every
        later check in that Region for the rest of the scan -- one denied call
        becomes a whole Region's worth of wrong rows. The accessor discipline is
        the primary control and the contract tests hold it per accessor; this is
        the backstop for the accessor written next year by someone who has not
        read that contract.

        It **skips and warns rather than raising**: by the time it fires, the
        accessor has already returned the error result to its caller correctly and
        the only defect is the attempted write, so raising would abort the
        calling check and lose its rows to a synthetic ERROR row for what is a
        harmless redundancy. A ``warning`` in the log is proportionate.

        It is a backstop and not a substitute, because it only sees
        error result-*shaped* dicts. An accessor that still encodes failure as
        ``[]``, ``{}``, ``None``, or ``False`` walks straight past it.
        """
        # Ahead of the lock: nothing is being mutated, and a refused write
        # should not contend for it.
        if is_error(value):
            logger.warning(
                f"ScanContext: refusing to cache an error result under "
                f"{namespace}:{key} ({value['Error'].get('Code')}); "
                f"the accessor should have returned it without caching it"
            )
            return

        with self._lock:
            namespace_cache = self._cache.get(namespace)
            if namespace_cache is None:
                namespace_cache = {}
                self._cache[namespace] = namespace_cache
            namespace_cache[key] = value

    def _has(self, namespace: str, key: str) -> bool:
        """Return ``True`` when ``(namespace, key)`` has a cached value.

        Intended for use by service base classes only. Acquires ``self._lock``
        for the dict access.
        """
        with self._lock:
            namespace_cache = self._cache.get(namespace)
            if namespace_cache is None:
                return False
            return key in namespace_cache

    # ------------------------------------------------------------------ #
    # Per-scan boto3 client cache (public typed accessor).
    # ------------------------------------------------------------------ #

    def get_client(self, service_name: str, region: Optional[str] = None) -> Any:
        """Return a boto3 client for ``(service_name, region)``, cached for the scan.

        The client is constructed from this context's ``Session`` and
        ``Client_Config``, so every client built here picks up the bounded
        timeouts, retry policy, and connection pool size documented on
        ``ScanContext``. Once a client has been built for a given
        ``(service_name, region)`` pair, the same instance is returned on every
        subsequent call within the same scan (Requirement 2.10). ``region=None``
        means the scan Region, so ``get_client(svc)`` and
        ``get_client(svc, region=ctx.scan_region)`` share one cache key and
        return the same instance, and no client is ever built without a Region
        (which would let botocore fall back to the commercial ``aws-global``
        endpoint).

        Thread-safety contract (Requirement 2.11): callers racing on the same
        ``(service_name, region)`` key are guaranteed to receive the same
        client object. The implementation uses double-checked locking: the
        cache is checked under the lock, the lock is released while
        ``session.client`` runs (because boto3 client construction can take
        non-trivial time and we don't want to serialize all callers behind
        it), and then the lock is re-acquired to insert the result. Under
        contention this means ``session.client`` may be called more than once
        for the same key, but only the first result that wins the second
        critical section is retained and returned to every caller; any extra
        clients built by losing threads are discarded so the cache always
        reflects a single instance per key.

        Args:
            service_name: The AWS service name as understood by ``boto3``
                (e.g., ``"s3"``, ``"guardduty"``, ``"organizations"``).
            region: The AWS region for the client. ``None`` means the scan
                Region (``self.scan_region``); a partition-global service such
                as IAM or Organizations then reaches the scan's partition.
                Forwarded as ``region_name=region`` to ``session.client``.

        Returns:
            The cached boto3 client instance for the given key.
        """
        region = region if region is not None else self._scan_region
        cache_key: Tuple[str, str] = (service_name, region)

        # First check: fast path under the lock for the common cache-hit case.
        with self._lock:
            cached = self._clients.get(cache_key)
            if cached is not None:
                return cached

        # Lock released. Construct the client outside the critical section so
        # concurrent callers for *different* keys aren't serialized behind us.
        new_client = self._session.client(
            service_name,
            region_name=region,
            config=self._client_config,
        )

        # Second check: another thread may have populated the cache while we
        # were building our client. If so, drop ours and return theirs so all
        # callers observe the same instance for this key.
        with self._lock:
            cached = self._clients.get(cache_key)
            if cached is not None:
                return cached
            self._clients[cache_key] = new_client
            return new_client

    # ------------------------------------------------------------------ #
    # Lazy typed accessors for per-scan AWS lookups.
    # ------------------------------------------------------------------ #
    #
    # ``get_account_info`` and ``get_enabled_regions`` each issue an AWS call the
    # first time they are invoked in a scan and cache a success for the
    # remainder of the scan (Requirements 1.2, 1.4); ``get_management_account_id``
    # reads the Organizations provider, which owns that cache. Both of the first
    # two follow the double-checked locking shape used by ``get_client``:
    #
    # 1. Acquire ``self._lock``, peek at the cache field. On hit, release and
    #    return the cached value.
    # 2. Lock released. Issue the AWS call(s), so threads racing on different
    #    lazy accessors don't serialize behind each other.
    # 3. Re-acquire ``self._lock`` and double-check. If another thread won the
    #    race, return its result and discard ours so every caller observes the
    #    same object. Otherwise store ours and return it.
    #
    # They follow the client-error contract (Requirement 13.3): an AWS failure is
    # returned as an error result, logged once as ``aws_call_failed`` at
    # ``debug`` by ``AWSClient.aws_error``, and never cached, so the next call
    # re-issues. Nothing here raises for an AWS outcome or logs one at
    # ``error``. Each boto3 client is acquired *before* its ``try``: acquisition
    # reads bundled endpoint data and is a defect if it fails, so a construction
    # failure propagates rather than becoming an error result describing a call
    # that was never made. A non-AWS exception (a defect) propagates too.

    def _call_failed(self, e: Exception) -> ErrorResult:
        """The error result for a failed lookup, through the one shared formatter.

        Args:
            e: A ``ClientError`` or ``BotoCoreError``.

        Returns:
            The error result, after exactly one ``aws_call_failed`` record.
        """
        return AWSClient(self._scan_region, self).aws_error(e)

    def get_account_info(self) -> Dict[str, str] | ErrorResult:
        """Return the account ID and name for the scan, cached after first success.

        Issues ``sts:GetCallerIdentity`` to resolve the account ID, then
        ``account:GetAccountInformation`` to resolve the human-readable
        account name. A success is cached for the remainder of the scan and
        every subsequent call returns the same dict object (Requirement 1.2).

        An STS failure is returned as an error result and nothing is cached, so
        a retry re-issues the STS call. The Account API call is best-effort for
        an AWS outcome: when it fails (commonly because the calling principal
        lacks ``account:GetAccountInformation``), or answers without an
        ``AccountName``, the name is ``""`` and the identity is still cached.

        Returns:
            ``{"account_id": ..., "account_name": ...}`` (``account_name`` is
            ``""`` when the Account API was unavailable), or the STS error
            result.
        """
        # First check: fast path under the lock for the common cache-hit case.
        with self._lock:
            if self._account_info is not None:
                return self._account_info

        # Both clients are acquired before their try: a construction failure is
        # a defect, not an AWS outcome, and propagates unchanged.
        sts_client = self.get_client("sts", region=self._scan_region)
        account_client = self.get_client("account", region=self._scan_region)
        try:
            response = sts_client.get_caller_identity()
        except AWS_EXCEPTIONS as e:
            return self._call_failed(e)  # never cached; the next caller re-issues
        account_id = response["Account"]

        logger.debug("Getting AWS account name from Account API")
        try:
            response = account_client.get_account_information()
        except AWS_EXCEPTIONS as e:
            self._call_failed(e)  # one debug record; the name is best-effort
            account_name = ""
        else:
            account_name = response.get("AccountName", "")
            logger.debug(f"Retrieved account name: {account_name}")

        new_info: Dict[str, str] = {
            "account_id": account_id,
            "account_name": account_name,
        }

        # Second check: another thread may have populated the cache while we
        # were calling AWS. If so, return its result and drop ours so every
        # caller sees the same object.
        with self._lock:
            if self._account_info is not None:
                return self._account_info
            self._account_info = new_info
            logger.debug(f"Cached account information for {account_id}")
            return new_info

    def get_management_account_id(self) -> str | ErrorResult:
        """Return the AWS Organizations management account ID.

        Delegates to ``self.organization.management_account_id()``, which reads
        the provider's cached ``DescribeOrganization`` answer, so the context
        keeps no field of its own and binds no Organizations client.

        Returns:
            The management account's ID, or the ``DescribeOrganization`` error
            result unchanged (never cached).
        """
        return self.organization.management_account_id()

    def get_enabled_regions(self) -> List[str] | ErrorResult:
        """Return the list of AWS regions for the scan.

        When an explicit, non-empty region list was supplied at construction
        time, that list is returned as-is and no AWS call is issued. Otherwise
        this method calls ``ec2:DescribeRegions(AllRegions=False)`` once
        (against the scan Region, so it answers for the scan's partition) to
        enumerate the regions enabled for the account, caches a success for
        the remainder of the scan, and returns it on every subsequent call
        (Requirement 1.4).

        A failure is returned as an error result and not cached, so a retry
        re-issues the call.

        Returns:
            A list of region name strings (e.g., ``["us-east-1", "us-west-2"]``),
            or the ``DescribeRegions`` error result.
        """
        # If the caller supplied an explicit, non-empty region list at
        # construction, honor it without ever calling EC2. An empty list or
        # ``None`` falls through to the lazy-resolve path below.
        if self._explicit_regions:
            return self._explicit_regions

        # First check: fast path under the lock for the common cache-hit case.
        with self._lock:
            if self._resolved_regions is not None:
                return self._resolved_regions

        logger.debug("Getting enabled AWS regions")
        # Acquired outside the try, like STS and Account above: a construction
        # failure (e.g. PartialCredentialsError) propagates unchanged.
        ec2_client = self.get_client("ec2", region=self._scan_region)
        try:
            response = ec2_client.describe_regions(AllRegions=False)
        except AWS_EXCEPTIONS as e:
            return self._call_failed(e)  # never cached; the next caller re-issues
        regions = [region["RegionName"] for region in response["Regions"]]
        logger.debug(f"Found {len(regions)} enabled regions")

        # Second check: another thread may have populated the cache while we
        # were calling AWS.
        with self._lock:
            if self._resolved_regions is not None:
                return self._resolved_regions
            self._resolved_regions = regions
            return regions
