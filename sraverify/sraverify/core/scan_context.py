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

from sraverify.core.logging import logger


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
        # Per-scan immutable inputs (Requirements 1.6, 1.7, 1.8, 1.9).
        self._session: boto3.Session = session
        self._explicit_regions: Optional[List[str]] = regions
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
        self._management_account_id: Optional[str] = None

        # Single lock guards all mutable state above so the future Phase 3.1
        # concurrent-execution work does not need a second refactor
        # (Requirement 1.11).
        self._lock: threading.Lock = threading.Lock()

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
    def audit_accounts(self) -> List[str]:
        """Audit account IDs for the scan; ``[]`` when none were supplied."""
        return self._audit_accounts

    @property
    def log_archive_accounts(self) -> List[str]:
        """Log-archive account IDs for the scan; ``[]`` when none were supplied."""
        return self._log_archive_accounts

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
        """
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
        subsequent call within the same scan (Requirement 2.10). When
        ``region`` is ``None`` the cache key uses the literal sentinel
        ``"__global__"`` so global services like IAM and Organizations stay
        distinct from any specific region.

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
            region: The AWS region for the client, or ``None`` for global
                services. Forwarded as ``region_name=region`` to
                ``session.client``; ``None`` lets boto3 pick the session's
                default region (the same behavior as calling
                ``session.client(service_name)`` directly).

        Returns:
            The cached boto3 client instance for the given key.
        """
        cache_key: Tuple[str, str] = (service_name, region if region is not None else "__global__")

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
    # ``get_account_info``, ``get_management_account_id``, and
    # ``get_enabled_regions`` each issue an AWS call the first time they are
    # invoked in a scan and cache the result for the remainder of the scan
    # (Requirements 1.2, 1.3, 1.4). All three follow the same double-checked
    # locking shape used by ``get_client``:
    #
    # 1. Acquire ``self._lock``, peek at the cache field. On hit, release and
    #    return the cached value.
    # 2. Lock released. Issue the AWS call(s) -- this is where the work
    #    happens, and we deliberately do not hold the lock across the call so
    #    threads racing on different lazy accessors don't serialize behind
    #    each other.
    # 3. Re-acquire ``self._lock`` and double-check. If another thread won the
    #    race and populated the cache while we were calling AWS, return its
    #    result and discard ours so every caller observes the same object.
    #    Otherwise store ours and return it.
    #
    # None of these methods caches a failure: if the AWS call raises, the
    # cache field stays ``None`` and the next call retries. This matches the
    # pre-refactor behavior where each call site issued the lookup directly
    # and a transient failure followed by a retry would re-issue the call.
    # All three obtain underlying boto3 clients via ``self.get_client(...)``
    # so the bounded ``Client_Config`` is applied (Requirement 2.12 spirit).

    def get_account_info(self) -> Dict[str, str]:
        """Return the account ID and name for the scan, cached after first call.

        Issues ``sts:GetCallerIdentity`` to resolve the account ID, then
        ``account:GetAccountInformation`` to resolve the human-readable
        account name. The result is cached for the remainder of the scan and
        every subsequent call returns the same dict object (Requirement 1.2).

        STS failure is fatal: it is re-raised to the caller and nothing is
        cached, so a retry will re-issue the STS call. The Account API call
        is best-effort -- when it fails (commonly because the calling
        principal lacks ``account:GetAccountInformation``), this method falls
        back to a blank ``account_name`` and still caches the result, which
        matches the pre-refactor ``SecurityCheck._get_account_info`` behavior.

        Returns:
            A dict with keys ``"account_id"`` and ``"account_name"``. The
            ``account_name`` value is ``""`` when the Account API was
            unavailable.
        """
        # First check: fast path under the lock for the common cache-hit case.
        with self._lock:
            if self._account_info is not None:
                return self._account_info

        # Lock released. Issue STS first -- this is the fatal call. Failure
        # here re-raises and leaves ``self._account_info`` unset so a later
        # caller can retry.
        sts_client = self.get_client("sts")
        try:
            response = sts_client.get_caller_identity()
            account_id = response["Account"]
        except Exception as e:
            logger.error(f"Failed to get account ID from STS: {str(e)}")
            raise Exception(f"Failed to get account ID: {str(e)}")

        # Account API is best-effort: a failure means we keep going with a
        # blank account name. This preserves the pre-refactor behavior.
        try:
            logger.debug("Getting AWS account name from Account API")
            account_client = self.get_client("account")
            response = account_client.get_account_information()
            account_name = response["AccountName"]
            logger.debug(f"Retrieved account name: {account_name}")
        except Exception as e:
            logger.warning(f"Failed to get account name from Account API: {str(e)}")
            account_name = ""

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

    def get_management_account_id(self) -> str:
        """Return the AWS Organizations management account ID, cached for the scan.

        Issues ``organizations:DescribeOrganization`` on the first call and
        returns the value of ``Organization.MasterAccountId``. Subsequent
        calls within the same scan return the cached string without issuing
        another AWS call (Requirement 1.3).

        Failures are propagated to the caller; nothing is cached on failure,
        so a retry will re-issue the AWS call. This matches the pre-refactor
        ``SecurityCheck.get_management_accountId`` behavior.

        Returns:
            The AWS account ID of the organization's management account.
        """
        # First check: fast path under the lock for the common cache-hit case.
        with self._lock:
            if self._management_account_id is not None:
                return self._management_account_id

        # Lock released. Issue the Organizations call. Failure re-raises and
        # leaves ``self._management_account_id`` unset so a later caller can
        # retry.
        try:
            logger.debug("Getting AWS management account ID")
            org_client = self.get_client("organizations")
            response = org_client.describe_organization()
            management_account_id = response["Organization"]["MasterAccountId"]
            logger.debug(f"Management account ID: {management_account_id}")
        except Exception as e:
            logger.error(f"Failed to get AWS management account ID: {str(e)}")
            raise Exception(f"Failed to get AWS management account ID: {str(e)}")

        # Second check: another thread may have populated the cache while we
        # were calling AWS.
        with self._lock:
            if self._management_account_id is not None:
                return self._management_account_id
            self._management_account_id = management_account_id
            return management_account_id

    def get_enabled_regions(self) -> List[str]:
        """Return the list of AWS regions for the scan.

        When an explicit, non-empty region list was supplied at construction
        time, that list is returned as-is and no AWS call is issued. Otherwise
        this method calls ``ec2:DescribeRegions(AllRegions=False)`` once
        (against ``us-east-1``) to enumerate the regions enabled for the
        account, caches the result for the remainder of the scan, and returns
        it on every subsequent call (Requirement 1.4).

        Failures are propagated; nothing is cached on failure so a retry
        will re-issue the AWS call.

        Returns:
            A list of region name strings (e.g., ``["us-east-1", "us-west-2"]``).
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

        # Lock released. Issue the EC2 call. Failure re-raises and leaves
        # ``self._resolved_regions`` unset so a later caller can retry.
        try:
            logger.debug("Getting enabled AWS regions")
            ec2_client = self.get_client("ec2", region="us-east-1")
            response = ec2_client.describe_regions(AllRegions=False)
            regions = [region["RegionName"] for region in response["Regions"]]
            logger.debug(f"Found {len(regions)} enabled regions")
        except Exception as e:
            logger.error(f"Failed to get enabled regions: {str(e)}")
            raise Exception(f"Failed to get enabled regions: {str(e)}")

        # Second check: another thread may have populated the cache while we
        # were calling AWS.
        with self._lock:
            if self._resolved_regions is not None:
                return self._resolved_regions
            self._resolved_regions = regions
            return regions
