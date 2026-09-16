"""
Base class for Security Lake security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"securitylake"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

**``AccessDeniedException`` is deliberately absent from**
:data:`NOT_CONFIGURED_ERRORS`, which declares only ``ResourceNotFoundException``.
Checked against a controlled account on 2026-09-15: from an account that is not
the Security Lake delegated administrator, both ``ListDataLakes`` and
``ListSubscribers`` answer

    AccessDeniedException: The request failed because you don't have sufficient
    permissions to perform this operation for your organization. Contact your
    administrator for assistance.

which is a permission failure by any reading -- the caller may not ask the
question -- and therefore an ERROR. Declaring it would turn every
non-delegated-administrator account in the organization into a fabricated FAIL.
An unreachable opt-in Region answers with an endpoint error rather than an AWS
code, which the transport path already covers.

:meth:`data_lake_present` is a pure helper over a success dict:
:meth:`is_security_lake_enabled` returns the ``ListDataLakes`` response, because a
``bool`` has nowhere to carry an error.
"""
from typing import Any, ClassVar, Dict, List, Mapping, Optional

from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.securitylake.client import SecurityLakeClient

#: Shared evidence for ``ResourceNotFoundException``, which is unambiguous for
#: every Security Lake read: the resource being requested *is* the data lake or its
#: configuration, so its absence is the finding.
_NOT_FOUND_EVIDENCE = (
    "https://docs.aws.amazon.com/security-lake/latest/APIReference/"
    "CommonErrors.html -- ResourceNotFoundException means the requested resource "
    "does not exist. For these five reads the requested resource is the data lake "
    "or a member of its configuration, so its absence is the control being absent "
    "rather than an inability to determine."
)


class SecurityLakeCheck(SecurityCheck):
    """Base class for all Security Lake security checks."""

    NAMESPACE = "securitylake"

    #: The ``(operation, code)`` pairs that mean "the control is not configured"
    #: for Security Lake.
    #:
    #: ``AccessDeniedException`` is **deliberately not here.** See the module
    #: docstring: it was confirmed on 2026-09-15 to mean "you don't have
    #: sufficient permissions ... for your organization", which is an ERROR.
    #: Declaring it would fabricate a FAIL for every account that is not the
    #: delegated administrator, and it is precisely the code behind the 8 measured
    #: masked-FAIL rows this batch exists to fix.
    #:
    #: ``UnauthorizedException`` is not here either, because it does not occur --
    #: the design predicted it and the controlled account disproved it.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        op: {"ResourceNotFoundException": NotConfigured(evidence=_NOT_FOUND_EVIDENCE)}
        for op in (
            "ListDataLakes",
            "GetDataLakeOrganizationConfiguration",
            "ListLogSources",
            "ListSubscribers",
            "GetDataLakeSources",
        )
    }

    def _setup_clients(self):
        """Set up Security Lake clients for each region.

        Each wrapper obtains its underlying boto3 ``securitylake``,
        ``organizations``, and ``sqs`` clients from ``self._ctx.get_client(...)``,
        so the per-scan ``Client_Config`` and client cache are applied.
        """
        self._clients.clear()
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
        return self._clients.get(region)

    def _cached_call(
        self, region: str, cache_key: str, method: str, *args: Any
    ) -> Mapping[str, Any]:
        """
        Run one client method for a Region through the accessor shape.

        Args:
            region: AWS region name.
            cache_key: Key within the ``"securitylake"`` namespace.
            method: Name of the :class:`SecurityLakeClient` method to call.
            *args: Positional arguments for that method.

        Returns:
            The cached or freshly fetched response dict, or an error result.
        """
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"SecurityLake: Using cached {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if client is None:
            logger.warning(
                f"SecurityLake: No client available for region {region}"
            )
            return no_client_result(service="Security Lake", region=region)

        logger.debug(f"SecurityLake: Fetching {cache_key}")
        result = getattr(client, method)(*args)

        if is_error(result):
            # Never cached, and this is the most consequential instance of the
            # rule in the tree: 17 checks share this namespace, so a cached
            # failure would be replayed to all of them.
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result

    # ----------------------------------------------------------------- #
    # Accessors -- each returns the response dict or an error result
    # ----------------------------------------------------------------- #

    def get_subscribers(self, region: str) -> Mapping[str, Any]:
        """
        Get Security Lake subscribers, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"subscribers": [...]}`` on success, or an error result.

            The measured masked-FAIL path. ``SRA-SECURITYLAKE-16`` and ``-17``
            must test for ``"Error"`` before concluding a subscriber is absent.
        """
        return self._cached_call(
            region, f"subscribers:{region}", "list_subscribers"
        )

    def is_security_lake_enabled(self, region: str) -> Mapping[str, Any]:
        """
        Get the ``ListDataLakes`` response for a Region, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"dataLakes": [...]}`` on success, or an error result. Read
            enablement with :meth:`data_lake_present` after testing for
            ``"Error"`` -- a ``bool`` has nowhere to carry a failure.
        """
        return self._cached_call(
            region, f"security_lake_status:{region}", "is_security_lake_enabled"
        )

    @staticmethod
    def data_lake_present(response: Mapping[str, Any]) -> bool:
        """
        Read enablement out of a successful ``ListDataLakes`` response.

        A pure helper over a **success dict**, never over an accessor's raw
        return. Call it only after ``"Error" in response`` is False.

        Args:
            response: A successful :meth:`is_security_lake_enabled` response.

        Returns:
            ``True`` when at least one data lake exists. Here ``False`` means
            exactly one thing, because a failure could not have reached this far.
        """
        return bool(response.get("dataLakes"))

    def get_organization_configuration(self, region: str) -> Mapping[str, Any]:
        """
        Get the Security Lake organization configuration, with caching.

        Args:
            region: AWS region name

        Returns:
            The ``GetDataLakeOrganizationConfiguration`` response, or an error
            result.
        """
        return self._cached_call(
            region,
            f"organization_configuration:{region}",
            "get_organization_configuration",
        )

    def get_delegated_administrators(self, region: str) -> Mapping[str, Any]:
        """
        Get the Organizations delegated administrators for Security Lake.

        Args:
            region: AWS region name

        Returns:
            ``{"DelegatedAdministrators": [...]}``, or an error result.
        """
        return self._cached_call(
            region,
            f"delegated_administrators:{region}",
            "list_delegated_administrators",
        )

    def get_organization_accounts(self, region: str) -> Mapping[str, Any]:
        """
        Get every account in the AWS Organization, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"Accounts": [...]}``, or an error result.
        """
        return self._cached_call(
            region, f"organization_accounts:{region}", "list_organization_accounts"
        )

    def get_sqs_queue_encryption(
        self, region: str, queue_url: str
    ) -> Mapping[str, Any]:
        """
        Get an SQS queue's encryption attributes, with caching.

        Args:
            region: AWS region name
            queue_url: The queue URL.

        Returns:
            The ``GetQueueAttributes`` response, or an error result. Read
            ``Attributes.KmsMasterKeyId`` after the error test.
        """
        return self._cached_call(
            region,
            f"sqs_encryption:{region}:{queue_url}",
            "get_sqs_queue_encryption",
            queue_url,
        )

    def get_data_lake_sources(
        self, region: str, account_id: Optional[str] = None
    ) -> Mapping[str, Any]:
        """
        Get Security Lake data lake sources, with caching.

        Args:
            region: AWS region name
            account_id: Optional account ID. ``None`` means all accounts.

        Returns:
            ``{"dataLakeSources": [...]}``, or an error result.
        """
        return self._cached_call(
            region,
            f"data_lake_sources:{region}:{account_id or 'all'}",
            "get_data_lake_sources",
            account_id,
        )

    # ----------------------------------------------------------------- #
    # Derived predicates -- bools over caches a check has already tested
    #
    # These return `bool` and cannot report a failure, which is safe only
    # because a check calls the error-bearing accessor first and classifies its
    # error result before reaching one of these. The accessor does not cache
    # failures, so by the time a predicate reads the cache the value there is a
    # success response or absent.
    # ----------------------------------------------------------------- #

    def get_enabled_regions(self) -> List[str]:
        """
        Get the Regions where Security Lake is enabled.

        Returns:
            Region names with at least one data lake. A Region whose lookup
            **failed** is omitted rather than guessed at, the same rule
            ``GuardDutyCheck.get_enabled_regions`` follows: the scanner does not
            know, and the check that consumed the error result reports it.
        """
        enabled_regions: List[str] = []
        for region in self.regions:
            response = self.is_security_lake_enabled(region)
            if is_error(response):
                logger.debug(
                    f"SecurityLake: enablement undetermined in {region}; omitted "
                    f"from enabled regions"
                )
                continue
            if self.data_lake_present(response):
                enabled_regions.append(region)
        return enabled_regions

    def get_log_sources(self, region: str) -> Mapping[str, Any]:
        """
        Get the ``ListLogSources`` response for a Region, with caching.

        The error-bearing accessor the three log-source predicates below are built
        on, and the one a check must guard before using any of them.

        It exists because those predicates return a bare ``bool`` and therefore
        cannot report a failure. Without this, a denied ``ListLogSources`` read as
        "the source is not configured" -- measured at **104 FAIL rows** in a
        single-Region log-archive scan, which is the same masked-FAIL shape this
        batch set out to remove, merely relocated from ``_16``/``_17`` to
        ``_06``..``_13``.

        Args:
            region: AWS region name

        Returns:
            ``{"sources": [...]}`` on success, or an error result.
        """
        return self._cached_call(
            region, f"log_sources:{region}", "list_log_sources", [region]
        )

    def get_log_source_status(self, region: str, source_name: str) -> bool:
        """
        Whether a log source is enabled anywhere in a Region.

        Args:
            region: AWS region name
            source_name: e.g. ``"ROUTE53"``, ``"VPC_FLOW"``.

        Returns:
            ``True`` if the source appears in this Region's log sources.
            ``False`` also when the lookup failed, which is why a caller must
            guard :meth:`get_log_sources` first.
        """
        response = self.get_log_sources(region)
        if is_error(response):
            logger.debug(
                f"SecurityLake: log sources undetermined in {region}; the caller "
                f"should have guarded get_log_sources() before asking"
            )
            return False

        for entry in response.get("sources", []):
            if entry.get("region") != region:
                continue
            for source in entry.get("sources", []):
                if source.get("awsLogSource", {}).get("sourceName") == source_name:
                    return True
        return False

    def get_account_log_source_status(self, region: str, source_name: str) -> bool:
        """
        Whether a log source is enabled for *this* account in a Region.

        Args:
            region: AWS region name
            source_name: e.g. ``"ROUTE53"``, ``"VPC_FLOW"``.

        Returns:
            ``True`` if the source is enabled for this account.
        """
        cache_key = f"account_data_lake_sources:{region}"
        if self._ctx._has(self.NAMESPACE, cache_key):
            response = self._ctx._get(self.NAMESPACE, cache_key)
        else:
            client = self.get_client(region)
            if client is None:
                return False
            response = client.get_data_lake_sources(self.account_id)
            if is_error(response):
                logger.debug(
                    f"SecurityLake: account data lake sources undetermined in "
                    f"{region}"
                )
                return False
            self._ctx._set(self.NAMESPACE, cache_key, response)

        for entry in response.get("dataLakeSources", []):
            if (
                entry.get("account") == self.account_id
                and entry.get("sourceName") == source_name
            ):
                return True
        return False

    def check_log_source_configured(
        self,
        region: str,
        source_name: str,
        account_id: Optional[str] = None,
        required_version: str = "2.0",
    ) -> bool:
        """
        Whether a log source is configured, at a required source version.

        Args:
            region: AWS region name
            source_name: e.g. ``"ROUTE53"``, ``"VPC_FLOW"``.
            account_id: Account to check; defaults to the scanned account.
            required_version: Required ``sourceVersion``.

        Returns:
            ``True`` if configured at that version.
        """
        target_account = account_id or self.account_id
        cache_key = f"list_log_sources:{target_account}:{region}"

        if not self._ctx._has(self.NAMESPACE, cache_key):
            self._prime_region_log_sources(region)

        log_sources = (
            self._ctx._get(self.NAMESPACE, cache_key)
            if self._ctx._has(self.NAMESPACE, cache_key)
            else []
        )

        for entry in log_sources:
            if (
                entry.get("account") == target_account
                and entry.get("region") == region
            ):
                for source in entry.get("sources", []):
                    aws_log_source = source.get("awsLogSource", {})
                    if (
                        aws_log_source.get("sourceName") == source_name
                        and aws_log_source.get("sourceVersion") == required_version
                    ):
                        return True
        return False

    def _prime_region_log_sources(self, region: str) -> None:
        """Populate the per-account log-source cache for ``region`` in one call.

        ``list_log_sources`` without an ``accounts`` filter returns entries for
        every account configured in the Region, so one regional call fills every
        per-account slot. That collapses ``N_accounts * N_regions`` calls
        (13 * 17 = 221) into ``N_regions`` (17).

        Two properties have to hold together here, and getting only one of them
        reintroduces a defect:

        * **A failure is never seeded as ``[]``.** Writing an empty list into every
          account's slot would turn one denied ``ListLogSources`` into a whole
          Region's worth of "source not configured".
        * **A failure is not re-issued per caller either.** Removing the seeding
          alone sent the call count from ~16 to **832** — 8 checks x 13 accounts x
          4 Regions, each re-priming — which is throttling territory. The regional
          call now goes through :meth:`get_log_sources`, so the *success* is cached
          under one key and shared; a failure returns fast to a caller that has
          already guarded it, so no fan-out occurs at all.

        Args:
            region: AWS region name.
        """
        response = self.get_log_sources(region)
        if is_error(response):
            logger.debug(
                f"SecurityLake: could not prime log sources in {region}; seeding "
                f"nothing rather than fabricating [] per account "
                f"({response['Error']['Code']})"
            )
            return

        org_accounts = (
            self._ctx._get(self.NAMESPACE, f"organization_accounts:{region}") or {}
        )
        account_ids = [
            a.get("Id")
            for a in org_accounts.get("Accounts", [])
            if isinstance(a, dict) and a.get("Id")
        ]
        if self.account_id and self.account_id not in account_ids:
            account_ids.append(self.account_id)

        per_account: Dict[str, List[Dict[str, Any]]] = {}
        for entry in response.get("sources", []):
            acct = entry.get("account")
            if acct:
                per_account.setdefault(acct, []).append(entry)

        for acct in account_ids:
            self._ctx._set(
                self.NAMESPACE,
                f"list_log_sources:{acct}:{region}",
                per_account.get(acct, []),
            )
        logger.debug(
            f"SecurityLake: primed log sources for {region}: "
            f"{len(per_account)} accounts with entries, {len(account_ids)} total"
        )
