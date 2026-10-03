"""
Base class for Security Hub security checks.

Per-scan cached AWS responses live on the attached :class:`ScanContext` under the
``"securityhub"`` namespace. Every accessor returns the client's response dict unchanged,
or an error result, and none caches a failure.

Cache keys are scoped to the typed method that wrote them (e.g.
``"enabled_standards:{region}"``), so :meth:`get_administrator_account` and
:meth:`get_organization_admin_accounts` cannot collide. The eight accessors share
one implementation, :meth:`_cached_call`.

:meth:`get_organization` deliberately reads and writes the **shared**
``"organizations"`` namespace under the key ``"organization"``, the same shape
``OrganizationsCheck.get_organization`` uses, so either service populates it for
the other and one scan issues ``DescribeOrganization`` once.
"""
import json
from typing import Any, ClassVar, Mapping, Optional

from sraverify.core.aws_errors import (
    NotConfigured,
    NotConfiguredTable,
    is_error,
    no_client_result,
)
from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.securityhub.client import SecurityHubClient

#: The EventBridge ``detail-type`` of a Security Hub (V2) finding event. Security
#: Hub CSPM uses ``Security Hub Findings - Imported`` instead.
#: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-cwe-event-types.html
V2_FINDINGS_DETAIL_TYPE = "Findings Imported V2"

#: The Organizations policy type that enables Security Hub (V2) org-wide.
SECURITYHUB_POLICY_TYPE = "SECURITYHUB_POLICY"

#: Evidence for the overloaded ``InvalidAccessException``.
_NOT_SUBSCRIBED_EVIDENCE = (
    "securityhub returns InvalidAccessException both when the account is not "
    "subscribed to Security Hub in the Region -- the control is genuinely absent "
    "-- and for other access problems, so the code alone cannot classify it. The "
    "message 'not subscribed to AWS Security Hub' separates them and is declared "
    "here as a needle. Observed in the 2026-09-12 CodeBuild log; the pair was "
    "already special-cased by hand in SecurityHubClient.get_enabled_standards "
    "and list_enabled_products_for_import before this migration, which is where "
    "the message string comes from. "
    "https://docs.aws.amazon.com/securityhub/1.0/APIReference/CommonErrors.html"
)


class SecurityHubCheck(SecurityCheck):
    """Base class for all SecurityHub security checks."""

    NAMESPACE = "securityhub"

    #: The ``(operation, code)`` pairs that mean "the control is not configured"
    #: for Security Hub.
    #:
    #: One code, six operations, and a message needle on every entry, because
    #: ``InvalidAccessException`` is overloaded. Without the needle this table
    #: would turn every Security Hub permission denial into a fabricated FAIL.
    #:
    #: No Organizations operation is declared here. The ones this service
    #: reaches through ``self.organization`` -- ``ListDelegatedAdministrators``,
    #: ``ListAccounts``, ``ListRoots``, ``ListPoliciesForTarget``,
    #: ``DescribePolicy`` and ``DescribeEffectivePolicy`` -- are classified by
    #: ``OrganizationsProvider.NOT_CONFIGURED_ERRORS``, which is where
    #: ``DescribeEffectivePolicy`` / ``EffectivePolicyNotFoundException`` ("no
    #: Security Hub policy reaches this account", what SRA-SECURITYHUB-17 asks)
    #: now lives.
    #:
    #: The V2 operations are needle-guarded like the rest: ``ConflictException``
    #: means "V2 is not enabled" from ``ListAggregatorsV2`` but "wrong Region" from
    #: ``GetAggregatorV2``, and only the first is declared.
    NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
        "GetEnabledStandards": {
            "InvalidAccessException": NotConfigured(
                evidence=_NOT_SUBSCRIBED_EVIDENCE,
                message="not subscribed to aws security hub",
            ),
        },
        "ListEnabledProductsForImport": {
            "InvalidAccessException": NotConfigured(
                evidence=_NOT_SUBSCRIBED_EVIDENCE,
                message="not subscribed to aws security hub",
            ),
        },
        "GetAdministratorAccount": {
            "InvalidAccessException": NotConfigured(
                evidence=_NOT_SUBSCRIBED_EVIDENCE,
                message="not subscribed to aws security hub",
            ),
        },
        "DescribeOrganizationConfiguration": {
            "InvalidAccessException": NotConfigured(
                evidence=_NOT_SUBSCRIBED_EVIDENCE,
                message="not subscribed to aws security hub",
            ),
        },
        "ListMembers": {
            "InvalidAccessException": NotConfigured(
                evidence=_NOT_SUBSCRIBED_EVIDENCE,
                message="not subscribed to aws security hub",
            ),
            # This entry is why SRA-SECURITYHUB-09 FAILs rather than PASSes in
            # a Region where Security Hub is not enabled: "no member accounts
            # found" is only a pass when the question could be asked.
            "BadRequestException": NotConfigured(
                evidence=(
                    "securityhub:ListMembers answers BadRequestException 'The "
                    "request is rejected since no such resource found.' when no "
                    "hub exists in the Region -- the missing resource is the hub "
                    "itself, so the control is absent rather than undetermined. "
                    "Verified directly on 2026-09-15 in a controlled account: "
                    "DescribeHub returns InvalidAccessException in us-east-2 and "
                    "us-west-1 and succeeds in us-east-1 and us-west-2, and "
                    "ListMembers returns exactly this BadRequestException in the "
                    "same two Regions and succeeds in the other two. The needle is "
                    "required because securityhub also returns BadRequestException "
                    "for an invalid or out-of-range input parameter, which is a "
                    "defect in the caller and must stay an ERROR. "
                    "https://docs.aws.amazon.com/securityhub/1.0/APIReference/"
                    "CommonErrors.html"
                ),
                message="no such resource found",
            ),
        },
        "ListOrganizationAdminAccounts": {
            "InvalidAccessException": NotConfigured(
                evidence=_NOT_SUBSCRIBED_EVIDENCE,
                message="not subscribed to aws security hub",
            ),
        },
        "DescribeSecurityHubV2": {
            "ResourceNotFoundException": NotConfigured(
                evidence=(
                    "Observed 2026-09-16 in account 195249513278 as "
                    "'ResourceNotFoundException: You are not subscribed to HubV2', "
                    "identically in us-east-1, us-west-2 and eu-west-1, while the "
                    "same account answered DescribeHub successfully -- so the "
                    "missing resource is the V2 hub itself and the control is "
                    "absent rather than undetermined. The needle is required "
                    "because the API reference documents ResourceNotFoundException "
                    "generically as 'we can't find the specified resource'. "
                    "https://docs.aws.amazon.com/securityhub/1.0/APIReference/"
                    "API_DescribeSecurityHubV2.html"
                ),
                message="not subscribed to hubv2",
            ),
        },
        "ListAggregatorsV2": {
            "ConflictException": NotConfigured(
                evidence=(
                    "Observed 2026-09-25 from management account 195249513278, "
                    "which has Security Hub V2 disabled, in us-east-1 and "
                    "eu-central-1 as 'aws_call_failed operation=ListAggregatorsV2 "
                    "code=ConflictException message=\"Security Hub V2 is not "
                    "enabled for 195249513278\"' -- the account has no V2 hub, so "
                    "it can hold no aggregator and the control is absent. The "
                    "needle is required: GetAggregatorV2 returns the same code for "
                    "'The current Region ... does not match the aggregation "
                    "Region', which is a fact about where we asked. "
                    "https://docs.aws.amazon.com/securityhub/1.0/APIReference/"
                    "API_ListAggregatorsV2.html"
                ),
                message="security hub v2 is not enabled",
            ),
        },
        "ListConfigurationPolicies": {
            "AccessDeniedException": NotConfigured(
                evidence=(
                    "Observed 2026-09-16: a non-delegated-administrator account "
                    "answers 'AccessDeniedException: Must be a Security Hub "
                    "delegated administrator with Central Configuration enabled', "
                    "which states central configuration is not in use -- the "
                    "control is absent. The needle is essential: the *same code* "
                    "arrives from the delegated administrator in a non-home Region "
                    "as 'Central Configuration APIs can only be called from the "
                    "aggregation region', which is a fact about where we asked and "
                    "must stay an ERROR, and a plain IAM denial must too. "
                    "https://docs.aws.amazon.com/securityhub/1.0/APIReference/"
                    "API_ListConfigurationPolicies.html"
                ),
                message="with central configuration enabled",
            ),
        },
    }

    def _setup_clients(self):
        """Set up SecurityHub clients for each region.

        Constructs one ``SecurityHubClient`` wrapper per region in
        ``self.regions``. Each wrapper obtains its underlying boto3
        ``securityhub`` and ``events`` clients from
        ``self._ctx.get_client(...)``, so the per-scan ``Client_Config`` and
        per-scan boto3 client cache are applied.
        """
        self._clients.clear()
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

    def _cached_call(
        self, region: str, cache_key: str, method: str, *args: Any
    ) -> Mapping[str, Any]:
        """
        Run one client method for a Region through the accessor shape.

        The eight public accessors below differ only in cache key and client
        method, so the shape is written once.

        Args:
            region: AWS region name.
            cache_key: Key within the ``"securityhub"`` namespace.
            method: Name of the :class:`SecurityHubClient` method to call.
            *args: Positional arguments for that method.

        Returns:
            The cached or freshly fetched response dict, or an error result.
        """
        if self._ctx._has(self.NAMESPACE, cache_key):
            logger.debug(f"SecurityHub: Using cached {cache_key}")
            return self._ctx._get(self.NAMESPACE, cache_key)

        client = self.get_client(region)
        if client is None:
            logger.warning(
                f"SecurityHub: No client available for region {region}"
            )
            return no_client_result(service="SecurityHub", region=region)

        logger.debug(f"SecurityHub: Fetching {cache_key}")
        result = getattr(client, method)(*args)

        if is_error(result):
            # Never cached: a retry has to be able to re-issue the call.
            return result

        self._ctx._set(self.NAMESPACE, cache_key, result)
        return result

    def get_enabled_standards(self, region: str) -> Mapping[str, Any]:
        """
        Get enabled Security Hub standards for a Region, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"StandardsSubscriptions": [...]}`` on success, or an error result.
            "Security Hub is not subscribed here" arrives as an
            ``InvalidAccessException`` that ``self.is_not_configured(error)``
            recognizes, which distinguishes it from a denied permission.
        """
        return self._cached_call(
            region, f"enabled_standards:{region}", "get_enabled_standards"
        )

    def get_security_hub_v2(self, region: str) -> Mapping[str, Any]:
        """
        Get the Security Hub V2 resource for a Region, with caching.

        Args:
            region: AWS region name

        Returns:
            The ``DescribeSecurityHubV2`` response on success, or an error
            result. "V2 is not enabled here" arrives as a
            ``ResourceNotFoundException`` that ``self.is_not_configured(error)``
            recognizes by its message.
        """
        return self._cached_call(
            region, f"security_hub_v2:{region}", "describe_security_hub_v2"
        )

    def get_finding_aggregators(self, region: str) -> Mapping[str, Any]:
        """
        Get the finding aggregators visible from a Region, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"FindingAggregators": [...]}`` on success, or an error result.
        """
        return self._cached_call(
            region, f"finding_aggregators:{region}", "list_finding_aggregators"
        )

    def get_configuration_policies(self, region: str) -> Mapping[str, Any]:
        """
        Get the central configuration policy summaries, with caching.

        Args:
            region: AWS region name. Must be the home Region.

        Returns:
            ``{"ConfigurationPolicySummaries": [...]}`` on success, or an error
            result.
        """
        return self._cached_call(
            region, f"configuration_policies:{region}", "list_configuration_policies"
        )

    def get_configuration_policy(
        self, region: str, identifier: str
    ) -> Mapping[str, Any]:
        """
        Get one central configuration policy, with caching.

        Args:
            region: AWS region name. Must be the home Region.
            identifier: The configuration policy ARN or UUID.

        Returns:
            The ``GetConfigurationPolicy`` response on success, or an error
            result.
        """
        return self._cached_call(
            region,
            f"configuration_policy:{region}:{identifier}",
            "get_configuration_policy",
            identifier,
        )

    @staticmethod
    def standard_name_of(standards_arn: str) -> str:
        """
        Reduce a standards ARN to its Region-independent name.

        The separator before ``standards`` is ``::``, not ``/`` -- a standards ARN
        reads ``arn:aws:securityhub:us-west-2::standards/<name>/v/<version>`` --
        so splitting on ``"/standards/"`` never matches and silently reports whole
        ARNs. Verified against live data on 2026-09-16.

        Args:
            standards_arn: A ``StandardsArn`` or ``EnabledStandardIdentifiers``
                value.

        Returns:
            e.g. ``"ai-security-best-practices/v/1.0.0"``, or the input unchanged
            when it is not in the expected shape.
        """
        _, _, name = standards_arn.partition("standards/")
        return name or standards_arn

    @staticmethod
    def home_region_of(response: Mapping[str, Any]) -> Optional[str]:
        """
        Read the central-configuration home Region from a finding aggregator.

        The home Region is the aggregation Region, and it is the only Region the
        configuration-policy operations may be called from. It is not returned as
        a field: it is the Region segment of the aggregator ARN, which is why this
        parse exists rather than a second ``GetFindingAggregator`` call.

        Args:
            response: A successful ``ListFindingAggregators`` response.

        Returns:
            The home Region, or ``None`` when no aggregator exists or its ARN is
            not in the expected shape. ``None`` means cross-Region aggregation is
            not configured, so central configuration cannot be in use.
        """
        aggregators = response.get("FindingAggregators") or []
        for aggregator in aggregators:
            arn = aggregator.get("FindingAggregatorArn") or ""
            # arn:aws:securityhub:<region>:<account>:finding-aggregator/<uuid>
            parts = arn.split(":")
            if len(parts) > 3 and parts[3]:
                return parts[3]
        return None

    # ------------------------------------------------------------------ #
    # Unified Security Hub (V2) organization surface
    # ------------------------------------------------------------------ #

    def get_organization_admin_accounts_v2(self, region: str) -> Mapping[str, Any]:
        """
        Get the Security Hub (V2) delegated administrator, with caching.

        Args:
            region: AWS region name. The answer is organization-wide; the Region
                only chooses the endpoint.

        Returns:
            ``{"AdminAccounts": [...]}`` on success, or an error result.
        """
        return self._cached_call(
            region,
            f"organization_admin_accounts_v2:{region}",
            "list_organization_admin_accounts_v2",
        )

    def get_aggregators_v2(self, region: str) -> Mapping[str, Any]:
        """
        Get the Security Hub (V2) aggregators visible from a Region, with caching.

        Args:
            region: AWS region name. Any V2-enabled Region answers.

        Returns:
            ``{"AggregatorsV2": [...]}`` on success, or an error result.
        """
        return self._cached_call(
            region, f"aggregators_v2:{region}", "list_aggregators_v2"
        )

    def get_aggregator_v2(self, region: str, aggregator_arn: str) -> Mapping[str, Any]:
        """
        Get one Security Hub (V2) aggregator, with caching.

        Args:
            region: AWS region name. Must be the aggregation Region.
            aggregator_arn: The ``AggregatorV2Arn``.

        Returns:
            The ``GetAggregatorV2`` response, or an error result.
        """
        return self._cached_call(
            region,
            f"aggregator_v2:{region}:{aggregator_arn}",
            "get_aggregator_v2",
            aggregator_arn,
        )

    #: ``GetFindingsV2`` filter selecting Security Hub coverage findings.
    #: ``metadata.product.name`` is ``Security Hub Coverage`` on every coverage
    #: finding (observed 2026-09-25; 612 of them in the Code org, one per
    #: account, Region and capability, each ``compliance.status`` Pass or Fail).
    COVERAGE_FINDINGS_FILTER: ClassVar[Mapping[str, Any]] = {
        "CompositeFilters": [
            {
                "StringFilters": [
                    {
                        "FieldName": "metadata.product.name",
                        "Filter": {
                            "Value": "Security Hub Coverage",
                            "Comparison": "EQUALS",
                        },
                    }
                ]
            }
        ]
    }

    def get_coverage_findings(self, region: str) -> Mapping[str, Any]:
        """
        Get the Security Hub coverage findings visible from a Region, with caching.

        From the delegated administrator the read already spans member accounts
        without ``Scopes`` (observed 2026-09-25), and from the aggregation Region
        it spans every linked Region.

        Args:
            region: AWS region name.

        Returns:
            ``{"Findings": [...]}`` on success, or an error result.
        """
        return self._cached_call(
            region,
            f"coverage_findings:{region}",
            "get_findings_v2",
            self.COVERAGE_FINDINGS_FILTER,
        )

    @staticmethod
    def aggregation_region_of(response: Mapping[str, Any]) -> Optional[str]:
        """
        Read the Security Hub (V2) aggregation Region from ``ListAggregatorsV2``.

        Args:
            response: A successful ``ListAggregatorsV2`` response.

        Returns:
            The Region segment of the first aggregator ARN
            (``arn:aws:securityhub:<region>:<account>:aggregatorv2/<id>``), or
            ``None`` when there is no aggregator.
        """
        for aggregator in response.get("AggregatorsV2") or []:
            parts = (aggregator.get("AggregatorV2Arn") or "").split(":")
            if len(parts) > 3 and parts[3]:
                return parts[3]
        return None

    @staticmethod
    def unlinked_regions(
        aggregator: Mapping[str, Any], regions: list[str]
    ) -> list[str]:
        """
        Return the Regions an aggregator does not aggregate into its home Region.

        ``RegionLinkingMode`` follows the finding-aggregator vocabulary:
        ``ALL_REGIONS`` links everything, ``ALL_REGIONS_EXCEPT_SPECIFIED`` links
        everything but ``LinkedRegions``, and ``SPECIFIED_REGIONS`` links only
        ``LinkedRegions`` (observed 2026-09-25). The aggregation Region itself is
        always covered. An unrecognized mode links nothing, so it reads as a gap
        rather than a pass.

        Args:
            aggregator: A successful ``GetAggregatorV2`` response.
            regions: The Regions that should be aggregated.

        Returns:
            The uncovered Regions, sorted.
        """
        home = aggregator.get("AggregationRegion")
        mode = aggregator.get("RegionLinkingMode")
        linked = set(aggregator.get("LinkedRegions") or [])
        uncovered = []
        for region in regions:
            if region == home or mode == "ALL_REGIONS":
                continue
            if mode == "ALL_REGIONS_EXCEPT_SPECIFIED" and region not in linked:
                continue
            if mode == "SPECIFIED_REGIONS" and region in linked:
                continue
            uncovered.append(region)
        return sorted(uncovered)

    @staticmethod
    def open_coverage_gaps(findings: list[Mapping[str, Any]]) -> dict[str, list[str]]:
        """
        Group coverage findings into open gaps per account.

        A gap is a coverage finding whose ``compliance.status`` is ``Fail`` and
        whose workflow ``status`` is not ``Suppressed``, ``Resolved`` or
        ``Archived`` -- suppression is how the console records an accepted
        exception, and a suppressed finding is excluded from coverage.

        Args:
            findings: OCSF coverage findings.

        Returns:
            ``{account_id: ["<capability> in <region>", ...]}`` for every account
            that has at least one coverage finding, with an empty list for an
            account whose every capability passes. Lists are sorted and
            de-duplicated so the row is diffable.
        """
        closed = {"Suppressed", "Resolved", "Archived"}
        by_account: dict[str, set[str]] = {}
        for finding in findings:
            account = ((finding.get("cloud") or {}).get("account") or {}).get("uid")
            if not account:
                continue
            gaps = by_account.setdefault(account, set())
            if finding.get("status") in closed:
                continue
            if (finding.get("compliance") or {}).get("status") != "Fail":
                continue
            capability = (finding.get("finding_info") or {}).get("title") or "Unknown"
            capability = capability.removesuffix(" Coverage Finding")
            region = (finding.get("cloud") or {}).get("region") or "unknown Region"
            gaps.add(f"{capability} in {region}")
        return {account: sorted(gaps) for account, gaps in by_account.items()}

    # ------------------------------------------------------------------ #
    # Organizations: the SECURITYHUB_POLICY management policy type
    # ------------------------------------------------------------------ #

    def get_roots(self, region: str) -> Mapping[str, Any]:
        """
        Get the organization roots and their policy types.

        Delegates to the scan's Organizations provider, which caches the answer
        once per scan.

        Args:
            region: AWS region name. Accepted and ignored: the answer is
                organization-wide.

        Returns:
            ``{"Roots": [...]}`` on success, or an error result.
        """
        return self.organization.roots()

    def get_policies_for_target(
        self, region: str, target_id: str, policy_type: str
    ) -> Mapping[str, Any]:
        """
        Get the policies of one type attached to a target.

        Delegates to the scan's Organizations provider, which caches the answer
        once per scan per target and type.

        Args:
            region: AWS region name. Accepted and ignored: the answer is
                organization-wide.
            target_id: A root, OU or account ID.
            policy_type: e.g. ``"SECURITYHUB_POLICY"``.

        Returns:
            ``{"Policies": [...]}`` on success, or an error result.
        """
        return self.organization.policies_for_target(target_id, policy_type)

    def get_policy(self, region: str, policy_id: str) -> Mapping[str, Any]:
        """
        Get one Organizations policy with its stored content.

        Delegates to the scan's Organizations provider, which caches the answer
        once per scan per policy.

        Args:
            region: AWS region name. Accepted and ignored: the answer is
                organization-wide.
            policy_id: The policy ID.

        Returns:
            The ``DescribePolicy`` response, or an error result.
        """
        return self.organization.describe_policy(policy_id)

    def get_effective_policy(
        self, region: str, policy_type: str, target_id: str
    ) -> Mapping[str, Any]:
        """
        Get an account's effective policy of one type.

        Delegates to the scan's Organizations provider, which caches the answer
        once per scan per type and target.

        Args:
            region: AWS region name. Accepted and ignored: the answer is
                organization-wide.
            policy_type: e.g. ``"SECURITYHUB_POLICY"``.
            target_id: An account ID.

        Returns:
            The ``DescribeEffectivePolicy`` response, or an error result. "No
            policy reaches this account" arrives as
            ``EffectivePolicyNotFoundException``, declared as not configured.
        """
        return self.organization.effective_policy(policy_type, target_id)

    @staticmethod
    def securityhub_policy_regions(
        content: Optional[str],
    ) -> Optional[tuple[list[str], list[str]]]:
        """
        Parse a Security Hub policy document into its two Region lists.

        Accepts both forms: the **stored** document from ``DescribePolicy``, where
        each list is wrapped in an inheritance operator (``{"@@assign": [...]}``
        or ``{"@@append": [...]}`` -- the console writes ``@@append``, observed
        2026-09-25), and the **effective** document from
        ``DescribeEffectivePolicy``, where the operators are resolved away to
        plain lists.

        Args:
            content: The policy JSON string.

        Returns:
            ``(enable_in_regions, disable_in_regions)``, or ``None`` when the
            document is not valid JSON or has no ``securityhub`` block.
        """
        try:
            document = json.loads(content or "")
        except ValueError:
            return None
        block = document.get("securityhub") if isinstance(document, dict) else None
        if not isinstance(block, dict):
            return None

        def _values(node: Any) -> list[str]:
            if isinstance(node, list):
                return [str(v) for v in node]
            if isinstance(node, dict):
                values: list[str] = []
                for operator in ("@@assign", "@@append"):
                    values.extend(str(v) for v in node.get(operator) or [])
                return values
            return []

        return (
            _values(block.get("enable_in_regions")),
            _values(block.get("disable_in_regions")),
        )

    @staticmethod
    def regions_not_enabled(
        enable: list[str], disable: list[str], regions: list[str]
    ) -> list[str]:
        """
        Return the Regions a Security Hub policy does not leave enabled.

        ``ALL_SUPPORTED`` stands for every Region, current and future, in either
        list, and ``disable_in_regions`` takes precedence over
        ``enable_in_regions``.

        Args:
            enable: ``enable_in_regions``.
            disable: ``disable_in_regions``.
            regions: The Regions that should be enabled.

        Returns:
            The Regions that are not enabled, sorted.
        """
        all_enabled = "ALL_SUPPORTED" in enable
        all_disabled = "ALL_SUPPORTED" in disable
        return sorted(
            region
            for region in regions
            if all_disabled
            or region in disable
            or not (all_enabled or region in enable)
        )

    # ------------------------------------------------------------------ #
    # EventBridge: the rules that route Security Hub findings
    # ------------------------------------------------------------------ #

    def get_event_rules(self, region: str) -> Mapping[str, Any]:
        """
        Get the EventBridge rules on the default bus in a Region, with caching.

        Args:
            region: AWS region name.

        Returns:
            ``{"Rules": [...]}`` on success, or an error result.
        """
        return self._cached_call(region, f"event_rules:{region}", "list_event_rules")

    def get_rule_targets(self, region: str, rule_name: str) -> Mapping[str, Any]:
        """
        Get the targets of one EventBridge rule, with caching.

        Args:
            region: AWS region name.
            rule_name: The rule name.

        Returns:
            ``{"Targets": [...]}`` on success, or an error result.
        """
        return self._cached_call(
            region,
            f"rule_targets:{region}:{rule_name}",
            "list_targets_by_rule",
            rule_name,
        )

    @staticmethod
    def matches_v2_findings(rule: Mapping[str, Any]) -> bool:
        """
        Return whether an EventBridge rule's pattern matches V2 finding events.

        The pattern must name ``aws.securityhub`` in ``source``, and either name
        ``Findings Imported V2`` in ``detail-type``, or be a bare source-only
        pattern with neither ``detail-type`` nor ``detail`` (which matches every
        Security Hub event, V2 included). A pattern that omits ``detail-type`` but
        filters on ``detail`` does **not** count: its filter was written against one
        finding schema, and in practice it is the CSPM ASFF schema -- observed
        2026-09-25 as ``{"source":["aws.securityhub"],"detail":{"findings":
        {"ProductName":["GuardDuty"],"Severity":{"Label":[...]}}}}``, which no
        OCSF V2 event can satisfy. A rule matching only the CSPM ``Security Hub
        Findings - Imported`` detail-type does not count either. A scheduled rule,
        or one whose pattern is not valid JSON, does not match.

        Args:
            rule: One ``ListRules`` entry.

        Returns:
            ``True`` if the rule would receive Security Hub V2 finding events.
        """
        try:
            pattern = json.loads(rule.get("EventPattern") or "")
        except ValueError:
            return False
        if not isinstance(pattern, dict):
            return False
        sources = pattern.get("source")
        if not isinstance(sources, list) or "aws.securityhub" not in sources:
            return False
        detail_types = pattern.get("detail-type")
        if detail_types is None:
            return "detail" not in pattern
        return (
            isinstance(detail_types, list)
            and V2_FINDINGS_DETAIL_TYPE in detail_types
        )

    def get_administrator_account(self, region: str) -> Mapping[str, Any]:
        """
        Get the Security Hub administrator account, with caching.

        Args:
            region: AWS region name

        Returns:
            The ``GetAdministratorAccount`` response, or an error result.
        """
        return self._cached_call(
            region, f"administrator_account:{region}", "get_administrator_account"
        )

    def get_organization_configuration(self, region: str) -> Mapping[str, Any]:
        """
        Get the Security Hub organization configuration, with caching.

        Args:
            region: AWS region name

        Returns:
            The ``DescribeOrganizationConfiguration`` response, or an error result.
        """
        return self._cached_call(
            region,
            f"organization_configuration:{region}",
            "describe_organization_configuration",
        )

    def get_enabled_products_for_import(self, region: str) -> Mapping[str, Any]:
        """
        Get enabled product integrations for a Region, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"ProductSubscriptions": [...]}`` on success, or an error result.
        """
        return self._cached_call(
            region,
            f"product_integrations:{region}",
            "list_enabled_products_for_import",
        )

    def get_delegated_administrators(self, region: str) -> Mapping[str, Any]:
        """
        Get the Organizations delegated administrators for Security Hub.

        Delegates to the scan's Organizations provider, which caches the answer
        once per scan per service principal.

        Args:
            region: AWS region name. Accepted and ignored: the answer is
                organization-wide.

        Returns:
            ``{"DelegatedAdministrators": [...]}`` on success, or an error result.
        """
        return self.organization.delegated_administrators("securityhub.amazonaws.com")

    def get_organization_admin_accounts(self, region: str) -> Mapping[str, Any]:
        """
        Get the Security Hub organization admin accounts, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"AdminAccounts": [...]}`` on success, or an error result.
        """
        return self._cached_call(
            region,
            f"organization_admin_accounts:{region}",
            "list_organization_admin_accounts",
        )

    def get_security_hub_members(self, region: str) -> Mapping[str, Any]:
        """
        Get Security Hub member accounts, with caching.

        Args:
            region: AWS region name

        Returns:
            ``{"Members": [...]}`` on success, or an error result.
        """
        return self._cached_call(
            region, f"securityhub_members:{region}", "list_members"
        )

    def get_organization(self) -> Mapping[str, Any]:
        """Return the AWS Organizations ``DescribeOrganization`` response.

        Delegates to ``self.organization.describe()``, the scan's one cached
        ``DescribeOrganization`` answer, shared with ``OrganizationsCheck`` and
        ``IAMCheck``. A failure is returned unchanged and never cached.

        Returns:
            The ``DescribeOrganization`` response, or an error result.
        """
        return self.organization.describe()
