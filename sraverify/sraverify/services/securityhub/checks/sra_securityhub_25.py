"""
SRA-SECURITYHUB-25: An EventBridge rule routes Security Hub CSPM findings to a response target.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import CSPM_FINDINGS_DETAIL_TYPE, SecurityHubCheck


class SRA_SECURITYHUB_25(SecurityHubCheck):
    """Check if an enabled EventBridge rule with a target matches CSPM finding events."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-25",
        title="EventBridge rule routes Security Hub CSPM findings to a response target",
        description=(
            "This check verifies that an ENABLED Amazon EventBridge rule on the default event "
            "bus matches Security Hub CSPM finding events (detail-type Security Hub Findings - "
            "Imported) and has at least one target, so findings drive automated response and "
            "remediation. With cross-Region aggregation, aggregated findings raise their "
            "events in the home Region, so that is where the rule is evaluated; without an "
            "aggregator, every scanned Region is evaluated. Rules filtered only on the unified "
            "Security Hub Findings Imported V2 event, or only on Custom Action events, do not "
            "count; SRA-SECURITYHUB-20 covers the V2 event."
        ),
        check_logic=(
            "Resolve the home Region from securityhub:ListFindingAggregators. Call "
            "events:ListRules there (every scanned Region if no aggregator) and "
            "events:ListTargetsByRule for each ENABLED rule naming source aws.securityhub and "
            "detail-type Security Hub Findings - Imported, or no detail-type. Passes on the "
            "first such rule with a target. Fails: no match, DISABLED, or no target."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="Security Hub CSPM",
        resource_type="AWS::Events::Rule",
        remediation=Remediation(
            text=(
                "In the delegated administrator account's home Region, create an EventBridge "
                "rule for source aws.securityhub and detail-type Security Hub Findings - "
                "Imported, and give it a response target such as a Lambda function, Step "
                "Functions state machine or SNS topic."
            ),
            cli=(
                "aws events put-rule --name securityhub-cspm-findings --event-pattern "
                "'{\"source\":[\"aws.securityhub\"],\"detail-type\":"
                "[\"Security Hub Findings - Imported\"]}' --state ENABLED "
                "--region <home-region>\n"
                "aws events put-targets --rule securityhub-cspm-findings "
                "--targets Id=1,Arn=<target-arn> --region <home-region>"
            ),
            console=(
                "EventBridge console in the delegated administrator account and home Region, "
                "Rules, Create rule, Event pattern: AWS services, Security Hub, Security Hub "
                "Findings - Imported; add a target."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Security Hub CSPM"),
        additional_urls=(
            "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-all-findings.html",
            "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-integration-types.html",
            "https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_ListRules.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the home Region, or one per scanned Region when there is
            no finding aggregator.
        """
        checked_value = (
            f"An ENABLED EventBridge rule with a target matches {CSPM_FINDINGS_DETAIL_TYPE} "
            f"events"
        )
        resource_id = f"events:rule/{self.account_id}"

        probe_region = self.regions[0]
        listed = self.get_finding_aggregators(probe_region)
        if "Error" in listed:
            error = listed["Error"]
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=resource_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"Security Hub CSPM is not enabled in {probe_region}, so no CSPM "
                        f"finding event can be routed from {probe_region}"
                    ),
                    remediation=(
                        f"Enable Security Hub CSPM in the delegated administrator account in "
                        f"{probe_region}, then create an EventBridge rule for "
                        f"{CSPM_FINDINGS_DETAIL_TYPE} events"
                    ),
                )
            else:
                yield self.error(
                    region="global",
                    resource_id=resource_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: {error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        home_region = self.home_region_of(listed)
        if home_region and home_region not in self.regions:
            yield self.error(
                region="global",
                resource_id=resource_id,
                checked_value=checked_value,
                actual_value=(
                    f"Security Hub CSPM aggregates findings into home Region {home_region}, "
                    f"which is not among the scanned Regions ({', '.join(self.regions)})"
                ),
                remediation=(
                    f"Re-run the check with {home_region} included in --regions so the "
                    f"EventBridge rules can be read from the home Region"
                ),
            )
            return

        # Aggregated findings raise their events in the home Region, so that is
        # where the routing rule belongs; without an aggregator, every Region
        # raises its own.
        for region in [home_region] if home_region else list(self.regions):
            yield from self._evaluate_region(region, checked_value, resource_id)

    def _evaluate_region(
        self, region: str, checked_value: str, resource_id: str
    ) -> Iterable[Finding]:
        """
        Evaluate one Region's EventBridge rules.

        Args:
            region: The Region.
            checked_value: The row's CheckedValue.
            resource_id: The ResourceId for a row that names no rule.

        Yields:
            One Finding.
        """
        rules_response = self.get_event_rules(region)
        if "Error" in rules_response:
            error = rules_response["Error"]
            yield self.error(
                region=region,
                resource_id=resource_id,
                checked_value=checked_value,
                actual_value=(
                    f"{error['Operation']} failed: {error['Code']}: {error['Message']}"
                ),
                remediation=self._remediation_for(error),
            )
            return

        matching = sorted(
            (
                rule
                for rule in rules_response.get("Rules", [])
                if self.matches_cspm_findings(rule)
            ),
            key=lambda rule: rule.get("Name", ""),
        )
        enabled = [rule for rule in matching if rule.get("State") == "ENABLED"]

        undetermined = None
        targetless = []
        for rule in enabled:
            name = rule.get("Name", "unknown")
            targets = self.get_rule_targets(region, name)
            if "Error" in targets:
                undetermined = undetermined or targets["Error"]
                continue
            if targets.get("Targets"):
                yield self.passed(
                    region=region,
                    resource_id=rule.get("Arn") or name,
                    checked_value=checked_value,
                    actual_value=(
                        f"EventBridge rule {name} is ENABLED, matches "
                        f"{CSPM_FINDINGS_DETAIL_TYPE} events and has "
                        f"{len(targets['Targets'])} target(s)"
                    ),
                )
                return
            targetless.append(name)

        if undetermined is not None:
            yield self.error(
                region=region,
                resource_id=resource_id,
                checked_value=checked_value,
                actual_value=(
                    f"{undetermined['Operation']} failed: {undetermined['Code']}: "
                    f"{undetermined['Message']}"
                ),
                remediation=self._remediation_for(undetermined),
            )
            return

        if targetless:
            detail = f"rule(s) {', '.join(targetless)} match but have no target"
        elif matching:
            detail = (
                f"rule(s) {', '.join(r.get('Name', 'unknown') for r in matching)} match "
                f"but are DISABLED"
            )
        else:
            detail = f"no rule matches {CSPM_FINDINGS_DETAIL_TYPE} events"

        yield self.failed(
            region=region,
            resource_id=resource_id,
            checked_value=checked_value,
            actual_value=(
                f"No EventBridge rule routes Security Hub CSPM findings in {region}: {detail}"
            ),
            remediation=(
                f"Create an EventBridge rule in {region} for source aws.securityhub and "
                f"detail-type {CSPM_FINDINGS_DETAIL_TYPE}, and give it a response target"
            ),
        )
