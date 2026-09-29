"""
SRA-SECURITYHUB-20: An EventBridge rule routes Security Hub V2 findings to a response target.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import V2_FINDINGS_DETAIL_TYPE, SecurityHubCheck


class SRA_SECURITYHUB_20(SecurityHubCheck):
    """Check if an enabled EventBridge rule with a target matches V2 finding events."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-20",
        title="EventBridge rule routes Security Hub V2 findings to a response target",
        description=(
            "This check verifies that the Security Hub delegated administrator has an enabled "
            "Amazon EventBridge rule, with at least one target, that matches Security Hub "
            "findings. Security Hub sends every new and updated finding to EventBridge as a "
            "Findings Imported V2 event, but nothing acts on those events until a rule routes "
            "them to automated response, remediation or ticketing. Rules matching only the "
            "CSPM Security Hub Findings - Imported event do not count."
        ),
        check_logic=(
            "From the audit account, in the ListAggregatorsV2 home Region or, with no "
            "aggregator, in each scanned Region, call events:ListRules on the default bus. "
            "Passes if an ENABLED rule's pattern names source aws.securityhub and detail-type "
            "Findings Imported V2 (or is source-only with no detail filter) and "
            "events:ListTargetsByRule returns a target."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="SecurityHub",
        resource_type="AWS::Events::Rule",
        remediation=Remediation(
            text=(
                "In the delegated administrator's home Region, create an EventBridge rule for "
                "Security Hub Findings Imported V2 events and add a response target such as a "
                "Lambda function, Step Functions state machine or SNS topic."
            ),
            cli=(
                "aws events put-rule --name securityhub-findings-v2 --event-pattern "
                "'{\"source\":[\"aws.securityhub\"],\"detail-type\":[\"Findings Imported V2\"]}' "
                "--region <home-region>\n"
                "aws events put-targets --rule securityhub-findings-v2 "
                "--targets Id=1,Arn=<target-arn> --region <home-region>"
            ),
            console=(
                "Amazon EventBridge console in the delegated administrator account and home "
                "Region, Rules, Create rule, AWS events, Security Hub, Findings Imported V2, "
                "select a target."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Security Hub"),
        additional_urls=(
            "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-cwe-event-types.html",
            "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-cwe-event-rules.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the home Region, or one per scanned Region when there is
            no aggregator.
        """
        checked_value = (
            f"An ENABLED EventBridge rule with a target matches {V2_FINDINGS_DETAIL_TYPE} "
            f"events"
        )
        resource_id = f"events:rule/{self.account_id}"

        listed = self.get_aggregators_v2(self.regions[0])
        if "Error" in listed:
            error = listed["Error"]
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=resource_id,
                    checked_value=checked_value,
                    actual_value=(
                        "Security Hub V2 is not enabled in this account, so no finding "
                        "events reach EventBridge"
                    ),
                    remediation=(
                        "Enable Security Hub V2 in the delegated administrator account, then "
                        "create an EventBridge rule for Findings Imported V2 events"
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

        home_region = self.aggregation_region_of(listed)
        if home_region and home_region not in self.regions:
            yield self.error(
                region="global",
                resource_id=resource_id,
                checked_value=checked_value,
                actual_value=(
                    f"Security Hub V2 aggregates into home Region {home_region}, which is "
                    f"not among the scanned Regions ({', '.join(self.regions)})"
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
                if self.matches_v2_findings(rule)
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
                        f"{V2_FINDINGS_DETAIL_TYPE} events and has "
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
            detail = f"no rule matches {V2_FINDINGS_DETAIL_TYPE} events"

        yield self.failed(
            region=region,
            resource_id=resource_id,
            checked_value=checked_value,
            actual_value=f"No EventBridge rule routes Security Hub V2 findings in {region}: {detail}",
            remediation=(
                f"Create an EventBridge rule in {region} for source aws.securityhub and "
                f"detail-type {V2_FINDINGS_DETAIL_TYPE}, and give it a response target"
            ),
        )
