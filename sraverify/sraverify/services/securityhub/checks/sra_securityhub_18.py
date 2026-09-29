"""
SRA-SECURITYHUB-18: Security Hub V2 cross-Region aggregation links all Regions to a home Region.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck


class SRA_SECURITYHUB_18(SecurityHubCheck):
    """Check if a Security Hub V2 aggregator links every scanned Region."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-18",
        title="Security Hub V2 cross-Region aggregation links all Regions to a home Region",
        description=(
            "This check verifies that the Security Hub delegated administrator has created an "
            "aggregator (AggregatorV2) that links every Region to a single home Region, so "
            "findings, resources and trends from all Regions and member accounts can be "
            "triaged in one place. This is the unified Security Hub aggregator and is a "
            "separate resource from the Security Hub CSPM finding aggregator. An aggregator "
            "with no linked Regions exists but replicates nothing."
        ),
        check_logic=(
            "From the audit account call securityhub:ListAggregatorsV2; the aggregator ARN names "
            "the home Region. Call GetAggregatorV2 there. Passes if RegionLinkingMode and "
            "LinkedRegions cover every scanned Region. Fails if no aggregator exists or a "
            "scanned Region is not linked, naming it. One row, labelled with the home Region."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="SecurityHub",
        resource_type="AWS::SecurityHub::AggregatorV2",
        remediation=Remediation(
            text=(
                "In the delegated administrator account, create a Security Hub aggregator in "
                "the chosen home Region that links all Regions."
            ),
            cli=(
                "aws securityhub create-aggregator-v2 --region-linking-mode SPECIFIED_REGIONS "
                "--linked-regions <region> <region> ... --region <home-region>"
            ),
            console=(
                "Security Hub console (securityhub/v2) in the delegated administrator account "
                "and home Region, Settings, Regions, Cross-Region aggregation, link all "
                "Regions."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Security Hub"),
        additional_urls=(
            "https://docs.aws.amazon.com/securityhub/latest/userguide/security-hub-region-aggregation.html",
            "https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetAggregatorV2.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding.
        """
        checked_value = "A Security Hub V2 aggregator links every scanned Region"
        resource_id = f"securityhub:aggregatorv2/{self.account_id}"

        # ListAggregatorsV2 answers from any V2-enabled Region, and its ARN carries
        # the home Region; GetAggregatorV2 answers only from the home Region.
        probe_region = self.regions[0]
        listed = self.get_aggregators_v2(probe_region)

        if "Error" in listed:
            error = listed["Error"]
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=resource_id,
                    checked_value=checked_value,
                    actual_value=(
                        "Security Hub V2 is not enabled in this account, so it has no "
                        "cross-Region aggregator"
                    ),
                    remediation=(
                        "Enable Security Hub V2 in the delegated administrator account, "
                        "then create an aggregator that links all Regions"
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
        if not home_region:
            yield self.failed(
                region="global",
                resource_id=resource_id,
                checked_value=checked_value,
                actual_value="No Security Hub V2 cross-Region aggregator exists",
            )
            return

        aggregator_arn = next(
            aggregator["AggregatorV2Arn"]
            for aggregator in listed.get("AggregatorsV2", [])
            if aggregator.get("AggregatorV2Arn")
        )

        if home_region not in self.regions:
            # Clients exist only for the scanned Regions, and no AWS call can move
            # the home Region into them, so this is decided before any call.
            yield self.error(
                region="global",
                resource_id=aggregator_arn,
                checked_value=checked_value,
                actual_value=(
                    f"The Security Hub V2 aggregator lives in home Region {home_region}, "
                    f"which is not among the scanned Regions ({', '.join(self.regions)})"
                ),
                remediation=(
                    f"Re-run the check with {home_region} included in --regions so the "
                    f"aggregator can be read from its home Region"
                ),
            )
            return

        aggregator = self.get_aggregator_v2(home_region, aggregator_arn)
        if "Error" in aggregator:
            error = aggregator["Error"]
            yield self.error(
                region=home_region,
                resource_id=aggregator_arn,
                checked_value=checked_value,
                actual_value=(
                    f"{error['Operation']} failed: {error['Code']}: {error['Message']}"
                ),
                remediation=self._remediation_for(error),
            )
            return

        mode = aggregator.get("RegionLinkingMode", "unknown")
        linked = sorted(aggregator.get("LinkedRegions") or [])
        unlinked = self.unlinked_regions(aggregator, list(self.regions))
        # UpdateAggregatorV2 accepts only SPECIFIED_REGIONS ("RegionLinkingMode must
        # be set to 'SPECIFIED_REGIONS'", observed 2026-09-26), so the fix is to
        # name every Region, keeping the ones already linked.
        wanted = sorted(set(linked) | set(unlinked))

        if unlinked:
            yield self.failed(
                region=home_region,
                resource_id=aggregator_arn,
                checked_value=checked_value,
                actual_value=(
                    f"Aggregator in {home_region} ({mode}, linked: "
                    f"{', '.join(linked) or 'none'}) does not aggregate "
                    f"{', '.join(unlinked)}"
                ),
                remediation=(
                    f"Link {', '.join(unlinked)} to the aggregator in {home_region}: aws "
                    f"securityhub update-aggregator-v2 --aggregator-v2-arn {aggregator_arn} "
                    f"--region-linking-mode SPECIFIED_REGIONS --linked-regions "
                    f"{' '.join(wanted)} --region {home_region}"
                ),
            )
        else:
            yield self.passed(
                region=home_region,
                resource_id=aggregator_arn,
                checked_value=checked_value,
                actual_value=(
                    f"Aggregator in {home_region} ({mode}) aggregates all "
                    f"{len(self.regions)} scanned Regions"
                ),
            )
