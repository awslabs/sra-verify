"""
SRA-SECURITYHUB-21: Security Hub CSPM cross-Region aggregation links all Regions to a home Region.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck


class SRA_SECURITYHUB_21(SecurityHubCheck):
    """Check if a Security Hub CSPM finding aggregator links every scanned Region."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-21",
        title="Security Hub CSPM cross-Region aggregation links all Regions to a home Region",
        description=(
            "This check verifies that the Security Hub CSPM delegated administrator has created "
            "a finding aggregator that links every Region to a single home Region, so findings, "
            "control statuses and security scores from all Regions and member accounts are "
            "replicated to one place. This is the CSPM finding aggregator and is a separate "
            "resource from the unified Security Hub AggregatorV2 (SRA-SECURITYHUB-18). An "
            "aggregator in NO_REGIONS mode exists but replicates nothing. Member accounts "
            "inherit the administrator's aggregation settings."
        ),
        check_logic=(
            "From the audit account call securityhub:ListFindingAggregators; the aggregator ARN "
            "names the home Region. Call GetFindingAggregator there. Passes if "
            "RegionLinkingMode and Regions cover every scanned Region. Fails if no aggregator "
            "exists or a scanned Region is not linked, naming it. One row, labelled with the "
            "home Region."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="Security Hub CSPM",
        resource_type="AWS::SecurityHub::FindingAggregator",
        remediation=Remediation(
            text=(
                "In the delegated administrator account, create or update the Security Hub "
                "CSPM finding aggregator in the home Region so that it links all Regions."
            ),
            cli=(
                "aws securityhub update-finding-aggregator --finding-aggregator-arn <arn> "
                "--region-linking-mode ALL_REGIONS --region <home-region>"
            ),
            console=(
                "Security Hub CSPM console in the delegated administrator account and home "
                "Region, Settings, Regions, Cross-Region aggregation, Edit, link all Regions."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Security Hub CSPM"),
        additional_urls=(
            "https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html",
            "https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingAggregator.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding.
        """
        checked_value = "A Security Hub CSPM finding aggregator links every scanned Region"
        resource_id = f"securityhub:finding-aggregator/{self.account_id}"

        # ListFindingAggregators answers from any subscribed Region, and its ARN
        # carries the home Region; the aggregator is read from the home Region.
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
                        f"Security Hub CSPM is not enabled in {probe_region}, so "
                        f"{probe_region} cannot be linked to a finding aggregator"
                    ),
                    remediation=(
                        f"Enable Security Hub CSPM in the delegated administrator account in "
                        f"{probe_region}, then link it to the finding aggregator"
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
        if not home_region:
            yield self.failed(
                region="global",
                resource_id=resource_id,
                checked_value=checked_value,
                actual_value=(
                    "No Security Hub CSPM finding aggregator exists, so findings are not "
                    "aggregated to a home Region"
                ),
            )
            return

        aggregator_arn = next(
            aggregator["FindingAggregatorArn"]
            for aggregator in listed.get("FindingAggregators", [])
            if aggregator.get("FindingAggregatorArn")
        )

        if home_region not in self.regions:
            # Clients exist only for the scanned Regions, and no AWS call can move
            # the home Region into them, so this is decided before any call.
            yield self.error(
                region="global",
                resource_id=aggregator_arn,
                checked_value=checked_value,
                actual_value=(
                    f"The finding aggregator lives in home Region {home_region}, which is "
                    f"not among the scanned Regions ({', '.join(self.regions)})"
                ),
                remediation=(
                    f"Re-run the check with {home_region} included in --regions so the "
                    f"aggregator can be read from its home Region"
                ),
            )
            return

        aggregator = self.get_finding_aggregator(home_region, aggregator_arn)
        if "Error" in aggregator:
            # Nothing on GetFindingAggregator is declared: a missing aggregator
            # that ListFindingAggregators just returned is not "control absent".
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
        listed_regions = sorted(aggregator.get("Regions") or [])
        unlinked = self.cspm_unlinked_regions(aggregator, list(self.regions))

        if unlinked:
            yield self.failed(
                region=home_region,
                resource_id=aggregator_arn,
                checked_value=checked_value,
                actual_value=(
                    f"Finding aggregator in {home_region} ({mode}, Regions: "
                    f"{', '.join(listed_regions) or 'none'}) does not aggregate "
                    f"{', '.join(unlinked)}"
                ),
                remediation=(
                    f"Link {', '.join(unlinked)}: aws securityhub update-finding-aggregator "
                    f"--finding-aggregator-arn {aggregator_arn} --region-linking-mode "
                    f"ALL_REGIONS --region {home_region}"
                ),
            )
        else:
            yield self.passed(
                region=home_region,
                resource_id=aggregator_arn,
                checked_value=checked_value,
                actual_value=(
                    f"Finding aggregator in {home_region} ({mode}) aggregates all "
                    f"{len(self.regions)} scanned Regions"
                ),
            )
