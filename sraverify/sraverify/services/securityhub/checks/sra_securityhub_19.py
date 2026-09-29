"""
SRA-SECURITYHUB-19: Security Hub V2 reports no open coverage gaps across the organization.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck


class SRA_SECURITYHUB_19(SecurityHubCheck):
    """Check if Security Hub coverage findings report any open gap, per account."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-19",
        title="Security Hub V2 reports no open coverage gaps across the organization",
        description=(
            "This check verifies that Security Hub coverage findings report no open gaps. "
            "Coverage findings record, per account and Region, whether GuardDuty and its "
            "protection plans, Amazon Inspector scan types, Macie automated sensitive data "
            "discovery and a Security Hub CSPM standard are enabled. Reading them from the "
            "delegated administrator gives one organization-wide answer to whether the "
            "building-block services are enabled uniformly. Suppressed findings are an "
            "accepted exception and are not counted."
        ),
        check_logic=(
            "From the audit account, call securityhub:GetFindingsV2 in each scanned Region, "
            "filtered to metadata.product.name 'Security Hub Coverage'. Passes per account "
            "when no unsuppressed finding in a scanned Region has compliance.status Fail. "
            "Fails naming each capability and Region. One row per account."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="SecurityHub",
        resource_type="AWS::Organizations::Account",
        remediation=Remediation(
            text=(
                "Enable the missing capability in each listed account and Region, or suppress "
                "the coverage finding with a recorded reason if the capability is not "
                "applicable."
            ),
            console=(
                "Security Hub console (securityhub/v2) in the delegated administrator account, "
                "Summary, Security coverage widget, View coverage findings."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Security Hub"),
        additional_urls=(
            "https://docs.aws.amazon.com/securityhub/latest/userguide/coverage-findings.html",
            "https://docs.aws.amazon.com/securityhub/latest/userguide/security-hub-account-coverage.html",
            "https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingsV2.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per account that has coverage findings, plus one ERROR row
            per Region whose findings could not be read.
        """
        checked_value = "No open Security Hub coverage gaps"
        resource_id = f"securityhub:coverage/{self.account_id}"

        # Every scanned Region is read, not only the aggregation home Region: a
        # Region the aggregator does not link is invisible from the home Region,
        # and reading only there would PASS an account whose gap sits in it
        # (observed 2026-09-25 -- eu-central-1 unlinked in the Code org). The home
        # Region's aggregated copies of linked-Region findings are harmless,
        # because gaps are de-duplicated per account by capability and Region.
        findings = []
        undetermined = False
        for region in self.regions:
            response = self.get_coverage_findings(region)
            if "Error" in response:
                error = response["Error"]
                undetermined = True
                yield self.error(
                    region=region,
                    resource_id=resource_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: {error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
                continue
            findings.extend(response.get("Findings", []))

        # The home Region also holds linked Regions the scan was not asked to
        # cover; keep only the scanned ones, so --regions scopes this check the
        # way it scopes every other.
        scanned = set(self.regions)
        findings = [
            finding
            for finding in findings
            if ((finding.get("cloud") or {}).get("region")) in scanned
        ]

        gaps_by_account = self.open_coverage_gaps(findings)

        if not gaps_by_account:
            if not undetermined:
                yield self.failed(
                    region="global",
                    resource_id=resource_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"Security Hub returned no coverage findings for the scanned Regions "
                        f"({', '.join(self.regions)}), so coverage cannot be validated for "
                        f"any account"
                    ),
                    remediation=(
                        "Confirm Security Hub V2 is enabled for the organization and allow up "
                        "to 24 hours for coverage findings to be generated"
                    ),
                )
            return

        for account_id in sorted(gaps_by_account):
            gaps = gaps_by_account[account_id]
            if gaps:
                yield self.failed(
                    region="global",
                    resource_id=account_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"{len(gaps)} open coverage gap(s) in account {account_id}: "
                        f"{'; '.join(gaps)}"
                    ),
                )
            elif not undetermined:
                # A PASS needs every Region read; with one missing, the account's
                # gaps in that Region are unknown and the ERROR row reports it.
                yield self.passed(
                    region="global",
                    resource_id=account_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"Every Security Hub coverage finding for account {account_id} "
                        f"passes"
                    ),
                )
