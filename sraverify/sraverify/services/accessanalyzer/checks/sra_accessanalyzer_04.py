"""
Check if IAM Access Analyzer external access analyzer is configured with Organization zone of trust in every region.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.accessanalyzer.base import AccessAnalyzerCheck


class SRA_ACCESSANALYZER_04(AccessAnalyzerCheck):
    """Check if IAM Access Analyzer has an analyzer with Organization zone of trust in every region."""

    meta = CheckMeta(
        check_id="SRA-ACCESSANALYZER-04",
        title=(
            "IAM Access Analyzer external access analyzer is configured with "
            "Organization zone of trust in every region"
        ),
        description=(
            "This check verifies whether IAA external access analyzer is configured with a zone of trust "
            "of your AWS organization in every available region. IAM Access Analyzer generates a finding for each instance of a "
            "resource-based policy that grants access to a resource within your zone of trust to a "
            "principal that is not within your zone of trust. When you configure an organization as the "
            "zone of trust for an analyzer- IAA generates findings or each instance of a resource-based "
            "policy that grants access to a resource within your AWS organization to a principal that is "
            "not within your AWS organization."
        ),
        check_logic=(
            "Check if an IAM Access Analyzer with Organization zone of trust exists in each region, "
            "created by the audit account"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="IAM Access Analyzer",
        resource_type="AWS::AccessAnalyzer::Analyzer",
        remediation=Remediation(
            text=(
                "Create an IAM Access Analyzer with an organization zone of trust from "
                "the audit account in every enabled Region."
            ),
            cli=(
                "aws accessanalyzer create-analyzer "
                "--analyzer-name org-analyzer --type ORGANIZATION --region <region>"
            ),
            console=(
                "IAM console in the audit account, Access Analyzer, Analyzers, Create "
                "analyzer, select the current organization as the zone of trust, "
                "Create analyzer."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """Execute the check for each region.

        Yields:
            One Finding per Region, or a single global Finding when no analyzer
            exists anywhere or Access Analyzer is available in no Region.
        """
        # First, verify this check is running from an audit account - silently add to findings without logging warnings
        if self.audit_accounts:
            if self.account_id not in self.audit_accounts:
                # Don't log a warning, just add to findings
                yield self.error(
                    region="global",
                    resource_id="accessanalyzer:account-validation",
                    actual_value=f"Invalid account for IAM Access Analyzer check: Account {self.account_id} is not an audit account",
                    remediation=f"This check must be run from an audit account ({', '.join(self.audit_accounts)}). Either run this check from one of the designated audit accounts or update your configuration to specify the correct audit account(s) using the --audit-account parameter.",
                )
                return

        # If no regions have Access Analyzer available, return a single error
        if not self._clients:
            yield self.error(
                region="global",
                resource_id=f"accessanalyzer:global",
                actual_value="IAM Access Analyzer not available in any specified region",
                remediation="Ensure IAM Access Analyzer service is available in at least one region and you have proper permissions",
            )
            return

        # Check if any analyzers exist across all regions
        total_analyzers = 0
        for region, client in self._clients.items():
            analyzers = self.get_analyzers(region)
            total_analyzers += len(analyzers)

        # If no analyzers exist at all, return a single global finding
        if total_analyzers == 0:
            yield self.failed(
                region="global",
                resource_id="accessanalyzer:global",
                actual_value="No IAM Access Analyzers found in any region",
                remediation=(
                    "Create IAM Access Analyzers with Organization zone of trust in each region using the AWS CLI command: "
                    "aws accessanalyzer create-analyzer --analyzer-name org-analyzer --type ORGANIZATION --region <region>"
                ),
            )
            return

        # Track if we found organization analyzers in any region
        found_org_analyzers = False
        all_regions_checked = True

        # Check each region where Access Analyzer is available
        for region, client in self._clients.items():
            try:
                # Get analyzers for this region using the base class method that handles caching
                analyzers = self.get_analyzers(region)

                # Look for analyzers with organization zone of trust in this specific region
                # that are created by this account
                org_analyzers = [
                    a for a in analyzers
                    if a.get('type') == 'ORGANIZATION'
                    and a.get('status') == 'ACTIVE'
                    and a.get('arn', '').split(':')[4] == self.account_id
                ]

                if org_analyzers:
                    # If we found organization analyzers in this region created by this account, report a PASS
                    found_org_analyzers = True
                    analyzer_names = [a.get('name', 'Unknown') for a in org_analyzers]
                    analyzer_arn = org_analyzers[0].get('arn', f"arn:aws:access-analyzer:{region}:{self.account_id}:analyzer/{region}")

                    yield self.passed(
                        region=region,
                        resource_id=analyzer_arn,
                        actual_value=f"Found IAM Access Analyzer with Organization zone of trust in {region}: {', '.join(analyzer_names)}",
                    )
                else:
                    # If no organization analyzers in this region created by this account
                    yield self.failed(
                        region=region,
                        resource_id="No Organization analyzer found in this region",
                        actual_value=f"No IAM Access Analyzer with Organization zone of trust found in {region}",
                        remediation=f"Create an IAM Access Analyzer with Organization zone of trust in {region} using the AWS CLI command: aws accessanalyzer create-analyzer --analyzer-name org-analyzer --type ORGANIZATION --region {region}",
                    )
            except Exception as e:
                all_regions_checked = False
                yield self.error(
                    region=region,
                    resource_id="error",
                    actual_value=f"Error checking IAM Access Analyzer in {region}: {str(e)}",
                    remediation="Ensure you have proper permissions to list IAM Access Analyzers and that the service is available in this region",
                )
