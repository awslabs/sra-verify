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

        # If no regions have Access Analyzer available, return a single error
        if not self._clients:
            yield self.error(
                region="global",
                resource_id=f"accessanalyzer:global",
                actual_value="IAM Access Analyzer not available in any specified region",
                remediation="Ensure IAM Access Analyzer service is available in at least one region and you have proper permissions",
            )
            return

        # Count analyzers across the Regions we could read. A Region whose
        # lookup failed is not evidence of zero analyzers, so it is counted
        # separately and reported in its own row by the main loop below -- this
        # check emits one row per Region, and an undetermined Region must not
        # collapse the others.
        total_analyzers = 0
        undetermined = 0
        for region in self._clients:
            analyzers_response = self.get_analyzers(region)
            if "Error" in analyzers_response:
                undetermined += 1
                continue
            total_analyzers += len(analyzers_response.get('analyzers', []))

        # "No analyzers anywhere" can only be asserted when every Region answered.
        # With even one Region undetermined, the global FAIL would be claiming more
        # than the scan established, so the per-Region rows below carry it instead.
        if total_analyzers == 0 and undetermined == 0:
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

        # Check each region where Access Analyzer is available
        for region in self._clients:
            analyzers_response = self.get_analyzers(region)

            if "Error" in analyzers_response:
                error = analyzers_response['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"access-analyzer/{self.account_id}/{region}",
                        actual_value=(
                            f"No IAM Access Analyzer with Organization zone of "
                            f"trust found in {region}"
                        ),
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"access-analyzer/{self.account_id}/{region}",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            analyzers = analyzers_response.get('analyzers', [])

            # Look for analyzers with organization zone of trust in this specific
            # region that are created by this account
            org_analyzers = [
                a for a in analyzers
                if a.get('type') == 'ORGANIZATION'
                and a.get('status') == 'ACTIVE'
                and a.get('arn', '').split(':')[4] == self.account_id
            ]

            if org_analyzers:
                analyzer_names = [a.get('name', 'Unknown') for a in org_analyzers]
                analyzer_arn = org_analyzers[0].get('arn', f"arn:aws:access-analyzer:{region}:{self.account_id}:analyzer/{region}")

                yield self.passed(
                    region=region,
                    resource_id=analyzer_arn,
                    actual_value=f"Found IAM Access Analyzer with Organization zone of trust in {region}: {', '.join(analyzer_names)}",
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id="No Organization analyzer found in this region",
                    actual_value=f"No IAM Access Analyzer with Organization zone of trust found in {region}",
                    remediation=f"Create an IAM Access Analyzer with Organization zone of trust in {region} using the AWS CLI command: aws accessanalyzer create-analyzer --analyzer-name org-analyzer --type ORGANIZATION --region {region}",
                )
