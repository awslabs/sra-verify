"""
Check if IAM Access Analyzer external access analyzer is configured with account zone of trust.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.logging import logger
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.accessanalyzer.base import AccessAnalyzerCheck


class SRA_ACCESSANALYZER_01(AccessAnalyzerCheck):
    """Check if IAM Access Analyzer external access analyzer is configured with account zone of trust."""

    meta = CheckMeta(
        check_id="SRA-ACCESSANALYZER-01",
        title="IAM Access Analyzer Account Zone of trust",
        description=(
            "This check verifies whether IAA external access analyzer is configured with a zone of "
            "trust of AWS account. IAM Access Analyzer generates a finding for each instance of a "
            "resource-based policy that grants access to a resource within your zone of trust to a "
            "principal that is not within your zone of trust. When you configure an AWS account as "
            "the zone of trust for an analyzer- IAA generates findings or each instance of a "
            "resource-based policy that grants access to a resource within your AWS account whether "
            "the analyzer exists to a principal that is not within your AWS account."
        ),
        check_logic=(
            "List analyzers in each Region. Check if analyzer exists and is configured with "
            "account zone of trust."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.APPLICATION,
        service="IAM Access Analyzer",
        resource_type="AWS::AccessAnalyzer::Analyzer",
        remediation=Remediation(
            text=(
                "Create an IAM Access Analyzer with an account zone of trust in every "
                "enabled Region."
            ),
            cli=(
                "aws accessanalyzer create-analyzer "
                "--analyzer-name account-analyzer --type ACCOUNT --region <region>"
            ),
            console=(
                "IAM console, Access Analyzer, Analyzers, Create analyzer, select the "
                "current account as the zone of trust, Create analyzer."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """Execute the check for each region.

        Yields:
            One Finding per Region, or a single global Finding when Access
            Analyzer is available in no Region.
        """
        logger.debug(f"Executing {self.check_id} check for account {self.account_id}")

        # If no regions have Access Analyzer available, return a single failure
        if not self._clients:
            logger.warning("No regions with Access Analyzer available")
            yield self.failed(
                region="global",
                resource_id="accessanalyzer:global",  # Generic format for global failure
                actual_value="IAM Access Analyzer not available in any region",
                remediation="Enable IAM Access Analyzer in at least one region and configure "
                        "with account zone of trust",
            )
            return

        # Check each region where Access Analyzer is available
        for region, client in self._clients.items():
            logger.debug(f"Checking region {region} for account-level analyzers")
            analyzers_response = self.get_analyzers(region)

            if "Error" in analyzers_response:
                error = analyzers_response['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"access-analyzer/{self.account_id}/{region}",
                        actual_value="No IAM Access Analyzer is configured in this Region",
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

            # Check if any analyzer exists with account-level zone of trust
            account_analyzer = None
            for analyzer in analyzers:
                if analyzer.get('type') == 'ACCOUNT':
                    account_analyzer = analyzer
                    logger.debug(f"Found account analyzer in {region}: {analyzer.get('name')}")
                    break

            if account_analyzer:
                yield self.passed(
                    region=region,
                    resource_id=account_analyzer['arn'],  # Use the actual analyzer ARN for PASS
                    actual_value="IAM Access Analyzer configured with account zone of trust",
                )
            else:
                logger.debug(f"No account analyzer found in {region}")
                yield self.failed(
                    region=region,
                    resource_id=f"accessanalyzer:{region}",  # Keep generic format for FAIL
                    actual_value="No IAM Access Analyzer configured with account zone of trust",
                    remediation="Create an IAM Access Analyzer with account zone of trust in this region",
                )
