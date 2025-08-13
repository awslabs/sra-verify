"""
Check if IAM Access Analyzer external access analyzer is configured with account zone of trust.
"""
from typing import Dict, List, Any
from sraverify.services.accessanalyzer.base import AccessAnalyzerCheck
from sraverify.core.logging import logger


class SRA_ACCESSANALYZER_01(AccessAnalyzerCheck):
    """Check if IAM Access Analyzer external access analyzer is configured with account zone of trust."""

    def __init__(self):
        """Initialize IAM Access Analyzer check."""
        super().__init__()
        self.check_id = "SRA-ACCESSANALYZER-01"
        self.check_name = "IAM Access Analyzer Account Zone of trust"
        self.description = ("This check verifies whether IAA external access analyzer is configured with a zone of "
                          "trust of AWS account. IAM Access Analyzer generates a finding for each instance of a "
                          "resource-based policy that grants access to a resource within your zone of trust to a "
                          "principal that is not within your zone of trust. When you configure an AWS account as "
                          "the zone of trust for an analyzer- IAA generates findings or each instance of a "
                          "resource-based policy that grants access to a resource within your AWS account whether "
                          "the analyzer exists to a principal that is not within your AWS account.")
        self.severity = "HIGH"
        self.check_logic = "List analyzers in each Region. Check if analyzer exists and is configured with account zone of trust."

    def execute(self) -> List[Dict[str, Any]]:
        """Execute the check for each region."""
        findings = []        
        logger.debug(f"Executing {self.check_id} check for account {self.account_id}")

        # If no regions have Access Analyzer available, return a single failure
        if not self._clients:
            logger.warning("No regions with Access Analyzer available")
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",                    
                    resource_id="accessanalyzer:global",  # Generic format for global failure
                    actual_value="IAM Access Analyzer not available in any region",
                    remediation="Enable IAM Access Analyzer in at least one region and configure "
                            "with account zone of trust"
                )
            )
            return findings

        # Check each region where Access Analyzer is available
        for region, client in self._clients.items():
            logger.debug(f"Checking region {region} for account-level analyzers")
            analyzers = self.get_analyzers(region)
            
            # Check if any analyzer exists with account-level zone of trust
            account_analyzer = None
            for analyzer in analyzers:
                if analyzer.get('type') == 'ACCOUNT':
                    account_analyzer = analyzer
                    logger.debug(f"Found account analyzer in {region}: {analyzer.get('name')}")
                    break

            if account_analyzer:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,                        
                        resource_id=account_analyzer['arn'],  # Use the actual analyzer ARN for PASS
                        actual_value="IAM Access Analyzer configured with account zone of trust",
                        remediation="No remediation needed"
                    )
                )
            else:
                logger.debug(f"No account analyzer found in {region}")
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,                        
                        resource_id=f"accessanalyzer:{region}",  # Keep generic format for FAIL
                        actual_value="No IAM Access Analyzer configured with account zone of trust",
                        remediation="Create an IAM Access Analyzer with account zone of trust in this region"
                    )
                )

        return findings
