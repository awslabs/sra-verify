"""
SRA-MACIE-02: Macie publish classification findings to Security Hub is enabled.
"""
from typing import List, Dict, Any
from sraverify.services.macie.base import MacieCheck
from sraverify.core.logging import logger


class SRA_MACIE_02(MacieCheck):
    """Check if Macie publish classification findings to Security Hub is enabled."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-MACIE-02"
        self.check_name = "Macie publish classification findings to Security Hub is enabled"
        self.description = (
            "This check verifies whether Macie is configured to publish sensitive data findings to AWS Security Hub. "
            "Sensitive data findings denotes potential sensitive data in as S3 object. Macie continually evaluates your "
            "S3 bucket inventory and uses sampling techniques to identify and select representative S3 objects from your buckets. "
            "Macie then retrieves and analyzes the selected objects, inspecting them for sensitive data."
        )
        self.severity = "HIGH"
        self.account_type = "application"
        self.check_logic = "Check validates macie2 get-findings-publication-configuration. Check PASS if 'publishClassificationFindings': true"
        self.resource_type = "AWS::Macie::Session"
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        for region in self.regions:
            # Get findings publication configuration using the base class method with caching
            config = self.get_findings_publication_configuration(region)
            
            # Check if the API call was successful
            if not config:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="publishClassificationFindings: true",
                        actual_value="Failed to retrieve Macie findings publication configuration",
                        remediation="Ensure Macie is enabled and you have the necessary permissions to call the Macie GetFindingsPublicationConfiguration API"
                    )
                )
                continue
            
            # Check if Security Hub configuration exists
            security_hub_config = config.get('securityHubConfiguration', {})
            if not security_hub_config:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="publishClassificationFindings: true",
                        actual_value="Security Hub configuration not found in Macie findings publication configuration",
                        remediation=(
                            f"Configure Macie to publish findings to Security Hub in region {region} using the AWS CLI command: "
                            f"aws macie2 put-findings-publication-configuration --security-hub-configuration publishClassificationFindings=true --region {region}"
                        )
                    )
                )
                continue
            
            # Check if classification findings are published to Security Hub
            publish_classification_findings = security_hub_config.get('publishClassificationFindings', False)
            
            if publish_classification_findings:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="publishClassificationFindings: true",
                        actual_value=f"Macie is configured to publish classification findings to Security Hub in region {region}",
                        remediation="No remediation needed"
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="publishClassificationFindings: true",
                        actual_value=f"Macie is not configured to publish classification findings to Security Hub in region {region}",
                        remediation=(
                            f"Configure Macie to publish classification findings to Security Hub in region {region} using the AWS CLI command: "
                            f"aws macie2 put-findings-publication-configuration --security-hub-configuration publishClassificationFindings=true --region {region}"
                        )
                    )
                )
        
        return findings
