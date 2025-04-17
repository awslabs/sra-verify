"""
SRA-MACIE-8: Macie AutoEnable configuration is enabled for new member accounts.
"""
from typing import List, Dict, Any
from sraverify.services.macie.base import MacieCheck
from sraverify.core.logging import logger


class SRA_MACIE_8(MacieCheck):
    """Check if Macie AutoEnable configuration is enabled for new member accounts."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-MACIE-8"
        self.check_name = "Macie AutoEnable configuration is enabled for new member accounts"
        self.description = (
            "This check verifies whether auto-enablement configuration for Macie is enabled for member accounts of the AWS Organization. "
            "This ensures that all existing and new member accounts will have Macie monitoring."
        )
        self.severity = "MEDIUM"
        self.account_type = "audit"
        self.check_logic = "Check runs macie2 describe-organization-configuration. PASS if autoenable = True"
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
            # Get organization configuration using the base class method with caching
            org_config = self.get_organization_configuration(region)
            
            # Check if the API call was successful
            if not org_config:
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="autoEnable: true",
                        actual_value="Failed to retrieve Macie organization configuration",
                        remediation="Ensure Macie is enabled and you have the necessary permissions to call the Macie DescribeOrganizationConfiguration API"
                    )
                )
                continue
            
            # Check if auto-enable is enabled
            auto_enable = org_config.get('autoEnable', False)
            
            if auto_enable:
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=f"macie2/{account_id}/{region}",
                        checked_value="autoEnable: true",
                        actual_value=f"Macie AutoEnable configuration is enabled for new member accounts in region {region}",
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
                        checked_value="autoEnable: true",
                        actual_value=f"Macie AutoEnable configuration is not enabled for new member accounts in region {region}",
                        remediation=(
                            f"Enable Macie AutoEnable configuration for new member accounts in region {region} using the AWS CLI command: "
                            f"aws macie2 update-organization-configuration --auto-enable --region {region}"
                        )
                    )
                )
        
        return findings
