"""
SRA-INSPECTOR-11: Inspector Lambda Code Auto-Enable is Configured.
"""
from typing import List, Dict, Any
from sraverify.services.inspector.base import InspectorCheck
from sraverify.core.logging import logger


class SRA_INSPECTOR_11(InspectorCheck):
    """Check if Inspector Lambda Code auto-enable is configured."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-INSPECTOR-11"
        self.check_name = "Inspector Lambda Code auto-enable is configured"
        self.account_type = "audit"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Inspector is configured to automatically enable Lambda Code scanning for new accounts. "
            "Auto-enable ensures that Lambda function code in new accounts added to the organization is automatically scanned."
        )
        self.check_logic = (
            "Check runs inspector2 describe-organization-configuration. Check PASS if autoEnable.lambdaCode=true"
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        account_id = self.get_session_accountId(self.session)
        
        # Check each region separately
        for region in self.regions:
            # Get organization configuration for this region
            org_config = self.get_organization_configuration(region)
            
            # Check if Lambda Code auto-enable is configured
            lambda_code_enabled = org_config.get('autoEnable', {}).get('lambdaCode', False)
            
            if not lambda_code_enabled:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"inspector2/{region}/organization-configuration/lambdaCode",
                        checked_value="Inspector Lambda Code auto-enable is configured",
                        actual_value="Lambda Code auto-enable is not configured",
                        remediation=(
                            "Configure Inspector Lambda Code auto-enable using the AWS Console or CLI command: "
                            f"aws inspector2 update-organization-configuration --auto-enable lambdaCode=true --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=f"inspector2/{region}/organization-configuration/lambdaCode",
                        checked_value="Inspector Lambda Code auto-enable is configured",
                        actual_value="Lambda Code auto-enable is configured",
                        remediation="No remediation needed"
                    )
                )
        
        return self.findings
