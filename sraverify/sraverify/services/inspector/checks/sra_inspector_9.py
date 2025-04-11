"""
SRA-INSPECTOR-9: Inspector ECR Auto-Enable is Configured.
"""
from typing import List, Dict, Any
from sraverify.services.inspector.base import InspectorCheck
from sraverify.core.logging import logger


class SRA_INSPECTOR_9(InspectorCheck):
    """Check if Inspector ECR auto-enable is configured."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-INSPECTOR-9"
        self.check_name = "Inspector ECR auto-enable is configured"
        self.account_type = "audit"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Inspector is configured to automatically enable ECR scanning for new accounts. "
            "Auto-enable ensures that container images in ECR repositories in new accounts added to the organization are automatically scanned."
        )
        self.check_logic = (
            "Check runs inspector2 describe-organization-configuration. Check PASS if autoEnable.ecr=true"
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
            
            # Check if ECR auto-enable is configured
            ecr_enabled = org_config.get('autoEnable', {}).get('ecr', False)
            
            if not ecr_enabled:
                self.findings.append(
                    self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"inspector2/{region}/organization-configuration/ecr",
                        checked_value="Inspector ECR auto-enable is configured",
                        actual_value="ECR auto-enable is not configured",
                        remediation=(
                            "Configure Inspector ECR auto-enable using the AWS Console or CLI command: "
                            f"aws inspector2 update-organization-configuration --auto-enable ecr=true --region {region}"
                        )
                    )
                )
            else:
                self.findings.append(
                    self.create_finding(
                        status="PASS",
                        region=region,
                        account_id=account_id,
                        resource_id=f"inspector2/{region}/organization-configuration/ecr",
                        checked_value="Inspector ECR auto-enable is configured",
                        actual_value="ECR auto-enable is configured",
                        remediation="No remediation needed"
                    )
                )
        
        return self.findings
