"""
SRA-CLOUDTRAIL-12: CloudTrail Delegated Administrator Configuration.
"""
from typing import List, Dict, Any
from sraverify.services.cloudtrail.base import CloudTrailCheck
from sraverify.core.logging import logger


class SRA_CLOUDTRAIL_12(CloudTrailCheck):
    """Check if CloudTrail service administration is delegated out of AWS Organization management account."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CLOUDTRAIL-12"
        self.check_name = "Delegated Administrator set for CloudTrail"
        self.account_type = "management"
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies whether CloudTrail service administration is delegated out of AWS Organization "
            "management account. The delegated administrator has permissions to create and manage analyzers "
            "with the AWS organization as the zone of trust."
        )
        self.check_logic = (
            "Check if there is at least one delegated administrator for CloudTrail service."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        
        # Get delegated administrators for CloudTrail
        # This will use the cache if available or make API calls if needed
        delegated_admins = self.get_delegated_administrators()
        
        if not delegated_admins:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=f"organization/{self.account_id}",
                    checked_value="At least one delegated administrator for CloudTrail",
                    actual_value="No delegated administrator configured for CloudTrail",
                    remediation=(
                        "Register a delegated administrator for CloudTrail using the AWS CLI command: "
                        "aws organizations register-delegated-administrator "
                        "--account-id ACCOUNT_ID --service-principal cloudtrail.amazonaws.com"
                    )
                )
            )
            return findings
        
        # If we have delegated administrators, create a PASS finding for each one
        for admin in delegated_admins:
            admin_id = admin.get('Id', 'Unknown')
            admin_name = admin.get('Name', 'Unknown')
            
            # Create a resource ID that includes the delegated admin info
            resource_id = f"cloudtrail arn has delegated administrator set to {admin_id}"
            
            findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",
                    resource_id=resource_id,
                    checked_value="At least one delegated administrator for CloudTrail",
                    actual_value=f"CloudTrail has delegated administrator: {admin_id} ({admin_name})",
                    remediation="No remediation needed"
                )
            )
        
        return findings
