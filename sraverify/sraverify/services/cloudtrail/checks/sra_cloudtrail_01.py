"""
SRA-CLOUDTRAIL-01: Organization CloudTrail Configuration.
"""
from typing import List, Dict, Any
from sraverify.services.cloudtrail.base import CloudTrailCheck
from sraverify.core.logging import logger


class SRA_CLOUDTRAIL_01(CloudTrailCheck):
    """Check if an Organization trail is configured for the AWS Organization."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CLOUDTRAIL-01"
        self.check_name = "An Organization trail is configured for the AWS Organization"
        self.account_type = "management"
        self.severity = "HIGH"
        self.description = (
            "This check verifies that an organization trail is configured for your AWS Organization. "
            "It is important to have uniform logging strategy for your AWS environment. Organization trail "
            "logs all events for all AWS accounts in that organization and delivers logs to a single S3 bucket, "
            "CloudWatch Logs and Event Bridge. Organization trails are automatically applied to all member accounts "
            "in the organization. Member accounts can see the organization trail, but can't modify or delete it. "
            "Organization trail should be configured for all AWS regions even if you are not operating out of any region."
        )
        self.check_logic = (
            "Check if at least one trail has IsOrganizationTrail set to true."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        
        # Get all trails using the base class method
        # This will use the cache if available or make API calls if needed
        all_trails = self.describe_trails()
        
        # Filter for organization trails
        org_trails = [
            trail for trail in all_trails 
            if trail.get('IsOrganizationTrail', False)
        ]
        
        if not org_trails:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=f"organization/{self.account_id}",
                    checked_value="IsOrganizationTrail: true",
                    actual_value="No organization trails found",
                    remediation=(
                        "Create an organization trail in the management account using the AWS CLI command: "
                        f"aws cloudtrail create-trail --name org-trail --is-organization-trail --s3-bucket-name cloudtrail-logs-{self.account_id} "
                        f"--is-multi-region-trail --region {self.regions[0] if self.regions else 'us-east-1'}"
                    )
                )
            )
            return findings
        
        # If we have organization trails, create a PASS finding for each one
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            
            findings.append(
                self.create_finding(
                    status="PASS",
                    region="global",
                    resource_id=trail_arn,
                    checked_value="IsOrganizationTrail: true",
                    actual_value=f"Organization trail '{trail_name}' is configured",
                    remediation="No remediation needed"
                )
            )
        
        return findings
