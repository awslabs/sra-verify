"""
SRA-CLOUDTRAIL-04: Organization CloudTrail Multi-Region Configuration.
"""
from typing import List, Dict, Any
from sraverify.services.cloudtrail.base import CloudTrailCheck
from sraverify.core.logging import logger


class SRA_CLOUDTRAIL_04(CloudTrailCheck):
    """Check if organization trails are configured as multi-region trails."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CLOUDTRAIL-04"
        self.check_name = "Organization Trail is a multi-region trail"
        self.account_type = "management"
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies whether the Organization trail is configured as a multi-region trail. "
            "This helps with visibility across your entire AWS environment, even for AWS Regions where "
            "you are not operating to ensure you detect any malicious and/or unauthorized activities."
        )
        self.check_logic = (
            "Check if organization trails have IsMultiRegionTrail set to true."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        
        # Get organization trails
        org_trails = self.get_organization_trails()
        
        if not org_trails:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=f"organization/{self.account_id}",
                    checked_value="IsMultiRegionTrail: true",
                    actual_value="No organization trails found",
                    remediation=(
                        "Create a multi-region organization trail in the management account using the AWS CLI command: "
                        f"aws cloudtrail create-trail --name org-trail --is-organization-trail --s3-bucket-name cloudtrail-logs-{self.account_id} "
                        f"--is-multi-region-trail --region {self.regions[0] if self.regions else 'us-east-1'}"
                    )
                )
            )
            return findings
        
        # Check each organization trail for multi-region configuration
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            is_multi_region_trail = trail.get('IsMultiRegionTrail', False)
            home_region = trail.get('HomeRegion', 'Unknown')
            
            if is_multi_region_trail:
                # Trail is a multi-region trail
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region="global",
                        resource_id=trail_arn,
                        checked_value="IsMultiRegionTrail: true",
                        actual_value=f"Organization trail '{trail_name}' is configured as a multi-region trail",
                        remediation="No remediation needed"
                    )
                )
            else:
                # Trail is not a multi-region trail
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",
                        resource_id=trail_arn,
                        checked_value="IsMultiRegionTrail: true",
                        actual_value=f"Organization trail '{trail_name}' is not configured as a multi-region trail",
                        remediation=(
                            f"Update the organization trail '{trail_name}' to be a multi-region trail using the AWS CLI command: "
                            f"aws cloudtrail update-trail --name {trail_name} --is-multi-region-trail --region {home_region}"
                        )
                    )
                )
        
        return findings
