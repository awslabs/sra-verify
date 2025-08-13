"""
SRA-CLOUDTRAIL-03: Organization CloudTrail Log File Validation.
"""
from typing import List, Dict, Any
from sraverify.services.cloudtrail.base import CloudTrailCheck
from sraverify.core.logging import logger


class SRA_CLOUDTRAIL_03(CloudTrailCheck):
    """Check if organization trails have log file validation enabled."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CLOUDTRAIL-03"
        self.check_name = "Organization trail has Log File validation enabled"
        self.account_type = "management"
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies that your organization trail has log file validation enabled. "
            "Validated log files are especially valuable in security and forensic investigations. "
            "CloudTrail log file integrity validation uses industry standard algorithms: SHA-256 for "
            "hashing and SHA-256 with RSA for digital signing. This makes it computationally unfeasible "
            "to modify, delete or forge CloudTrail log files without detection."
        )
        self.check_logic = (
            "Check if organization trails have LogFileValidationEnabled set to true."
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
                    checked_value="LogFileValidationEnabled: true",
                    actual_value="No organization trails found",
                    remediation=(
                        "Create an organization trail with log file validation in the management account using the AWS CLI command: "
                        f"aws cloudtrail create-trail --name org-trail --is-organization-trail --s3-bucket-name cloudtrail-logs-{self.account_id} "
                        f"--enable-log-file-validation --is-multi-region-trail --region {self.regions[0] if self.regions else 'us-east-1'}"
                    )
                )
            )
            return findings
        
        # Check each organization trail for log file validation
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            log_file_validation_enabled = trail.get('LogFileValidationEnabled', False)
            home_region = trail.get('HomeRegion', 'Unknown')
            
            if log_file_validation_enabled:
                # Trail has log file validation enabled
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region="global",
                        resource_id=trail_arn,
                        checked_value="LogFileValidationEnabled: true",
                        actual_value=f"Organization trail '{trail_name}' has log file validation enabled",
                        remediation="No remediation needed"
                    )
                )
            else:
                # Trail does not have log file validation enabled
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",
                        resource_id=trail_arn,
                        checked_value="LogFileValidationEnabled: true",
                        actual_value=f"Organization trail '{trail_name}' does not have log file validation enabled",
                        remediation=(
                            f"Update the organization trail '{trail_name}' to enable log file validation using the AWS CLI command: "
                            f"aws cloudtrail update-trail --name {trail_name} --enable-log-file-validation --region {home_region}"
                        )
                    )
                )
        
        return findings
