"""
SRA-CT-7: Organization CloudTrail Active Logging.
"""
from typing import List, Dict, Any
from sraverify.services.cloudtrail.base import CloudTrailCheck
from sraverify.core.logging import logger


class SRA_CT_7(CloudTrailCheck):
    """Check if organization trails are actively publishing events."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CT-7"
        self.check_name = "Organization trail is actively publishing events"
        self.account_type = "management"
        self.severity = "HIGH"
        self.description = (
            "This check verifies that your organization trail is running and actively logging events. "
            "If a trail is modified to stop logging, accidently or by malicious user, you will not have "
            "visibility into any API activity across your AWS environment."
        )
        self.check_logic = (
            "Check if organization trails have IsLogging set to true in their status."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        
        # Get organization trails
        org_trails = self.get_organization_trails()
        
        if not org_trails:
            findings.append(
                self.create_finding(
                    status="FAIL",
                    region="global",
                    account_id=account_id,
                    resource_id=f"organization/{account_id}",
                    checked_value="IsLogging: true",
                    actual_value="No organization trails found",
                    remediation=(
                        "Create an organization trail in the management account using the AWS CLI command: "
                        f"aws cloudtrail create-trail --name org-trail --is-organization-trail --s3-bucket-name cloudtrail-logs-{account_id} "
                        f"--is-multi-region-trail --region {self.regions[0] if self.regions else 'us-east-1'} && "
                        f"aws cloudtrail start-logging --name org-trail --region {self.regions[0] if self.regions else 'us-east-1'}"
                    )
                )
            )
            return findings
        
        # Check each organization trail for active logging
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            home_region = trail.get('HomeRegion', 'Unknown')
            
            # Get trail status to check if logging is enabled
            trail_status = self.get_trail_status(home_region, trail_arn)
            is_logging = trail_status.get('IsLogging', False)
            
            if is_logging:
                # Trail is actively logging
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region="global",
                        account_id=account_id,
                        resource_id=trail_arn,
                        checked_value="IsLogging: true",
                        actual_value=f"Organization trail '{trail_name}' is actively logging events",
                        remediation="No remediation needed"
                    )
                )
            else:
                # Trail is not actively logging
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",
                        account_id=account_id,
                        resource_id=trail_arn,
                        checked_value="IsLogging: true",
                        actual_value=f"Organization trail '{trail_name}' is not actively logging events",
                        remediation=(
                            f"Start logging for the organization trail '{trail_name}' using the AWS CLI command: "
                            f"aws cloudtrail start-logging --name {trail_name} --region {home_region}"
                        )
                    )
                )
        
        return findings
