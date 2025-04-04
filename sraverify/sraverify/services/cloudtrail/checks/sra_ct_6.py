"""
SRA-CT-6: Organization CloudTrail Global Service Events.
"""
from typing import List, Dict, Any
from sraverify.services.cloudtrail.base import CloudTrailCheck
from sraverify.core.logging import logger


class SRA_CT_6(CloudTrailCheck):
    """Check if organization trails are configured to publish events from global services."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CT-6"
        self.check_name = "Organization trail is configured to publish events from global services"
        self.account_type = "management"
        self.severity = "MEDIUM"
        self.description = (
            "This check verifies that your organization trail is configured to publish event from AWS global services. "
            "The organization trail should capture events from global services such as AWS IAM, AWS STS and Amazon CloudFront. "
            "Trails created using CloudTrail console by default have global service event configured but if you are creating "
            "trail with AWS CLI, AWS SDKs, or CloudTrail API you have to specify to included global services events."
        )
        self.check_logic = (
            "Check if organization trails have IncludeGlobalServiceEvents set to true."
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
                    checked_value="IncludeGlobalServiceEvents: true",
                    actual_value="No organization trails found",
                    remediation=(
                        "Create an organization trail with global service events in the management account using the AWS CLI command: "
                        f"aws cloudtrail create-trail --name org-trail --is-organization-trail --s3-bucket-name cloudtrail-logs-{account_id} "
                        f"--include-global-service-events --is-multi-region-trail --region {self.regions[0] if self.regions else 'us-east-1'}"
                    )
                )
            )
            return findings
        
        # Check each organization trail for global service events
        for trail in org_trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', 'Unknown')
            include_global_service_events = trail.get('IncludeGlobalServiceEvents', False)
            home_region = trail.get('HomeRegion', 'Unknown')
            
            if include_global_service_events:
                # Trail includes global service events
                findings.append(
                    self.create_finding(
                        status="PASS",
                        region="global",
                        account_id=account_id,
                        resource_id=trail_arn,
                        checked_value="IncludeGlobalServiceEvents: true",
                        actual_value=f"Organization trail '{trail_name}' is configured to publish events from global services",
                        remediation=""
                    )
                )
            else:
                # Trail does not include global service events
                findings.append(
                    self.create_finding(
                        status="FAIL",
                        region="global",
                        account_id=account_id,
                        resource_id=trail_arn,
                        checked_value="IncludeGlobalServiceEvents: true",
                        actual_value=f"Organization trail '{trail_name}' is not configured to publish events from global services",
                        remediation=(
                            f"Update the organization trail '{trail_name}' to include global service events using the AWS CLI command: "
                            f"aws cloudtrail update-trail --name {trail_name} --include-global-service-events --region {home_region}"
                        )
                    )
                )
        
        return findings
