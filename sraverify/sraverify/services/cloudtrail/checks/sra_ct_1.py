"""
SRA-CT-1: Organization CloudTrail Configuration.
"""
from typing import List, Dict, Any
from sraverify.services.cloudtrail.base import CloudTrailCheck


class SRA_CT_1(CloudTrailCheck):
    """Check if an organization trail is configured for the AWS Organization."""
    
    def __init__(self):
        """Initialize the check."""
        super().__init__()
        self.check_id = "SRA-CT-1"
        self.check_name = "Organization CloudTrail Configuration"
        self.check_type = "management"
        self.severity = "HIGH"
        self.description = (
            "This check verifies that an organization trail is configured for your AWS Organization. "
            "It is important to have uniform logging strategy for your AWS environment. Organization "
            "trail logs all events for all AWS accounts in that organization and delivers logs to a "
            "single S3 bucket, CloudWatch Logs and Event Bridge. Organization trails are automatically "
            "applied to all member accounts in the organization. Member accounts can see the "
            "organization trail, but can't modify or delete it. Organization trail should be "
            "configured for all AWS regions even if you are not operating out of any region."
        )
        self.check_logic = (
            "Verify execution from Organization Management account and checks for organization trail."
        )
    
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        findings = []
        account_id = self.get_session_accountId(self.session)
        management_account_id = self.get_management_accountId(self.session)
        
        for region in self.regions:
            try:
                # Check if this is the management account
                # if management_account_id != account_id:
                #     return [self.create_finding(
                #         status="ERROR",
                #         region=region,
                #         account_id=account_id,
                #         resource_id=account_id,
                #         actual_value="Not running from management account",
                #         remediation="Run this check from the Organization Management Account"
                #     )]
                    
                # Use get_trails from base class which handles the client interaction
                result = self.get_trails(region)
                
                # Check if we got an error
                if isinstance(result, dict) and result.get("error"):
                    findings.append(self.create_finding(
                        status="ERROR",
                        region=region,
                        account_id=account_id,
                        resource_id=f"cloudtrail:{region}",
                        actual_value=f"Error accessing CloudTrail: {result.get('message', 'Unknown error')}",
                        remediation="Check permissions or SCP policies for this region"
                    ))
                    continue
                
                # Now we know we have a valid list of trails (might be empty)
                trails = result
                
                organization_trails = [
                    trail for trail in trails 
                    if trail.get('IsOrganizationTrail', False)
                ]
                
                if not organization_trails:
                    findings.append(self.create_finding(
                        status="FAIL",
                        region=region,
                        account_id=account_id,
                        resource_id=f"cloudtrail:{region}",
                        actual_value="No organization trail found",
                        remediation="Configure an organization trail for your AWS Organization"
                    ))
                else:
                    # Use a for loop to append each finding
                    for trail in organization_trails:
                        findings.append(self.create_finding(
                            status="PASS",
                            region=region,
                            account_id=account_id,
                            resource_id=trail['TrailARN'],
                            actual_value=f"Organization trail found: {trail['Name']}",
                            remediation=""
                        ))
            except Exception as e:
                print(f"Error processing region {region}: {str(e)}")
                # Add a finding for regions with errors
                findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    account_id=account_id,
                    resource_id=f"cloudtrail:{region}",
                    actual_value=f"Error processing region: {str(e)}",
                    remediation="Check permissions or SCP policies for this region"
                ))
        
        # Return findings after processing all regions
        return findings
