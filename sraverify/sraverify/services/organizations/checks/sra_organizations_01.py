"""
Check if AWS Organizations is enabled.
"""
from typing import Dict, List, Any
from sraverify.services.organizations.base import OrganizationsCheck


class SRA_ORGANIZATIONS_01(OrganizationsCheck):
    """Check if AWS Organizations is enabled."""

    def __init__(self):
        """Initialize Organizations enabled check."""
        super().__init__(resource_type="AWS::Organizations::Organization")
        self.check_id = "SRA-ORGANIZATIONS-01"
        self.check_name = "AWS Organizations is enabled"
        self.description = (
            "This check verifies that AWS Organizations is enabled for the account. "
            "AWS Organizations enables central management and governance of multiple AWS accounts, "
            "providing consolidated billing, account management, and policy-based controls."
        )
        self.severity = "HIGH"
        self.check_logic = (
            "Call DescribeOrganization API to confirm an organization exists. "
            "Check passes if an organization is found, fails if no organization exists."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.
        
        Returns:
            List of findings
        """
        # Organizations is a global service, use "global" as region
        region = "global"
        
        # Get organization details
        response = self.get_organization()
        
        # Check for errors
        if "Error" in response:
            error_code = response["Error"].get("Code", "")
            error_message = response["Error"].get("Message", "Unknown error")
            
            # AWSOrganizationsNotInUseException means no organization exists
            if error_code == "AWSOrganizationsNotInUseException":
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=None,
                    actual_value="No organization exists",
                    remediation=(
                        "Create an AWS Organization by navigating to AWS Organizations in the console "
                        "and clicking 'Create organization', or use the AWS CLI command: "
                        "aws organizations create-organization"
                    ),
                    checked_value="AWS Organizations enabled"
                ))
            else:
                # Other errors (permissions, service errors)
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=None,
                    actual_value=f"Error: {error_message}",
                    remediation="Check IAM permissions for Organizations API access",
                    checked_value="AWS Organizations enabled"
                ))
            return self.findings
        
        # Organization exists - extract details
        organization = response.get("Organization", {})
        org_id = organization.get("Id", "Unknown")
        
        self.findings.append(self.create_finding(
            status="PASS",
            region=region,
            resource_id=org_id,
            actual_value=f"Organization exists: {org_id}",
            remediation="No remediation needed",
            checked_value="AWS Organizations enabled"
        ))
        
        return self.findings
