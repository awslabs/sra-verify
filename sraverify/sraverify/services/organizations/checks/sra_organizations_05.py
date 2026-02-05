"""
Check if organization has all features enabled.
"""
from typing import Dict, List, Any
from sraverify.services.organizations.base import OrganizationsCheck


class SRA_ORGANIZATIONS_05(OrganizationsCheck):
    """Check if organization has all features enabled."""

    def __init__(self):
        """Initialize all features enabled check."""
        super().__init__(resource_type="AWS::Organizations::Organization")
        self.check_id = "SRA-ORGANIZATIONS-05"
        self.check_name = "Organization has all features enabled"
        self.description = (
            "This check verifies that the organization has all features enabled. "
            "All features mode enables full governance capabilities including Service Control Policies (SCPs), "
            "tag policies, backup policies, and AI services opt-out policies. Organizations with only "
            "consolidated billing have limited governance capabilities."
        )
        self.severity = "HIGH"
        self.check_logic = (
            "Call DescribeOrganization API to retrieve organization details. "
            "Check passes if FeatureSet equals 'ALL', fails if FeatureSet equals 'CONSOLIDATED_BILLING'."
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
            error_message = response["Error"].get("Message", "Unknown error")
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=None,
                actual_value=f"Error: {error_message}",
                remediation="Check IAM permissions for Organizations API access",
                checked_value="Organization FeatureSet"
            ))
            return self.findings

        # Extract organization details
        organization = response.get("Organization", {})
        org_id = organization.get("Id", "Unknown")
        feature_set = organization.get("FeatureSet", "Unknown")

        if feature_set == "ALL":
            self.findings.append(self.create_finding(
                status="PASS",
                region=region,
                resource_id=org_id,
                actual_value=f"FeatureSet: {feature_set}",
                remediation="No remediation needed",
                checked_value="Organization FeatureSet"
            ))
        elif feature_set == "CONSOLIDATED_BILLING":
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=org_id,
                actual_value=f"FeatureSet: {feature_set}",
                remediation=(
                    "Enable all features in AWS Organizations to gain full governance capabilities. "
                    "Navigate to AWS Organizations in the console and enable all features. "
                    "Note: This requires consent from all member accounts. "
                    "See: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_support-all-features.html"
                ),
                checked_value="Organization FeatureSet"
            ))
        else:
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=org_id,
                actual_value=f"Unknown FeatureSet: {feature_set}",
                remediation="Verify organization configuration",
                checked_value="Organization FeatureSet"
            ))

        return self.findings
