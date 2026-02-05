"""
Check if organization has Resource Control Policies configured.
"""
from typing import Dict, List, Any
from sraverify.services.organizations.base import OrganizationsCheck


class SRA_ORGANIZATIONS_07(OrganizationsCheck):
    """Check if organization has Resource Control Policies configured."""

    def __init__(self):
        """Initialize RCP check."""
        super().__init__(resource_type="AWS::Organizations::Policy")
        self.check_id = "SRA-ORGANIZATIONS-07"
        self.check_name = "Organization has Resource Control Policies configured"
        self.description = (
            "This check verifies that the organization has at least one custom Resource Control Policy (RCP) "
            "configured beyond the default RCPFullAWSAccess policy. RCPs are a type of organization policy "
            "that help you centrally establish data perimeter controls across AWS resources in your organization. "
            "RCPs complement SCPs by controlling what resources can be accessed rather than what actions "
            "principals can perform."
        )
        self.severity = "MEDIUM"
        self.check_logic = (
            "Call ListPolicies API with filter for RESOURCE_CONTROL_POLICY type. "
            "Check passes if at least one custom RCP exists (AwsManaged=False), "
            "fails if only the default RCPFullAWSAccess policy exists or no RCPs are found."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """
        # Organizations is a global service, use "global" as region
        region = "global"

        # Get organization details for org_id
        org_response = self.get_organization()
        org_id = None
        if "Organization" in org_response:
            org_id = org_response["Organization"].get("Id", "Unknown")

        # Get RCPs
        response = self.list_policies("RESOURCE_CONTROL_POLICY")

        # Check for errors
        if "Error" in response:
            error_code = response["Error"].get("Code", "")
            error_message = response["Error"].get("Message", "Unknown error")

            # PolicyTypeNotEnabledException means RCPs are not enabled
            if error_code == "PolicyTypeNotEnabledException":
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=org_id,
                    actual_value="Resource Control Policies are not enabled",
                    remediation=(
                        "Enable Resource Control Policies in AWS Organizations. "
                        "Navigate to AWS Organizations > Policies > Resource control policies and enable RCPs. "
                        "Then create RCPs to implement data perimeter controls across your organization."
                    ),
                    checked_value="RCPs configured"
                ))
            else:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=org_id,
                    actual_value=f"Error: {error_message}",
                    remediation="Check IAM permissions for Organizations API access",
                    checked_value="RCPs configured"
                ))
            return self.findings

        policies = response.get("Policies", [])

        # Count custom RCPs (not AWS managed - exclude RCPFullAWSAccess)
        custom_rcps = [p for p in policies if not p.get("AwsManaged", False)]
        custom_rcp_count = len(custom_rcps)

        if not policies:
            # No RCPs at all - RCPs might not be enabled
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=org_id,
                actual_value="No Resource Control Policies found",
                remediation=(
                    "Enable Resource Control Policies in AWS Organizations and create RCPs. "
                    "Navigate to AWS Organizations > Policies > Resource control policies and enable RCPs. "
                    "Then create RCPs to implement data perimeter controls such as restricting access "
                    "to resources based on organization membership or network location."
                ),
                checked_value="Custom RCPs configured"
            ))
        elif custom_rcp_count == 0:
            # Only AWS managed policies (RCPFullAWSAccess)
            policy_names = [p.get("Name", "Unknown") for p in policies]
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=org_id,
                actual_value=f"Only default policies found: {', '.join(policy_names)}",
                remediation=(
                    "Create custom Resource Control Policies to implement data perimeter controls. "
                    "Navigate to AWS Organizations > Policies > Resource control policies and create new RCPs. "
                    "Consider implementing RCPs for: restricting access to resources based on organization "
                    "membership, enforcing HTTPS connections, and cross-service confused deputy protection."
                ),
                checked_value="Custom RCPs configured"
            ))
        else:
            # Custom RCPs exist
            custom_rcp_names = [p.get("Name", "Unknown") for p in custom_rcps]
            self.findings.append(self.create_finding(
                status="PASS",
                region=region,
                resource_id=org_id,
                actual_value=f"{custom_rcp_count} custom RCP(s) configured: {', '.join(custom_rcp_names)}",
                remediation="No remediation needed",
                checked_value="Custom RCPs configured"
            ))

        return self.findings
