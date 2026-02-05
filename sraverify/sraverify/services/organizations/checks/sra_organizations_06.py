"""
Check if organization has Service Control Policies configured.
"""
from typing import Dict, List, Any
from sraverify.services.organizations.base import OrganizationsCheck


class SRA_ORGANIZATIONS_06(OrganizationsCheck):
    """Check if organization has Service Control Policies configured."""

    def __init__(self):
        """Initialize SCP check."""
        super().__init__(resource_type="AWS::Organizations::Policy")
        self.check_id = "SRA-ORGANIZATIONS-06"
        self.check_name = "Organization has Service Control Policies configured"
        self.description = (
            "This check verifies that the organization has at least one custom Service Control Policy (SCP) "
            "configured beyond the default FullAWSAccess policy. SCPs are essential for implementing "
            "permission guardrails across the organization to enforce security and compliance requirements."
        )
        self.severity = "HIGH"
        self.check_logic = (
            "Call ListPolicies API with filter for SERVICE_CONTROL_POLICY type. "
            "Check passes if at least one custom SCP exists (AwsManaged=False), "
            "fails if only the default FullAWSAccess policy exists or no SCPs are found."
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

        # Get SCPs
        response = self.list_policies("SERVICE_CONTROL_POLICY")

        # Check for errors
        if "Error" in response:
            error_code = response["Error"].get("Code", "")
            error_message = response["Error"].get("Message", "Unknown error")

            # PolicyTypeNotEnabledException means SCPs are not enabled
            if error_code == "PolicyTypeNotEnabledException":
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=org_id,
                    actual_value="Service Control Policies are not enabled",
                    remediation=(
                        "Enable Service Control Policies in AWS Organizations. "
                        "Navigate to AWS Organizations > Policies > Service control policies and enable SCPs. "
                        "Then create custom SCPs to implement permission guardrails."
                    ),
                    checked_value="Custom SCPs configured"
                ))
            else:
                self.findings.append(self.create_finding(
                    status="ERROR",
                    region=region,
                    resource_id=org_id,
                    actual_value=f"Error: {error_message}",
                    remediation="Check IAM permissions for Organizations API access",
                    checked_value="Custom SCPs configured"
                ))
            return self.findings

        policies = response.get("Policies", [])

        # Count custom SCPs (not AWS managed)
        custom_scps = [p for p in policies if not p.get("AwsManaged", False)]
        custom_scp_count = len(custom_scps)

        if not policies:
            # No SCPs at all - SCPs might not be enabled
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=org_id,
                actual_value="No Service Control Policies found",
                remediation=(
                    "Enable Service Control Policies in AWS Organizations and create custom SCPs. "
                    "Navigate to AWS Organizations > Policies > Service control policies and enable SCPs. "
                    "Then create custom SCPs to implement permission guardrails."
                ),
                checked_value="Custom SCPs configured"
            ))
        elif custom_scp_count == 0:
            # Only AWS managed policies (FullAWSAccess)
            policy_names = [p.get("Name", "Unknown") for p in policies]
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=org_id,
                actual_value=f"Only default policies found: {', '.join(policy_names)}",
                remediation=(
                    "Create custom Service Control Policies to implement permission guardrails. "
                    "Navigate to AWS Organizations > Policies > Service control policies and create new SCPs. "
                    "Consider implementing SCPs for: denying root user actions, restricting regions, "
                    "preventing disabling of security services, and enforcing encryption."
                ),
                checked_value="Custom SCPs configured"
            ))
        else:
            # Custom SCPs exist
            custom_scp_names = [p.get("Name", "Unknown") for p in custom_scps]
            self.findings.append(self.create_finding(
                status="PASS",
                region=region,
                resource_id=org_id,
                actual_value=f"{custom_scp_count} custom SCP(s) configured: {', '.join(custom_scp_names)}",
                remediation="No remediation needed",
                checked_value="Custom SCPs configured"
            ))

        return self.findings
