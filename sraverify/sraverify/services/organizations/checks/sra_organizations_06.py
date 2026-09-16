"""
Check if organization has Service Control Policies configured.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.organizations.base import OrganizationsCheck


class SRA_ORGANIZATIONS_06(OrganizationsCheck):
    """Check if organization has Service Control Policies configured."""

    meta = CheckMeta(
        check_id="SRA-ORGANIZATIONS-06",
        title="Organization has Service Control Policies configured",
        description=(
            "This check verifies that the organization has at least one custom Service Control Policy (SCP) "
            "configured beyond the default FullAWSAccess policy. SCPs are essential for implementing "
            "permission guardrails across the organization to enforce security and compliance requirements."
        ),
        check_logic=(
            "Call ListPolicies API with filter for SERVICE_CONTROL_POLICY type. "
            "Check passes if at least one custom SCP exists (AwsManaged=False), "
            "fails if only the default FullAWSAccess policy exists or no SCPs are found."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="Organizations",
        resource_type="AWS::Organizations::Policy",
        remediation=Remediation(
            text=(
                "Enable the SERVICE_CONTROL_POLICY policy type on the organization "
                "root and create at least one custom SCP that implements permission "
                "guardrails, then attach it to the root or to an organizational unit."
            ),
            cli=(
                "aws organizations enable-policy-type --root-id <root-id> "
                "--policy-type SERVICE_CONTROL_POLICY\n"
                "aws organizations create-policy --name <name> "
                "--type SERVICE_CONTROL_POLICY --description <description> "
                "--content file://scp.json"
            ),
            console=(
                "AWS Organizations console, Policies, Service control policies, "
                "Enable service control policies, then Create policy."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the organization's Service Control Policies.
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
            error = response["Error"]
            error_code = response["Error"].get("Code", "")
            error_message = response["Error"].get("Message", "Unknown error")

            # PolicyTypeNotEnabledException means SCPs are not enabled
            if self.is_not_configured(error):
                yield self.failed(
                    region=region,
                    resource_id=org_id,
                    actual_value="Service Control Policies are not enabled",
                    remediation=(
                        "Enable Service Control Policies in AWS Organizations. "
                        "Navigate to AWS Organizations > Policies > Service control policies and enable SCPs. "
                        "Then create custom SCPs to implement permission guardrails."
                    ),
                    checked_value="Custom SCPs configured",
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=org_id,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation="Check IAM permissions for Organizations API access",
                    checked_value="Custom SCPs configured",
                )
            return

        policies = response.get("Policies", [])

        # Count custom SCPs (not AWS managed)
        custom_scps = [p for p in policies if not p.get("AwsManaged", False)]
        custom_scp_count = len(custom_scps)

        if not policies:
            # No SCPs at all - SCPs might not be enabled
            yield self.failed(
                region=region,
                resource_id=org_id,
                actual_value="No Service Control Policies found",
                remediation=(
                    "Enable Service Control Policies in AWS Organizations and create custom SCPs. "
                    "Navigate to AWS Organizations > Policies > Service control policies and enable SCPs. "
                    "Then create custom SCPs to implement permission guardrails."
                ),
                checked_value="Custom SCPs configured",
            )
        elif custom_scp_count == 0:
            # Only AWS managed policies (FullAWSAccess)
            policy_names = [p.get("Name", "Unknown") for p in policies]
            yield self.failed(
                region=region,
                resource_id=org_id,
                actual_value=f"Only default policies found: {', '.join(policy_names)}",
                remediation=(
                    "Create custom Service Control Policies to implement permission guardrails. "
                    "Navigate to AWS Organizations > Policies > Service control policies and create new SCPs. "
                    "Consider implementing SCPs for: denying root user actions, restricting regions, "
                    "preventing disabling of security services, and enforcing encryption."
                ),
                checked_value="Custom SCPs configured",
            )
        else:
            # Custom SCPs exist
            custom_scp_names = [p.get("Name", "Unknown") for p in custom_scps]
            yield self.passed(
                region=region,
                resource_id=org_id,
                actual_value=f"{custom_scp_count} custom SCP(s) configured: {', '.join(custom_scp_names)}",
                checked_value="Custom SCPs configured",
            )
