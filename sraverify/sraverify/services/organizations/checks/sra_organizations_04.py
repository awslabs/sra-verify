"""
Check if organization has foundational OU - Workloads.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.organizations.base import OrganizationsCheck


class SRA_ORGANIZATIONS_04(OrganizationsCheck):
    """Check if organization has foundational OU - Workloads."""

    meta = CheckMeta(
        check_id="SRA-ORGANIZATIONS-04",
        title="Organization has foundational OU - Workloads",
        description=(
            "This check verifies that the organization has a Workloads organizational unit (OU) "
            "directly under the root. The Workloads OU is a foundational OU recommended by AWS SRA "
            "for organizing application workload accounts including production and non-production environments."
        ),
        check_logic=(
            "Retrieve the organization root using ListRoots API, then list all OUs under the root "
            "using ListOrganizationalUnitsForParent API. Check passes if an OU named 'Workloads' "
            "exists directly under the root."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.MANAGEMENT,
        service="Organizations",
        resource_type="AWS::Organizations::OrganizationalUnit",
        remediation=Remediation(
            text=(
                "Create an organizational unit named Workloads directly under the "
                "organization root and move the application workload accounts into it."
            ),
            cli=(
                "aws organizations create-organizational-unit "
                "--parent-id <root-id> --name Workloads"
            ),
            console=(
                "AWS Organizations console, AWS accounts, select Root, "
                "Actions, Create new, name the OU Workloads."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the Workloads OU.
        """
        # Organizations is a global service, use "global" as region
        region = "global"

        # Get organization roots
        roots_response = self.get_roots()

        # Check for errors getting roots
        if "Error" in roots_response:
            error_message = roots_response["Error"].get("Message", "Unknown error")
            yield self.error(
                region=region,
                resource_id=None,
                actual_value=f"Error: {error_message}",
                remediation="Check IAM permissions for Organizations API access",
                checked_value="Workloads OU exists under root",
            )
            return

        roots = roots_response.get("Roots", [])
        if not roots:
            yield self.error(
                region=region,
                resource_id=None,
                actual_value="No organization root found",
                remediation="Ensure AWS Organizations is enabled and properly configured",
                checked_value="Workloads OU exists under root",
            )
            return

        # Get the first root (organizations have only one root)
        root = roots[0]
        root_id = root.get("Id", "")

        # Get OUs under the root
        ous_response = self.get_ous_for_parent(root_id)

        # Check for errors getting OUs
        if "Error" in ous_response:
            error_message = ous_response["Error"].get("Message", "Unknown error")
            yield self.error(
                region=region,
                resource_id=root_id,
                actual_value=f"Error: {error_message}",
                remediation="Check IAM permissions for Organizations API access",
                checked_value="Workloads OU exists under root",
            )
            return

        ous = ous_response.get("OrganizationalUnits", [])

        # Look for Workloads OU
        workloads_ou = None
        for ou in ous:
            if ou.get("Name") == "Workloads":
                workloads_ou = ou
                break

        if workloads_ou:
            ou_id = workloads_ou.get("Id", "Unknown")
            yield self.passed(
                region=region,
                resource_id=ou_id,
                actual_value=f"Workloads OU exists: {ou_id}",
                checked_value="Workloads OU exists under root",
            )
        else:
            # List existing OUs for context
            existing_ous = [ou.get("Name", "Unknown") for ou in ous]
            existing_ous_str = ", ".join(existing_ous) if existing_ous else "None"
            yield self.failed(
                region=region,
                resource_id=root_id,
                actual_value=f"Workloads OU not found. Existing OUs under root: {existing_ous_str}",
                remediation=(
                    "Create a Workloads organizational unit under the organization root. "
                    "Navigate to AWS Organizations in the console, select the root, and create "
                    "a new OU named 'Workloads'. Alternatively, use the AWS CLI: "
                    f"aws organizations create-organizational-unit --parent-id {root_id} --name Workloads"
                ),
                checked_value="Workloads OU exists under root",
            )
