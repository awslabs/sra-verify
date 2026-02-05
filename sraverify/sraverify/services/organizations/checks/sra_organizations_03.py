"""
Check if organization has foundational OU - Infrastructure.
"""
from typing import Dict, List, Any
from sraverify.services.organizations.base import OrganizationsCheck


class SRA_ORGANIZATIONS_03(OrganizationsCheck):
    """Check if organization has foundational OU - Infrastructure."""

    def __init__(self):
        """Initialize Infrastructure OU check."""
        super().__init__(resource_type="AWS::Organizations::OrganizationalUnit")
        self.check_id = "SRA-ORGANIZATIONS-03"
        self.check_name = "Organization has foundational OU - Infrastructure"
        self.description = (
            "This check verifies that the organization has an Infrastructure organizational unit (OU) "
            "directly under the root. The Infrastructure OU is a foundational OU recommended by AWS SRA "
            "for organizing infrastructure-related accounts such as shared services and networking accounts."
        )
        self.severity = "MEDIUM"
        self.check_logic = (
            "Retrieve the organization root using ListRoots API, then list all OUs under the root "
            "using ListOrganizationalUnitsForParent API. Check passes if an OU named 'Infrastructure' "
            "exists directly under the root."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """
        # Organizations is a global service, use "global" as region
        region = "global"

        # Get organization roots
        roots_response = self.get_roots()

        # Check for errors getting roots
        if "Error" in roots_response:
            error_message = roots_response["Error"].get("Message", "Unknown error")
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=None,
                actual_value=f"Error: {error_message}",
                remediation="Check IAM permissions for Organizations API access",
                checked_value="Infrastructure OU exists under root"
            ))
            return self.findings

        roots = roots_response.get("Roots", [])
        if not roots:
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=None,
                actual_value="No organization root found",
                remediation="Ensure AWS Organizations is enabled and properly configured",
                checked_value="Infrastructure OU exists under root"
            ))
            return self.findings

        # Get the first root (organizations have only one root)
        root = roots[0]
        root_id = root.get("Id", "")

        # Get OUs under the root
        ous_response = self.get_ous_for_parent(root_id)

        # Check for errors getting OUs
        if "Error" in ous_response:
            error_message = ous_response["Error"].get("Message", "Unknown error")
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=root_id,
                actual_value=f"Error: {error_message}",
                remediation="Check IAM permissions for Organizations API access",
                checked_value="Infrastructure OU exists under root"
            ))
            return self.findings

        ous = ous_response.get("OrganizationalUnits", [])

        # Look for Infrastructure OU
        infrastructure_ou = None
        for ou in ous:
            if ou.get("Name") == "Infrastructure":
                infrastructure_ou = ou
                break

        if infrastructure_ou:
            ou_id = infrastructure_ou.get("Id", "Unknown")
            self.findings.append(self.create_finding(
                status="PASS",
                region=region,
                resource_id=ou_id,
                actual_value=f"Infrastructure OU exists: {ou_id}",
                remediation="No remediation needed",
                checked_value="Infrastructure OU exists under root"
            ))
        else:
            # List existing OUs for context
            existing_ous = [ou.get("Name", "Unknown") for ou in ous]
            existing_ous_str = ", ".join(existing_ous) if existing_ous else "None"
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=root_id,
                actual_value=f"Infrastructure OU not found. Existing OUs under root: {existing_ous_str}",
                remediation=(
                    "Create an Infrastructure organizational unit under the organization root. "
                    "Navigate to AWS Organizations in the console, select the root, and create "
                    "a new OU named 'Infrastructure'. Alternatively, use the AWS CLI: "
                    f"aws organizations create-organizational-unit --parent-id {root_id} --name Infrastructure"
                ),
                checked_value="Infrastructure OU exists under root"
            ))

        return self.findings
