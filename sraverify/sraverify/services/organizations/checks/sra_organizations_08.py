"""
Check if audit account is in Security OU.
"""
from typing import Dict, List, Any
from sraverify.services.organizations.base import OrganizationsCheck


class SRA_ORGANIZATIONS_08(OrganizationsCheck):
    """Check if audit account is in Security OU."""

    def __init__(self):
        """Initialize audit account in Security OU check."""
        super().__init__(resource_type="AWS::Organizations::Account")
        self.check_id = "SRA-ORGANIZATIONS-08"
        self.check_name = "Audit account is in Security OU"
        self.description = (
            "This check verifies that the audit account (Security Tooling account) is located in the "
            "Security organizational unit. According to AWS SRA best practices, the audit account should "
            "be placed in the Security OU to ensure proper isolation and governance of security tooling."
        )
        self.severity = "HIGH"
        self.check_logic = (
            "Get the Security OU under the organization root, then list all accounts in the Security OU. "
            "Check passes if the audit account (provided via --audit-account CLI parameter) is found in "
            "the Security OU."
        )
        self._audit_accounts = []  # Will be populated from CLI --audit-account parameter

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """
        # Organizations is a global service, use "global" as region
        region = "global"

        # Check if audit account is provided
        if not self._audit_accounts:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=None,
                actual_value="Audit account ID not provided",
                remediation="Run check with --audit-account parameter to specify the audit account ID",
                checked_value="Audit account in Security OU"
            ))
            return self.findings

        # Get organization roots
        roots_response = self.get_roots()
        if "Error" in roots_response:
            error_message = roots_response["Error"].get("Message", "Unknown error")
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=None,
                actual_value=f"Error: {error_message}",
                remediation="Check IAM permissions for Organizations API access",
                checked_value="Audit account in Security OU"
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
                checked_value="Audit account in Security OU"
            ))
            return self.findings

        root = roots[0]
        root_id = root.get("Id", "")

        # Get OUs under the root to find Security OU
        ous_response = self.get_ous_for_parent(root_id)
        if "Error" in ous_response:
            error_message = ous_response["Error"].get("Message", "Unknown error")
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=root_id,
                actual_value=f"Error: {error_message}",
                remediation="Check IAM permissions for Organizations API access",
                checked_value="Audit account in Security OU"
            ))
            return self.findings

        ous = ous_response.get("OrganizationalUnits", [])

        # Find Security OU
        security_ou = None
        for ou in ous:
            if ou.get("Name") == "Security":
                security_ou = ou
                break

        if not security_ou:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=root_id,
                actual_value="Security OU not found under organization root",
                remediation=(
                    "Create a Security organizational unit under the organization root and move the "
                    "audit account into it. Navigate to AWS Organizations in the console, create the "
                    "Security OU, then move the audit account to the Security OU."
                ),
                checked_value="Audit account in Security OU"
            ))
            return self.findings

        security_ou_id = security_ou.get("Id", "")

        # Get accounts in Security OU
        accounts_response = self.get_accounts_for_parent(security_ou_id)
        if "Error" in accounts_response:
            error_message = accounts_response["Error"].get("Message", "Unknown error")
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=security_ou_id,
                actual_value=f"Error: {error_message}",
                remediation="Check IAM permissions for Organizations API access",
                checked_value="Audit account in Security OU"
            ))
            return self.findings

        accounts = accounts_response.get("Accounts", [])
        account_ids_in_security_ou = [acc.get("Id") for acc in accounts]

        # Check if audit account(s) are in Security OU
        for audit_account_id in self._audit_accounts:
            if audit_account_id in account_ids_in_security_ou:
                # Find account name for better reporting
                account_name = next(
                    (acc.get("Name", "Unknown") for acc in accounts if acc.get("Id") == audit_account_id),
                    "Unknown"
                )
                self.findings.append(self.create_finding(
                    status="PASS",
                    region=region,
                    resource_id=audit_account_id,
                    actual_value=f"Audit account {audit_account_id} ({account_name}) is in Security OU",
                    remediation="No remediation needed",
                    checked_value="Audit account in Security OU"
                ))
            else:
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region=region,
                    resource_id=audit_account_id,
                    actual_value=f"Audit account {audit_account_id} is not in Security OU",
                    remediation=(
                        f"Move the audit account {audit_account_id} to the Security OU. "
                        "Navigate to AWS Organizations in the console, select the audit account, "
                        "and move it to the Security OU."
                    ),
                    checked_value="Audit account in Security OU"
                ))

        return self.findings
