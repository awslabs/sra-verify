"""
Check if the Security Incident Response triage service linked role exists.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityincidentresponse.base import SecurityIncidentResponseCheck


class SRA_SECURITYINCIDENTRESPONSE_05(SecurityIncidentResponseCheck):
    """Check if the Security Incident Response triage service linked role exists."""

    meta = CheckMeta(
        check_id="SRA-SECURITYINCIDENTRESPONSE-05",
        title="Security Incident Response triage service linked role exists",
        description=(
            "Verifies that the AWSServiceRoleForSecurityIncidentResponse_Triage "
            "service linked role exists"
        ),
        check_logic=(
            "Checks if the AWSServiceRoleForSecurityIncidentResponse_Triage IAM role "
            "exists in the account"
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="SecurityIncidentResponse",
        resource_type="AWS::Organizations::DelegatedAdministrator",
        remediation=Remediation(
            text=(
                "Create the AWSServiceRoleForSecurityIncidentResponse_Triage service "
                "linked role in the account, either by onboarding the account to AWS "
                "Security Incident Response or by creating the role directly."
            ),
            cli=(
                "aws iam create-service-linked-role "
                "--aws-service-name triage.security-ir.amazonaws.com"
            ),
            console=(
                "AWS Security Incident Response console, onboard the account to the "
                "membership, which creates the triage service linked role."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding describing the triage service linked role.
        """
        region = "global"  # IAM is global
        role_name = "AWSServiceRoleForSecurityIncidentResponse_Triage"
        management_account_id = self.get_management_accountId(self.session)
        is_management_account = self.account_id == management_account_id

        response = self.get_role(role_name)

        if "Error" in response:
            error_code = response["Error"].get("Code")
            if error_code == "NoSuchEntity":
                if is_management_account:
                    remediation = "Security Incident Response cannot automatically create the triage service linked role in the management account. Create it manually using: aws iam create-service-linked-role --aws-service-name triage.security-ir.amazonaws.com"
                else:
                    remediation = "The triage service linked role is created when onboarding to Security Incident Response. If deleted, recreate by onboarding to the service again or manually using: aws iam create-service-linked-role --aws-service-name triage.security-ir.amazonaws.com"

                yield self.failed(
                    region=region,
                    resource_id=f"arn:aws:iam::{self.account_id}:role/{role_name}",
                    actual_value=f"Service linked role {role_name} does not exist",
                    remediation=remediation
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=f"arn:aws:iam::{self.account_id}:role/{role_name}",
                    actual_value=response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for GetRole API access"
                )
        else:
            role_arn = response.get("Role", {}).get("Arn")
            yield self.passed(
                region=region,
                resource_id=role_arn,
                actual_value=f"Service linked role {role_name} exists"
            )
