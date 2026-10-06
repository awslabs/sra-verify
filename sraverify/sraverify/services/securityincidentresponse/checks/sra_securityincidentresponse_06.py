"""
SRA-SECURITYINCIDENTRESPONSE-06: Security Incident Response service linked role exists.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityincidentresponse.base import SecurityIncidentResponseCheck

ROLE_NAME = "AWSServiceRoleForSecurityIncidentResponse"
ROLE_PATH = "/aws-service-role/security-ir.amazonaws.com/"


class SRA_SECURITYINCIDENTRESPONSE_06(SecurityIncidentResponseCheck):
    """Check if the Security Incident Response service linked role exists."""

    meta = CheckMeta(
        check_id="SRA-SECURITYINCIDENTRESPONSE-06",
        title="Security Incident Response service linked role exists",
        description=(
            "This check verifies that the AWSServiceRoleForSecurityIncidentResponse "
            "service linked role exists in the Security Incident Response delegated "
            "administrator account. The service uses this role to act on the "
            "organization's behalf, so it has to be in place before an incident rather "
            "than discovered missing during one. This is a step of the Security Incident "
            "Response configuration validation procedure."
        ),
        check_logic=(
            "Call iam:GetRole for AWSServiceRoleForSecurityIncidentResponse. Passes if "
            "the role exists. Fails if IAM answers NoSuchEntity."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="SecurityIncidentResponse",
        resource_type="AWS::IAM::Role",
        remediation=Remediation(
            text=(
                "Create the AWSServiceRoleForSecurityIncidentResponse service linked role "
                "in the Security Incident Response delegated administrator account."
            ),
            cli="aws iam create-service-linked-role --aws-service-name security-ir.amazonaws.com",
            console="IAM console, Roles, Create role, AWS service, Security Incident Response.",
        ),
        sra_sections=("Security Tooling account", "AWS Security Incident Response"),
        additional_urls=(
            "https://docs.aws.amazon.com/security-ir/latest/userguide/config-validation.md",
            "https://docs.aws.amazon.com/security-ir/latest/userguide/using-service-linked-roles.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            Exactly one Finding, with ``region="global"``: IAM is global and the
            role is an account-wide fact.
        """
        response = self.get_role(ROLE_NAME)
        # The literal ``aws`` partition matches SRA-SECURITYINCIDENTRESPONSE-05;
        # the scanner has no ARN partition helper today.
        expected_arn = f"arn:aws:iam::{self.account_id}:role{ROLE_PATH}{ROLE_NAME}"

        if "Error" in response:
            error = response["Error"]
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=expected_arn,
                    actual_value=f"Service linked role {ROLE_NAME} does not exist in this account",
                    # The row carries the command itself: Remediation.cli does
                    # not reach the CSV.
                    remediation=(
                        f"{self.meta.remediation.text} Run: {self.meta.remediation.cli}"
                    ),
                )
            else:
                yield self.error(
                    region="global",
                    resource_id=expected_arn,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                )
            return

        role = response.get("Role")
        role_arn = role.get("Arn") if isinstance(role, dict) else None
        yield self.passed(
            region="global",
            resource_id=role_arn if isinstance(role_arn, str) and role_arn else expected_arn,
            actual_value=f"Service linked role {ROLE_NAME} exists",
        )
