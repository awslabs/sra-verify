"""
SRA-ACCOUNT-01: Verify security alternate contact is configured
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.account.base import AccountCheck


class SRA_ACCOUNT_01(AccountCheck):
    """Check if security alternate contact is configured for the AWS account."""

    meta = CheckMeta(
        check_id="SRA-ACCOUNT-01",
        title="Security alternate contact configured",
        description=(
            "Verifies that a security alternate contact is configured for the AWS account"
        ),
        check_logic=(
            "Uses GetAlternateContact API to verify security contact exists and has "
            "required fields"
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="Account",
        resource_type="AWS::Account::AlternateContact",
        remediation=Remediation(
            text=(
                "Configure a security alternate contact for the account, supplying both "
                "a name and an email address, so AWS can reach the security team about "
                "account security matters."
            ),
            cli=(
                "aws account put-alternate-contact "
                "--alternate-contact-type SECURITY --email-address <email> "
                "--name <name> --phone-number <phone> --title <title>"
            ),
            console=(
                "AWS Console, Account Settings, Alternate contacts, Security, Edit."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """Execute the security alternate contact check.

        Yields:
            One Finding for the account.
        """
        account_id = self.account_id

        # Account-level check only needs to run once, use first region
        region = self.regions[0] if self.regions else "us-east-1"

        contact_info = self.get_alternate_contact(region, "SECURITY")

        if "Error" in contact_info:
            error_code = contact_info["Error"].get("Code", "")
            if error_code == "ResourceNotFoundException":
                yield self.failed(
                    region=region,
                    resource_id=f"account-{account_id}",
                    actual_value="No security alternate contact configured",
                    remediation="Configure a security alternate contact using AWS Console > Account Settings > Alternate contacts or AWS CLI: aws account put-alternate-contact --alternate-contact-type SECURITY --email-address <email> --name <name> --phone-number <phone> --title <title>",
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=f"account-{account_id}",
                    actual_value=contact_info["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Account Management API access",
                )
        else:
            contact = contact_info.get("AlternateContact", {})
            if contact and contact.get("EmailAddress") and contact.get("Name"):
                yield self.passed(
                    region=region,
                    resource_id=f"account-{account_id}",
                    actual_value=f"Security contact configured: {contact.get('Name')} ({contact.get('EmailAddress')})",
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"account-{account_id}",
                    actual_value="Security alternate contact exists but missing required fields",
                    remediation="Update security alternate contact to include name and email address using AWS Console > Account Settings > Alternate contacts",
                )
