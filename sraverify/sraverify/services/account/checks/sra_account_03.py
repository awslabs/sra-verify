"""
SRA-ACCOUNT-03: Verify operations alternate contact is configured
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.account.base import AccountCheck


class SRA_ACCOUNT_03(AccountCheck):
    """Check if operations alternate contact is configured for the AWS account."""

    meta = CheckMeta(
        check_id="SRA-ACCOUNT-03",
        title="Operations alternate contact configured",
        description=(
            "Verifies that an operations alternate contact is configured for the AWS "
            "account"
        ),
        check_logic=(
            "Uses GetAlternateContact API to verify operations contact exists and has "
            "required fields"
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="Account",
        resource_type="AWS::Account::AlternateContact",
        remediation=Remediation(
            text=(
                "Configure an operations alternate contact for the account, supplying "
                "both a name and an email address, so AWS can reach the operations team "
                "about operational issues affecting the account."
            ),
            cli=(
                "aws account put-alternate-contact "
                "--alternate-contact-type OPERATIONS --email-address <email> "
                "--name <name> --phone-number <phone> --title <title>"
            ),
            console=(
                "AWS Console, Account Settings, Alternate contacts, Operations, Edit."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """Execute the operations alternate contact check.

        Yields:
            One Finding for the account.
        """
        account_id = self.account_id
        region = self.regions[0] if self.regions else "us-east-1"

        contact_info = self.get_alternate_contact(region, "OPERATIONS")

        if "Error" in contact_info:
            error = contact_info["Error"]
            error_code = contact_info["Error"].get("Code", "")
            if self.is_not_configured(error):
                yield self.failed(
                    region=region,
                    resource_id=f"account-{account_id}",
                    actual_value="No operations alternate contact configured",
                    remediation="Configure an operations alternate contact using AWS Console > Account Settings > Alternate contacts or AWS CLI: aws account put-alternate-contact --alternate-contact-type OPERATIONS --email-address <email> --name <name> --phone-number <phone> --title <title>",
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=f"account-{account_id}",
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation="Check IAM permissions for Account Management API access",
                )
        else:
            contact = contact_info.get("AlternateContact", {})
            if contact and contact.get("EmailAddress") and contact.get("Name"):
                yield self.passed(
                    region=region,
                    resource_id=f"account-{account_id}",
                    actual_value=f"Operations contact configured: {contact.get('Name')} ({contact.get('EmailAddress')})",
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"account-{account_id}",
                    actual_value="Operations alternate contact exists but missing required fields",
                    remediation="Update operations alternate contact to include name and email address using AWS Console > Account Settings > Alternate contacts",
                )
