"""
SRA-CLOUDTRAIL-13: CloudTrail Delegated Administrator is the Audit Account.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.cloudtrail.base import CloudTrailCheck


class SRA_CLOUDTRAIL_13(CloudTrailCheck):
    """Check if CloudTrail delegated administrator is the Audit account."""

    meta = CheckMeta(
        check_id="SRA-CLOUDTRAIL-13",
        title="The audit account is the Delegated Administrator set for CloudTrail",
        description=(
            "This check verifies whether CloudTrail delegated admin account is the audit account of your AWS organization. "
            "Audit account is dedicated to operating security services, monitoring AWS accounts, and "
            "automating security alerting and response. CloudTrail helps monitor API activities across "
            "all your AWS accounts and regions."
        ),
        check_logic=(
            "Check if the delegated administrator account matches any of the specified Audit account IDs."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="CloudTrail",
        resource_type="AWS::CloudTrail::Trail",
        remediation=Remediation(
            text=(
                "Register the audit account as the delegated administrator for the "
                "cloudtrail.amazonaws.com service principal, deregistering any other "
                "account first."
            ),
            cli=(
                "aws organizations deregister-delegated-administrator "
                "--account-id <current-admin-account-id> "
                "--service-principal cloudtrail.amazonaws.com\n"
                "aws organizations register-delegated-administrator "
                "--account-id <audit-account-id> "
                "--service-principal cloudtrail.amazonaws.com"
            ),
            console=(
                "CloudTrail console in the management account, Settings, and set the "
                "delegated administrator to the audit account."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per delegated administrator, or one Finding when the
            check cannot be completed.
        """
        # Get delegated administrators for CloudTrail
        # This will use the cache if available or make API calls if needed
        delegated_admins = self.get_delegated_administrators()

        if not delegated_admins:
            yield self.failed(
                region="global",
                resource_id=f"organization/{self.account_id}",
                checked_value="CloudTrail delegated administrator is an Audit account",
                actual_value="No delegated administrator configured for CloudTrail",
                remediation=(
                    "Register an Audit account as delegated administrator for CloudTrail using the AWS CLI command: "
                    "aws organizations register-delegated-administrator "
                    "--account-id AUDIT_ACCOUNT_ID --service-principal cloudtrail.amazonaws.com"
                ),
            )
            return

        audit_accounts = self.audit_accounts

        if not audit_accounts:
            yield self.error(
                region="global",
                resource_id=f"organization/{self.account_id}",
                checked_value="CloudTrail delegated administrator is an Audit account",
                actual_value="Audit Account ID not provided",
                remediation="Provide the Audit account IDs using --audit-account flag",
            )
            return

        # Check if any of the delegated administrators is an Audit account
        for admin in delegated_admins:
            admin_id = admin.get('Id', 'Unknown')
            admin_name = admin.get('Name', 'Unknown')

            # Create a resource ID that includes the delegated admin and audit account info
            resource_id = f"cloudtrail arn has delegated administrator set to {admin_id}, audit account is {audit_accounts[0]}, {admin_id in audit_accounts}"

            if admin_id in audit_accounts:
                # This delegated admin is in the audit accounts list
                yield self.passed(
                    region="global",
                    resource_id=resource_id,
                    checked_value=f"CloudTrail delegated administrator is an Audit account ({', '.join(audit_accounts)})",
                    actual_value=f"CloudTrail delegated administrator {admin_id} ({admin_name}) is an Audit account",
                )
            else:
                # This delegated admin is not in the audit accounts list
                yield self.failed(
                    region="global",
                    resource_id=resource_id,
                    checked_value=f"CloudTrail delegated administrator is an Audit account ({', '.join(audit_accounts)})",
                    actual_value=(
                        f"CloudTrail delegated administrator {admin_id} ({admin_name}) "
                        f"is not in the specified Audit accounts ({', '.join(audit_accounts)})"
                    ),
                    remediation=(
                        "Deregister the current delegated administrator and register an Audit account "
                        "as delegated administrator for CloudTrail using the AWS CLI commands: "
                        f"aws organizations deregister-delegated-administrator "
                        f"--account-id {admin_id} --service-principal cloudtrail.amazonaws.com && "
                        "aws organizations register-delegated-administrator "
                        f"--account-id {audit_accounts[0]} --service-principal cloudtrail.amazonaws.com"
                    ),
                )
