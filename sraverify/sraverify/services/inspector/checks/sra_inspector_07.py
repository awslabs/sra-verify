"""
SRA-INSPECTOR-07: All Active Member Accounts Have Inspector Enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.inspector.base import InspectorCheck


class SRA_INSPECTOR_07(InspectorCheck):
    """Check if all active member accounts have Inspector enabled."""

    meta = CheckMeta(
        check_id="SRA-INSPECTOR-07",
        title="All active member accounts have Inspector enabled",
        description=(
            "This check verifies whether all active members accounts of the AWS Organization have Inspector enabled. "
            "Inspector is an automated vulnerability management service that continually scans Amazon Elastic Compute Cloud (EC2), "
            "AWS Lambda functions, and container images in Amazon ECR."
        ),
        check_logic=(
            "Check runs aws organizations list-accounts AND aws inspector2 batch-get-account-status. "
            "PASS if all organization accounts (except audit) have Inspector enabled"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="Inspector",
        resource_type="AWS::Inspector::Assessment",
        remediation=Remediation(
            text=(
                "Enable Amazon Inspector for every active member account of the "
                "organization in each enabled Region."
            ),
            cli=(
                "aws inspector2 enable --account-ids <account-id> [<account-id> ...] "
                "--resource-types EC2 ECR LAMBDA LAMBDA_CODE --region <region>"
            ),
            console=(
                "Inspector console in the delegated administrator account, Settings, "
                "Account management, select the accounts, Activate."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check using BatchGetAccountStatus.

        Yields:
            One Finding per Region.
        """

        # Check each region separately
        for region in self.regions:
            # Get organization members
            org_accounts = self.get_organization_members(region)

            # Create a set of all active organization account IDs
            org_account_ids = set()
            for account in org_accounts:
                if account.get('Status') == 'ACTIVE':
                    org_account_ids.add(account.get('Id'))

            # Get delegated admin account
            delegated_admin_response = self.get_delegated_admin(region)
            delegated_admin = delegated_admin_response.get('delegatedAdmin', {})
            delegated_admin_id = delegated_admin.get('accountId')

            # Exclude the supplied audit account(s) and the Inspector delegated
            # admin. The delegated admin is always excluded when it is known;
            # when neither an audit account nor a delegated admin is known, fall
            # back to the account running the scan.
            excluded_accounts = set(self.audit_accounts)
            if delegated_admin_id:
                excluded_accounts.add(delegated_admin_id)
            if not excluded_accounts:
                excluded_accounts = {self.account_id}

            # Remove the excluded accounts from the list of accounts to check
            accounts_to_check = org_account_ids - excluded_accounts

            # Convert to list for the API call
            accounts_list = list(accounts_to_check)

            # Use BatchGetAccountStatus to check which accounts have Inspector enabled
            account_statuses = self.batch_get_account_status(region, accounts_list)

            # Find accounts that should have Inspector enabled but don't
            missing_accounts = set()
            for acc_id in accounts_to_check:
                # Check if the account is in the results
                if acc_id not in account_statuses:
                    missing_accounts.add(acc_id)
                    continue

                # Check if Inspector is enabled for this account
                status = account_statuses[acc_id].get('state', {}).get('status')
                if status != 'ENABLED':
                    missing_accounts.add(acc_id)

            if missing_accounts:
                yield self.failed(
                    region=region,
                    resource_id=f"inspector2/{region}/organization/members",
                    checked_value="All active organization accounts (except audit) have Inspector enabled",
                    actual_value=f"The following accounts do not have Inspector enabled in {region}: {', '.join(missing_accounts)}",
                    remediation=(
                        "Enable Inspector for all member accounts using the AWS Console or CLI command: "
                        f"aws inspector2 enable --account-ids {' '.join(missing_accounts)} --resource-types EC2 ECR LAMBDA LAMBDA_CODE --region {region}"
                    ),
                )
            else:
                yield self.passed(
                    region=region,
                    resource_id=f"inspector2/{region}/organization/members",
                    checked_value="All active organization accounts (except audit) have Inspector enabled",
                    actual_value=f"All {len(accounts_to_check)} active organization accounts (except audit) have Inspector enabled in {region}",
                )
