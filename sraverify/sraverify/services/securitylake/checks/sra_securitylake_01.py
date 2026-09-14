"""Check if Amazon Security Lake is enabled."""

from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.logging import logger
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securitylake.base import SecurityLakeCheck


class SRA_SECURITYLAKE_01(SecurityLakeCheck):
    """Check if Amazon Security Lake is enabled."""

    meta = CheckMeta(
        check_id="SRA-SECURITYLAKE-01",
        title="Security Lake is enabled for all organization accounts",
        description=(
            "This check verifies whether Amazon Security Lake is enabled for all active accounts in the organization. "
            "Amazon Security Lake is a fully managed security data lake service that you "
            "can use to automatically centralize security data from AWS environments, "
            "SaaS providers, on premises, cloud sources, and third-party sources into a "
            "purpose-built data lake that's stored in your AWS account. The data lake is "
            "backed by Amazon S3 buckets, and you retain ownership over your data. You "
            "must enable security lake in every AWS account and AWS region to collect "
            "security logs and event from your entire AWS environment. "
            "This check runs from the delegated administrator account "
            "and validates configuration across all organization member accounts."
        ),
        check_logic=(
            "Checks if Security Lake is enabled for all active organization accounts by calling get_data_lake_sources API. "
            "The check passes if Security Lake is enabled for all active accounts in the organization. "
            "The check fails if any active account does not have Security Lake enabled."
        ),
        severity=Severity.HIGH,
        # Check all org accounts from delegated admin
        account_type=AccountType.LOG_ARCHIVE,
        service="SecurityLake",
        resource_type="AWS::SecurityLake::SecurityLake",
        remediation=Remediation(
            text=(
                "Enable Security Lake for every active organization account in every "
                "enabled Region."
            ),
            cli="aws securitylake create-data-lake --region <region>",
            console=(
                "Security Lake console in the delegated administrator account, "
                "Settings, enable Security Lake for the account and Region."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per organization account per Region.
        """

        for region in self.regions:
            logger.debug(f"Checking if Security Lake is enabled for all organization accounts in {region}")

            # Get all organization accounts
            org_accounts = self.get_organization_accounts(region)
            if not org_accounts:
                logger.debug("No organization accounts found, checking current account only")
                org_accounts = [{'Id': self.account_id, 'Status': 'ACTIVE'}]

            # Create sets of active account IDs
            active_org_account_ids = set()
            for account in org_accounts:
                if account.get('Status') == 'ACTIVE':
                    active_org_account_ids.add(account.get('Id'))

            # Get accounts with Security Lake enabled
            enabled_accounts = set()
            sources_data = self.get_data_lake_sources(region)  # No account_id = get all accounts
            for source in sources_data:
                account_id = source.get('account')
                if account_id:
                    enabled_accounts.add(account_id)

            # Check each account in the organization
            for account_id in active_org_account_ids:
                resource_id = f"arn:aws:securitylake:{region}:{account_id}:datalake/default"

                if account_id not in enabled_accounts:
                    yield self.failed(
                        region=region,
                        resource_id=resource_id,
                        checked_value="Security Lake enabled",
                        actual_value=f"Security Lake is not enabled for account {account_id}",
                        remediation=(
                            f"Enable Security Lake for account {account_id}. In the Security Lake console, "
                            "navigate to Settings and enable Security Lake. Alternatively, use the AWS CLI command: "
                            f"aws securitylake create-data-lake --region {region}"
                        ),
                    )
                else:
                    yield self.passed(
                        region=region,
                        resource_id=resource_id,
                        checked_value="Security Lake enabled",
                        actual_value=f"Security Lake is enabled for account {account_id}",
                    )
