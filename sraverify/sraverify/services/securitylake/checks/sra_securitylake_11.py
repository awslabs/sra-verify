"""Check if CloudTrail management logs are enabled for Security Lake."""

from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.logging import logger
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securitylake.base import SecurityLakeCheck


class SRA_SECURITYLAKE_11(SecurityLakeCheck):
    """Check if CloudTrail management logs are enabled for Security Lake."""

    meta = CheckMeta(
        check_id="SRA-SECURITYLAKE-11",
        title="Security Lake CloudTrail management logs enabled with version 2.0 for all organization accounts",
        description=(
            "This check verifies whether Amazon Security Lake is configured with "
            "CloudTrail management log and event source version 2.0 for all active accounts in the organization. "
            "CloudTrail management events, also known as control plane events, provide insight into management "
            "operations that are performed on CloudTrail in your AWS account. To "
            "collect CloudTrail management events in Security Lake, there must be at "
            "least one CloudTrail multi-Region organization trail that collects read "
            "and write CloudTrail management events. Logging must be enabled for the trail. "
            "This check runs from the delegated administrator account "
            "and validates configuration across all organization member accounts."
        ),
        check_logic=(
            "Checks if the CloudTrail management logs source version 2.0 is enabled in Security Lake "
            "for all active organization accounts. The check passes if the CLOUD_TRAIL_MGMT log source version 2.0 is enabled. "
            "The check fails if the CLOUD_TRAIL_MGMT log source is not enabled or configured with version 1.0."
        ),
        severity=Severity.HIGH,
        # Check all org accounts from delegated admin
        account_type=AccountType.LOG_ARCHIVE,
        service="SecurityLake",
        resource_type="AWS::SecurityLake::SecurityLake",
        remediation=Remediation(
            text=(
                "Enable the CLOUD_TRAIL_MGMT log source at version 2.0 in Security "
                "Lake, backed by a multi-Region organization trail that logs read "
                "and write management events."
            ),
            cli=(
                "aws securitylake create-aws-log-source --sources "
                "'[{\"regions\":[\"<region>\"],\"sourceName\":\"CLOUD_TRAIL_MGMT\","
                "\"sourceVersion\":\"2.0\"}]' --region <region>"
            ),
            console=(
                "Security Lake console, Settings, Log sources, enable CloudTrail "
                "management events at version 2.0."
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
            logger.debug(f"Checking if CloudTrail management logs are enabled in {region}")

            # Get all organization accounts
            accounts_response = self.get_organization_accounts(region)

            if "Error" in accounts_response:
                error = accounts_response['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"arn:aws:securitylake:{region}:{self.account_id}:datalake/default",
                        checked_value="Log source configured for every active account",
                        actual_value="No AWS Organization exists, so it has no accounts whose log sources could be configured",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"arn:aws:securitylake:{region}:{self.account_id}:datalake/default",
                        checked_value="Log source configured for every active account",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            org_accounts = accounts_response.get('Accounts', [])

            # check_log_source_configured() answers a bare bool and cannot report
            # a failure, so the log-source read is guarded here, once per Region,
            # before anything consults it. Without this a denied ListLogSources
            # read as "the source is not configured" -- 104 such FAIL rows in a
            # single-Region log-archive scan.
            log_sources_response = self.get_log_sources(region)
            if "Error" in log_sources_response:
                error = log_sources_response['Error']
                semantic = self.is_not_configured(error)
                active_ids = sorted(
                    a.get('Id') for a in org_accounts
                    if a.get('Status') == 'ACTIVE' and a.get('Id')
                )
                for account_id in active_ids:
                    resource_id = (
                        f"arn:aws:securitylake:{region}:{account_id}:"
                        f"log-source/CLOUD_TRAIL_MGMT"
                    )
                    if semantic:
                        yield self.failed(
                            region=region,
                            resource_id=resource_id,
                            checked_value="CLOUD_TRAIL_MGMT log source configured",
                            actual_value=(
                                f"No Security Lake data lake exists in {region}, "
                                f"so no log source is configured for account "
                                f"{account_id}"
                            ),
                        )
                    else:
                        yield self.error(
                            region=region,
                            resource_id=resource_id,
                            checked_value="CLOUD_TRAIL_MGMT log source configured",
                            actual_value=(
                                f"{error['Operation']} failed: {error['Code']}: "
                                f"{error['Message']}"
                            ),
                            remediation=self._remediation_for(error),
                        )
                continue
            if not org_accounts:
                logger.debug("No organization accounts found, checking current account only")
                org_accounts = [{'Id': self.account_id, 'Status': 'ACTIVE'}]

            # Create sets of active account IDs
            active_org_account_ids = set()
            for account in org_accounts:
                if account.get('Status') == 'ACTIVE':
                    active_org_account_ids.add(account.get('Id'))

            # Check each account in the organization
            for account_id in active_org_account_ids:
                resource_id = f"arn:aws:securitylake:{region}:{account_id}:log-source/CLOUD_TRAIL_MGMT"

                # Check CloudTrail management logs configuration
                cloudtrail_v2_enabled = self.check_log_source_configured(region, "CLOUD_TRAIL_MGMT", account_id, "2.0")

                if not cloudtrail_v2_enabled:
                    # Only check v1.0 if v2.0 is not enabled (uses cached data)
                    cloudtrail_v1_enabled = self.check_log_source_configured(region, "CLOUD_TRAIL_MGMT", account_id, "1.0")

                    if cloudtrail_v1_enabled:
                        actual_value = f"CloudTrail management logs are configured with version 1.0 instead of 2.0 for account {account_id}"
                        remediation = (
                            f"Update CloudTrail management logs to version 2.0 for account {account_id}. "
                            "In the Security Lake console, navigate to Sources and update the CloudTrail management logs source version. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake update-data-lake --sources '[{{\"regions\":[\"{region}\"],\"sourceName\":\"CLOUD_TRAIL_MGMT\",\"sourceVersion\":\"2.0\"}}]' --region {region}"
                        )
                    else:
                        actual_value = f"CloudTrail management logs are not configured for account {account_id}"
                        remediation = (
                            "Enable CloudTrail management logs in Security Lake. In the Security Lake console, "
                            "navigate to Settings > Log Sources and enable CloudTrail management logs. "
                            "Ensure you have at least one CloudTrail multi-Region organization trail that collects "
                            "read and write management events. Alternatively, use the AWS CLI command: "
                            f"aws securitylake create-aws-log-source --sources '[{{\"regions\":[\"{region}\"],\"sourceName\":\"CLOUD_TRAIL_MGMT\",\"sourceVersion\":\"2.0\"}}]' --region {region}"
                        )

                    yield self.failed(
                        region=region,
                        resource_id=resource_id,
                        checked_value="CloudTrail management logs enabled with version 2.0",
                        actual_value=actual_value,
                        remediation=remediation,
                    )
                else:
                    yield self.passed(
                        region=region,
                        resource_id=resource_id,
                        checked_value="CloudTrail management logs enabled with version 2.0",
                        actual_value=f"CloudTrail management logs are enabled with version 2.0 in {region} for account {account_id}",
                    )
