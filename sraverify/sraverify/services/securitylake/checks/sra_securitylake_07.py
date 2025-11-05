"""Check if CloudTrail S3 data events are enabled for Security Lake."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_07(SecurityLakeCheck):
    """Check if CloudTrail S3 data events are enabled for Security Lake."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.account_type = "log-archive"  # Check all org accounts from delegated admin
        self.check_id = "SRA-SECURITYLAKE-07"
        self.check_name = "Security Lake CloudTrail S3 data events enabled with version 2.0 for all organization accounts"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Amazon Security Lake is configured with "
            "CloudTrail data event for S3 log and event source version 2.0 for all active accounts in the organization. "
            "CloudTrail data events, also known as data plane operations, show "
            "the resource operations performed on or within resources in your AWS "
            "account. These operations are often high-volume activities and should "
            "be enabled as per your requirement. Security Lake pulls data directly "
            "from S3 through an independent and duplicated stream of events. "
            "This check runs from the delegated administrator account "
            "and validates configuration across all organization member accounts."
        )
        self.check_logic = (
            "Checks if the CloudTrail S3 data events log source version 2.0 is enabled in Security Lake "
            "for all active organization accounts. The check passes if the S3_DATA log source version 2.0 is enabled. "
            "The check fails if the S3_DATA log source is not enabled or configured with version 1.0."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking if CloudTrail S3 data events are enabled in {region}")

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

            # Check each account in the organization
            for account_id in active_org_account_ids:
                resource_id = f"arn:aws:securitylake:{region}:{account_id}:log-source/S3_DATA"

                # Check CloudTrail S3 data events configuration
                s3_data_v2_enabled = self.check_log_source_configured(region, "S3_DATA", account_id, "2.0")
                
                if not s3_data_v2_enabled:
                    # Only check v1.0 if v2.0 is not enabled (uses cached data)
                    s3_data_v1_enabled = self.check_log_source_configured(region, "S3_DATA", account_id, "1.0")
                    
                    if s3_data_v1_enabled:
                        actual_value = f"CloudTrail S3 data events are configured with version 1.0 instead of 2.0 for account {account_id}"
                        remediation = (
                            f"Update CloudTrail S3 data events to version 2.0 for account {account_id}. "
                            "In the Security Lake console, navigate to Sources and update the S3 data events source version. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake update-data-lake --sources '[{{\"regions\":[\"{region}\"],\"sourceName\":\"S3_DATA\",\"sourceVersion\":\"2.0\"}}]' --region {region}"
                        )
                    else:
                        actual_value = f"CloudTrail S3 data events are not configured for account {account_id}"
                        remediation = (
                            "Enable CloudTrail S3 data events in Security Lake. In the Security Lake console, "
                            "navigate to Settings > Log Sources and enable CloudTrail S3 data events. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake create-aws-log-source --sources '[{{\"regions\":[\"{region}\"],\"sourceName\":\"S3_DATA\",\"sourceVersion\":\"2.0\"}}]' --region {region}"
                        )
                    
                    self.findings.append(
                        self.create_finding(
                            status="FAIL",
                            region=region,
                            resource_id=resource_id,
                            checked_value="CloudTrail S3 data events enabled with version 2.0",
                            actual_value=actual_value,
                            remediation=remediation
                        )
                    )
                else:
                    self.findings.append(
                        self.create_finding(
                            status="PASS",
                            region=region,
                            resource_id=resource_id,
                            checked_value="CloudTrail S3 data events enabled with version 2.0",
                            actual_value=f"CloudTrail S3 data events are enabled with version 2.0 in {region} for account {account_id}",
                            remediation="No remediation needed"
                        )
                    )

        return self.findings
