"""Check if Route 53 log source is enabled for Security Lake."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_06(SecurityLakeCheck):
    """Check if Route 53 log source is enabled for Security Lake."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.account_type = "log-archive"  # Check from log archive account
        self.check_id = "SRA-SECURITYLAKE-06"
        self.check_name = "Security Lake Route 53 log source enabled with version 2.0 for all organization accounts"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Amazon Security Lake is configured with "
            "Route 53 log and event source version 2.0 for all active accounts in the organization. "
            "Route 53 resolver query logs track DNS queries made by resources within Amazon VPC. "
            "Security Lake collects resolver query logs directly from Route 53 through an independent "
            "and duplicated stream of events. This check runs from the delegated administrator account "
            "and validates configuration across all organization member accounts."
        )
        self.check_logic = (
            "Checks if the Route 53 log source is enabled in Security Lake with version 2.0. "
            "The check passes if the ROUTE53 log source is configured. "
            "The check fails if the ROUTE53 log source is not configured."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """
        for region in self.regions:
            logger.debug(f"Checking if Route 53 log source is enabled in {region}")

            # Get all organization accounts to check
            org_accounts = self.get_organization_accounts(region)
            if not org_accounts:
                logger.warning("No organization accounts found")
                org_accounts = [self.account_id]  # Fall back to current account

            # Create sets of active account IDs
            active_org_account_ids = set()
            for account in org_accounts:
                if account.get('Status') == 'ACTIVE':
                    active_org_account_ids.add(account.get('Id'))

            # Check each account in the organization
            for account_id in active_org_account_ids:
                resource_id = f"arn:aws:securitylake:{region}:{account_id}:log-source/ROUTE53"

                # Check Route 53 log source configuration (call API once, check both versions)
                route53_v2_enabled = self.check_log_source_configured(region, "ROUTE53", account_id, "2.0")

                if not route53_v2_enabled:
                    # Only check v1.0 if v2.0 is not enabled (uses cached data)
                    route53_v1_enabled = self.check_log_source_configured(region, "ROUTE53", account_id, "1.0")

                    if route53_v1_enabled:
                        actual_value = f"Route 53 log source is configured with version 1.0 instead of 2.0 for account {account_id}"
                        remediation = (
                            f"Update Route 53 log source to version 2.0 for account {account_id}. "
                            "In the Security Lake console, navigate to Sources and update the Route 53 source version. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake update-data-lake --sources '[{{\"regions\":[\"{region}\"],\"sourceName\":\"ROUTE53\",\"sourceVersion\":\"2.0\"}}]' --region {region}"
                        )
                    else:
                        actual_value = f"Route 53 log source is not configured for account {account_id}"
                        remediation = (
                            "Enable Route 53 log source in Security Lake. In the Security Lake console, "
                            "navigate to Settings > Log Sources and enable Route 53 logs. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake create-aws-log-source --sources '[{{\"regions\":[\"{region}\"],\"sourceName\":\"ROUTE53\",\"sourceVersion\":\"2.0\"}}]' --region {region}"
                        )

                    self.findings.append(
                        self.create_finding(
                            status="FAIL",
                            region=region,
                            resource_id=resource_id,
                            checked_value="Route 53 log source enabled with version 2.0",
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
                            checked_value="Route 53 log source enabled with version 2.0",
                            actual_value=f"Route 53 log source is configured in {region} for account {account_id}",
                            remediation="No remediation needed"
                        )
                    )

        return self.findings
