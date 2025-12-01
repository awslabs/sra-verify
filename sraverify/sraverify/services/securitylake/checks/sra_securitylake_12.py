"""Check if WAF logs are enabled for Security Lake."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_12(SecurityLakeCheck):
    """Check if WAF logs are enabled for Security Lake."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.account_type = "log-archive"  # Check all org accounts from delegated admin
        self.check_id = "SRA-SECURITYLAKE-12"
        self.check_name = "Security Lake WAF logs enabled with version 2.0 for all organization accounts"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Amazon Security Lake is configured with "
            "WAF log and event source version 2.0 for all active accounts in the organization. "
            "AWS WAF is a web application firewall that "
            "helps protect your web applications or APIs against common web exploits "
            "and bots that may affect availability, compromise security, or consume "
            "excessive resources. Security Lake collects WAF logs directly from "
            "AWS WAF through an independent and duplicated stream of events. "
            "This check runs from the delegated administrator account "
            "and validates configuration across all organization member accounts."
        )
        self.check_logic = (
            "Checks if the WAF logs source version 2.0 is enabled in Security Lake "
            "for all active organization accounts. The check passes if the WAF log source version 2.0 is enabled. "
            "The check fails if the WAF log source is not enabled or configured with version 1.0."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking if WAF logs are enabled in {region}")

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
                resource_id = f"arn:aws:securitylake:{region}:{account_id}:log-source/WAF"

                # Check WAF logs configuration
                waf_v2_enabled = self.check_log_source_configured(region, "WAF", account_id, "2.0")
                
                if not waf_v2_enabled:
                    # Only check v1.0 if v2.0 is not enabled (uses cached data)
                    waf_v1_enabled = self.check_log_source_configured(region, "WAF", account_id, "1.0")
                    
                    if waf_v1_enabled:
                        actual_value = f"WAF logs are configured with version 1.0 instead of 2.0 for account {account_id}"
                        remediation = (
                            f"Update WAF logs to version 2.0 for account {account_id}. "
                            "In the Security Lake console, navigate to Sources and update the WAF logs source version. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake update-data-lake --sources '[{{\"regions\":[\"{region}\"],\"sourceName\":\"WAF\",\"sourceVersion\":\"2.0\"}}]' --region {region}"
                        )
                    else:
                        actual_value = f"WAF logs are not configured for account {account_id}"
                        remediation = (
                            "Enable WAF logs in Security Lake. In the Security Lake console, "
                            "navigate to Settings > Log Sources and enable WAF logs. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake create-aws-log-source --sources '[{{\"regions\":[\"{region}\"],\"sourceName\":\"WAF\",\"sourceVersion\":\"2.0\"}}]' --region {region}"
                        )
                    
                    self.findings.append(
                        self.create_finding(
                            status="FAIL",
                            region=region,
                            resource_id=resource_id,
                            checked_value="WAF logs enabled with version 2.0",
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
                            checked_value="WAF logs enabled with version 2.0",
                            actual_value=f"WAF logs are enabled with version 2.0 in {region} for account {account_id}",
                            remediation="No remediation needed"
                        )
                    )

        return self.findings
