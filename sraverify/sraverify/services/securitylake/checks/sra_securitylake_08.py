"""Check if Security Hub findings are enabled for Security Lake."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_08(SecurityLakeCheck):
    """Check if Security Hub findings are enabled for Security Lake."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.account_type = "log-archive"  # Check all org accounts from delegated admin
        self.check_id = "SRA-SECURITYLAKE-08"
        self.check_name = "Security Lake Security Hub findings enabled with version 2.0 for all organization accounts"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Amazon Security Lake is configured with "
            "SecurityHub findings log and event source version 2.0 for all active accounts in the organization. "
            "Security Hub findings help you understand your security posture in AWS and let you check your "
            "environment against security industry standards and best practices. "
            "Security Lake collects findings directly from Security Hub through "
            "an independent and duplicated stream of events. "
            "This check runs from the delegated administrator account "
            "and validates configuration across all organization member accounts."
        )
        self.check_logic = (
            "Checks if the Security Hub findings log source version 2.0 is enabled in Security Lake "
            "for all active organization accounts. The check passes if the SH_FINDINGS log source version 2.0 is enabled. "
            "The check fails if the SH_FINDINGS log source is not enabled or configured with version 1.0."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking if Security Hub findings are enabled in {region}")

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
                resource_id = f"arn:aws:securitylake:{region}:{account_id}:log-source/SH_FINDINGS"

                # Check Security Hub findings configuration
                sh_findings_v2_enabled = self.check_log_source_configured(region, "SH_FINDINGS", account_id, "2.0")
                
                if not sh_findings_v2_enabled:
                    # Only check v1.0 if v2.0 is not enabled (uses cached data)
                    sh_findings_v1_enabled = self.check_log_source_configured(region, "SH_FINDINGS", account_id, "1.0")
                    
                    if sh_findings_v1_enabled:
                        actual_value = f"Security Hub findings are configured with version 1.0 instead of 2.0 for account {account_id}"
                        remediation = (
                            f"Update Security Hub findings to version 2.0 for account {account_id}. "
                            "In the Security Lake console, navigate to Sources and update the Security Hub findings source version. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake update-data-lake --sources '[{{\"regions\":[\"{region}\"],\"sourceName\":\"SH_FINDINGS\",\"sourceVersion\":\"2.0\"}}]' --region {region}"
                        )
                    else:
                        actual_value = f"Security Hub findings are not configured for account {account_id}"
                        remediation = (
                            "Enable Security Hub findings in Security Lake. In the Security Lake console, "
                            "navigate to Settings > Log Sources and enable Security Hub findings. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake create-aws-log-source --sources '[{{\"regions\":[\"{region}\"],\"sourceName\":\"SH_FINDINGS\",\"sourceVersion\":\"2.0\"}}]' --region {region}"
                        )
                    
                    self.findings.append(
                        self.create_finding(
                            status="FAIL",
                            region=region,
                            resource_id=resource_id,
                            checked_value="Security Hub findings enabled with version 2.0",
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
                            checked_value="Security Hub findings enabled with version 2.0",
                            actual_value=f"Security Hub findings are enabled with version 2.0 in {region} for account {account_id}",
                            remediation="No remediation needed"
                        )
                    )

        return self.findings
