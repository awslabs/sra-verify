"""Check if EKS Audit logs are enabled for Security Lake."""

from typing import List, Dict, Any
from sraverify.services.securitylake.base import SecurityLakeCheck
from sraverify.core.logging import logger


class SRA_SECURITYLAKE_09(SecurityLakeCheck):
    """Check if EKS Audit logs are enabled for Security Lake."""

    def __init__(self):
        """Initialize check."""
        super().__init__()
        self.account_type = "log-archive"  # Check all org accounts from delegated admin
        self.check_id = "SRA-SECURITYLAKE-09"
        self.check_name = "Security Lake EKS audit logs enabled with version 2.0 for all organization accounts"
        self.severity = "HIGH"
        self.description = (
            "This check verifies whether Amazon Security Lake is configured with "
            "EKS Audit log and event source version 2.0 for all active accounts in the organization. "
            "EKS Audit Logs help you detect potentially suspicious activities in your EKS clusters within the "
            "Amazon Elastic Kubernetes Service. Security Lake consumes EKS Audit "
            "Log events directly from the Amazon EKS control plane logging feature "
            "through an independent and duplicative stream of audit logs. "
            "This check runs from the delegated administrator account "
            "and validates configuration across all organization member accounts."
        )
        self.check_logic = (
            "Checks if the EKS Audit logs source version 2.0 is enabled in Security Lake "
            "for all active organization accounts. The check passes if the EKS_AUDIT log source version 2.0 is enabled. "
            "The check fails if the EKS_AUDIT log source is not enabled or configured with version 1.0."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings
        """

        for region in self.regions:
            logger.debug(f"Checking if EKS Audit logs are enabled in {region}")

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
                resource_id = f"arn:aws:securitylake:{region}:{account_id}:log-source/EKS_AUDIT"

                # Check EKS Audit logs configuration
                eks_audit_v2_enabled = self.check_log_source_configured(region, "EKS_AUDIT", account_id, "2.0")
                
                if not eks_audit_v2_enabled:
                    # Only check v1.0 if v2.0 is not enabled (uses cached data)
                    eks_audit_v1_enabled = self.check_log_source_configured(region, "EKS_AUDIT", account_id, "1.0")
                    
                    if eks_audit_v1_enabled:
                        actual_value = f"EKS Audit logs are configured with version 1.0 instead of 2.0 for account {account_id}"
                        remediation = (
                            f"Update EKS Audit logs to version 2.0 for account {account_id}. "
                            "In the Security Lake console, navigate to Sources and update the EKS Audit logs source version. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake update-data-lake --sources '[{{\"regions\":[\"{region}\"],\"sourceName\":\"EKS_AUDIT\",\"sourceVersion\":\"2.0\"}}]' --region {region}"
                        )
                    else:
                        actual_value = f"EKS Audit logs are not configured for account {account_id}"
                        remediation = (
                            "Enable EKS Audit logs in Security Lake. In the Security Lake console, "
                            "navigate to Settings > Log Sources and enable EKS Audit logs. "
                            "Alternatively, use the AWS CLI command: "
                            f"aws securitylake create-aws-log-source --sources '[{{\"regions\":[\"{region}\"],\"sourceName\":\"EKS_AUDIT\",\"sourceVersion\":\"2.0\"}}]' --region {region}"
                        )
                    
                    self.findings.append(
                        self.create_finding(
                            status="FAIL",
                            region=region,
                            resource_id=resource_id,
                            checked_value="EKS Audit logs enabled with version 2.0",
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
                            checked_value="EKS Audit logs enabled with version 2.0",
                            actual_value=f"EKS Audit logs are enabled with version 2.0 in {region} for account {account_id}",
                            remediation="No remediation needed"
                        )
                    )

        return self.findings
