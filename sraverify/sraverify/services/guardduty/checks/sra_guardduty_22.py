"""
Check if GuardDuty EKS Audit Logs are configured for auto-enablement.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_22(GuardDutyCheck):
    """Check if GuardDuty EKS Audit Logs are configured for auto-enablement."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-22",
        title="GuardDuty EKS Audit Logs auto-enablement configured",
        description=(
            "This check verifies whether EKS Audit Logs are configured for auto-enablement "
            "in GuardDuty for all member accounts. EKS Audit Logs monitoring analyzes Kubernetes "
            "audit logs to detect potentially suspicious activities in Amazon EKS clusters."
        ),
        check_logic=(
            "Check if EKS_AUDIT_LOGS feature is configured with AutoEnable set to ALL."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text=(
                "Set AutoEnable to ALL for the GuardDuty EKS_AUDIT_LOGS feature in every "
                "enabled Region."
            ),
            cli=(
                "aws guardduty update-organization-configuration "
                "--detector-id <detector-id> "
                "--features Name=EKS_AUDIT_LOGS,AutoEnable=ALL --region <region>"
            ),
            console=(
                "GuardDuty console in the delegated administrator account, Settings, "
                "Accounts, EKS Protection, Enable for all accounts."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        # Check all regions
        for region in self.regions:
            detector_id = self.get_detector_id(region)

            # Handle regions where we can't access GuardDuty
            if not detector_id:
                yield self.error(
                    region=region,
                    resource_id=f"guardduty:{region}",
                    actual_value="Unable to access GuardDuty in this region",
                    remediation="Check permissions or if GuardDuty is supported in this region",
                )
                continue

            # Get organization configuration for GuardDuty
            org_config = self.get_organization_configuration(region)

            # Check if there was an error in the response
            if "Error" in org_config:
                error_code = org_config["Error"].get("Code", "Unknown")
                error_message = org_config["Error"].get("Message", "Unknown error")

                # Handle BadRequestException specifically for non-management accounts
                if error_code == "BadRequestException":
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"{error_code} {error_message}",
                        remediation="Verify that GuardDuty is the delegated admin in this Region and run the check again.",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"Error accessing GuardDuty organization configuration: {error_code}",
                        remediation="Check permissions and AWS Organizations configuration",
                    )
                continue

            # Check if EKS Audit Logs are configured for auto-enablement
            # Look for EKS_AUDIT_LOGS in Features
            eks_audit_logs_found = False
            eks_audit_logs_auto_enable = "NOT_CONFIGURED"
            features = org_config.get('Features', [])

            for feature in features:
                if feature.get('Name') == 'EKS_AUDIT_LOGS':
                    eks_audit_logs_found = True
                    eks_audit_logs_auto_enable = feature.get('AutoEnable', 'NONE')
                    break

            if eks_audit_logs_found and eks_audit_logs_auto_enable == 'ALL':
                yield self.passed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="GuardDuty EKS Audit Logs are configured for auto-enablement for all accounts (AutoEnable=ALL)",
                )
            elif eks_audit_logs_found:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=f"GuardDuty EKS Audit Logs are configured with AutoEnable={eks_audit_logs_auto_enable}, but should be ALL",
                    remediation=f"Configure EKS Audit Logs auto-enablement for all accounts in {region} by setting AutoEnable to ALL",
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=f"GuardDuty EKS Audit Logs feature is not configured",
                    remediation=f"Enable EKS Audit Logs feature and configure auto-enablement for all accounts in {region}",
                )
