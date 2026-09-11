"""
Check if GuardDuty auto-enablement is configured for member accounts.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_15(GuardDutyCheck):
    """Check if GuardDuty auto-enablement is configured for member accounts."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-15",
        title="GuardDuty auto-enablement configured",
        description=(
            "This check verifies whether auto-enablement configuration for GuardDuty is "
            "enabled for member accounts of the AWS Organization. This ensures that all "
            "existing and new member accounts will have GuardDuty monitoring."
        ),
        check_logic=(
            "Check if GuardDuty AutoEnableOrganizationMembers is set to ALL using "
            "describe-organization-configuration API."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text=(
                "Set AutoEnableOrganizationMembers to ALL in every enabled Region so that "
                "GuardDuty is enabled for all organization members."
            ),
            cli=(
                "aws guardduty update-organization-configuration "
                "--detector-id <detector-id> --auto-enable-organization-members ALL "
                "--region <region>"
            ),
            console=(
                "GuardDuty console in the delegated administrator account, Settings, "
                "Accounts, Auto-enable GuardDuty for all accounts."
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

                # Handle BadRequestException specifically for non-delegated admin accounts
                if error_code == "BadRequestException":
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value="This account is not the GuardDuty delegated administrator",
                        remediation="This check must be run from the GuardDuty delegated administrator account. Verify that this account is the delegated admin for GuardDuty in this region.",
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=f"Error accessing GuardDuty organization configuration: {error_code}",
                        remediation="Check permissions and AWS Organizations configuration",
                    )
                continue

            # Check if AutoEnableOrganizationMembers is set to ALL
            auto_enable_org_members = org_config.get('AutoEnableOrganizationMembers', 'NONE')

            if auto_enable_org_members == 'ALL':
                yield self.passed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="GuardDuty AutoEnableOrganizationMembers is set to ALL",
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=f"GuardDuty AutoEnableOrganizationMembers is set to {auto_enable_org_members}",
                    remediation=f"Set AutoEnableOrganizationMembers to ALL in {region} to ensure GuardDuty is enabled for all organization members",
                )
