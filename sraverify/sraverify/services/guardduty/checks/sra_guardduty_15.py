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
            detectors = self.get_detector_id(region)

            # Test for the error result before reading any success-path key: this
            # is where "GuardDuty is not enabled here" and "the call failed" part
            # company.
            if "Error" in detectors:
                error = detectors["Error"]
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}",
                        actual_value=(
                            f"GuardDuty is not configured in this Region "
                            f"({error['Code']})"
                        ),
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"guardduty:{region}",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            detector_id = self.detector_id_of(detectors)

            if not detector_id:
                # Reached only after the error test above passed, so ListDetectors
                # succeeded and named no detector: GuardDuty is not enabled in this
                # Region. AWS answered, and the answer is that the control is absent,
                # which is a FAIL. Reporting it as ERROR asserted an inability to
                # determine something we had in fact determined.
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}",
                    actual_value="No GuardDuty detector in this Region",
                    remediation=f"Enable GuardDuty in {region}",
                )
                continue

            # Get organization configuration for GuardDuty
            org_config = self.get_organization_configuration(region)

            # Check if there was an error in the response
            if "Error" in org_config:
                error = org_config["Error"]
                if self.is_not_configured(error):
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
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
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
