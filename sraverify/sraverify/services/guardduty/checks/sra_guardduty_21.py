"""
Check if GuardDuty EBS Malware Protection is configured for auto-enablement.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_21(GuardDutyCheck):
    """Check if GuardDuty EBS Malware Protection is configured for auto-enablement."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-21",
        title="GuardDuty EBS Malware Protection auto-enablement configured",
        description=(
            "This check verifies whether EBS Malware Protection is configured for auto-enablement "
            "in GuardDuty for all member accounts. EBS Malware Protection scans EBS volumes for "
            "malware when GuardDuty detects a potential threat, helping to identify and remediate "
            "malware infections in your AWS environment."
        ),
        check_logic=(
            "Check if EBS_MALWARE_PROTECTION feature is configured with AutoEnable set to ALL."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text=(
                "Set AutoEnable to ALL for the GuardDuty EBS_MALWARE_PROTECTION feature in "
                "every enabled Region."
            ),
            cli=(
                "aws guardduty update-organization-configuration "
                "--detector-id <detector-id> "
                "--features Name=EBS_MALWARE_PROTECTION,AutoEnable=ALL --region <region>"
            ),
            console=(
                "GuardDuty console in the delegated administrator account, Settings, "
                "Accounts, Malware Protection for EC2, Enable for all accounts."
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
                error = org_config["Error"]
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"guardduty:{region}:{detector_id}",
                        actual_value=(
                            "No GuardDuty delegated administrator is enabled "
                            "for this Region"
                        ),
                        remediation="Verify that GuardDuty is the delegated admin in this Region and run the check again.",
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
            # Check if EBS Malware Protection is configured for auto-enablement
            # Look for EBS_MALWARE_PROTECTION in Features
            ebs_malware_protection_found = False
            ebs_malware_protection_auto_enable = "NOT_CONFIGURED"
            features = org_config.get('Features', [])

            for feature in features:
                if feature.get('Name') == 'EBS_MALWARE_PROTECTION':
                    ebs_malware_protection_found = True
                    ebs_malware_protection_auto_enable = feature.get('AutoEnable', 'NONE')
                    break

            if ebs_malware_protection_found and ebs_malware_protection_auto_enable == 'ALL':
                yield self.passed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="GuardDuty EBS Malware Protection is configured for auto-enablement for all accounts (AutoEnable=ALL)",
                )
            elif ebs_malware_protection_found:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=f"GuardDuty EBS Malware Protection is configured with AutoEnable={ebs_malware_protection_auto_enable}, but should be ALL",
                    remediation=f"Configure EBS Malware Protection auto-enablement for all accounts in {region} by setting AutoEnable to ALL",
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=f"GuardDuty EBS Malware Protection feature is not configured",
                    remediation=f"Enable EBS Malware Protection feature and configure auto-enablement for all accounts in {region}",
                )
