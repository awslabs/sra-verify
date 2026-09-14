"""
Check if GuardDuty Runtime Monitoring is configured for auto-enablement.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.guardduty.base import GuardDutyCheck


class SRA_GUARDDUTY_23(GuardDutyCheck):
    """Check if GuardDuty Runtime Monitoring is configured for auto-enablement."""

    meta = CheckMeta(
        check_id="SRA-GUARDDUTY-23",
        title="GuardDuty Runtime Monitoring auto-enablement configured",
        description=(
            "This check verifies whether Runtime Monitoring and its components (ECS Fargate Agent Management, "
            "EC2 Agent Management, and EKS Addon Management) are configured for auto-enablement "
            "in GuardDuty for all member accounts. Runtime Monitoring provides threat detection for "
            "runtime behavior of resources, helping to identify malicious activities."
        ),
        check_logic=(
            "Check if RUNTIME_MONITORING feature and its components are configured with "
            "AutoEnable set to ALL."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="GuardDuty",
        resource_type="AWS::GuardDuty::Detector",
        remediation=Remediation(
            text=(
                "Set AutoEnable to ALL for the GuardDuty RUNTIME_MONITORING feature and for "
                "its ECS_FARGATE_AGENT_MANAGEMENT, EC2_AGENT_MANAGEMENT, and "
                "EKS_ADDON_MANAGEMENT components in every enabled Region."
            ),
            cli=(
                "aws guardduty update-organization-configuration "
                "--detector-id <detector-id> "
                "--features "
                "'Name=RUNTIME_MONITORING,AutoEnable=ALL,"
                "AdditionalConfiguration=["
                "{Name=ECS_FARGATE_AGENT_MANAGEMENT,AutoEnable=ALL},"
                "{Name=EC2_AGENT_MANAGEMENT,AutoEnable=ALL},"
                "{Name=EKS_ADDON_MANAGEMENT,AutoEnable=ALL}]' "
                "--region <region>"
            ),
            console=(
                "GuardDuty console in the delegated administrator account, Settings, "
                "Accounts, Runtime Monitoring, Enable for all accounts, then enable each "
                "automated agent configuration for all accounts."
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

            # Check if Runtime Monitoring is configured for auto-enablement
            # Look for RUNTIME_MONITORING in Features
            runtime_monitoring_found = False
            runtime_monitoring_auto_enable = "NOT_CONFIGURED"
            additional_config = {}
            features = org_config.get('Features', [])

            for feature in features:
                if feature.get('Name') == 'RUNTIME_MONITORING':
                    runtime_monitoring_found = True
                    runtime_monitoring_auto_enable = feature.get('AutoEnable', 'NONE')

                    # Check additional configuration for the three components
                    additional_configuration = feature.get('AdditionalConfiguration', [])
                    for config in additional_configuration:
                        config_name = config.get('Name')
                        config_auto_enable = config.get('AutoEnable', 'NONE')
                        additional_config[config_name] = config_auto_enable

                    break

            # Check if all required components are properly configured
            required_components = {
                'ECS_FARGATE_AGENT_MANAGEMENT': 'ALL',
                'EC2_AGENT_MANAGEMENT': 'ALL',
                'EKS_ADDON_MANAGEMENT': 'ALL'
            }

            missing_components = []
            misconfigured_components = []

            for component, expected_value in required_components.items():
                if component not in additional_config:
                    missing_components.append(component)
                elif additional_config[component] != expected_value:
                    misconfigured_components.append(f"{component}={additional_config[component]}")

            # Determine the status based on the findings
            if runtime_monitoring_found and runtime_monitoring_auto_enable == 'ALL' and not missing_components and not misconfigured_components:
                yield self.passed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value="GuardDuty Runtime Monitoring and all its components are configured for auto-enablement for all accounts (AutoEnable=ALL)",
                )
            elif not runtime_monitoring_found:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=f"GuardDuty Runtime Monitoring feature is not configured",
                    remediation=f"Enable Runtime Monitoring feature and configure auto-enablement for all accounts in {region}",
                )
            elif runtime_monitoring_auto_enable != 'ALL':
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=f"GuardDuty Runtime Monitoring is configured with AutoEnable={runtime_monitoring_auto_enable}, but should be ALL",
                    remediation=f"Configure Runtime Monitoring auto-enablement for all accounts in {region} by setting AutoEnable to ALL",
                )
            elif missing_components:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=f"GuardDuty Runtime Monitoring is missing the following components: {', '.join(missing_components)}",
                    remediation=f"Configure all required Runtime Monitoring components in {region}",
                )
            elif misconfigured_components:
                yield self.failed(
                    region=region,
                    resource_id=f"guardduty:{region}:{detector_id}",
                    actual_value=f"GuardDuty Runtime Monitoring has misconfigured components: {', '.join(misconfigured_components)}",
                    remediation=f"Set AutoEnable to ALL for all Runtime Monitoring components in {region}",
                )
