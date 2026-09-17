"""
SRA-CONFIG-10: AWS Config recorder records the AI/ML resource types.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.config.base import ConfigCheck

#: The resource types the Security Hub AI Security Best Practices standard's
#: change-triggered controls evaluate, derived from the standard's control list
#: crossed with the "Required AWS Config resources for control findings" table.
#: Held as a literal tuple, in a fixed order, so the FAIL cell listing what is
#: missing is deterministic and diffable across runs.
#:
#: Deliberately NOT validated against botocore's ``ResourceType`` enum: that enum
#: omits types AWS Config can genuinely record, so validating against it would
#: drop types from this list and under-report.
AI_ML_RESOURCE_TYPES = (
    "AWS::Bedrock::DataSource",
    "AWS::BedrockAgentCore::BrowserCustom",
    "AWS::BedrockAgentCore::CodeInterpreterCustom",
    "AWS::BedrockAgentCore::Gateway",
    "AWS::BedrockAgentCore::Memory",
    "AWS::BedrockAgentCore::Runtime",
    "AWS::SageMaker::FeatureGroup",
    "AWS::SageMaker::InferenceExperiment",
    "AWS::SageMaker::Model",
    "AWS::SageMaker::ModelExplainabilityJobDefinition",
    "AWS::SageMaker::ModelQualityJobDefinition",
    "AWS::SageMaker::MonitoringSchedule",
    "AWS::SageMaker::NotebookInstance",
)


class SRA_CONFIG_10(ConfigCheck):
    """Check if the AWS Config recorder records the AI/ML resource types."""

    meta = CheckMeta(
        check_id="SRA-CONFIG-10",
        title="AWS Config recorder records the AI/ML resource types",
        description=(
            "This check verifies that the AWS Config configuration recorder in each Region "
            "records the 13 resource types the Security Hub AI Security Best Practices standard "
            "evaluates: AWS::Bedrock::DataSource, five AWS::BedrockAgentCore types "
            "(BrowserCustom, CodeInterpreterCustom, Gateway, Memory, Runtime) and seven "
            "AWS::SageMaker types (FeatureGroup, InferenceExperiment, Model, "
            "ModelExplainabilityJobDefinition, ModelQualityJobDefinition, MonitoringSchedule, "
            "NotebookInstance). Change-triggered controls on an unrecorded type return WARNING "
            "instead of a verdict, which reads as clean."
        ),
        check_logic=(
            "Call config:DescribeConfigurationRecorders and inspect each recorder's "
            "recordingGroup. ALL_SUPPORTED_RESOURCE_TYPES covers all 13. "
            "INCLUSION_BY_RESOURCE_TYPES must list all 13 in resourceTypes. "
            "EXCLUSION_BY_RESOURCE_TYPES must list none of the 13 in "
            "exclusionByResourceTypes.resourceTypes. Passes if any recorder covers all 13."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.APPLICATION,
        service="Config",
        resource_type="AWS::Config::ConfigurationRecorder",
        remediation=Remediation(
            text=(
                "Update the configuration recorder to record all supported resource types, or "
                "add the missing AI/ML resource types to its inclusion list (or remove them from "
                "its exclusion list)."
            ),
            cli=(
                "aws configservice put-configuration-recorder --configuration-recorder "
                "name=<recorder-name>,roleARN=<role-arn> --recording-group "
                "allSupported=true,includeGlobalResourceTypes=true --region <region>"
            ),
            console=(
                "AWS Config console, Settings, Recorder, Edit, Recording strategy, All resource "
                "types with customizable overrides, or add the missing types under Specific "
                "resource types."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Config"),
        additional_urls=(
            "https://docs.aws.amazon.com/securityhub/latest/userguide/controls-config-resources.html",
            "https://docs.aws.amazon.com/config/latest/developerguide/select-resources.html",
        ),
    )

    @staticmethod
    def missing_types_for(recorder: dict) -> tuple[str, ...]:
        """
        Return the AI/ML resource types a recorder does not record.

        All three recording strategies have to be read differently, and the
        exclusion strategy is the one that catches a reader out: it covers every
        type in ``AI_ML_RESOURCE_TYPES`` while ``resourceTypes`` is empty, so
        treating an empty inclusion list as "records nothing" would report a
        fully covering recorder as a failure.

        Args:
            recorder: One entry from DescribeConfigurationRecorders.

        Returns:
            The missing types, in AI_ML_RESOURCE_TYPES order, empty when the
            recorder covers all of them.
        """
        group = recorder.get("recordingGroup") or {}
        strategy = (group.get("recordingStrategy") or {}).get("useOnly")

        if strategy is None:
            # Pre-recordingStrategy recorders express the same fact through
            # allSupported alone.
            strategy = (
                "ALL_SUPPORTED_RESOURCE_TYPES"
                if group.get("allSupported")
                else "INCLUSION_BY_RESOURCE_TYPES"
            )

        if strategy == "ALL_SUPPORTED_RESOURCE_TYPES":
            return ()

        if strategy == "EXCLUSION_BY_RESOURCE_TYPES":
            excluded = set(
                (group.get("exclusionByResourceTypes") or {}).get("resourceTypes") or []
            )
            return tuple(t for t in AI_ML_RESOURCE_TYPES if t in excluded)

        included = set(group.get("resourceTypes") or [])
        return tuple(t for t in AI_ML_RESOURCE_TYPES if t not in included)

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        checked_value = (
            f"All {len(AI_ML_RESOURCE_TYPES)} AI/ML resource types are recorded"
        )

        if not self.regions:
            yield self.error(
                region="global",
                resource_id="config:global",
                actual_value="No regions specified for check",
                remediation="Specify at least one region when running the check",
                checked_value=checked_value,
            )
            return

        for region in self.regions:
            recorders_response = self.get_configuration_recorders(region)

            if "Error" in recorders_response:
                error = recorders_response['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=f"config:{self.account_id}:{region}",
                        actual_value=f"AWS Config is not configured in {region}",
                        checked_value=checked_value,
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=f"config:{self.account_id}:{region}",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                        checked_value=checked_value,
                    )
                continue

            recorders = recorders_response.get('ConfigurationRecorders', [])

            if not recorders:
                yield self.failed(
                    region=region,
                    resource_id=(
                        f"arn:aws:config:{region}:{self.account_id}:"
                        f"configurationRecorder/default"
                    ),
                    actual_value=(
                        "No configuration recorder found in this region, so none of the "
                        "AI/ML resource types are recorded"
                    ),
                    checked_value=checked_value,
                )
                continue

            # An account may carry more than one recorder -- a customer-managed
            # one alongside a Security Hub service-linked one -- and coverage is
            # the union. Report against the recorder that covers the most, so a
            # narrow service-linked recorder cannot mask a compliant one.
            best_recorder = min(
                recorders, key=lambda r: len(self.missing_types_for(r))
            )
            missing = self.missing_types_for(best_recorder)
            recorder_name = best_recorder.get('name', 'default')
            recorder_arn = (
                f"arn:aws:config:{region}:{self.account_id}:"
                f"configurationRecorder/{recorder_name}"
            )

            if not missing:
                yield self.passed(
                    region=region,
                    resource_id=recorder_arn,
                    actual_value=(
                        f"Configuration recorder '{recorder_name}' records all "
                        f"{len(AI_ML_RESOURCE_TYPES)} AI/ML resource types"
                    ),
                    checked_value=checked_value,
                )
            else:
                yield self.failed(
                    region=region,
                    resource_id=recorder_arn,
                    actual_value=(
                        f"Configuration recorder '{recorder_name}' does not record "
                        f"{len(missing)} of {len(AI_ML_RESOURCE_TYPES)} AI/ML resource "
                        f"types: {', '.join(missing)}"
                    ),
                    remediation=(
                        f"Record the missing AI/ML resource types in {region}, either by "
                        f"setting the recording strategy to all supported resource types "
                        f"or by adding them to recorder '{recorder_name}'"
                    ),
                    checked_value=checked_value,
                )
