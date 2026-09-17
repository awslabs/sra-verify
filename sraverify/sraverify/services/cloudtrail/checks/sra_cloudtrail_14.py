"""
SRA-CLOUDTRAIL-14: Organization trail selects Bedrock and AgentCore data events.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.cloudtrail.base import CloudTrailCheck

#: Every Amazon Bedrock and Amazon Bedrock AgentCore ``resources.type`` literal
#: published in the CloudTrail data-events table: 18 under ``AWS::Bedrock::`` and
#: 14 under ``AWS::BedrockAgentCore::``. Held as a literal tuple, in a fixed
#: order, so the FAIL cell listing what is missing is deterministic and diffable.
#:
#: Note ``AWS::Bedrock::PromptVersion`` rather than ``AWS::Bedrock::Prompt`` --
#: the table spells the prompt type with the version suffix.
AI_DATA_EVENT_RESOURCE_TYPES = (
    "AWS::Bedrock::AdvancedOptimizePromptJob",
    "AWS::Bedrock::AgentAlias",
    "AWS::Bedrock::AsyncInvoke",
    "AWS::Bedrock::AutomatedReasoningPolicy",
    "AWS::Bedrock::AutomatedReasoningPolicyVersion",
    "AWS::Bedrock::Blueprint",
    "AWS::Bedrock::DataAutomationInvocation",
    "AWS::Bedrock::DataAutomationProfile",
    "AWS::Bedrock::DataAutomationProject",
    "AWS::Bedrock::FlowAlias",
    "AWS::Bedrock::FlowExecution",
    "AWS::Bedrock::Guardrail",
    "AWS::Bedrock::InlineAgent",
    "AWS::Bedrock::KnowledgeBase",
    "AWS::Bedrock::Model",
    "AWS::Bedrock::PromptVersion",
    "AWS::Bedrock::Session",
    "AWS::Bedrock::Tool",
    "AWS::BedrockAgentCore::APIKeyCredentialProvider",
    "AWS::BedrockAgentCore::Browser",
    "AWS::BedrockAgentCore::BrowserCustom",
    "AWS::BedrockAgentCore::CodeInterpreter",
    "AWS::BedrockAgentCore::CodeInterpreterCustom",
    "AWS::BedrockAgentCore::Evaluator",
    "AWS::BedrockAgentCore::Gateway",
    "AWS::BedrockAgentCore::Memory",
    "AWS::BedrockAgentCore::OAuth",
    "AWS::BedrockAgentCore::Runtime",
    "AWS::BedrockAgentCore::RuntimeEndpoint",
    "AWS::BedrockAgentCore::TokenVault",
    "AWS::BedrockAgentCore::WorkloadIdentity",
    "AWS::BedrockAgentCore::WorkloadIdentityDirectory",
)


class SRA_CLOUDTRAIL_14(CloudTrailCheck):
    """Check if the organization trail selects Bedrock and AgentCore data events."""

    meta = CheckMeta(
        check_id="SRA-CLOUDTRAIL-14",
        title="Organization trail selects Amazon Bedrock and AgentCore data events",
        description=(
            "This check verifies that the organization trail's advanced event selectors capture "
            "data events for every published Amazon Bedrock and Amazon Bedrock AgentCore "
            "resource type (32 types: 18 AWS::Bedrock and 14 AWS::BedrockAgentCore), so AI "
            "data-plane activity such as model invocation, guardrail application, knowledge "
            "base retrieval and agent runtime calls is logged org-wide and a member account "
            "cannot opt out. A trail that logs only management events passes every other "
            "CloudTrail check while capturing none of this activity."
        ),
        check_logic=(
            "For each organization trail call cloudtrail:GetEventSelectors with the TrailARN in "
            "its HomeRegion. Collect resources.type Equals values from AdvancedEventSelectors "
            "whose eventCategory equals Data. Passes if all 32 Bedrock and BedrockAgentCore "
            "types are present. Fails listing the missing types, or if only basic "
            "EventSelectors are configured."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.MANAGEMENT,
        service="CloudTrail",
        resource_type="AWS::CloudTrail::Trail",
        remediation=Remediation(
            text=(
                "Add advanced event selectors to the organization trail for each Amazon Bedrock "
                "and Bedrock AgentCore data event resource type. Data events incur additional "
                "CloudTrail charges."
            ),
            cli=(
                "aws cloudtrail put-event-selectors --trail-name <trail-arn> "
                "--advanced-event-selectors '[{\"Name\":\"Bedrock model data events\","
                "\"FieldSelectors\":[{\"Field\":\"eventCategory\",\"Equals\":[\"Data\"]},"
                "{\"Field\":\"resources.type\",\"Equals\":[\"AWS::Bedrock::Model\"]}]}]' "
                "--region <home-region>"
            ),
            console=(
                "CloudTrail console in the management account, Trails, select the organization "
                "trail, Edit data events, Add data event type, choose each Bedrock and Bedrock "
                "AgentCore type, Log all events."
            ),
        ),
        sra_sections=("Management account", "AWS CloudTrail"),
        additional_urls=(
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#logging-data-events",
            "https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html",
        ),
    )

    @staticmethod
    def data_event_resource_types(response: dict) -> frozenset[str]:
        """
        Collect the resource types a trail's advanced selectors capture as data events.

        Only ``FieldSelectors`` groups whose ``eventCategory`` includes ``Data``
        contribute: a management-event selector names no resource type, and a
        selector for some other category would not capture AI data events.

        Args:
            response: A successful ``GetEventSelectors`` response.

        Returns:
            The captured ``resources.type`` literals.
        """
        captured: set[str] = set()
        for selector in response.get("AdvancedEventSelectors") or []:
            categories: set[str] = set()
            resource_types: set[str] = set()
            for field_selector in selector.get("FieldSelectors") or []:
                field = field_selector.get("Field")
                if field == "eventCategory":
                    categories.update(field_selector.get("Equals") or [])
                elif field == "resources.type":
                    resource_types.update(field_selector.get("Equals") or [])
            if "Data" in categories:
                captured.update(resource_types)
        return frozenset(captured)

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per organization trail.
        """
        checked_value = (
            f"All {len(AI_DATA_EVENT_RESOURCE_TYPES)} Bedrock and AgentCore "
            f"resource types are selected as data events"
        )

        trails_response = self.get_organization_trails()

        if "Error" in trails_response:
            error = trails_response['Error']
            if self.is_not_configured(error):
                yield self.failed(
                    region="global",
                    resource_id=f"organization/{self.account_id}",
                    actual_value=(
                        "No CloudTrail trail exists for this account, so no "
                        "organization trail selects Bedrock or AgentCore data events"
                    ),
                    checked_value=checked_value,
                )
            else:
                yield self.error(
                    region="global",
                    resource_id=f"organization/{self.account_id}",
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                    checked_value=checked_value,
                )
            return

        org_trails = trails_response.get('trailList', [])

        if not org_trails:
            yield self.failed(
                region="global",
                resource_id=f"organization/{self.account_id}",
                actual_value=(
                    "No organization trails found, so no Bedrock or AgentCore data "
                    "events are captured org-wide"
                ),
                remediation=(
                    "Create an organization trail in the management account, then add "
                    "advanced event selectors for the Bedrock and Bedrock AgentCore "
                    "data event resource types"
                ),
                checked_value=checked_value,
            )
            return

        for trail in org_trails:
            trail_arn = trail.get('TrailARN', 'Unknown')
            home_region = trail.get('HomeRegion', 'Unknown')

            # The full owner ARN, never trail.get('Name'): a bare name resolves
            # against the calling account and answers TrailNotFoundException for a
            # trail owned elsewhere.
            selectors_response = self.get_event_selectors(home_region, trail_arn)

            # Inside the per-trail loop, so one undetermined trail costs one row
            # rather than the whole check's output.
            if "Error" in selectors_response:
                error = selectors_response['Error']
                if self.is_not_configured(error):
                    yield self.failed(
                        region=home_region,
                        resource_id=trail_arn,
                        actual_value=f"Trail {trail_arn} does not exist",
                        checked_value=checked_value,
                    )
                else:
                    yield self.error(
                        region=home_region,
                        resource_id=trail_arn,
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                        checked_value=checked_value,
                    )
                continue

            # A trail carries either basic EventSelectors or AdvancedEventSelectors,
            # never both. Basic selectors can only name S3, Lambda and DynamoDB
            # resources, so a trail using them cannot capture Bedrock data events at
            # all -- AWS answered, and the answer is that the control is absent.
            if not selectors_response.get('AdvancedEventSelectors'):
                yield self.failed(
                    region="global",
                    resource_id=trail_arn,
                    actual_value=(
                        "Trail uses basic event selectors, which cannot select "
                        "Bedrock or AgentCore data events"
                    ),
                    remediation=(
                        f"Replace the basic event selectors on {trail_arn} with "
                        f"advanced event selectors that name the Bedrock and Bedrock "
                        f"AgentCore data event resource types"
                    ),
                    checked_value=checked_value,
                )
                continue

            captured = self.data_event_resource_types(selectors_response)
            missing = tuple(
                t for t in AI_DATA_EVENT_RESOURCE_TYPES if t not in captured
            )

            if not missing:
                yield self.passed(
                    region="global",
                    resource_id=trail_arn,
                    actual_value=(
                        f"Organization trail selects all "
                        f"{len(AI_DATA_EVENT_RESOURCE_TYPES)} Bedrock and AgentCore "
                        f"resource types as data events"
                    ),
                    checked_value=checked_value,
                )
            elif len(missing) == len(AI_DATA_EVENT_RESOURCE_TYPES):
                # Keep the common case short: naming all 32 types would produce a
                # ~1400-character cell that says only "none of them".
                yield self.failed(
                    region="global",
                    resource_id=trail_arn,
                    actual_value=(
                        f"Organization trail has advanced event selectors but selects "
                        f"none of the {len(AI_DATA_EVENT_RESOURCE_TYPES)} Bedrock and "
                        f"AgentCore resource types as data events"
                    ),
                    checked_value=checked_value,
                )
            else:
                yield self.failed(
                    region="global",
                    resource_id=trail_arn,
                    actual_value=(
                        f"Organization trail does not select {len(missing)} of "
                        f"{len(AI_DATA_EVENT_RESOURCE_TYPES)} Bedrock and AgentCore "
                        f"resource types as data events: {', '.join(missing)}"
                    ),
                    checked_value=checked_value,
                )
