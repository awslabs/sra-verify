"""
Check if the organization has a customer-managed Amazon Bedrock policy.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.organizations.base import OrganizationsCheck

#: The Organizations policy type that carries Amazon Bedrock Guardrail
#: enforcement. ``list_policies`` takes the type as its only argument, so this
#: check needs no client change.
BEDROCK_POLICY_TYPE = "BEDROCK_POLICY"


class SRA_ORGANIZATIONS_11(OrganizationsCheck):
    """Check if the organization has a customer-managed Amazon Bedrock policy."""

    meta = CheckMeta(
        check_id="SRA-ORGANIZATIONS-11",
        title="Customer-managed Amazon Bedrock policy exists in the organization",
        description=(
            "This check verifies that at least one customer-managed Amazon Bedrock policy "
            "exists in the organization. A Bedrock policy names a Guardrail owned by the "
            "management account and enforces it on model inference in every account the "
            "policy reaches, so Guardrail enforcement is defined centrally rather than left "
            "to each account. An organization with the policy type enabled but no policy "
            "defined enforces nothing."
        ),
        check_logic=(
            "Call organizations:ListPolicies with Filter BEDROCK_POLICY. Check passes if at "
            "least one policy has AwsManaged false. Fails if the list is empty, if only "
            "AWS-managed policies exist, or if the policy type is not enabled "
            "(PolicyTypeNotEnabledException)."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="Organizations",
        resource_type="AWS::Organizations::Policy",
        remediation=Remediation(
            text=(
                "Create an Amazon Bedrock policy in the management account that names a "
                "versioned Guardrail, and attach it to the root or to the OUs that run "
                "Bedrock workloads."
            ),
            cli=(
                "aws organizations create-policy --name <name> --type BEDROCK_POLICY "
                "--content file://bedrock-policy.json\n"
                "aws organizations attach-policy --policy-id <policy-id> "
                "--target-id <root-or-ou-id>"
            ),
            console=(
                "AWS Organizations console, Policies, Amazon Bedrock policies, Create policy, "
                "then Attach to the root or OU."
            ),
        ),
        sra_sections=("Management account", "AWS Organizations"),
        additional_urls=(
            "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_bedrock_syntax.html",
            "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-enforcements.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the organization's Amazon Bedrock policies.
        """
        # Organizations is a global service, use "global" as region
        region = "global"
        checked_value = f"Customer-managed {BEDROCK_POLICY_TYPE} configured"

        # Read only for the resource_id; the verdict comes from ListPolicies.
        org_response = self.get_organization()
        org_id = None
        if "Organization" in org_response:
            org_id = org_response["Organization"].get("Id", "Unknown")

        response = self.list_policies(BEDROCK_POLICY_TYPE)

        if "Error" in response:
            error = response["Error"]
            if self.is_not_configured(error):
                # PolicyTypeNotEnabledException on ListPolicies is declared
                # semantic: AWS answered, and the answer is that the policy type
                # is not enabled, so no Bedrock policy can exist. Live testing
                # showed a disabled type may instead answer with an empty list,
                # which the success path below reports as the same FAIL.
                yield self.failed(
                    region=region,
                    resource_id=org_id,
                    actual_value=(
                        f"AWS Organizations reports the control absent: "
                        f"{error['Code']}"
                    ),
                    remediation=(
                        f"Enable the {BEDROCK_POLICY_TYPE} policy type on the "
                        f"organization root, then create a customer-managed Amazon "
                        f"Bedrock policy"
                    ),
                    checked_value=checked_value,
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=org_id,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                    checked_value=checked_value,
                )
            return

        policies = response.get("Policies", [])
        custom_policies = [p for p in policies if not p.get("AwsManaged", False)]

        if not policies:
            yield self.failed(
                region=region,
                resource_id=org_id,
                actual_value=(
                    f"No {BEDROCK_POLICY_TYPE} policies exist in the organization"
                ),
                checked_value=checked_value,
            )
        elif not custom_policies:
            policy_names = sorted(p.get("Name", "Unknown") for p in policies)
            yield self.failed(
                region=region,
                resource_id=org_id,
                actual_value=(
                    f"Only AWS-managed {BEDROCK_POLICY_TYPE} policies exist: "
                    f"{', '.join(policy_names)}"
                ),
                checked_value=checked_value,
            )
        else:
            custom_policy_names = sorted(
                p.get("Name", "Unknown") for p in custom_policies
            )
            yield self.passed(
                region=region,
                resource_id=org_id,
                actual_value=(
                    f"{len(custom_policies)} customer-managed {BEDROCK_POLICY_TYPE} "
                    f"policy(ies) configured: {', '.join(custom_policy_names)}"
                ),
                checked_value=checked_value,
            )
