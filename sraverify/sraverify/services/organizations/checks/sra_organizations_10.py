"""
Check if the BEDROCK_POLICY policy type is enabled on the organization root.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.organizations.base import OrganizationsCheck

#: The Organizations policy type that carries Amazon Bedrock Guardrail
#: enforcement. Enabling all features only makes a policy type *available*;
#: ListRoots reports separately whether it is enabled on the root, and only an
#: enabled type takes effect.
BEDROCK_POLICY_TYPE = "BEDROCK_POLICY"


class SRA_ORGANIZATIONS_10(OrganizationsCheck):
    """Check if the BEDROCK_POLICY policy type is enabled on the organization root."""

    meta = CheckMeta(
        check_id="SRA-ORGANIZATIONS-10",
        title="Amazon Bedrock policy type is enabled on the organization root",
        description=(
            "This check verifies that the BEDROCK_POLICY policy type is enabled on the "
            "organization root. Enabling all features (FeatureSet=ALL) only makes the "
            "policy type available; a policy type must also be enabled on the root before "
            "any policy of that type takes effect. Amazon Bedrock policies let the management "
            "account enforce a Bedrock Guardrail on model inference across the organization, "
            "so with the type disabled no Bedrock policy can reach any account."
        ),
        check_logic=(
            "Call organizations:ListRoots and read Roots[0].PolicyTypes. Check passes if an "
            "entry has Type BEDROCK_POLICY and Status ENABLED. Fails if the entry is absent "
            "or its Status is PENDING_ENABLE or PENDING_DISABLE."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.MANAGEMENT,
        service="Organizations",
        resource_type="AWS::Organizations::Organization",
        remediation=Remediation(
            text=(
                "Enable the BEDROCK_POLICY policy type on the organization root from the "
                "management account."
            ),
            cli=(
                "aws organizations enable-policy-type --root-id <root-id> "
                "--policy-type BEDROCK_POLICY"
            ),
            console=(
                "AWS Organizations console, Policies, Amazon Bedrock policies, Enable "
                "Amazon Bedrock policies."
            ),
        ),
        sra_sections=("Management account", "AWS Organizations"),
        additional_urls=(
            "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_bedrock.html",
            "https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListRoots.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding for the organization root.
        """
        # Organizations is a global service, use "global" as region
        region = "global"
        checked_value = f"{BEDROCK_POLICY_TYPE} policy type Status is ENABLED on the root"

        roots_response = self.get_roots()

        if "Error" in roots_response:
            error = roots_response["Error"]
            if self.is_not_configured(error):
                # A declared semantic pair: AWS answered and the control is
                # absent. For Organizations that means either no organization
                # exists, or the policy type is not enabled.
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value=(
                        f"AWS Organizations reports the control absent: "
                        f"{error['Code']}"
                    ),
                    checked_value=checked_value,
                )
            else:
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=(
                        f"{error['Operation']} failed: {error['Code']}: "
                        f"{error['Message']}"
                    ),
                    remediation=self._remediation_for(error),
                    checked_value=checked_value,
                )
            return

        roots = roots_response.get("Roots", [])
        if not roots:
            # ListRoots succeeded and named no root. Every organization has
            # exactly one, so this is a response we cannot draw a verdict from
            # rather than evidence the policy type is disabled.
            yield self.error(
                region=region,
                resource_id=None,
                actual_value="ListRoots succeeded but returned no organization root",
                remediation=(
                    "Re-run the check from the organization management account and "
                    "confirm the member role may call organizations:ListRoots"
                ),
                checked_value=checked_value,
            )
            return

        # Organizations have only one root.
        root = roots[0]
        root_id = root.get("Id", "")

        # AWS omits a policy type from PolicyTypes entirely until it has been
        # enabled on the root, so an absent entry is the common FAIL and has to
        # be treated as non-compliant rather than skipped.
        policy_types = root.get("PolicyTypes", [])
        bedrock_status = None
        for policy_type in policy_types:
            if policy_type.get("Type") == BEDROCK_POLICY_TYPE:
                bedrock_status = policy_type.get("Status", "UNKNOWN")
                break

        if bedrock_status == "ENABLED":
            yield self.passed(
                region=region,
                resource_id=root_id,
                actual_value=(
                    f"{BEDROCK_POLICY_TYPE} policy type is ENABLED on root {root_id}"
                ),
                checked_value=checked_value,
            )
        elif bedrock_status is not None:
            # PENDING_ENABLE or PENDING_DISABLE: the type is not in effect yet,
            # or is on its way out, so no Bedrock policy is being enforced.
            yield self.failed(
                region=region,
                resource_id=root_id,
                actual_value=(
                    f"{BEDROCK_POLICY_TYPE} policy type is {bedrock_status} on root "
                    f"{root_id}, but should be ENABLED"
                ),
                remediation=(
                    f"Wait for the policy type transition on root {root_id} to finish, "
                    f"then confirm {BEDROCK_POLICY_TYPE} is ENABLED"
                ),
                checked_value=checked_value,
            )
        else:
            enabled_types = sorted(
                policy_type.get("Type", "Unknown") for policy_type in policy_types
            )
            enabled_types_str = ", ".join(enabled_types) if enabled_types else "None"
            yield self.failed(
                region=region,
                resource_id=root_id,
                actual_value=(
                    f"{BEDROCK_POLICY_TYPE} policy type is not enabled on root "
                    f"{root_id}. Policy types on the root: {enabled_types_str}"
                ),
                remediation=(
                    f"Enable the {BEDROCK_POLICY_TYPE} policy type on root {root_id}: "
                    f"aws organizations enable-policy-type --root-id {root_id} "
                    f"--policy-type {BEDROCK_POLICY_TYPE}"
                ),
                checked_value=checked_value,
            )
