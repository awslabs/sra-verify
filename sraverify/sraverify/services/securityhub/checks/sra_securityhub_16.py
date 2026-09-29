"""
SRA-SECURITYHUB-16: A Security Hub policy attached to the root enables all supported Regions.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SECURITYHUB_POLICY_TYPE, SecurityHubCheck


class SRA_SECURITYHUB_16(SecurityHubCheck):
    """Check if a root-attached Security Hub policy enables ALL_SUPPORTED Regions."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-16",
        title="Security Hub V2 policy attached to the organization root enables all supported Regions",
        description=(
            "This check verifies that a Security Hub policy (Organizations policy type "
            "SECURITYHUB_POLICY) is attached to the organization root and enables Security Hub "
            "in ALL_SUPPORTED Regions. Security Hub policies are how the delegated administrator "
            "enables Security Hub across the organization: attachment at the root reaches every "
            "account including accounts created later, and ALL_SUPPORTED includes Regions AWS "
            "adds later. The policy type must also be enabled on the root before any policy of "
            "that type takes effect."
        ),
        check_logic=(
            "Call organizations:ListRoots and require PolicyTypes to hold SECURITYHUB_POLICY with "
            "Status ENABLED. Call ListPoliciesForTarget on the root with that filter and "
            "DescribePolicy for each. Passes if one policy's securityhub.enable_in_regions "
            "contains ALL_SUPPORTED and its disable_in_regions is empty. One global row."
        ),
        severity=Severity.HIGH,
        account_type=AccountType.MANAGEMENT,
        service="SecurityHub",
        resource_type="AWS::Organizations::Policy",
        remediation=Remediation(
            text=(
                "Enable the SECURITYHUB_POLICY policy type on the root, then attach a Security "
                "Hub policy to the root that enables ALL_SUPPORTED Regions with an empty "
                "disable list."
            ),
            cli=(
                "aws organizations enable-policy-type --root-id <root-id> "
                "--policy-type SECURITYHUB_POLICY\n"
                "aws organizations create-policy --type SECURITYHUB_POLICY --name securityhub-all "
                "--content '{\"securityhub\":{\"enable_in_regions\":{\"@@assign\":"
                "[\"ALL_SUPPORTED\"]},\"disable_in_regions\":{\"@@assign\":[]}}}'\n"
                "aws organizations attach-policy --policy-id <policy-id> --target-id <root-id>"
            ),
            console=(
                "Security Hub console (securityhub/v2) in the delegated administrator account, "
                "Management, Configurations, Security Hub (essential and additional "
                "capabilities), All organizational units and accounts, Enable all Regions with "
                "new Regions enabled automatically."
            ),
        ),
        sra_sections=("Security Tooling account", "AWS Security Hub"),
        additional_urls=(
            "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_security_hub.html",
            "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_security_hub_syntax.html",
            "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-da-policy.html",
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One global Finding.
        """
        checked_value = (
            "A SECURITYHUB_POLICY attached to the root enables ALL_SUPPORTED Regions "
            "and disables none"
        )
        # Organizations is global; the Region only picks a client endpoint.
        region = self.regions[0]

        roots_response = self.get_roots(region)
        if "Error" in roots_response:
            error = roots_response["Error"]
            yield self.error(
                region="global",
                resource_id=f"organizations:root/{self.account_id}",
                checked_value=checked_value,
                actual_value=(
                    f"{error['Operation']} failed: {error['Code']}: {error['Message']}"
                ),
                remediation=self._remediation_for(error),
            )
            return

        roots = roots_response.get("Roots", [])
        if not roots:
            yield self.failed(
                region="global",
                resource_id=f"organizations:root/{self.account_id}",
                checked_value=checked_value,
                actual_value="ListRoots returned no organization root",
            )
            return

        root = roots[0]
        root_id = root.get("Id", "unknown")
        type_status = next(
            (
                policy_type.get("Status")
                for policy_type in root.get("PolicyTypes", [])
                if policy_type.get("Type") == SECURITYHUB_POLICY_TYPE
            ),
            None,
        )
        if type_status != "ENABLED":
            yield self.failed(
                region="global",
                resource_id=root_id,
                checked_value=checked_value,
                actual_value=(
                    f"The {SECURITYHUB_POLICY_TYPE} policy type is not enabled on root "
                    f"{root_id} (status: {type_status or 'absent'})"
                ),
                remediation=(
                    f"Enable the policy type: aws organizations enable-policy-type "
                    f"--root-id {root_id} --policy-type {SECURITYHUB_POLICY_TYPE}, then "
                    f"attach a Security Hub policy that enables ALL_SUPPORTED Regions"
                ),
            )
            return

        attached = self.get_policies_for_target(region, root_id, SECURITYHUB_POLICY_TYPE)
        if "Error" in attached:
            error = attached["Error"]
            yield self.error(
                region="global",
                resource_id=root_id,
                checked_value=checked_value,
                actual_value=(
                    f"{error['Operation']} failed: {error['Code']}: {error['Message']}"
                ),
                remediation=self._remediation_for(error),
            )
            return

        policies = sorted(attached.get("Policies", []), key=lambda p: p.get("Id", ""))
        if not policies:
            yield self.failed(
                region="global",
                resource_id=root_id,
                checked_value=checked_value,
                actual_value=f"No Security Hub policy is attached to root {root_id}",
            )
            return

        # The verdict is "does ANY root policy enable everything", so one policy
        # that cannot be read only decides the row when no other policy passes.
        undetermined = None
        observations = []
        for summary in policies:
            policy_id = summary.get("Id", "unknown")
            name = summary.get("Name", policy_id)
            policy_response = self.get_policy(region, policy_id)
            if "Error" in policy_response:
                undetermined = undetermined or policy_response["Error"]
                continue

            content = (policy_response.get("Policy") or {}).get("Content")
            region_lists = self.securityhub_policy_regions(content)
            if region_lists is None:
                observations.append(f"{name} has no parseable securityhub block")
                continue

            enable, disable = region_lists
            if "ALL_SUPPORTED" in enable and not disable:
                yield self.passed(
                    region="global",
                    resource_id=summary.get("Arn") or policy_id,
                    checked_value=checked_value,
                    actual_value=(
                        f"Security Hub policy {name} is attached to root {root_id}, "
                        f"enables ALL_SUPPORTED Regions and disables none"
                    ),
                )
                return
            observations.append(
                f"{name} enables [{', '.join(enable) or 'none'}] and disables "
                f"[{', '.join(disable) or 'none'}]"
            )

        if undetermined is not None:
            yield self.error(
                region="global",
                resource_id=root_id,
                checked_value=checked_value,
                actual_value=(
                    f"{undetermined['Operation']} failed: {undetermined['Code']}: "
                    f"{undetermined['Message']}"
                ),
                remediation=self._remediation_for(undetermined),
            )
            return

        yield self.failed(
            region="global",
            resource_id=root_id,
            checked_value=checked_value,
            actual_value=(
                f"No Security Hub policy attached to root {root_id} enables every "
                f"supported Region: {'; '.join(observations)}"
            ),
        )
