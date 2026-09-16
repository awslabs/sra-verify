"""
Check if Firewall Manager manages Shield Advanced policies.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.firewallmanager.base import FirewallManagerCheck


class SRA_FIREWALLMANAGER_04(FirewallManagerCheck):
    """Check if Firewall Manager manages Shield Advanced policies."""

    meta = CheckMeta(
        check_id="SRA-FIREWALLMANAGER-04",
        title="Firewall Manager manages Shield Advanced policies",
        description=(
            "Verifies that AWS Firewall Manager has Shield Advanced policies configured "
            "in each region"
        ),
        check_logic=(
            "Calls list_policies() per region and checks for policies with "
            "SecurityServiceType of SHIELD_ADVANCED"
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="FirewallManager",
        resource_type="AWS::FMS::Policy",
        remediation=Remediation(
            text=(
                "Create an AWS Firewall Manager Shield Advanced policy in every enabled "
                "Region so that Shield Advanced protection is applied centrally to "
                "in-scope resources."
            ),
            cli="aws fms put-policy --policy file://shield-advanced-policy.json --region <region>",
            console=(
                "AWS Firewall Manager console, Security policies, Create policy, "
                "AWS Shield Advanced. Repeat per Region."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        for region in self.regions:
            policies_response = self.list_policies(region)

            if "Error" in policies_response:
                error = policies_response["Error"]
                # Inside the per-Region loop, so one undetermined Region costs one
                # row rather than the whole check's output.
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=None,
                        actual_value="No Shield Advanced policies configured",
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
                    )
                continue

            policies = policies_response.get("PolicyList", [])
            shield_policies = [
                p for p in policies
                if p.get("SecurityServiceType") == "SHIELD_ADVANCED"
            ]

            if not shield_policies:
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="No Shield Advanced policies configured",
                    remediation="Create Firewall Manager Shield Advanced policies: https://docs.aws.amazon.com/waf/latest/developerguide/shield-policies.html"
                )
            else:
                policy_names = [p.get("PolicyName", "Unknown") for p in shield_policies]
                yield self.passed(
                    region=region,
                    resource_id=",".join([p.get("PolicyId", "") for p in shield_policies]),
                    actual_value=f"{len(shield_policies)} Shield Advanced policy(ies) configured: {', '.join(policy_names)}"
                )
