"""
Check if Firewall Manager policy remediation is enabled.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.firewallmanager.base import FirewallManagerCheck


class SRA_FIREWALLMANAGER_08(FirewallManagerCheck):
    """Check if Firewall Manager policy remediation is enabled."""

    meta = CheckMeta(
        check_id="SRA-FIREWALLMANAGER-08",
        title="Firewall Manager policy remediation is enabled",
        description=(
            "Verifies that AWS Firewall Manager policies have remediation enabled to "
            "automatically apply to new resources"
        ),
        check_logic=(
            "Calls list_policies() per region and checks that all policies have "
            "RemediationEnabled set to true"
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="FirewallManager",
        resource_type="AWS::FMS::Policy",
        remediation=Remediation(
            text=(
                "Enable automatic remediation on every AWS Firewall Manager policy so "
                "that protections are applied to new and non-compliant in-scope "
                "resources without manual action."
            ),
            cli="aws fms put-policy --policy file://policy-with-remediation-enabled.json --region <region>",
            console=(
                "AWS Firewall Manager console, Security policies, select the policy, "
                "Edit, Policy action, Auto remediate any noncompliant resources."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per policy, or one Finding per Region where no policy exists.
        """
        for region in self.regions:
            policies_response = self.list_policies(region)

            if "Error" in policies_response:
                error = policies_response["Error"]
                # Inside the per-Region loop, so one undetermined Region costs one
                # row rather than the whole check's output.
                #
                # No is_not_configured branch, unlike SRA-FIREWALLMANAGER-01..07.
                # Nothing is declared for ListPolicies -- "no policies" arrives
                # there as a successful response with an empty PolicyList -- and
                # this check treats that successful empty response as a PASS, on
                # the reasoning that a Region with no policies has no policy with
                # remediation disabled. A FAIL arm here would contradict that
                # verdict, so any error from this call is an inability to
                # determine.
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

            if not policies:
                yield self.passed(
                    region=region,
                    resource_id=None,
                    actual_value="No Firewall Manager policies configured in region"
                )
                continue

            for policy in policies:
                policy_id = policy.get("PolicyId", "")
                policy_name = policy.get("PolicyName", "Unknown")
                remediation_enabled = policy.get("RemediationEnabled", False)

                if not remediation_enabled:
                    yield self.failed(
                        region=region,
                        resource_id=policy_id,
                        actual_value=f"Policy '{policy_name}' has remediation disabled",
                        remediation=f"Enable remediation on policy '{policy_name}' to automatically apply to new resources"
                    )
                else:
                    yield self.passed(
                        region=region,
                        resource_id=policy_id,
                        actual_value=f"Policy '{policy_name}' has remediation enabled"
                    )
