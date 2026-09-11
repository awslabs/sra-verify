"""
Check if Firewall Manager policies are in active status.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.firewallmanager.base import FirewallManagerCheck


class SRA_FIREWALLMANAGER_09(FirewallManagerCheck):
    """Check if Firewall Manager policies are in active status."""

    meta = CheckMeta(
        check_id="SRA-FIREWALLMANAGER-09",
        title="Firewall Manager policies are in active status",
        description=(
            "Verifies that AWS Firewall Manager policies are in ACTIVE status and not "
            "out of admin scope"
        ),
        check_logic=(
            "Calls list_policies() per region and checks that all policies have "
            "PolicyStatus set to ACTIVE"
        ),
        severity=Severity.HIGH,
        account_type=AccountType.AUDIT,
        service="FirewallManager",
        resource_type="AWS::FMS::Policy",
        remediation=Remediation(
            text=(
                "Bring every AWS Firewall Manager policy back into ACTIVE status by "
                "extending the Firewall Manager administrator's scope to cover the "
                "accounts, Regions, and policy types the policy uses."
            ),
            cli="aws fms put-admin-account --admin-account <admin-account-id> --admin-scope file://admin-scope.json --region us-east-1",
            console=(
                "AWS Firewall Manager console in the management account, Settings, "
                "Firewall Manager administrators, select the administrator, Edit scope."
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
                yield self.error(
                    region=region,
                    resource_id=None,
                    actual_value=policies_response["Error"].get("Message", "Unknown error"),
                    remediation="Check IAM permissions for Firewall Manager API access"
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
                policy_status = policy.get("PolicyStatus", "")

                if policy_status != "ACTIVE":
                    yield self.failed(
                        region=region,
                        resource_id=policy_id,
                        actual_value=f"Policy '{policy_name}' has status '{policy_status}'",
                        remediation=f"Ensure policy '{policy_name}' is within admin scope to make it ACTIVE"
                    )
                else:
                    yield self.passed(
                        region=region,
                        resource_id=policy_id,
                        actual_value=f"Policy '{policy_name}' is ACTIVE"
                    )
