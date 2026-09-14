"""
Check if Firewall Manager manages security groups.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.firewallmanager.base import FirewallManagerCheck


class SRA_FIREWALLMANAGER_02(FirewallManagerCheck):
    """Check if Firewall Manager manages security groups."""

    meta = CheckMeta(
        check_id="SRA-FIREWALLMANAGER-02",
        title="Firewall Manager manages security groups",
        description=(
            "Verifies that AWS Firewall Manager has security group policies configured "
            "in each region"
        ),
        check_logic=(
            "Calls list_policies() per region and checks for policies with "
            "SecurityServiceType of SECURITY_GROUPS_COMMON, "
            "SECURITY_GROUPS_CONTENT_AUDIT, or SECURITY_GROUPS_USAGE_AUDIT"
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="FirewallManager",
        resource_type="AWS::FMS::Policy",
        remediation=Remediation(
            text=(
                "Create an AWS Firewall Manager security group policy in every enabled "
                "Region, using a common security group policy, a content audit policy, "
                "or a usage audit policy as the organization requires."
            ),
            cli="aws fms put-policy --policy file://security-group-policy.json --region <region>",
            console=(
                "AWS Firewall Manager console, Security policies, Create policy, "
                "Security group, then select the policy type. Repeat per Region."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        account_id = self.account_id

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
            sg_policies = [
                p for p in policies
                if p.get("SecurityServiceType") in [
                    "SECURITY_GROUPS_COMMON",
                    "SECURITY_GROUPS_CONTENT_AUDIT",
                    "SECURITY_GROUPS_USAGE_AUDIT"
                ]
            ]

            if not sg_policies:
                yield self.failed(
                    region=region,
                    resource_id=None,
                    actual_value="No security group policies configured",
                    remediation="Create Firewall Manager security group policies: https://docs.aws.amazon.com/waf/latest/developerguide/security-group-policies.html"
                )
            else:
                policy_names = [p.get("PolicyName", "Unknown") for p in sg_policies]
                yield self.passed(
                    region=region,
                    resource_id=",".join([p.get("PolicyId", "") for p in sg_policies]),
                    actual_value=f"{len(sg_policies)} security group policy(ies) configured: {', '.join(policy_names)}"
                )
