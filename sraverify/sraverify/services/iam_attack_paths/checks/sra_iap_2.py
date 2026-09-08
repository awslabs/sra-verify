"""
SRA-IAP-2: CreatePolicyVersion privilege escalation check.

Detects principals with iam:CreatePolicyVersion on their own
attached managed policies, which is a single-step path to admin.
"""
from typing import Dict, List, Any

from sraverify.services.iam_attack_paths.base import IAMAttackPathCheck
from sraverify.services.iam_attack_paths.privilege_graph import (
    has_action,
    has_action_on_resource,
)


class SRA_IAP_2(IAMAttackPathCheck):
    """Detect principals with CreatePolicyVersion self-escalation."""

    def __init__(self):
        """Initialize CreatePolicyVersion check."""
        super().__init__()
        self.check_id = "SRA-IAP-2"
        self.check_name = "CreatePolicyVersion Self-Escalation"
        self.description = (
            "Detects IAM principals with iam:CreatePolicyVersion permission "
            "on their own attached managed policies. This allows creating a "
            "new policy version with Action:* Resource:* and setting it as "
            "default — a one-call path to admin."
        )
        self.severity = "CRITICAL"
        self.check_logic = (
            "For each principal with iam:CreatePolicyVersion, check if they "
            "can target their own attached managed policy ARNs."
        )
        self.remediation = (
            "Remove iam:CreatePolicyVersion permission or constrain its "
            "Resource to exclude the principal's own policies. Use SCPs "
            "to deny this action broadly."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the CreatePolicyVersion check.

        Returns:
            List of findings
        """
        graph = self.get_privilege_graph()
        auth_details = self.get_auth_details()
        found_escalation = False

        for node in graph.nodes.values():
            if node.is_admin:
                continue

            if not has_action(node, 'iam:CreatePolicyVersion'):
                continue

            # Get this principal's attached managed policy ARNs
            attached_policy_arns = self._get_attached_policy_arns(
                node.arn, node.principal_type, auth_details
            )

            # Check if they can CreatePolicyVersion on their own policies
            vulnerable_policies = []
            for policy_arn in attached_policy_arns:
                if has_action_on_resource(
                    node, 'iam:CreatePolicyVersion', policy_arn
                ):
                    vulnerable_policies.append(policy_arn)

            if vulnerable_policies:
                found_escalation = True
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=node.arn,
                    actual_value=(
                        f"Can CreatePolicyVersion on own policies: "
                        f"{', '.join(vulnerable_policies)}"
                    ),
                    remediation=(
                        f"Remove iam:CreatePolicyVersion from {node.name} "
                        f"or constrain Resource to exclude own policies."
                    ),
                ))

        if not found_escalation:
            self.findings.append(self.create_finding(
                status="PASS",
                region="global",
                resource_id="N/A",
                actual_value=(
                    "No CreatePolicyVersion self-escalation detected"
                ),
                remediation="",
            ))

        return self.findings

    def _get_attached_policy_arns(
        self, principal_arn: str, principal_type: str,
        auth_details: Dict[str, Any]
    ) -> List[str]:
        """
        Get managed policy ARNs attached to a principal.

        Args:
            principal_arn: ARN of the principal
            principal_type: 'User' or 'Role'
            auth_details: Full authorization details

        Returns:
            List of attached managed policy ARNs
        """
        if principal_type == 'User':
            for user in auth_details.get('users', []):
                if user.get('Arn') == principal_arn:
                    return [
                        p['PolicyArn']
                        for p in user.get('AttachedManagedPolicies', [])
                    ]
        elif principal_type == 'Role':
            for role in auth_details.get('roles', []):
                if role.get('Arn') == principal_arn:
                    return [
                        p['PolicyArn']
                        for p in role.get('AttachedManagedPolicies', [])
                    ]
        return []
