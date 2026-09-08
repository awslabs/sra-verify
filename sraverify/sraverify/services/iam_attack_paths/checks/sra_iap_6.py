"""
SRA-IAP-6: Deny policy detachment check.

Detects principals with permissions to detach or delete policies
from other principals, which can remove protective deny policies
and enable privilege escalation.
"""
from typing import Dict, List, Any

from sraverify.services.iam_attack_paths.base import IAMAttackPathCheck
from sraverify.services.iam_attack_paths.privilege_graph import (
    has_action,
    has_action_on_resource,
)


class SRA_IAP_6(IAMAttackPathCheck):
    """Detect principals that can detach/delete deny policies."""

    def __init__(self):
        """Initialize deny policy detachment check."""
        super().__init__()
        self.check_id = "SRA-IAP-6"
        self.check_name = "Deny Policy Detachment"
        self.description = (
            "Detects IAM principals with iam:DetachUserPolicy, "
            "iam:DetachRolePolicy, iam:DeleteUserPolicy, or "
            "iam:DeleteRolePolicy permissions. These can be used to "
            "remove protective deny policies from principals, enabling "
            "previously blocked escalation paths."
        )
        self.severity = "HIGH"
        self.check_logic = (
            "Check if any non-admin principal has Detach*Policy or "
            "Delete*Policy permissions that could target other principals."
        )
        self.remediation = (
            "Remove policy detachment/deletion permissions from "
            "non-admin principals. Use SCPs to protect critical "
            "deny policies from removal."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the deny policy detachment check.

        Returns:
            List of findings
        """
        graph = self.get_privilege_graph()
        found_escalation = False

        dangerous_actions = [
            'iam:DetachUserPolicy',
            'iam:DetachRolePolicy',
            'iam:DeleteUserPolicy',
            'iam:DeleteRolePolicy',
        ]

        for node in graph.nodes.values():
            if node.is_admin:
                continue

            # Check which dangerous actions this principal has
            has_dangerous = [
                action for action in dangerous_actions
                if has_action(node, action)
            ]

            if not has_dangerous:
                continue

            # Check if they can target other principals
            targetable = []
            for dest in graph.nodes.values():
                if dest.arn == node.arn:
                    continue

                for action in has_dangerous:
                    if ('User' in action and dest.principal_type == 'User'):
                        if has_action_on_resource(node, action, dest.arn):
                            targetable.append(dest.name)
                            break
                    elif ('Role' in action and dest.principal_type == 'Role'):
                        if has_action_on_resource(node, action, dest.arn):
                            targetable.append(dest.name)
                            break

            if targetable:
                found_escalation = True
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=node.arn,
                    actual_value=(
                        f"Has {', '.join(has_dangerous)}; can target: "
                        f"{', '.join(targetable[:10])}"
                        + (f" (+{len(targetable) - 10} more)"
                           if len(targetable) > 10 else "")
                    ),
                    remediation=(
                        f"Remove policy detach/delete permissions from "
                        f"{node.name}. Protect deny policies with SCPs."
                    ),
                ))

        if not found_escalation:
            self.findings.append(self.create_finding(
                status="PASS",
                region="global",
                resource_id="N/A",
                actual_value=(
                    "No deny policy detachment risks detected"
                ),
                remediation="",
            ))

        return self.findings
