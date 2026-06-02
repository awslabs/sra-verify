"""
SRA-IAP-5: Permissions boundary removal check.

Detects principals with iam:DeleteUserPermissionsBoundary or
iam:DeleteRolePermissionsBoundary, which can remove protective
guardrails from other principals.
"""
from typing import Dict, List, Any

from sraverify.services.iam_attack_paths.base import IAMAttackPathCheck
from sraverify.services.iam_attack_paths.privilege_graph import (
    has_action,
    has_action_on_resource,
)


class SRA_IAP_5(IAMAttackPathCheck):
    """Detect principals that can remove permissions boundaries."""

    def __init__(self):
        """Initialize permissions boundary removal check."""
        super().__init__()
        self.check_id = "SRA-IAP-5"
        self.check_name = "Permissions Boundary Removal"
        self.description = (
            "Detects IAM principals with iam:DeleteUserPermissionsBoundary "
            "or iam:DeleteRolePermissionsBoundary permissions. Removing a "
            "permissions boundary can instantly escalate a bounded principal "
            "to their full policy permissions."
        )
        self.severity = "HIGH"
        self.check_logic = (
            "Check if any principal has Delete*PermissionsBoundary "
            "permissions targeting principals that have boundaries attached."
        )
        self.remediation = (
            "Remove iam:Delete*PermissionsBoundary permissions. Use SCPs "
            "to deny boundary removal across the organization."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the permissions boundary removal check.

        Returns:
            List of findings
        """
        graph = self.get_privilege_graph()
        found_escalation = False

        # Find principals with boundaries
        bounded_principals = [
            n for n in graph.nodes.values()
            if n.has_permissions_boundary
        ]

        for node in graph.nodes.values():
            if node.is_admin:
                continue

            can_remove_user_boundary = has_action(
                node, 'iam:DeleteUserPermissionsBoundary'
            )
            can_remove_role_boundary = has_action(
                node, 'iam:DeleteRolePermissionsBoundary'
            )

            if not (can_remove_user_boundary or can_remove_role_boundary):
                continue

            # Check which bounded principals they can target
            targets = []
            for bounded in bounded_principals:
                if bounded.arn == node.arn:
                    continue
                if (bounded.principal_type == 'User'
                        and can_remove_user_boundary):
                    if has_action_on_resource(
                        node, 'iam:DeleteUserPermissionsBoundary',
                        bounded.arn
                    ):
                        targets.append(bounded.name)
                elif (bounded.principal_type == 'Role'
                      and can_remove_role_boundary):
                    if has_action_on_resource(
                        node, 'iam:DeleteRolePermissionsBoundary',
                        bounded.arn
                    ):
                        targets.append(bounded.name)

            if targets:
                found_escalation = True
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=node.arn,
                    actual_value=(
                        f"Can remove permissions boundary from: "
                        f"{', '.join(targets[:10])}"
                        + (f" (+{len(targets) - 10} more)"
                           if len(targets) > 10 else "")
                    ),
                    remediation=(
                        f"Remove iam:Delete*PermissionsBoundary from "
                        f"{node.name}. Use SCP to deny this action."
                    ),
                ))

        if not found_escalation:
            self.findings.append(self.create_finding(
                status="PASS",
                region="global",
                resource_id="N/A",
                actual_value=(
                    "No permissions boundary removal risks detected"
                ),
                remediation="",
            ))

        return self.findings
