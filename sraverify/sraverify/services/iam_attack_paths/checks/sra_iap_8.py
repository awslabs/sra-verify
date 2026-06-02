"""
SRA-IAP-8: Lambda code injection check.

Detects principals with lambda:UpdateFunctionCode who can hijack
existing Lambda functions that have privileged execution roles.
"""
from typing import Dict, List, Any

from sraverify.services.iam_attack_paths.base import IAMAttackPathCheck
from sraverify.services.iam_attack_paths.privilege_graph import (
    has_action,
    has_action_on_resource,
)


class SRA_IAP_8(IAMAttackPathCheck):
    """Detect Lambda code injection privilege escalation."""

    def __init__(self):
        """Initialize Lambda code injection check."""
        super().__init__()
        self.check_id = "SRA-IAP-8"
        self.check_name = "Lambda Code Injection"
        self.description = (
            "Detects IAM principals with lambda:UpdateFunctionCode permission "
            "who can modify the code of existing Lambda functions that run "
            "with privileged execution roles. This allows injecting code that "
            "executes with the function's role permissions."
        )
        self.severity = "HIGH"
        self.check_logic = (
            "Check if any non-admin principal has lambda:UpdateFunctionCode. "
            "Correlate with Lambda functions that have privileged (admin) "
            "execution roles in the privilege graph."
        )
        self.remediation = (
            "Remove lambda:UpdateFunctionCode permission or constrain its "
            "Resource to specific, non-privileged function ARNs. Separate "
            "deployment roles from runtime roles."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the Lambda code injection check.

        Returns:
            List of findings
        """
        graph = self.get_privilege_graph()
        found_escalation = False

        # Find roles that are likely Lambda execution roles (admin)
        admin_roles = [
            n for n in graph.nodes.values()
            if n.principal_type == 'Role' and n.is_admin
        ]

        # Check for Lambda code injection edges in graph
        for node in graph.nodes.values():
            if node.is_admin:
                continue

            if not has_action(node, 'lambda:UpdateFunctionCode'):
                continue

            # This principal can update Lambda code
            # Check if they can target functions with privileged roles
            # (In a full implementation, we'd correlate with actual
            # Lambda functions. Here we check the graph edges.)
            injectable_targets = [
                edge.destination.name
                for edge in node.outbound_edges
                if edge.edge_type == 'LambdaCodeInjection'
            ]

            # Also flag broadly: if UpdateFunctionCode is on Resource: *
            # and admin roles exist, there's risk
            if not injectable_targets and admin_roles:
                # Check if the permission is broadly scoped
                if has_action_on_resource(
                    node, 'lambda:UpdateFunctionCode', '*'
                ):
                    injectable_targets = [
                        f"{r.name} (admin role)"
                        for r in admin_roles[:5]
                    ]

            if injectable_targets:
                found_escalation = True
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=node.arn,
                    actual_value=(
                        f"Can inject code into Lambda functions with "
                        f"privileged roles: "
                        f"{', '.join(injectable_targets[:5])}"
                        + (f" (+{len(injectable_targets) - 5} more)"
                           if len(injectable_targets) > 5 else "")
                    ),
                    remediation=(
                        f"Constrain lambda:UpdateFunctionCode on "
                        f"{node.name} to specific non-privileged "
                        f"function ARNs."
                    ),
                ))

        if not found_escalation:
            self.findings.append(self.create_finding(
                status="PASS",
                region="global",
                resource_id="N/A",
                actual_value=(
                    "No Lambda code injection risks detected"
                ),
                remediation="",
            ))

        return self.findings
