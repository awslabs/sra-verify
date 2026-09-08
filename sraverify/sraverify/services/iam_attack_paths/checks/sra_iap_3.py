"""
SRA-IAP-3: PassRole + Lambda privilege escalation check.

Detects principals with iam:PassRole + lambda:CreateFunction +
lambda:InvokeFunction, which allows creating a Lambda function
with a privileged role and invoking it to steal credentials.
"""
from typing import Dict, List, Any

from sraverify.services.iam_attack_paths.base import IAMAttackPathCheck
from sraverify.services.iam_attack_paths.privilege_graph import (
    EdgeType,
    has_action,
    has_passrole_on,
)


class SRA_IAP_3(IAMAttackPathCheck):
    """Detect principals with PassRole + Lambda escalation."""

    def __init__(self):
        """Initialize PassRole + Lambda check."""
        super().__init__()
        self.check_id = "SRA-IAP-3"
        self.check_name = "PassRole + Lambda Privilege Escalation"
        self.description = (
            "Detects IAM principals that have iam:PassRole combined with "
            "lambda:CreateFunction and lambda:InvokeFunction. This allows "
            "creating a Lambda function with a privileged execution role "
            "and invoking it to execute arbitrary code with that role's "
            "permissions."
        )
        self.severity = "HIGH"
        self.check_logic = (
            "Check if principal has iam:PassRole + lambda:CreateFunction + "
            "lambda:InvokeFunction. Flag if any passable target roles exist."
        )
        self.remediation = (
            "Constrain iam:PassRole Resource to specific role ARNs. Add "
            "iam:PassedToService condition key limiting to "
            "lambda.amazonaws.com only for intended roles."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the PassRole + Lambda check.

        Returns:
            List of findings
        """
        graph = self.get_privilege_graph()
        found_escalation = False

        for node in graph.nodes.values():
            if node.is_admin:
                continue

            if not has_action(node, 'iam:PassRole'):
                continue
            if not has_action(node, 'lambda:CreateFunction'):
                continue
            if not has_action(node, 'lambda:InvokeFunction'):
                continue

            # Find privileged roles that can be passed
            passable_roles = []
            for dest in graph.nodes.values():
                if dest.principal_type != 'Role':
                    continue
                if has_passrole_on(node, dest) and dest.is_admin:
                    passable_roles.append(dest.name)

            # Check for PassRole+Lambda edges in graph
            has_lambda_edge = any(
                edge.edge_type == EdgeType.PASSROLE_LAMBDA
                for edge in node.outbound_edges
            )

            if has_lambda_edge or passable_roles:
                found_escalation = True
                target_info = (
                    f"Can pass admin roles to Lambda: "
                    f"{', '.join(passable_roles)}"
                    if passable_roles
                    else "Has PassRole + Lambda Create/Invoke (broad scope)"
                )
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=node.arn,
                    actual_value=target_info,
                    remediation=(
                        f"Constrain iam:PassRole on {node.name} to specific "
                        f"Lambda execution role ARNs."
                    ),
                ))

        if not found_escalation:
            self.findings.append(self.create_finding(
                status="PASS",
                region="global",
                resource_id="N/A",
                actual_value=(
                    "No PassRole + Lambda escalation paths detected"
                ),
                remediation="",
            ))

        return self.findings
