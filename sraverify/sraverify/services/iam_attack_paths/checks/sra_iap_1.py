"""
SRA-IAP-1: PassRole + EC2 privilege escalation check.

Detects principals with iam:PassRole (Resource: *) combined with
ec2:RunInstances, which allows launching EC2 instances with any
role and stealing credentials via IMDS.
"""
from typing import Dict, List, Any

from sraverify.services.iam_attack_paths.base import IAMAttackPathCheck
from sraverify.services.iam_attack_paths.privilege_graph import (
    EdgeType,
    has_action,
    has_passrole_on,
)


class SRA_IAP_1(IAMAttackPathCheck):
    """Detect principals with PassRole + EC2 RunInstances escalation."""

    def __init__(self):
        """Initialize PassRole + EC2 check."""
        super().__init__()
        self.check_id = "SRA-IAP-1"
        self.check_name = "PassRole + EC2 Privilege Escalation"
        self.description = (
            "Detects IAM principals that have iam:PassRole with broad "
            "resource scope combined with ec2:RunInstances. This allows "
            "launching an EC2 instance with any privileged role attached "
            "and stealing credentials via the Instance Metadata Service (IMDS)."
        )
        self.severity = "HIGH"
        self.check_logic = (
            "Check if principal has iam:PassRole (Resource: *) AND "
            "ec2:RunInstances. Flag if target roles with instance profiles exist."
        )
        self.remediation = (
            "Constrain iam:PassRole Resource to specific role ARNs instead "
            "of '*'. Add iam:PassedToService condition key to limit which "
            "services can receive the passed role."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the PassRole + EC2 check.

        Returns:
            List of findings
        """
        graph = self.get_privilege_graph()
        found_escalation = False

        for node in graph.nodes.values():
            if node.is_admin:
                continue

            # Check if this principal has the dangerous combo
            if not has_action(node, 'ec2:RunInstances'):
                continue
            if not has_action(node, 'iam:PassRole'):
                continue

            # Find roles with instance profiles that can be passed
            passable_admin_roles = []
            for dest in graph.nodes.values():
                if dest.principal_type != 'Role':
                    continue
                if not dest.instance_profiles:
                    continue
                if has_passrole_on(node, dest) and dest.is_admin:
                    passable_admin_roles.append(dest.name)

            # Also flag if PassRole is on Resource: * (any role)
            has_wildcard_passrole = any(
                edge.edge_type == EdgeType.PASSROLE_EC2
                for edge in node.outbound_edges
            )

            if has_wildcard_passrole or passable_admin_roles:
                found_escalation = True
                target_info = (
                    f"Can pass roles: {', '.join(passable_admin_roles)}"
                    if passable_admin_roles
                    else "Has PassRole + EC2 RunInstances (broad scope)"
                )
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=node.arn,
                    actual_value=target_info,
                    remediation=(
                        f"Constrain iam:PassRole on {node.name} to specific "
                        f"role ARNs. Remove ec2:RunInstances if not required."
                    ),
                ))

        if not found_escalation:
            self.findings.append(self.create_finding(
                status="PASS",
                region="global",
                resource_id="N/A",
                actual_value="No PassRole + EC2 escalation paths detected",
                remediation="",
            ))

        return self.findings
