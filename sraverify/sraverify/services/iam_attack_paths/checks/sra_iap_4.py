"""
SRA-IAP-4: Transitive privilege escalation check.

Detects multi-hop escalation paths to admin (>= 2 hops) using
BFS/DFS graph traversal. These paths are invisible to IAM Access
Analyzer and represent the highest-risk attack vectors.
"""
from typing import Dict, List, Any

from sraverify.services.iam_attack_paths.base import IAMAttackPathCheck


class SRA_IAP_4(IAMAttackPathCheck):
    """Detect multi-hop transitive escalation paths to admin."""

    def __init__(self):
        """Initialize transitive escalation check."""
        super().__init__()
        self.check_id = "SRA-IAP-4"
        self.check_name = "Transitive Privilege Escalation Paths"
        self.description = (
            "Identifies principals that can reach admin privileges through "
            "multi-hop escalation chains (e.g., AssumeRole -> PassRole -> "
            "Admin). These paths are invisible to IAM Access Analyzer and "
            "represent compound attack vectors."
        )
        self.severity = "CRITICAL"
        self.check_logic = (
            "Build privilege graph from GetAccountAuthorizationDetails. "
            "Run BFS from each non-admin principal. Report paths with "
            ">= 2 hops to any admin node."
        )
        self.remediation = (
            "Break the escalation chain by constraining iam:PassRole "
            "resources, tightening role trust policies, or adding "
            "permissions boundaries."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the transitive escalation analysis.

        Returns:
            List of findings
        """
        graph = self.get_privilege_graph()
        escalation_findings = graph.get_transitive_escalation_findings()

        for finding in escalation_findings:
            self.findings.append(self.create_finding(
                status="FAIL",
                region="global",
                resource_id=finding['principal_arn'],
                actual_value=(
                    f"Path: {finding['path_description']} "
                    f"({finding['path_length']} hops)"
                ),
                remediation=finding['remediation'],
            ))

        if not escalation_findings:
            self.findings.append(self.create_finding(
                status="PASS",
                region="global",
                resource_id="N/A",
                actual_value=(
                    "No multi-hop escalation paths detected"
                ),
                remediation="",
            ))

        return self.findings
