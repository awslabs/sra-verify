"""
SRA-IAP-7: Cross-account trust without ExternalId check.

Detects roles with cross-account trust policies that do not require
an ExternalId condition, making them vulnerable to confused deputy
attacks.
"""
from typing import Dict, List, Any

from sraverify.services.iam_attack_paths.base import IAMAttackPathCheck
from sraverify.core.logging import logger


class SRA_IAP_7(IAMAttackPathCheck):
    """Detect cross-account trust without ExternalId."""

    def __init__(self):
        """Initialize cross-account trust check."""
        super().__init__()
        self.check_id = "SRA-IAP-7"
        self.check_name = "Cross-Account Trust Without ExternalId"
        self.description = (
            "Detects IAM roles with cross-account trust policies that do "
            "not require a Condition with sts:ExternalId. Without ExternalId, "
            "these roles are vulnerable to confused deputy attacks where a "
            "third-party service could be tricked into assuming the role."
        )
        self.severity = "MEDIUM"
        self.check_logic = (
            "Scan all role trust policies for cross-account AWS principals. "
            "Check if Condition: StringEquals: sts:ExternalId is present."
        )
        self.remediation = (
            "Add a Condition block requiring sts:ExternalId to all "
            "cross-account trust policies. Use unique ExternalId values "
            "per trusted account relationship."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the cross-account trust check.

        Returns:
            List of findings
        """
        graph = self.get_privilege_graph()
        found_issues = False

        # Determine current account ID from any node ARN
        current_account = self._get_current_account(graph)

        for node in graph.nodes.values():
            if node.principal_type != 'Role':
                continue
            if not node.trust_policy:
                continue

            cross_account_principals = self._find_cross_account_trusts(
                node.trust_policy, current_account
            )

            if not cross_account_principals:
                continue

            # Check if ExternalId condition exists
            has_external_id = self._has_external_id_condition(
                node.trust_policy
            )

            if not has_external_id:
                found_issues = True
                self.findings.append(self.create_finding(
                    status="FAIL",
                    region="global",
                    resource_id=node.arn,
                    actual_value=(
                        f"Cross-account trust without ExternalId. "
                        f"Trusted accounts: "
                        f"{', '.join(cross_account_principals[:5])}"
                    ),
                    remediation=(
                        f"Add sts:ExternalId condition to {node.name}'s "
                        f"trust policy for cross-account principals."
                    ),
                ))

        if not found_issues:
            self.findings.append(self.create_finding(
                status="PASS",
                region="global",
                resource_id="N/A",
                actual_value=(
                    "All cross-account trusts require ExternalId "
                    "or no cross-account trusts exist"
                ),
                remediation="",
            ))

        return self.findings

    def _get_current_account(self, graph) -> str:
        """Get current account ID from node ARNs."""
        for node in graph.nodes.values():
            parts = node.arn.split(':')
            if len(parts) >= 5:
                return parts[4]
        return ""

    def _find_cross_account_trusts(
        self, trust_policy: Dict, current_account: str
    ) -> List[str]:
        """
        Find cross-account AWS principals in a trust policy.

        Args:
            trust_policy: Role trust policy document
            current_account: Current AWS account ID

        Returns:
            List of cross-account principal identifiers
        """
        cross_account = []
        statements = trust_policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get('Effect') != 'Allow':
                continue

            principals = stmt.get('Principal', {})
            if isinstance(principals, str):
                if principals == '*':
                    cross_account.append('*')
                    continue
                principals = {'AWS': [principals]}

            aws_principals = principals.get('AWS', [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]

            for principal in aws_principals:
                if principal == '*':
                    cross_account.append('*')
                    continue

                # Extract account from ARN
                parts = principal.split(':')
                if len(parts) >= 5:
                    account = parts[4]
                    if account and account != current_account:
                        cross_account.append(principal)

        return cross_account

    def _has_external_id_condition(self, trust_policy: Dict) -> bool:
        """
        Check if trust policy has sts:ExternalId condition.

        Args:
            trust_policy: Role trust policy document

        Returns:
            True if ExternalId condition is present
        """
        statements = trust_policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get('Effect') != 'Allow':
                continue

            condition = stmt.get('Condition', {})

            # Check StringEquals and StringLike for sts:ExternalId
            for operator in ['StringEquals', 'StringLike',
                             'ForAnyValue:StringEquals']:
                cond_block = condition.get(operator, {})
                if 'sts:ExternalId' in cond_block:
                    return True

        return False
