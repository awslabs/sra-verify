"""
Base class for IAM Attack Path security checks.

Provides class-level caching for authorization details and the
privilege graph, ensuring the graph is built once and shared
across all IAP check instances.
"""
from typing import Dict, List, Optional, Any, Set
from sraverify.core.check import SecurityCheck
from sraverify.services.iam_attack_paths.client import IAMAttackPathClient
from sraverify.core.logging import logger


class IAMAttackPathCheck(SecurityCheck):
    """Base class for all IAM Attack Path security checks."""

    # Class-level caches shared across all instances
    _auth_details_cache: Optional[Dict[str, List[Dict[str, Any]]]] = None
    _privilege_graph_cache = None
    _clients: Dict[str, IAMAttackPathClient] = {}

    def __init__(self):
        """Initialize IAM Attack Path base check."""
        super().__init__(
            account_type="application",
            service="IAM Attack Paths",
            resource_type="AWS::IAM::Principal"
        )

    def _setup_clients(self):
        """Set up IAM client (global, us-east-1 only)."""
        if 'us-east-1' not in IAMAttackPathCheck._clients:
            IAMAttackPathCheck._clients['us-east-1'] = IAMAttackPathClient(
                region='us-east-1', session=self.session
            )
        self._clients = IAMAttackPathCheck._clients

    def get_client(self, region: str = 'us-east-1') -> Optional[IAMAttackPathClient]:
        """
        Get IAM Attack Path client.

        Args:
            region: AWS region (defaults to us-east-1 for IAM global)

        Returns:
            IAMAttackPathClient instance or None
        """
        return self._clients.get(region)

    def get_auth_details(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get account authorization details with class-level caching.

        Returns:
            Authorization details dictionary with users, roles, groups, policies
        """
        if IAMAttackPathCheck._auth_details_cache is not None:
            logger.debug("IAMAttackPath: Using cached authorization details")
            return IAMAttackPathCheck._auth_details_cache

        client = self.get_client()
        if not client:
            logger.error("IAMAttackPath: No IAM client available")
            return {'users': [], 'roles': [], 'groups': [], 'policies': []}

        logger.debug("IAMAttackPath: Fetching authorization details (first call)")
        IAMAttackPathCheck._auth_details_cache = (
            client.get_account_authorization_details()
        )
        return IAMAttackPathCheck._auth_details_cache

    def get_privilege_graph(self):
        """
        Get the privilege graph with class-level caching.

        The graph is built once from authorization details and shared
        across all IAP check instances.

        Returns:
            PrivilegeGraph instance
        """
        if IAMAttackPathCheck._privilege_graph_cache is not None:
            logger.debug("IAMAttackPath: Using cached privilege graph")
            return IAMAttackPathCheck._privilege_graph_cache

        # Import here to avoid circular imports
        from sraverify.services.iam_attack_paths.privilege_graph import PrivilegeGraph

        auth_details = self.get_auth_details()
        logger.debug("IAMAttackPath: Building privilege graph (first call)")
        IAMAttackPathCheck._privilege_graph_cache = PrivilegeGraph(
            auth_details, self.session
        )

        stats = IAMAttackPathCheck._privilege_graph_cache.stats
        logger.debug(
            f"IAMAttackPath: Graph built — {stats['total_nodes']} nodes, "
            f"{stats['total_edges']} edges, {stats['admin_nodes']} admins"
        )
        return IAMAttackPathCheck._privilege_graph_cache

    @staticmethod
    def is_admin_policy(policy_document: Dict[str, Any]) -> bool:
        """
        Check if a policy document grants full admin access.

        A policy is admin if any statement has:
        Effect: Allow, Action: *, Resource: *

        Args:
            policy_document: IAM policy document

        Returns:
            True if the policy grants admin access
        """
        statements = policy_document.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get('Effect') != 'Allow':
                continue

            actions = stmt.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]

            resources = stmt.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]

            if '*' in actions and '*' in resources:
                return True

        return False

    @staticmethod
    def principal_has_action(
        effective_actions: Set[str], action: str
    ) -> bool:
        """
        Check if a set of effective actions includes the specified action.

        Handles wildcard matching (e.g., 'iam:*' matches 'iam:PassRole').

        Args:
            effective_actions: Set of action patterns the principal has
            action: The action to check for

        Returns:
            True if the action is covered by effective_actions
        """
        import fnmatch

        action_lower = action.lower()
        for pattern in effective_actions:
            if pattern == '*':
                return True
            if fnmatch.fnmatch(action_lower, pattern.lower()):
                return True
        return False

    @classmethod
    def reset_caches(cls):
        """Reset all class-level caches. Used in testing."""
        cls._auth_details_cache = None
        cls._privilege_graph_cache = None
        cls._clients = {}
