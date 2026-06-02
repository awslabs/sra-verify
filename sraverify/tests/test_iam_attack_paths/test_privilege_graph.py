"""
Tests for the privilege graph engine.

Covers: graph construction, policy evaluation, BFS/DFS queries.
"""
import pytest

from sraverify.services.iam_attack_paths.privilege_graph import (
    PrivilegeGraph,
    PrincipalNode,
    EdgeType,
    build_nodes,
    build_edges,
    has_action,
    has_action_on_resource,
    trust_policy_allows,
    can_assume_role,
    has_passrole_on,
    find_path_to_admin,
    find_all_paths_to_admin,
    find_transitive_escalation_paths,
    compute_blast_radius,
)


class TestPolicyEvaluation:
    """Tests for local policy evaluation functions."""

    def test_has_action_exact_match(self):
        """Action exactly matches."""
        node = PrincipalNode(
            arn="arn:aws:iam::123456789012:user/test",
            name="test",
            principal_type="User",
            effective_actions={'iam:PassRole', 's3:GetObject'},
        )
        assert has_action(node, 'iam:PassRole') is True
        assert has_action(node, 's3:GetObject') is True
        assert has_action(node, 'ec2:RunInstances') is False

    def test_has_action_wildcard_star(self):
        """Wildcard '*' matches everything."""
        node = PrincipalNode(
            arn="arn:aws:iam::123456789012:user/admin",
            name="admin",
            principal_type="User",
            effective_actions={'*'},
        )
        assert has_action(node, 'iam:PassRole') is True
        assert has_action(node, 'anything:AtAll') is True

    def test_has_action_service_wildcard(self):
        """Service wildcard 'iam:*' matches service actions."""
        node = PrincipalNode(
            arn="arn:aws:iam::123456789012:user/test",
            name="test",
            principal_type="User",
            effective_actions={'iam:*'},
        )
        assert has_action(node, 'iam:PassRole') is True
        assert has_action(node, 'iam:CreateUser') is True
        assert has_action(node, 's3:GetObject') is False

    def test_has_action_case_insensitive(self):
        """Action matching is case-insensitive."""
        node = PrincipalNode(
            arn="arn:aws:iam::123456789012:user/test",
            name="test",
            principal_type="User",
            effective_actions={'IAM:PassRole'},
        )
        assert has_action(node, 'iam:passrole') is True
        assert has_action(node, 'iam:PassRole') is True

    def test_has_action_on_resource_wildcard(self):
        """Resource: '*' allows any resource."""
        node = PrincipalNode(
            arn="arn:aws:iam::123456789012:user/test",
            name="test",
            principal_type="User",
            effective_actions={'iam:PassRole'},
            policy_statements=[{
                'Effect': 'Allow',
                'Action': 'iam:PassRole',
                'Resource': '*',
            }],
        )
        assert has_action_on_resource(
            node, 'iam:PassRole',
            'arn:aws:iam::123456789012:role/any-role'
        ) is True

    def test_has_action_on_resource_constrained(self):
        """Constrained Resource only matches specific ARNs."""
        node = PrincipalNode(
            arn="arn:aws:iam::123456789012:user/test",
            name="test",
            principal_type="User",
            effective_actions={'iam:PassRole'},
            policy_statements=[{
                'Effect': 'Allow',
                'Action': 'iam:PassRole',
                'Resource': 'arn:aws:iam::123456789012:role/app-*',
            }],
        )
        assert has_action_on_resource(
            node, 'iam:PassRole',
            'arn:aws:iam::123456789012:role/app-web'
        ) is True
        assert has_action_on_resource(
            node, 'iam:PassRole',
            'arn:aws:iam::123456789012:role/admin-role'
        ) is False

    def test_has_action_on_resource_explicit_deny(self):
        """Explicit Deny overrides Allow."""
        node = PrincipalNode(
            arn="arn:aws:iam::123456789012:user/test",
            name="test",
            principal_type="User",
            effective_actions={'iam:PassRole'},
            policy_statements=[
                {
                    'Effect': 'Allow',
                    'Action': 'iam:PassRole',
                    'Resource': '*',
                },
                {
                    'Effect': 'Deny',
                    'Action': 'iam:PassRole',
                    'Resource': 'arn:aws:iam::123456789012:role/protected-*',
                },
            ],
        )
        assert has_action_on_resource(
            node, 'iam:PassRole',
            'arn:aws:iam::123456789012:role/protected-admin'
        ) is False
        assert has_action_on_resource(
            node, 'iam:PassRole',
            'arn:aws:iam::123456789012:role/app-role'
        ) is True

    def test_trust_policy_allows_exact_arn(self):
        """Trust policy allows specific ARN."""
        trust = {
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {
                    'AWS': 'arn:aws:iam::123456789012:user/attacker'
                },
                'Action': 'sts:AssumeRole'
            }]
        }
        assert trust_policy_allows(
            trust, 'arn:aws:iam::123456789012:user/attacker'
        ) is True
        assert trust_policy_allows(
            trust, 'arn:aws:iam::123456789012:user/other'
        ) is False

    def test_trust_policy_allows_account_root(self):
        """Trust policy with :root allows any principal in account."""
        trust = {
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {
                    'AWS': 'arn:aws:iam::123456789012:root'
                },
                'Action': 'sts:AssumeRole'
            }]
        }
        assert trust_policy_allows(
            trust, 'arn:aws:iam::123456789012:user/anyone'
        ) is True
        assert trust_policy_allows(
            trust, 'arn:aws:iam::999999999999:user/other-account'
        ) is False

    def test_trust_policy_allows_wildcard(self):
        """Trust policy with '*' allows everyone."""
        trust = {
            'Statement': [{
                'Effect': 'Allow',
                'Principal': '*',
                'Action': 'sts:AssumeRole'
            }]
        }
        assert trust_policy_allows(
            trust, 'arn:aws:iam::999999999999:user/anyone'
        ) is True


class TestGraphConstruction:
    """Tests for node and edge construction."""

    def test_build_nodes_users(self, least_privilege_auth_details):
        """Users are correctly built as nodes."""
        nodes = build_nodes(least_privilege_auth_details)
        user_arn = 'arn:aws:iam::123456789012:user/readonly'
        assert user_arn in nodes
        node = nodes[user_arn]
        assert node.principal_type == 'User'
        assert node.name == 'readonly'
        assert node.is_admin is False

    def test_build_nodes_admin_detection(self, least_privilege_auth_details):
        """Admin roles are correctly detected."""
        nodes = build_nodes(least_privilege_auth_details)
        admin_arn = 'arn:aws:iam::123456789012:role/admin-role'
        assert admin_arn in nodes
        assert nodes[admin_arn].is_admin is True

    def test_build_nodes_skips_service_linked_roles(self):
        """Service-linked roles are excluded."""
        auth = {
            'users': [],
            'roles': [{
                'Arn': 'arn:aws:iam::123456789012:role/aws-service-role/sso.amazonaws.com/AWSServiceRoleForSSO',
                'RoleName': 'AWSServiceRoleForSSO',
                'Path': '/aws-service-role/sso.amazonaws.com/',
                'AssumeRolePolicyDocument': {},
                'RolePolicyList': [],
                'AttachedManagedPolicies': [],
                'InstanceProfileList': [],
                'Tags': [],
            }],
            'groups': [],
            'policies': [],
        }
        nodes = build_nodes(auth)
        assert len(nodes) == 0

    def test_build_edges_passrole_ec2(self, passrole_ec2_auth_details):
        """PassRole+EC2 edge is created correctly."""
        nodes = build_nodes(passrole_ec2_auth_details)
        edges = build_edges(nodes, passrole_ec2_auth_details)

        passrole_edges = [
            e for e in edges if e.edge_type == EdgeType.PASSROLE_EC2
        ]
        assert len(passrole_edges) >= 1
        assert passrole_edges[0].source.name == 'attacker'
        assert passrole_edges[0].destination.name == 'admin-role'

    def test_build_edges_assume_role(self, multi_hop_auth_details):
        """AssumeRole edges are created for matching trust policies."""
        nodes = build_nodes(multi_hop_auth_details)
        edges = build_edges(nodes, multi_hop_auth_details)

        assume_edges = [
            e for e in edges if e.edge_type == EdgeType.ASSUME_ROLE
        ]
        # attacker -> middle-role, middle-role -> admin-role
        assert len(assume_edges) == 2

    def test_no_edges_for_least_privilege(self, least_privilege_auth_details):
        """Read-only user generates no escalation edges."""
        nodes = build_nodes(least_privilege_auth_details)
        edges = build_edges(nodes, least_privilege_auth_details)
        assert len(edges) == 0


class TestGraphTraversal:
    """Tests for BFS/DFS path finding."""

    def test_find_path_to_admin_direct(self, passrole_ec2_auth_details):
        """Direct one-hop path to admin is found."""
        nodes = build_nodes(passrole_ec2_auth_details)
        build_edges(nodes, passrole_ec2_auth_details)

        path = find_path_to_admin(
            nodes, 'arn:aws:iam::123456789012:user/attacker'
        )
        assert path is not None
        assert len(path) == 1
        assert path[0].destination.is_admin is True

    def test_find_path_to_admin_multi_hop(self, multi_hop_auth_details):
        """Multi-hop path (attacker -> middle -> admin) is found."""
        nodes = build_nodes(multi_hop_auth_details)
        build_edges(nodes, multi_hop_auth_details)

        path = find_path_to_admin(
            nodes, 'arn:aws:iam::123456789012:user/attacker'
        )
        assert path is not None
        assert len(path) == 2
        assert path[0].destination.name == 'middle-role'
        assert path[1].destination.name == 'admin-role'

    def test_no_path_for_least_privilege(self, least_privilege_auth_details):
        """Read-only user has no path to admin."""
        nodes = build_nodes(least_privilege_auth_details)
        build_edges(nodes, least_privilege_auth_details)

        path = find_path_to_admin(
            nodes, 'arn:aws:iam::123456789012:user/readonly'
        )
        assert path is None

    def test_find_all_paths(self, multi_hop_auth_details):
        """DFS finds all paths."""
        nodes = build_nodes(multi_hop_auth_details)
        build_edges(nodes, multi_hop_auth_details)

        paths = find_all_paths_to_admin(
            nodes, 'arn:aws:iam::123456789012:user/attacker'
        )
        assert len(paths) >= 1

    def test_transitive_escalation_multi_hop_only(
        self, multi_hop_auth_details
    ):
        """Transitive escalation only reports >= 2 hops."""
        nodes = build_nodes(multi_hop_auth_details)
        build_edges(nodes, multi_hop_auth_details)

        findings = find_transitive_escalation_paths(nodes)
        # attacker has a 2-hop path
        assert len(findings) >= 1
        assert all(f['path_length'] >= 2 for f in findings)

    def test_blast_radius(self, multi_hop_auth_details):
        """Blast radius correctly counts reachable nodes."""
        nodes = build_nodes(multi_hop_auth_details)
        build_edges(nodes, multi_hop_auth_details)

        radius = compute_blast_radius(
            nodes, 'arn:aws:iam::123456789012:user/attacker'
        )
        assert radius['total_reachable'] >= 2
        assert radius['admin_reachable'] is True

    def test_depth_limit_respected(self, multi_hop_auth_details):
        """Max depth limit prevents infinite search."""
        nodes = build_nodes(multi_hop_auth_details)
        build_edges(nodes, multi_hop_auth_details)

        # With max_depth=1, the 2-hop path should not be found
        path = find_path_to_admin(
            nodes, 'arn:aws:iam::123456789012:user/attacker',
            max_depth=1
        )
        assert path is None


class TestPrivilegeGraphClass:
    """Tests for the PrivilegeGraph wrapper class."""

    def test_graph_construction(self, multi_hop_auth_details):
        """PrivilegeGraph builds correctly from auth details."""
        graph = PrivilegeGraph(multi_hop_auth_details, session=None)
        assert graph.stats['total_nodes'] == 3
        assert graph.stats['admin_nodes'] == 1
        assert graph.stats['total_edges'] >= 2

    def test_query_path_to_admin(self, multi_hop_auth_details):
        """PrivilegeGraph.query_path_to_admin works."""
        graph = PrivilegeGraph(multi_hop_auth_details, session=None)
        path = graph.query_path_to_admin(
            'arn:aws:iam::123456789012:user/attacker'
        )
        assert path is not None
        assert len(path) == 2

    def test_stats(self, passrole_ec2_auth_details):
        """Stats property returns correct values."""
        graph = PrivilegeGraph(passrole_ec2_auth_details, session=None)
        stats = graph.stats
        assert stats['users'] == 1
        assert stats['roles'] == 1
        assert stats['total_nodes'] == 2
