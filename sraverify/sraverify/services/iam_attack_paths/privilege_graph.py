"""
Lightweight in-memory privilege graph for IAM attack path analysis.

Design principles:
- Single data source: GetAccountAuthorizationDetails (1 API call)
- No external deps (no networkx, no neo4j)
- Class-level caching: graph built once, shared across all IAP checks
- O(V + E) traversal for path queries
- Designed for accounts up to ~1000 principals
"""
import fnmatch
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any

from sraverify.core.logging import logger


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------


@dataclass
class PrincipalNode:
    """Represents an IAM User or Role in the privilege graph."""

    arn: str
    name: str
    principal_type: str  # "User" or "Role"

    # Effective permissions (resolved from all attached + inline policies)
    effective_actions: Set[str] = field(default_factory=set)

    # Full policy statements for resource-level evaluation
    policy_statements: List[Dict[str, Any]] = field(default_factory=list)

    # For roles: the trust policy
    trust_policy: Optional[Dict] = None

    # Flags
    is_admin: bool = False
    has_permissions_boundary: bool = False
    permissions_boundary_arn: Optional[str] = None

    # Graph connectivity (built during edge generation)
    outbound_edges: List['PrivilegeEdge'] = field(default_factory=list)
    inbound_edges: List['PrivilegeEdge'] = field(default_factory=list)

    # Metadata
    instance_profiles: List[str] = field(default_factory=list)
    group_memberships: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class PrivilegeEdge:
    """Represents an escalation path from source to destination."""

    source: PrincipalNode
    destination: PrincipalNode
    edge_type: str
    reason: str
    required_permissions: List[str]
    severity: str
    intermediary_service: Optional[str] = None


class EdgeType:
    """Enumeration of privilege escalation edge types."""

    ASSUME_ROLE = "AssumeRole"
    PASSROLE_EC2 = "PassRole+EC2"
    PASSROLE_LAMBDA = "PassRole+Lambda"
    PASSROLE_CLOUDFORMATION = "PassRole+CloudFormation"
    PASSROLE_GLUE = "PassRole+Glue"
    PASSROLE_ECS = "PassRole+ECS"
    POLICY_ATTACH = "PolicyAttach"
    POLICY_CREATE_VERSION = "PolicyCreateVersion"
    POLICY_PUT_INLINE = "PolicyPutInline"
    CREATE_ACCESS_KEY = "CreateAccessKey"
    UPDATE_LOGIN_PROFILE = "UpdateLoginProfile"
    ADD_TO_GROUP = "AddToGroup"
    UPDATE_TRUST_POLICY = "UpdateAssumeRolePolicy"
    LAMBDA_CODE_INJECTION = "LambdaCodeInjection"
    REMOVE_PERMISSIONS_BOUNDARY = "RemovePermissionsBoundary"


# Actions that indicate a principal may be involved in escalation
ESCALATION_ACTIONS = {
    'iam:PassRole', 'iam:CreatePolicyVersion', 'iam:AttachUserPolicy',
    'iam:AttachRolePolicy', 'iam:PutUserPolicy', 'iam:PutRolePolicy',
    'iam:UpdateAssumeRolePolicy', 'iam:CreateAccessKey', 'iam:AddUserToGroup',
    'iam:UpdateLoginProfile', 'iam:DeleteUserPermissionsBoundary',
    'iam:DeleteRolePermissionsBoundary', 'iam:DetachUserPolicy',
    'iam:DetachRolePolicy', 'iam:DeleteUserPolicy', 'iam:DeleteRolePolicy',
    'lambda:CreateFunction', 'lambda:UpdateFunctionCode', 'ec2:RunInstances',
    'cloudformation:CreateStack', 'glue:CreateDevEndpoint', 'sts:AssumeRole',
}


# ---------------------------------------------------------------------------
# Policy Evaluation (Local, No API Calls)
# ---------------------------------------------------------------------------


def has_action(principal: PrincipalNode, action: str) -> bool:
    """
    Check if principal has the specified action in their effective permissions.

    Args:
        principal: The principal node to check
        action: IAM action string (e.g., 'iam:PassRole')

    Returns:
        True if principal has the action
    """
    action_lower = action.lower()
    for pattern in principal.effective_actions:
        if pattern == '*':
            return True
        if fnmatch.fnmatch(action_lower, pattern.lower()):
            return True
    return False


def has_action_on_resource(
    principal: PrincipalNode, action: str, resource_arn: str
) -> bool:
    """
    Check if principal has the action on a specific resource.

    Evaluates full policy statements including Resource constraints.

    Args:
        principal: The principal node
        action: IAM action to check
        resource_arn: Target resource ARN

    Returns:
        True if action is allowed on the resource
    """
    if not principal.policy_statements:
        # Fall back to simple action check if no statements available
        return has_action(principal, action)

    explicitly_allowed = False
    explicitly_denied = False

    for stmt in principal.policy_statements:
        effect = stmt.get('Effect')

        if not _action_matches(stmt, action):
            continue

        if not _resource_matches(stmt, resource_arn):
            continue

        if effect == 'Deny':
            explicitly_denied = True
            break
        elif effect == 'Allow':
            explicitly_allowed = True

    return explicitly_allowed and not explicitly_denied


def can_assume_role(source: PrincipalNode, target_role: PrincipalNode) -> bool:
    """
    Check if source can assume target role.

    Two conditions must be true:
    1. Source has sts:AssumeRole permission on target role ARN
    2. Target role's trust policy allows the source principal

    Args:
        source: Source principal
        target_role: Target role to assume

    Returns:
        True if source can assume the target role
    """
    if not has_action_on_resource(source, 'sts:AssumeRole', target_role.arn):
        return False

    if not target_role.trust_policy:
        return False

    return trust_policy_allows(target_role.trust_policy, source.arn)


def trust_policy_allows(trust_policy: Dict, source_arn: str) -> bool:
    """
    Evaluate whether a role's trust policy allows the source to assume it.

    Args:
        trust_policy: The role's AssumeRolePolicyDocument
        source_arn: ARN of the source principal

    Returns:
        True if the trust policy allows assumption
    """
    statements = trust_policy.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]

    source_account = source_arn.split(':')[4] if ':' in source_arn else ''

    for stmt in statements:
        if stmt.get('Effect') != 'Allow':
            continue

        principals = stmt.get('Principal', {})
        if isinstance(principals, str):
            if principals == '*':
                return True
            principals = {'AWS': [principals]}

        aws_principals = principals.get('AWS', [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]

        for allowed in aws_principals:
            if allowed == '*':
                return True
            if allowed == source_arn:
                return True
            # Account-level trust: "arn:aws:iam::123456789012:root"
            if (allowed.endswith(':root') and source_account and
                    source_account == allowed.split(':')[4]):
                return True

    return False


def has_passrole_on(source: PrincipalNode, target_role: PrincipalNode) -> bool:
    """
    Check if source can PassRole the target role (resource-aware).

    Args:
        source: Source principal
        target_role: Target role to pass

    Returns:
        True if source can pass the target role
    """
    return has_action_on_resource(source, 'iam:PassRole', target_role.arn)


def _action_matches(statement: Dict, action: str) -> bool:
    """Check if statement's Action/NotAction matches the target action."""
    if 'NotAction' in statement:
        not_actions = statement['NotAction']
        if isinstance(not_actions, str):
            not_actions = [not_actions]
        for pattern in not_actions:
            if fnmatch.fnmatch(action.lower(), pattern.lower()):
                return False
        return True

    actions = statement.get('Action', [])
    if isinstance(actions, str):
        actions = [actions]

    for pattern in actions:
        if pattern == '*':
            return True
        if fnmatch.fnmatch(action.lower(), pattern.lower()):
            return True
    return False


def _resource_matches(statement: Dict, resource_arn: str) -> bool:
    """Check if statement's Resource/NotResource matches the target ARN."""
    if 'NotResource' in statement:
        not_resources = statement['NotResource']
        if isinstance(not_resources, str):
            not_resources = [not_resources]
        for pattern in not_resources:
            if pattern == '*' or fnmatch.fnmatch(resource_arn, pattern):
                return False
        return True

    resources = statement.get('Resource', ['*'])
    if isinstance(resources, str):
        resources = [resources]

    for pattern in resources:
        if pattern == '*':
            return True
        if fnmatch.fnmatch(resource_arn, pattern):
            return True
    return False


# ---------------------------------------------------------------------------
# Node Construction
# ---------------------------------------------------------------------------


def build_nodes(auth_details: Dict) -> Dict[str, PrincipalNode]:
    """
    Build all principal nodes from authorization details.

    Args:
        auth_details: Output from GetAccountAuthorizationDetails

    Returns:
        Dictionary mapping ARN to PrincipalNode
    """
    nodes: Dict[str, PrincipalNode] = {}

    # Build User nodes
    for user in auth_details.get('users', []):
        node = PrincipalNode(
            arn=user['Arn'],
            name=user['UserName'],
            principal_type='User',
            group_memberships=[
                g['GroupName'] if isinstance(g, dict) else g
                for g in user.get('GroupList', [])
            ],
            has_permissions_boundary='PermissionsBoundary' in user,
            permissions_boundary_arn=user.get(
                'PermissionsBoundary', {}
            ).get('PermissionsBoundaryArn'),
            tags={
                t['Key']: t['Value'] for t in user.get('Tags', [])
            },
        )
        actions, statements = _resolve_effective_actions_user(
            user, auth_details
        )
        node.effective_actions = actions
        node.policy_statements = statements
        node.is_admin = _check_is_admin(statements)
        nodes[node.arn] = node

    # Build Role nodes
    for role in auth_details.get('roles', []):
        # Skip service-linked roles (not exploitable)
        path = role.get('Path', '/')
        if path.startswith('/aws-service-role/'):
            continue

        node = PrincipalNode(
            arn=role['Arn'],
            name=role['RoleName'],
            principal_type='Role',
            trust_policy=role.get('AssumeRolePolicyDocument', {}),
            instance_profiles=[
                ip['InstanceProfileName']
                for ip in role.get('InstanceProfileList', [])
            ],
            has_permissions_boundary='PermissionsBoundary' in role,
            permissions_boundary_arn=role.get(
                'PermissionsBoundary', {}
            ).get('PermissionsBoundaryArn'),
            tags={
                t['Key']: t['Value'] for t in role.get('Tags', [])
            },
        )
        actions, statements = _resolve_effective_actions_role(
            role, auth_details
        )
        node.effective_actions = actions
        node.policy_statements = statements
        node.is_admin = _check_is_admin(statements)
        nodes[node.arn] = node

    logger.debug(
        f"PrivilegeGraph: Built {len(nodes)} nodes "
        f"({sum(1 for n in nodes.values() if n.principal_type == 'User')} users, "
        f"{sum(1 for n in nodes.values() if n.principal_type == 'Role')} roles)"
    )
    return nodes


def _resolve_effective_actions_user(
    user_detail: Dict, auth_details: Dict
) -> Tuple[Set[str], List[Dict]]:
    """
    Resolve effective actions for a user from all policy sources.

    Args:
        user_detail: User detail from GetAccountAuthorizationDetails
        auth_details: Full authorization details (for group/managed policy lookup)

    Returns:
        Tuple of (set of action patterns, list of all policy statements)
    """
    allowed_actions: Set[str] = set()
    all_statements: List[Dict] = []

    # 1. User inline policies
    for policy in user_detail.get('UserPolicyList', []):
        doc = policy.get('PolicyDocument', {})
        if isinstance(doc, str):
            import json
            doc = json.loads(doc)
        _extract_actions(doc, allowed_actions, all_statements)

    # 2. User attached managed policies
    for attached in user_detail.get('AttachedManagedPolicies', []):
        policy_doc = _get_managed_policy_document(
            attached['PolicyArn'], auth_details
        )
        if policy_doc:
            _extract_actions(policy_doc, allowed_actions, all_statements)

    # 3. Group policies (inline + attached)
    group_list = user_detail.get('GroupList', [])
    for group_ref in group_list:
        group_name = group_ref['GroupName'] if isinstance(group_ref, dict) else group_ref
        group = _find_group(group_name, auth_details)
        if group:
            for policy in group.get('GroupPolicyList', []):
                doc = policy.get('PolicyDocument', {})
                if isinstance(doc, str):
                    import json
                    doc = json.loads(doc)
                _extract_actions(doc, allowed_actions, all_statements)
            for attached in group.get('AttachedManagedPolicies', []):
                policy_doc = _get_managed_policy_document(
                    attached['PolicyArn'], auth_details
                )
                if policy_doc:
                    _extract_actions(
                        policy_doc, allowed_actions, all_statements
                    )

    return allowed_actions, all_statements


def _resolve_effective_actions_role(
    role_detail: Dict, auth_details: Dict
) -> Tuple[Set[str], List[Dict]]:
    """
    Resolve effective actions for a role from all policy sources.

    Args:
        role_detail: Role detail from GetAccountAuthorizationDetails
        auth_details: Full authorization details

    Returns:
        Tuple of (set of action patterns, list of all policy statements)
    """
    allowed_actions: Set[str] = set()
    all_statements: List[Dict] = []

    # 1. Role inline policies
    for policy in role_detail.get('RolePolicyList', []):
        doc = policy.get('PolicyDocument', {})
        if isinstance(doc, str):
            import json
            doc = json.loads(doc)
        _extract_actions(doc, allowed_actions, all_statements)

    # 2. Role attached managed policies
    for attached in role_detail.get('AttachedManagedPolicies', []):
        policy_doc = _get_managed_policy_document(
            attached['PolicyArn'], auth_details
        )
        if policy_doc:
            _extract_actions(policy_doc, allowed_actions, all_statements)

    return allowed_actions, all_statements


def _extract_actions(
    policy_doc: Dict, allowed: Set[str], all_statements: List[Dict]
) -> None:
    """
    Extract actions from a policy document into the allowed set.

    Args:
        policy_doc: IAM policy document
        allowed: Set to add allowed action patterns to
        all_statements: List to append all statements to
    """
    statements = policy_doc.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        all_statements.append(stmt)

        if stmt.get('Effect') != 'Allow':
            continue

        # Handle NotAction (allows everything except listed)
        if 'NotAction' in stmt:
            allowed.add('*')  # Simplified: NotAction with Allow is broad
            continue

        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]

        allowed.update(actions)


def _get_managed_policy_document(
    policy_arn: str, auth_details: Dict
) -> Optional[Dict]:
    """
    Get the default version document of a managed policy.

    Args:
        policy_arn: ARN of the managed policy
        auth_details: Full authorization details

    Returns:
        Policy document or None
    """
    for policy in auth_details.get('policies', []):
        if policy.get('Arn') == policy_arn:
            for version in policy.get('PolicyVersionList', []):
                if version.get('IsDefaultVersion'):
                    doc = version.get('Document', {})
                    if isinstance(doc, str):
                        import json
                        doc = json.loads(doc)
                    return doc
    return None


def _find_group(group_name: str, auth_details: Dict) -> Optional[Dict]:
    """
    Find a group by name in authorization details.

    Args:
        group_name: Name of the group
        auth_details: Full authorization details

    Returns:
        Group detail dict or None
    """
    for group in auth_details.get('groups', []):
        if group.get('GroupName') == group_name:
            return group
    return None


def _check_is_admin(statements: List[Dict]) -> bool:
    """
    Check if a set of policy statements grants full admin access.

    Admin = Effect: Allow, Action: *, Resource: *

    Args:
        statements: List of policy statements

    Returns:
        True if admin access is granted
    """
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


# ---------------------------------------------------------------------------
# Edge Generation
# ---------------------------------------------------------------------------


def build_edges(
    nodes: Dict[str, PrincipalNode], auth_details: Dict
) -> List[PrivilegeEdge]:
    """
    Generate all privilege escalation edges (optimized).

    Uses three-layer optimization:
    1. Filter sources with dangerous permissions
    2. Only check relevant edge types per source
    3. Pre-compute PassRole resource constraints

    Args:
        nodes: All principal nodes
        auth_details: Full authorization details

    Returns:
        List of privilege edges
    """
    edges: List[PrivilegeEdge] = []
    roles = [n for n in nodes.values() if n.principal_type == 'Role']

    # Layer 1: Filter interesting sources
    sources = _filter_interesting_sources(nodes)
    logger.debug(
        f"PrivilegeGraph: Checking {len(sources)} interesting sources "
        f"against {len(nodes)} total nodes"
    )

    for source in sources:
        # Layer 2: Only check relevant edge types
        source_has_assume = has_action(source, 'sts:AssumeRole')
        source_has_passrole = has_action(source, 'iam:PassRole')
        source_has_create_policy_ver = has_action(
            source, 'iam:CreatePolicyVersion'
        )
        source_has_attach_policy = (
            has_action(source, 'iam:AttachUserPolicy') or
            has_action(source, 'iam:AttachRolePolicy') or
            has_action(source, 'iam:AttachGroupPolicy')
        )
        source_has_put_policy = (
            has_action(source, 'iam:PutUserPolicy') or
            has_action(source, 'iam:PutRolePolicy') or
            has_action(source, 'iam:PutGroupPolicy')
        )
        source_has_create_access_key = has_action(
            source, 'iam:CreateAccessKey'
        )
        source_has_update_login = has_action(
            source, 'iam:UpdateLoginProfile'
        )
        source_has_update_trust = has_action(
            source, 'iam:UpdateAssumeRolePolicy'
        )
        source_has_add_to_group = has_action(source, 'iam:AddUserToGroup')
        source_has_lambda_update = has_action(
            source, 'lambda:UpdateFunctionCode'
        )
        source_has_remove_boundary = (
            has_action(source, 'iam:DeleteUserPermissionsBoundary') or
            has_action(source, 'iam:DeleteRolePermissionsBoundary')
        )

        for dest in nodes.values():
            if source.arn == dest.arn:
                continue

            # --- AssumeRole ---
            if source_has_assume and dest.principal_type == 'Role':
                if can_assume_role(source, dest):
                    edges.append(PrivilegeEdge(
                        source=source, destination=dest,
                        edge_type=EdgeType.ASSUME_ROLE,
                        reason=(
                            f"{source.name} can assume {dest.name} "
                            f"via trust policy"
                        ),
                        required_permissions=['sts:AssumeRole'],
                        severity='HIGH' if dest.is_admin else 'MEDIUM',
                    ))

            # --- PassRole + EC2 ---
            if (source_has_passrole and dest.principal_type == 'Role'
                    and dest.instance_profiles):
                if (has_passrole_on(source, dest)
                        and has_action(source, 'ec2:RunInstances')):
                    edges.append(PrivilegeEdge(
                        source=source, destination=dest,
                        edge_type=EdgeType.PASSROLE_EC2,
                        reason=(
                            f"{source.name} can pass {dest.name} to EC2 "
                            f"and steal IMDS credentials"
                        ),
                        required_permissions=[
                            'iam:PassRole', 'ec2:RunInstances'
                        ],
                        severity='HIGH',
                        intermediary_service='EC2',
                    ))

            # --- PassRole + Lambda ---
            if (source_has_passrole and dest.principal_type == 'Role'):
                if (has_passrole_on(source, dest)
                        and has_action(source, 'lambda:CreateFunction')
                        and has_action(source, 'lambda:InvokeFunction')):
                    edges.append(PrivilegeEdge(
                        source=source, destination=dest,
                        edge_type=EdgeType.PASSROLE_LAMBDA,
                        reason=(
                            f"{source.name} can create Lambda with "
                            f"{dest.name}'s role and invoke it"
                        ),
                        required_permissions=[
                            'iam:PassRole', 'lambda:CreateFunction',
                            'lambda:InvokeFunction',
                        ],
                        severity='HIGH',
                        intermediary_service='Lambda',
                    ))

            # --- PassRole + CloudFormation ---
            if (source_has_passrole and dest.principal_type == 'Role'):
                if (has_passrole_on(source, dest)
                        and has_action(source, 'cloudformation:CreateStack')):
                    edges.append(PrivilegeEdge(
                        source=source, destination=dest,
                        edge_type=EdgeType.PASSROLE_CLOUDFORMATION,
                        reason=(
                            f"{source.name} can pass {dest.name} to "
                            f"CloudFormation stack"
                        ),
                        required_permissions=[
                            'iam:PassRole', 'cloudformation:CreateStack'
                        ],
                        severity='HIGH',
                        intermediary_service='CloudFormation',
                    ))

            # --- PassRole + Glue ---
            if (source_has_passrole and dest.principal_type == 'Role'):
                if (has_passrole_on(source, dest)
                        and (has_action(source, 'glue:CreateDevEndpoint')
                             or has_action(source, 'glue:CreateJob'))):
                    edges.append(PrivilegeEdge(
                        source=source, destination=dest,
                        edge_type=EdgeType.PASSROLE_GLUE,
                        reason=(
                            f"{source.name} can pass {dest.name} to Glue"
                        ),
                        required_permissions=[
                            'iam:PassRole', 'glue:CreateDevEndpoint'
                        ],
                        severity='HIGH',
                        intermediary_service='Glue',
                    ))

            # --- PassRole + ECS ---
            if (source_has_passrole and dest.principal_type == 'Role'):
                if (has_passrole_on(source, dest)
                        and has_action(source, 'ecs:RunTask')):
                    edges.append(PrivilegeEdge(
                        source=source, destination=dest,
                        edge_type=EdgeType.PASSROLE_ECS,
                        reason=(
                            f"{source.name} can pass {dest.name} to ECS task"
                        ),
                        required_permissions=[
                            'iam:PassRole', 'ecs:RunTask'
                        ],
                        severity='HIGH',
                        intermediary_service='ECS',
                    ))

            # --- PolicyAttach ---
            if source_has_attach_policy:
                if _can_attach_policy_to(source, dest):
                    edges.append(PrivilegeEdge(
                        source=source, destination=dest,
                        edge_type=EdgeType.POLICY_ATTACH,
                        reason=(
                            f"{source.name} can attach admin policy "
                            f"to {dest.name}"
                        ),
                        required_permissions=[
                            f'iam:Attach{dest.principal_type}Policy'
                        ],
                        severity='HIGH',
                    ))

            # --- PolicyPutInline ---
            if source_has_put_policy:
                if _can_put_inline_policy(source, dest):
                    edges.append(PrivilegeEdge(
                        source=source, destination=dest,
                        edge_type=EdgeType.POLICY_PUT_INLINE,
                        reason=(
                            f"{source.name} can put inline admin policy "
                            f"on {dest.name}"
                        ),
                        required_permissions=[
                            f'iam:Put{dest.principal_type}Policy'
                        ],
                        severity='HIGH',
                    ))

            # --- CreateAccessKey (user targets only) ---
            if (source_has_create_access_key
                    and dest.principal_type == 'User'):
                if has_action_on_resource(
                    source, 'iam:CreateAccessKey', dest.arn
                ):
                    edges.append(PrivilegeEdge(
                        source=source, destination=dest,
                        edge_type=EdgeType.CREATE_ACCESS_KEY,
                        reason=(
                            f"{source.name} can create access keys "
                            f"for {dest.name}"
                        ),
                        required_permissions=['iam:CreateAccessKey'],
                        severity='HIGH' if dest.is_admin else 'MEDIUM',
                    ))

            # --- UpdateLoginProfile (user targets only) ---
            if (source_has_update_login
                    and dest.principal_type == 'User'):
                if has_action_on_resource(
                    source, 'iam:UpdateLoginProfile', dest.arn
                ):
                    edges.append(PrivilegeEdge(
                        source=source, destination=dest,
                        edge_type=EdgeType.UPDATE_LOGIN_PROFILE,
                        reason=(
                            f"{source.name} can reset {dest.name}'s "
                            f"console password"
                        ),
                        required_permissions=['iam:UpdateLoginProfile'],
                        severity='HIGH' if dest.is_admin else 'MEDIUM',
                    ))

            # --- UpdateAssumeRolePolicy ---
            if (source_has_update_trust
                    and dest.principal_type == 'Role'):
                if has_action_on_resource(
                    source, 'iam:UpdateAssumeRolePolicy', dest.arn
                ):
                    edges.append(PrivilegeEdge(
                        source=source, destination=dest,
                        edge_type=EdgeType.UPDATE_TRUST_POLICY,
                        reason=(
                            f"{source.name} can modify {dest.name}'s "
                            f"trust policy to allow self-assumption"
                        ),
                        required_permissions=[
                            'iam:UpdateAssumeRolePolicy'
                        ],
                        severity='CRITICAL',
                    ))

            # --- AddToGroup (user targets only) ---
            if (source_has_add_to_group
                    and dest.principal_type == 'User'):
                if has_action_on_resource(
                    source, 'iam:AddUserToGroup', dest.arn
                ):
                    edges.append(PrivilegeEdge(
                        source=source, destination=dest,
                        edge_type=EdgeType.ADD_TO_GROUP,
                        reason=(
                            f"{source.name} can add {dest.name} to "
                            f"a privileged group"
                        ),
                        required_permissions=['iam:AddUserToGroup'],
                        severity='MEDIUM',
                    ))

            # --- RemovePermissionsBoundary ---
            if source_has_remove_boundary:
                if (dest.has_permissions_boundary and
                        _can_remove_boundary(source, dest)):
                    edges.append(PrivilegeEdge(
                        source=source, destination=dest,
                        edge_type=EdgeType.REMOVE_PERMISSIONS_BOUNDARY,
                        reason=(
                            f"{source.name} can remove permissions "
                            f"boundary from {dest.name}"
                        ),
                        required_permissions=[
                            f'iam:Delete{dest.principal_type}'
                            f'PermissionsBoundary'
                        ],
                        severity='HIGH',
                    ))

    # Wire edges into nodes
    for edge in edges:
        edge.source.outbound_edges.append(edge)
        edge.destination.inbound_edges.append(edge)

    logger.debug(f"PrivilegeGraph: Generated {len(edges)} edges")
    return edges


def _filter_interesting_sources(
    nodes: Dict[str, PrincipalNode]
) -> List[PrincipalNode]:
    """
    Filter to principals with escalation-relevant permissions.

    Args:
        nodes: All principal nodes

    Returns:
        List of principals worth checking for outbound edges
    """
    interesting = []
    for node in nodes.values():
        if node.is_admin:
            continue
        if any(has_action(node, a) for a in ESCALATION_ACTIONS):
            interesting.append(node)
    return interesting


def _can_attach_policy_to(
    source: PrincipalNode, dest: PrincipalNode
) -> bool:
    """Check if source can attach a managed policy to dest."""
    if dest.principal_type == 'User':
        return has_action_on_resource(
            source, 'iam:AttachUserPolicy', dest.arn
        )
    elif dest.principal_type == 'Role':
        return has_action_on_resource(
            source, 'iam:AttachRolePolicy', dest.arn
        )
    return False


def _can_put_inline_policy(
    source: PrincipalNode, dest: PrincipalNode
) -> bool:
    """Check if source can put an inline policy on dest."""
    if dest.principal_type == 'User':
        return has_action_on_resource(
            source, 'iam:PutUserPolicy', dest.arn
        )
    elif dest.principal_type == 'Role':
        return has_action_on_resource(
            source, 'iam:PutRolePolicy', dest.arn
        )
    return False


def _can_remove_boundary(
    source: PrincipalNode, dest: PrincipalNode
) -> bool:
    """Check if source can remove permissions boundary from dest."""
    if dest.principal_type == 'User':
        return has_action_on_resource(
            source, 'iam:DeleteUserPermissionsBoundary', dest.arn
        )
    elif dest.principal_type == 'Role':
        return has_action_on_resource(
            source, 'iam:DeleteRolePermissionsBoundary', dest.arn
        )
    return False


# ---------------------------------------------------------------------------
# Graph Traversal
# ---------------------------------------------------------------------------


def find_path_to_admin(
    nodes: Dict[str, PrincipalNode],
    start_arn: str,
    max_depth: int = 5
) -> Optional[List[PrivilegeEdge]]:
    """
    BFS to find shortest escalation path from start to any admin node.

    Args:
        nodes: All nodes indexed by ARN
        start_arn: Starting principal ARN
        max_depth: Maximum hops to search

    Returns:
        List of edges forming the shortest path, or None if no path exists
    """
    if start_arn not in nodes:
        return None

    start_node = nodes[start_arn]

    if start_node.is_admin:
        return []

    queue: deque = deque([(start_node, [])])
    visited: Set[str] = {start_arn}

    while queue:
        current, path = queue.popleft()

        if len(path) >= max_depth:
            continue

        for edge in current.outbound_edges:
            dest = edge.destination

            if dest.arn in visited:
                continue

            new_path = path + [edge]

            if dest.is_admin:
                return new_path

            visited.add(dest.arn)
            queue.append((dest, new_path))

    return None


def find_all_paths_to_admin(
    nodes: Dict[str, PrincipalNode],
    start_arn: str,
    max_depth: int = 5
) -> List[List[PrivilegeEdge]]:
    """
    DFS to find ALL escalation paths (not just shortest).

    Args:
        nodes: All nodes indexed by ARN
        start_arn: Starting principal ARN
        max_depth: Maximum hops

    Returns:
        List of paths (each path is a list of edges)
    """
    if start_arn not in nodes:
        return []

    start_node = nodes[start_arn]
    all_paths: List[List[PrivilegeEdge]] = []

    if start_node.is_admin:
        return []

    stack = [(start_node, [], {start_arn})]

    while stack:
        current, path, visited = stack.pop()

        if len(path) >= max_depth:
            continue

        for edge in current.outbound_edges:
            dest = edge.destination

            if dest.arn in visited:
                continue

            new_path = path + [edge]

            if dest.is_admin:
                all_paths.append(new_path)
                continue

            new_visited = visited | {dest.arn}
            stack.append((dest, new_path, new_visited))

    return all_paths


def find_principals_reaching_target(
    nodes: Dict[str, PrincipalNode],
    target_arn: str,
    max_depth: int = 5
) -> List[Tuple[PrincipalNode, List[PrivilegeEdge]]]:
    """
    Reverse BFS: find all principals that can reach the target.

    Args:
        nodes: All nodes indexed by ARN
        target_arn: Target principal ARN
        max_depth: Maximum hops

    Returns:
        List of (source_principal, path_to_target) tuples
    """
    if target_arn not in nodes:
        return []

    target_node = nodes[target_arn]
    results: List[Tuple[PrincipalNode, List[PrivilegeEdge]]] = []

    queue: deque = deque([(target_node, [])])
    visited: Set[str] = {target_arn}

    while queue:
        current, reverse_path = queue.popleft()

        if len(reverse_path) >= max_depth:
            continue

        for edge in current.inbound_edges:
            source = edge.source

            if source.arn in visited:
                continue

            path = [edge] + reverse_path
            results.append((source, path))

            visited.add(source.arn)
            queue.append((source, [edge] + reverse_path))

    return results


def compute_blast_radius(
    nodes: Dict[str, PrincipalNode],
    compromised_arn: str,
    max_depth: int = 5
) -> Dict[str, Any]:
    """
    Compute the blast radius if a principal is compromised.

    Args:
        nodes: All nodes indexed by ARN
        compromised_arn: ARN of the compromised principal
        max_depth: Maximum traversal depth

    Returns:
        Dictionary with blast radius statistics
    """
    if compromised_arn not in nodes:
        return {
            'compromised_principal': compromised_arn,
            'total_reachable': 0,
            'admin_reachable': False,
            'reachable_admins': [],
            'max_depth_reached': 0,
            'reachable_by_depth': {},
        }

    start_node = nodes[compromised_arn]
    reachable: Dict[str, int] = {}
    queue: deque = deque([(start_node, 0)])
    visited: Set[str] = {compromised_arn}

    while queue:
        current, depth = queue.popleft()

        if depth >= max_depth:
            continue

        for edge in current.outbound_edges:
            dest = edge.destination
            if dest.arn in visited:
                continue

            visited.add(dest.arn)
            reachable[dest.arn] = depth + 1
            queue.append((dest, depth + 1))

    return {
        'compromised_principal': compromised_arn,
        'total_reachable': len(reachable),
        'admin_reachable': any(
            nodes[arn].is_admin for arn in reachable
        ),
        'reachable_admins': [
            arn for arn in reachable if nodes[arn].is_admin
        ],
        'max_depth_reached': max(reachable.values()) if reachable else 0,
        'reachable_by_depth': reachable,
    }


# ---------------------------------------------------------------------------
# Transitive Escalation Detection
# ---------------------------------------------------------------------------


def find_transitive_escalation_paths(
    nodes: Dict[str, PrincipalNode],
    max_depth: int = 5
) -> List[Dict[str, Any]]:
    """
    Find all principals with multi-hop paths to admin.

    Only reports paths with >= 2 hops (single-hop is handled
    by direct checks).

    Args:
        nodes: All principal nodes
        max_depth: Maximum path depth

    Returns:
        List of finding dictionaries with path details
    """
    findings: List[Dict[str, Any]] = []

    for arn, node in nodes.items():
        if node.is_admin:
            continue

        path = find_path_to_admin(nodes, arn, max_depth=max_depth)

        if path and len(path) > 1:
            findings.append({
                'principal_arn': arn,
                'principal_name': node.name,
                'path_length': len(path),
                'path_description': ' -> '.join(
                    [node.name] + [e.destination.name for e in path]
                ),
                'path_details': [
                    {
                        'hop': i + 1,
                        'from': edge.source.name,
                        'to': edge.destination.name,
                        'via': edge.edge_type,
                        'reason': edge.reason,
                    }
                    for i, edge in enumerate(path)
                ],
                'severity': 'CRITICAL' if len(path) <= 3 else 'HIGH',
                'remediation': _generate_path_remediation(path),
            })

    findings.sort(
        key=lambda f: (f['severity'] != 'CRITICAL', f['path_length'])
    )
    return findings


def _generate_path_remediation(path: List[PrivilegeEdge]) -> str:
    """Generate remediation for the weakest link in a path."""
    first_edge = path[0]

    templates = {
        EdgeType.ASSUME_ROLE: (
            "Restrict the trust policy on {dest} to deny {source}"
        ),
        EdgeType.PASSROLE_EC2: (
            "Constrain iam:PassRole resource to specific role ARNs (not '*')"
        ),
        EdgeType.PASSROLE_LAMBDA: (
            "Constrain iam:PassRole resource; add condition key "
            "iam:PassedToService"
        ),
        EdgeType.PASSROLE_CLOUDFORMATION: (
            "Constrain iam:PassRole resource for CloudFormation roles"
        ),
        EdgeType.POLICY_ATTACH: (
            "Remove iam:Attach*Policy from {source}; use SCPs to deny"
        ),
        EdgeType.POLICY_PUT_INLINE: (
            "Remove iam:Put*Policy from {source}; use SCPs to deny"
        ),
        EdgeType.CREATE_ACCESS_KEY: (
            "Remove iam:CreateAccessKey from {source} or constrain "
            "to own user"
        ),
        EdgeType.UPDATE_TRUST_POLICY: (
            "Remove iam:UpdateAssumeRolePolicy; this is a critical permission"
        ),
        EdgeType.REMOVE_PERMISSIONS_BOUNDARY: (
            "Remove iam:Delete*PermissionsBoundary from {source}"
        ),
    }

    template = templates.get(
        first_edge.edge_type,
        f"Remove {first_edge.required_permissions} from {{source}}"
    )

    return template.format(
        source=first_edge.source.name,
        dest=first_edge.destination.name,
    )


# ---------------------------------------------------------------------------
# Main Graph Class
# ---------------------------------------------------------------------------


class PrivilegeGraph:
    """
    Main privilege graph class.

    Built once from GetAccountAuthorizationDetails, shared across
    all IAP checks via class-level caching.
    """

    def __init__(self, auth_details: Dict, session: Any):
        """
        Build the privilege graph from authorization details.

        Args:
            auth_details: Output from GetAccountAuthorizationDetails
            session: AWS boto3 session (for account context)
        """
        self.session = session
        self.nodes: Dict[str, PrincipalNode] = {}
        self.edges: List[PrivilegeEdge] = []
        self.admin_arns: Set[str] = set()

        # Phase 1: Build nodes
        self.nodes = build_nodes(auth_details)
        self.admin_arns = {
            arn for arn, n in self.nodes.items() if n.is_admin
        }

        # Phase 2: Build edges
        self.edges = build_edges(self.nodes, auth_details)

    def query_path_to_admin(
        self, principal_arn: str
    ) -> Optional[List[PrivilegeEdge]]:
        """BFS shortest path to any admin node."""
        return find_path_to_admin(self.nodes, principal_arn)

    def query_all_paths(
        self, principal_arn: str
    ) -> List[List[PrivilegeEdge]]:
        """DFS all paths to admin."""
        return find_all_paths_to_admin(self.nodes, principal_arn)

    def query_blast_radius(self, principal_arn: str) -> Dict[str, Any]:
        """Compute blast radius of a compromised principal."""
        return compute_blast_radius(self.nodes, principal_arn)

    def query_who_can_reach(
        self, target_arn: str
    ) -> List[Tuple[PrincipalNode, List[PrivilegeEdge]]]:
        """Reverse BFS: who can reach this target?"""
        return find_principals_reaching_target(self.nodes, target_arn)

    def get_transitive_escalation_findings(self) -> List[Dict[str, Any]]:
        """Run the full multi-hop escalation scan."""
        return find_transitive_escalation_paths(self.nodes)

    @property
    def stats(self) -> Dict[str, Any]:
        """Get graph statistics."""
        return {
            'total_nodes': len(self.nodes),
            'total_edges': len(self.edges),
            'admin_nodes': len(self.admin_arns),
            'users': sum(
                1 for n in self.nodes.values()
                if n.principal_type == 'User'
            ),
            'roles': sum(
                1 for n in self.nodes.values()
                if n.principal_type == 'Role'
            ),
        }
