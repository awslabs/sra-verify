"""
Shared fixtures for IAM Attack Path tests.

Provides mocked authorization details for various escalation scenarios.
"""
import json
import pytest
from unittest.mock import MagicMock, patch
from sraverify.services.iam_attack_paths.base import IAMAttackPathCheck


@pytest.fixture(autouse=True)
def reset_caches():
    """Reset class-level caches before each test."""
    IAMAttackPathCheck.reset_caches()
    yield
    IAMAttackPathCheck.reset_caches()


@pytest.fixture
def mock_session():
    """Create a mock boto3 session."""
    session = MagicMock()
    session.region_name = 'us-east-1'

    # Mock STS get_caller_identity
    sts_client = MagicMock()
    sts_client.get_caller_identity.return_value = {
        'Account': '123456789012'
    }

    # Mock Account API
    account_client = MagicMock()
    account_client.get_account_information.return_value = {
        'AccountName': 'test-account'
    }

    def client_factory(service, **kwargs):
        if service == 'sts':
            return sts_client
        if service == 'account':
            return account_client
        if service == 'ec2':
            mock_ec2 = MagicMock()
            mock_ec2.describe_regions.return_value = {
                'Regions': [{'RegionName': 'us-east-1'}]
            }
            return mock_ec2
        return MagicMock()

    session.client.side_effect = client_factory
    return session


@pytest.fixture
def least_privilege_auth_details():
    """Auth details with a read-only user — no escalation possible."""
    return {
        'users': [{
            'Arn': 'arn:aws:iam::123456789012:user/readonly',
            'UserName': 'readonly',
            'Path': '/',
            'UserPolicyList': [{
                'PolicyName': 'readonly',
                'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': ['s3:GetObject', 's3:ListBucket'],
                        'Resource': '*'
                    }]
                }
            }],
            'AttachedManagedPolicies': [],
            'GroupList': [],
            'Tags': [],
        }],
        'roles': [{
            'Arn': 'arn:aws:iam::123456789012:role/admin-role',
            'RoleName': 'admin-role',
            'Path': '/',
            'AssumeRolePolicyDocument': {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'AWS': 'arn:aws:iam::123456789012:root'},
                    'Action': 'sts:AssumeRole'
                }]
            },
            'RolePolicyList': [{
                'PolicyName': 'admin',
                'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*'
                    }]
                }
            }],
            'AttachedManagedPolicies': [],
            'InstanceProfileList': [],
            'Tags': [],
        }],
        'groups': [],
        'policies': [],
    }


@pytest.fixture
def passrole_ec2_auth_details():
    """Auth details with a user that has PassRole + EC2 escalation."""
    return {
        'users': [{
            'Arn': 'arn:aws:iam::123456789012:user/attacker',
            'UserName': 'attacker',
            'Path': '/',
            'UserPolicyList': [{
                'PolicyName': 'dangerous',
                'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': ['iam:PassRole', 'ec2:RunInstances'],
                        'Resource': '*'
                    }]
                }
            }],
            'AttachedManagedPolicies': [],
            'GroupList': [],
            'Tags': [],
        }],
        'roles': [{
            'Arn': 'arn:aws:iam::123456789012:role/admin-role',
            'RoleName': 'admin-role',
            'Path': '/',
            'AssumeRolePolicyDocument': {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'Service': 'ec2.amazonaws.com'},
                    'Action': 'sts:AssumeRole'
                }]
            },
            'RolePolicyList': [{
                'PolicyName': 'admin',
                'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*'
                    }]
                }
            }],
            'AttachedManagedPolicies': [],
            'InstanceProfileList': [
                {'InstanceProfileName': 'admin-instance-profile'}
            ],
            'Tags': [],
        }],
        'groups': [],
        'policies': [],
    }


@pytest.fixture
def passrole_lambda_auth_details():
    """Auth details with PassRole + Lambda escalation."""
    return {
        'users': [{
            'Arn': 'arn:aws:iam::123456789012:user/lambda-attacker',
            'UserName': 'lambda-attacker',
            'Path': '/',
            'UserPolicyList': [{
                'PolicyName': 'lambda-power',
                'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': [
                            'iam:PassRole',
                            'lambda:CreateFunction',
                            'lambda:InvokeFunction',
                        ],
                        'Resource': '*'
                    }]
                }
            }],
            'AttachedManagedPolicies': [],
            'GroupList': [],
            'Tags': [],
        }],
        'roles': [{
            'Arn': 'arn:aws:iam::123456789012:role/lambda-admin-role',
            'RoleName': 'lambda-admin-role',
            'Path': '/',
            'AssumeRolePolicyDocument': {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'Service': 'lambda.amazonaws.com'},
                    'Action': 'sts:AssumeRole'
                }]
            },
            'RolePolicyList': [{
                'PolicyName': 'admin',
                'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*'
                    }]
                }
            }],
            'AttachedManagedPolicies': [],
            'InstanceProfileList': [],
            'Tags': [],
        }],
        'groups': [],
        'policies': [],
    }


@pytest.fixture
def multi_hop_auth_details():
    """Auth details with a 3-hop escalation chain.

    attacker -> (AssumeRole) -> middle-role -> (AssumeRole) -> admin-role
    """
    return {
        'users': [{
            'Arn': 'arn:aws:iam::123456789012:user/attacker',
            'UserName': 'attacker',
            'Path': '/',
            'UserPolicyList': [{
                'PolicyName': 'assume-middle',
                'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': 'sts:AssumeRole',
                        'Resource': 'arn:aws:iam::123456789012:role/middle-role'
                    }]
                }
            }],
            'AttachedManagedPolicies': [],
            'GroupList': [],
            'Tags': [],
        }],
        'roles': [
            {
                'Arn': 'arn:aws:iam::123456789012:role/middle-role',
                'RoleName': 'middle-role',
                'Path': '/',
                'AssumeRolePolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': 'arn:aws:iam::123456789012:user/attacker'
                        },
                        'Action': 'sts:AssumeRole'
                    }]
                },
                'RolePolicyList': [{
                    'PolicyName': 'assume-admin',
                    'PolicyDocument': {
                        'Version': '2012-10-17',
                        'Statement': [{
                            'Effect': 'Allow',
                            'Action': 'sts:AssumeRole',
                            'Resource': 'arn:aws:iam::123456789012:role/admin-role'
                        }]
                    }
                }],
                'AttachedManagedPolicies': [],
                'InstanceProfileList': [],
                'Tags': [],
            },
            {
                'Arn': 'arn:aws:iam::123456789012:role/admin-role',
                'RoleName': 'admin-role',
                'Path': '/',
                'AssumeRolePolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': 'arn:aws:iam::123456789012:role/middle-role'
                        },
                        'Action': 'sts:AssumeRole'
                    }]
                },
                'RolePolicyList': [{
                    'PolicyName': 'admin',
                    'PolicyDocument': {
                        'Version': '2012-10-17',
                        'Statement': [{
                            'Effect': 'Allow',
                            'Action': '*',
                            'Resource': '*'
                        }]
                    }
                }],
                'AttachedManagedPolicies': [],
                'InstanceProfileList': [],
                'Tags': [],
            },
        ],
        'groups': [],
        'policies': [],
    }


@pytest.fixture
def create_policy_version_auth_details():
    """Auth details with CreatePolicyVersion self-escalation."""
    return {
        'users': [{
            'Arn': 'arn:aws:iam::123456789012:user/policy-editor',
            'UserName': 'policy-editor',
            'Path': '/',
            'UserPolicyList': [],
            'AttachedManagedPolicies': [{
                'PolicyArn': 'arn:aws:iam::123456789012:policy/my-policy',
                'PolicyName': 'my-policy',
            }],
            'GroupList': [],
            'Tags': [],
        }],
        'roles': [],
        'groups': [],
        'policies': [{
            'Arn': 'arn:aws:iam::123456789012:policy/my-policy',
            'PolicyName': 'my-policy',
            'PolicyVersionList': [{
                'VersionId': 'v1',
                'IsDefaultVersion': True,
                'Document': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': 'iam:CreatePolicyVersion',
                        'Resource': '*'
                    }]
                }
            }],
        }],
    }


@pytest.fixture
def cross_account_trust_auth_details():
    """Auth details with cross-account trust without ExternalId."""
    return {
        'users': [],
        'roles': [{
            'Arn': 'arn:aws:iam::123456789012:role/cross-account-role',
            'RoleName': 'cross-account-role',
            'Path': '/',
            'AssumeRolePolicyDocument': {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {
                        'AWS': 'arn:aws:iam::999888777666:root'
                    },
                    'Action': 'sts:AssumeRole'
                }]
            },
            'RolePolicyList': [{
                'PolicyName': 'some-access',
                'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': 's3:*',
                        'Resource': '*'
                    }]
                }
            }],
            'AttachedManagedPolicies': [],
            'InstanceProfileList': [],
            'Tags': [],
        }],
        'groups': [],
        'policies': [],
    }


@pytest.fixture
def permissions_boundary_auth_details():
    """Auth details with a principal that can remove permissions boundaries."""
    return {
        'users': [
            {
                'Arn': 'arn:aws:iam::123456789012:user/boundary-remover',
                'UserName': 'boundary-remover',
                'Path': '/',
                'UserPolicyList': [{
                    'PolicyName': 'boundary-mgmt',
                    'PolicyDocument': {
                        'Version': '2012-10-17',
                        'Statement': [{
                            'Effect': 'Allow',
                            'Action': [
                                'iam:DeleteUserPermissionsBoundary',
                                'iam:DeleteRolePermissionsBoundary',
                            ],
                            'Resource': '*'
                        }]
                    }
                }],
                'AttachedManagedPolicies': [],
                'GroupList': [],
                'Tags': [],
            },
            {
                'Arn': 'arn:aws:iam::123456789012:user/bounded-user',
                'UserName': 'bounded-user',
                'Path': '/',
                'PermissionsBoundary': {
                    'PermissionsBoundaryType': 'Policy',
                    'PermissionsBoundaryArn': (
                        'arn:aws:iam::123456789012:policy/boundary'
                    ),
                },
                'UserPolicyList': [{
                    'PolicyName': 'broad-access',
                    'PolicyDocument': {
                        'Version': '2012-10-17',
                        'Statement': [{
                            'Effect': 'Allow',
                            'Action': '*',
                            'Resource': '*'
                        }]
                    }
                }],
                'AttachedManagedPolicies': [],
                'GroupList': [],
                'Tags': [],
            },
        ],
        'roles': [],
        'groups': [],
        'policies': [],
    }
