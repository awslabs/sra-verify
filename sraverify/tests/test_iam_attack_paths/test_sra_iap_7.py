"""
Tests for SRA-IAP-7: Cross-account trust without ExternalId.
"""
import pytest
from unittest.mock import patch

from sraverify.services.iam_attack_paths.checks.sra_iap_7 import SRA_IAP_7
from sraverify.services.iam_attack_paths.base import IAMAttackPathCheck


class TestSRAIAP7:
    """Tests for cross-account trust without ExternalId."""

    def test_cross_account_without_external_id_detected(
        self, mock_session, cross_account_trust_auth_details
    ):
        """Cross-account trust without ExternalId is flagged."""
        with patch.object(
            IAMAttackPathCheck, 'get_auth_details',
            return_value=cross_account_trust_auth_details
        ):
            check = SRA_IAP_7()
            check.initialize(session=mock_session, regions=['us-east-1'])
            findings = check.execute()

        fail_findings = [f for f in findings if f['Status'] == 'FAIL']
        assert len(fail_findings) == 1
        assert '999888777666' in fail_findings[0]['ActualValue']

    def test_cross_account_with_external_id_passes(self, mock_session):
        """Cross-account trust WITH ExternalId passes."""
        auth_details = {
            'users': [],
            'roles': [{
                'Arn': 'arn:aws:iam::123456789012:role/safe-role',
                'RoleName': 'safe-role',
                'Path': '/',
                'AssumeRolePolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': 'arn:aws:iam::999888777666:root'
                        },
                        'Action': 'sts:AssumeRole',
                        'Condition': {
                            'StringEquals': {
                                'sts:ExternalId': 'unique-external-id-123'
                            }
                        }
                    }]
                },
                'RolePolicyList': [],
                'AttachedManagedPolicies': [],
                'InstanceProfileList': [],
                'Tags': [],
            }],
            'groups': [],
            'policies': [],
        }

        with patch.object(
            IAMAttackPathCheck, 'get_auth_details',
            return_value=auth_details
        ):
            check = SRA_IAP_7()
            check.initialize(session=mock_session, regions=['us-east-1'])
            findings = check.execute()

        pass_findings = [f for f in findings if f['Status'] == 'PASS']
        assert len(pass_findings) == 1

    def test_same_account_trust_not_flagged(self, mock_session):
        """Same-account trust is not flagged (not cross-account)."""
        auth_details = {
            'users': [],
            'roles': [{
                'Arn': 'arn:aws:iam::123456789012:role/internal-role',
                'RoleName': 'internal-role',
                'Path': '/',
                'AssumeRolePolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': 'arn:aws:iam::123456789012:root'
                        },
                        'Action': 'sts:AssumeRole'
                    }]
                },
                'RolePolicyList': [],
                'AttachedManagedPolicies': [],
                'InstanceProfileList': [],
                'Tags': [],
            }],
            'groups': [],
            'policies': [],
        }

        with patch.object(
            IAMAttackPathCheck, 'get_auth_details',
            return_value=auth_details
        ):
            check = SRA_IAP_7()
            check.initialize(session=mock_session, regions=['us-east-1'])
            findings = check.execute()

        pass_findings = [f for f in findings if f['Status'] == 'PASS']
        assert len(pass_findings) == 1
