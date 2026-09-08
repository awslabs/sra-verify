"""
Tests for SRA-IAP-2: CreatePolicyVersion self-escalation check.
"""
import pytest
from unittest.mock import patch

from sraverify.services.iam_attack_paths.checks.sra_iap_2 import SRA_IAP_2
from sraverify.services.iam_attack_paths.base import IAMAttackPathCheck


class TestSRAIAP2:
    """Tests for CreatePolicyVersion self-escalation check."""

    def test_create_policy_version_detected(
        self, mock_session, create_policy_version_auth_details
    ):
        """User with CreatePolicyVersion on own policy is flagged."""
        with patch.object(
            IAMAttackPathCheck, 'get_auth_details',
            return_value=create_policy_version_auth_details
        ):
            check = SRA_IAP_2()
            check.initialize(session=mock_session, regions=['us-east-1'])
            findings = check.execute()

        fail_findings = [f for f in findings if f['Status'] == 'FAIL']
        assert len(fail_findings) == 1
        assert 'policy-editor' in fail_findings[0]['ResourceId']
        assert 'my-policy' in fail_findings[0]['ActualValue']

    def test_no_create_policy_version(
        self, mock_session, least_privilege_auth_details
    ):
        """User without CreatePolicyVersion passes."""
        with patch.object(
            IAMAttackPathCheck, 'get_auth_details',
            return_value=least_privilege_auth_details
        ):
            check = SRA_IAP_2()
            check.initialize(session=mock_session, regions=['us-east-1'])
            findings = check.execute()

        pass_findings = [f for f in findings if f['Status'] == 'PASS']
        assert len(pass_findings) == 1
