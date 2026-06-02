"""
Tests for SRA-IAP-5: Permissions boundary removal check.
"""
import pytest
from unittest.mock import patch

from sraverify.services.iam_attack_paths.checks.sra_iap_5 import SRA_IAP_5
from sraverify.services.iam_attack_paths.base import IAMAttackPathCheck


class TestSRAIAP5:
    """Tests for permissions boundary removal check."""

    def test_boundary_removal_detected(
        self, mock_session, permissions_boundary_auth_details
    ):
        """Principal that can remove boundaries is flagged."""
        with patch.object(
            IAMAttackPathCheck, 'get_auth_details',
            return_value=permissions_boundary_auth_details
        ):
            check = SRA_IAP_5()
            check.initialize(session=mock_session, regions=['us-east-1'])
            findings = check.execute()

        fail_findings = [f for f in findings if f['Status'] == 'FAIL']
        assert len(fail_findings) >= 1
        assert 'boundary-remover' in fail_findings[0]['ResourceId']
        assert 'bounded-user' in fail_findings[0]['ActualValue']

    def test_no_boundary_removal_for_readonly(
        self, mock_session, least_privilege_auth_details
    ):
        """Read-only user passes boundary removal check."""
        with patch.object(
            IAMAttackPathCheck, 'get_auth_details',
            return_value=least_privilege_auth_details
        ):
            check = SRA_IAP_5()
            check.initialize(session=mock_session, regions=['us-east-1'])
            findings = check.execute()

        pass_findings = [f for f in findings if f['Status'] == 'PASS']
        assert len(pass_findings) == 1
