"""
Tests for SRA-IAP-4: Transitive privilege escalation check.
"""
import pytest
from unittest.mock import patch

from sraverify.services.iam_attack_paths.checks.sra_iap_4 import SRA_IAP_4
from sraverify.services.iam_attack_paths.base import IAMAttackPathCheck


class TestSRAIAP4:
    """Tests for transitive privilege escalation check."""

    def test_multi_hop_escalation_detected(
        self, mock_session, multi_hop_auth_details
    ):
        """3-hop chain (user -> middle -> admin) is detected."""
        with patch.object(
            IAMAttackPathCheck, 'get_auth_details',
            return_value=multi_hop_auth_details
        ):
            check = SRA_IAP_4()
            check.initialize(session=mock_session, regions=['us-east-1'])
            findings = check.execute()

        fail_findings = [f for f in findings if f['Status'] == 'FAIL']
        assert len(fail_findings) >= 1
        # Should include path description
        assert 'attacker' in fail_findings[0]['ActualValue']
        assert 'admin-role' in fail_findings[0]['ActualValue']

    def test_no_escalation_for_least_privilege(
        self, mock_session, least_privilege_auth_details
    ):
        """No transitive paths for read-only user."""
        with patch.object(
            IAMAttackPathCheck, 'get_auth_details',
            return_value=least_privilege_auth_details
        ):
            check = SRA_IAP_4()
            check.initialize(session=mock_session, regions=['us-east-1'])
            findings = check.execute()

        pass_findings = [f for f in findings if f['Status'] == 'PASS']
        assert len(pass_findings) == 1

    def test_single_hop_not_reported(
        self, mock_session, passrole_ec2_auth_details
    ):
        """Single-hop paths are NOT reported by SRA-IAP-4 (handled by other checks)."""
        with patch.object(
            IAMAttackPathCheck, 'get_auth_details',
            return_value=passrole_ec2_auth_details
        ):
            check = SRA_IAP_4()
            check.initialize(session=mock_session, regions=['us-east-1'])
            findings = check.execute()

        # Single-hop paths should result in PASS for this check
        # (other checks handle single-hop)
        fail_findings = [f for f in findings if f['Status'] == 'FAIL']
        # Ensure no single-hop paths are reported
        for f in fail_findings:
            assert '1 hops' not in f['ActualValue']
