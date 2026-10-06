"""SRA-SECURITYHUB-21's FAIL remediation recommends SPECIFIED_REGIONS, never ALL_REGIONS.

Observed live on 2026-10-05: ``update-finding-aggregator --region-linking-mode
ALL_REGIONS`` also subscribed the delegated administrator to Security Hub CSPM in
every enabled Region. ``SPECIFIED_REGIONS`` replaces the linked list, so the
recommended ``--regions`` must keep what is already linked.
"""
from unittest.mock import MagicMock, patch

import pytest

from sraverify.core.scan_context import ScanContext
from sraverify.services.securityhub.checks.sra_securityhub_21 import SRA_SECURITYHUB_21

_ACCOUNT = "111122223333"
_ARN = f"arn:aws:securityhub:us-west-2:{_ACCOUNT}:finding-aggregator/abc"


def _run(aggregator: dict, regions: list[str]):
    ctx = MagicMock(spec=ScanContext)
    ctx.regions = regions
    ctx.audit_accounts = [_ACCOUNT]
    ctx.log_archive_accounts = []
    ctx.get_account_info.return_value = {"account_id": _ACCOUNT, "account_name": "probe"}
    check = SRA_SECURITYHUB_21()
    with patch.object(SRA_SECURITYHUB_21, "_setup_clients", lambda self: None):
        check.initialize(ctx)
    listed = {"FindingAggregators": [{"FindingAggregatorArn": _ARN}]}
    with patch.object(SRA_SECURITYHUB_21, "get_finding_aggregators", return_value=listed), \
            patch.object(SRA_SECURITYHUB_21, "get_finding_aggregator", return_value=aggregator):
        return list(check.execute())


@pytest.mark.parametrize(
    ("mode", "listed", "expected"),
    [
        # Keeps the already-linked us-east-1 and adds the unlinked eu-central-1.
        ("SPECIFIED_REGIONS", ["us-east-1"], "--regions eu-central-1 us-east-1 "),
        # Keeps a linked Region that was not scanned.
        ("SPECIFIED_REGIONS", ["ap-south-1"], "--regions ap-south-1 eu-central-1 us-east-1 "),
        ("NO_REGIONS", [], "--regions eu-central-1 us-east-1 "),
        ("ALL_REGIONS_EXCEPT_SPECIFIED", ["eu-central-1"], "--regions eu-central-1 us-east-1 "),
    ],
)
def test_fail_remediation_names_specified_regions(mode, listed, expected):
    aggregator = {"FindingAggregatorArn": _ARN, "FindingAggregationRegion": "us-west-2",
                  "RegionLinkingMode": mode, "Regions": listed}
    (row,) = _run(aggregator, ["us-west-2", "us-east-1", "eu-central-1"])
    assert row.status.value == "FAIL"
    assert "--region-linking-mode SPECIFIED_REGIONS " in row.remediation
    assert expected in row.remediation
    assert "--region us-west-2" in row.remediation
    # The home Region is never in the list, and ALL_REGIONS is only ever a warning.
    assert "us-west-2 " not in row.remediation.split("--regions ")[1].split(" --region")[0] + " "
    assert "--region-linking-mode ALL_REGIONS" not in row.remediation
    assert "Avoid ALL_REGIONS" in row.remediation


def test_metadata_warns_about_all_regions():
    remediation = SRA_SECURITYHUB_21.meta.remediation
    for field in (remediation.text, remediation.cli, remediation.console):
        assert "ALL_REGIONS" in field or "all Regions" in field
    assert "--region-linking-mode SPECIFIED_REGIONS" in remediation.cli
