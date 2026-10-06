"""
Pure helpers on ``SecurityHubCheck`` used by the CSPM checks SRA-SECURITYHUB-21..25.

``cspm_unlinked_regions`` (``-21``), ``association_of`` (``-22``),
``matches_cspm_findings`` (``-25``) and ``standard_name_of`` on the legacy CIS
``ruleset/`` ARN (``-24``). All four are static and pure, so the tests need no
context and no mocks.
"""
from __future__ import annotations

from typing import Any

import pytest

from sraverify.services.securityhub.base import SecurityHubCheck

_SCANNED = ["eu-west-1", "us-east-1", "us-west-2"]


@pytest.mark.parametrize(
    ("aggregator", "expected"),
    [
        pytest.param(
            {"FindingAggregationRegion": "us-east-1", "RegionLinkingMode": "ALL_REGIONS"},
            [],
            id="all-regions-links-everything",
        ),
        pytest.param(
            {
                "FindingAggregationRegion": "us-east-1",
                "RegionLinkingMode": "ALL_REGIONS_EXCEPT_SPECIFIED",
                "Regions": ["eu-west-1"],
            },
            ["eu-west-1"],
            id="except-specified-excludes-listed",
        ),
        pytest.param(
            {
                "FindingAggregationRegion": "us-east-1",
                "RegionLinkingMode": "SPECIFIED_REGIONS",
                "Regions": ["us-west-2"],
            },
            ["eu-west-1"],
            id="specified-links-only-listed",
        ),
        pytest.param(
            {"FindingAggregationRegion": "us-east-1", "RegionLinkingMode": "NO_REGIONS"},
            ["eu-west-1", "us-west-2"],
            id="no-regions-links-nothing-but-home",
        ),
        pytest.param(
            {
                "FindingAggregationRegion": "us-east-1",
                "RegionLinkingMode": "SPECIFIED_REGIONS",
            },
            ["eu-west-1", "us-west-2"],
            id="specified-with-absent-regions",
        ),
        pytest.param(
            {
                "FindingAggregationRegion": "us-east-1",
                "RegionLinkingMode": "ALL_REGIONS_EXCEPT_SPECIFIED",
            },
            [],
            id="except-specified-with-absent-regions",
        ),
        pytest.param(
            {"FindingAggregationRegion": "us-east-1", "RegionLinkingMode": "SOMETHING_NEW"},
            ["eu-west-1", "us-west-2"],
            id="unknown-mode-links-nothing",
        ),
        pytest.param(
            {"FindingAggregationRegion": "us-east-1"},
            ["eu-west-1", "us-west-2"],
            id="absent-mode-links-nothing",
        ),
    ],
)
def test_cspm_unlinked_regions(aggregator: dict[str, Any], expected: list[str]) -> None:
    """Each linking mode leaves exactly the expected scanned Regions uncovered."""
    assert SecurityHubCheck.cspm_unlinked_regions(aggregator, list(_SCANNED)) == expected


def test_cspm_unlinked_regions_always_covers_the_home_region() -> None:
    """The home Region is covered even when the mode and list exclude it."""
    aggregator = {
        "FindingAggregationRegion": "us-west-2",
        "RegionLinkingMode": "ALL_REGIONS_EXCEPT_SPECIFIED",
        "Regions": ["us-west-2"],
    }
    assert "us-west-2" not in SecurityHubCheck.cspm_unlinked_regions(
        aggregator, list(_SCANNED)
    )


def test_cspm_unlinked_regions_is_sorted() -> None:
    """The result is sorted regardless of input order, so the cell is diffable."""
    aggregator = {"FindingAggregationRegion": "us-east-1", "RegionLinkingMode": "NO_REGIONS"}
    assert SecurityHubCheck.cspm_unlinked_regions(
        aggregator, ["us-west-2", "us-east-1", "eu-west-1"]
    ) == ["eu-west-1", "us-west-2"]


_ACCOUNT = "111122223333"
_OTHER = "444455556666"


def test_association_of_matches_the_account_entry() -> None:
    """An ACCOUNT summary naming the account is returned."""
    summary = {"TargetType": "ACCOUNT", "TargetId": _ACCOUNT, "AssociationStatus": "SUCCESS"}
    assert SecurityHubCheck.association_of([summary], _ACCOUNT) is summary


def test_association_of_ignores_ou_and_root_entries() -> None:
    """An OU or root summary is never an account's association, even on an ID clash."""
    summaries = [
        {"TargetType": "ORGANIZATIONAL_UNIT", "TargetId": _ACCOUNT},
        {"TargetType": "ROOT", "TargetId": _ACCOUNT},
    ]
    assert SecurityHubCheck.association_of(summaries, _ACCOUNT) is None


def test_association_of_absent_account_is_none() -> None:
    """An account with no ACCOUNT summary yields None."""
    summaries = [{"TargetType": "ACCOUNT", "TargetId": _OTHER}]
    assert SecurityHubCheck.association_of(summaries, _ACCOUNT) is None


def test_association_of_first_match_wins() -> None:
    """Two entries for one account resolve to the first, deterministically."""
    first = {"TargetType": "ACCOUNT", "TargetId": _ACCOUNT, "ConfigurationPolicyId": "a"}
    second = {"TargetType": "ACCOUNT", "TargetId": _ACCOUNT, "ConfigurationPolicyId": "b"}
    assert SecurityHubCheck.association_of([first, second], _ACCOUNT) is first


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        pytest.param(
            '{"source":["aws.securityhub"],"detail-type":["Security Hub Findings - Imported"]}',
            True,
            id="cspm-detail-type",
        ),
        pytest.param('{"source":["aws.securityhub"]}', True, id="source-only"),
        pytest.param(
            '{"source":["aws.securityhub"],"detail":{"findings":{"ProductName":["GuardDuty"]}}}',
            True,
            id="detail-only-is-asff",
        ),
        pytest.param(
            '{"source":["aws.securityhub"],"detail-type":["Findings Imported V2"]}',
            False,
            id="v2-only",
        ),
        pytest.param(
            '{"source":["aws.securityhub"],'
            '"detail-type":["Security Hub Findings - Custom Action"]}',
            False,
            id="custom-action-only",
        ),
        pytest.param(
            '{"source":["aws.guardduty"],"detail-type":["Security Hub Findings - Imported"]}',
            False,
            id="wrong-source",
        ),
        pytest.param('{"source":', False, id="invalid-json"),
        pytest.param('["aws.securityhub"]', False, id="not-a-dict"),
        pytest.param(None, False, id="scheduled-rule-no-pattern"),
    ],
)
def test_matches_cspm_findings(pattern: str | None, expected: bool) -> None:
    """Only patterns that would receive CSPM finding events match."""
    rule: dict[str, Any] = {"Name": "r"}
    if pattern is not None:
        rule["EventPattern"] = pattern
    assert SecurityHubCheck.matches_cspm_findings(rule) is expected


def test_standard_name_of_returns_the_legacy_cis_ruleset_arn_whole() -> None:
    """The v1.2.0 CIS ARN has no ``standards/`` segment, so it is returned unchanged."""
    arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
    assert SecurityHubCheck.standard_name_of(arn) == arn


def test_standard_name_of_reduces_a_current_cis_arn() -> None:
    """A v3.0.0 CIS standards ARN reduces to its Region-independent name."""
    arn = "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/3.0.0"
    assert SecurityHubCheck.standard_name_of(arn) == "cis-aws-foundations-benchmark/v/3.0.0"
