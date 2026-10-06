"""
Per-arm unit tests for the five SIR log-readiness checks.

``SRA-SECURITYINCIDENTRESPONSE-06`` and ``-07``, ``SRA-CLOUDTRAIL-15``,
``SRA-EC2-02`` and ``SRA-ROUTE53RESOLVER-01``. Each test builds a real
``ScanContext`` with a mock session, patches only the identity lookup and the
base-class accessors, and drives ``execute()``. No AWS call is possible:
``tests/conftest.py`` refuses outbound HTTP.
"""
from __future__ import annotations

import json
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Callable
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import sraverify.services
from sraverify.core.aws_errors import error_result
from sraverify.core.enums import Status
from sraverify.core.finding import Finding
from sraverify.core.scan_context import ScanContext
from sraverify.services.cloudtrail.base import CloudTrailCheck
from sraverify.services.cloudtrail.checks.sra_cloudtrail_15 import SRA_CLOUDTRAIL_15
from sraverify.services.ec2.base import EC2Check
from sraverify.services.ec2.checks.sra_ec2_02 import SRA_EC2_02
from sraverify.services.route53resolver.base import Route53ResolverCheck
from sraverify.services.route53resolver.checks.sra_route53resolver_01 import (
    SRA_ROUTE53RESOLVER_01,
)
from sraverify.services.securityincidentresponse.base import (
    SecurityIncidentResponseCheck,
)
from sraverify.services.securityincidentresponse.checks.sra_securityincidentresponse_06 import (
    SRA_SECURITYINCIDENTRESPONSE_06,
)
from sraverify.services.securityincidentresponse.checks.sra_securityincidentresponse_07 import (
    SIR_MANAGED_BY,
    SRA_SECURITYINCIDENTRESPONSE_07,
)

_ACCOUNT = "111122223333"
_OTHER = "999988887777"
_R1 = "us-east-1"
_R2 = "us-west-2"
_SERVICES_ROOT = Path(sraverify.services.__file__).resolve().parent


def _denied(operation: str) -> dict[str, Any]:
    return error_result(code="AccessDenied", message="not authorized", operation=operation)


def _transport() -> dict[str, Any]:
    return error_result(
        code="EndpointConnectionError", message="Could not connect", operation="Request"
    )


def _run(
    check_cls: type,
    base_cls: type,
    accessors: dict[str, Callable[..., Any]],
    regions: list[str] | None = None,
) -> tuple[list[Finding], dict[str, MagicMock]]:
    """Run a check with patched accessors; return its rows and the accessor mocks."""
    ctx = ScanContext(session=MagicMock(name="session"), regions=regions or [_R1])
    with ExitStack() as stack:
        stack.enter_context(
            patch.object(
                ScanContext,
                "get_account_info",
                return_value={"account_id": _ACCOUNT, "account_name": "test"},
            )
        )
        check = check_cls()
        check.initialize(ctx)
        mocks = {
            name: stack.enter_context(patch.object(base_cls, name, side_effect=fn))
            for name, fn in accessors.items()
        }
        rows = list(check.execute())
    return rows, mocks


# --------------------------------------------------------------------------- #
# SRA-SECURITYINCIDENTRESPONSE-06
# --------------------------------------------------------------------------- #

_SLR_ARN = (
    f"arn:aws:iam::{_ACCOUNT}:role/aws-service-role/security-ir.amazonaws.com/"
    "AWSServiceRoleForSecurityIncidentResponse"
)


def _sir06(response: dict[str, Any]) -> list[Finding]:
    rows, _ = _run(
        SRA_SECURITYINCIDENTRESPONSE_06,
        SecurityIncidentResponseCheck,
        {"get_role": lambda name: response},
    )
    assert len(rows) == 1
    assert rows[0].region == "global"
    return rows


def test_sir06_role_present_passes_with_the_returned_arn() -> None:
    rows = _sir06({"Role": {"Arn": _SLR_ARN}})
    assert rows[0].status is Status.PASS
    assert rows[0].resource_id == _SLR_ARN
    assert "exists" in rows[0].actual_value


def test_sir06_no_such_entity_fails_with_the_expected_arn() -> None:
    rows = _sir06(
        error_result(code="NoSuchEntity", message="cannot be found", operation="GetRole")
    )
    assert rows[0].status is Status.FAIL
    assert rows[0].resource_id == _SLR_ARN
    assert "does not exist" in rows[0].actual_value
    assert (
        "aws iam create-service-linked-role --aws-service-name security-ir.amazonaws.com"
        in rows[0].remediation
    )


@pytest.mark.parametrize("failure", [_denied("GetRole"), _transport()])
def test_sir06_other_errors_are_error_rows(failure: dict[str, Any]) -> None:
    rows = _sir06(failure)
    assert rows[0].status is Status.ERROR
    assert rows[0].resource_id == _SLR_ARN
    err = failure["Error"]
    assert rows[0].actual_value.startswith(f"{err['Operation']} failed: {err['Code']}: ")


# --------------------------------------------------------------------------- #
# SRA-SECURITYINCIDENTRESPONSE-07
# --------------------------------------------------------------------------- #


def _rule(name: Any, source: Any, state: Any = "ENABLED", managed: bool = True, **extra) -> dict:
    rule: dict[str, Any] = {"EventBusName": "default", **extra}
    if name is not _MISSING:
        rule["Name"] = name
    if state is not _MISSING:
        rule["State"] = state
    if managed:
        rule["ManagedBy"] = SIR_MANAGED_BY
    if source is not _MISSING:
        rule["EventPattern"] = json.dumps({"source": source, "detail-type": ["x"]})
    return rule


_MISSING = object()
_GD = _rule("SIRGuardDutyRule", ["aws.guardduty"])
_SH = _rule("SIRSecurityHubRule", ["aws.securityhub"])


def _sir07(by_region: dict[str, Any]) -> list[Finding]:
    regions = list(by_region)
    rows, _ = _run(
        SRA_SECURITYINCIDENTRESPONSE_07,
        SecurityIncidentResponseCheck,
        {"get_event_rules": lambda region: by_region[region]},
        regions=regions,
    )
    assert [r.region for r in rows] == regions
    for row in rows:
        assert row.resource_id == f"events:{row.region}:{_ACCOUNT}"
    return rows


def test_sir07_both_rules_enabled_passes() -> None:
    (row,) = _sir07({_R1: {"Rules": [_SH, _GD]}})
    assert row.status is Status.PASS
    assert row.actual_value == (
        "SIR-managed rules ENABLED: SIRGuardDutyRule (GuardDuty), "
        "SIRSecurityHubRule (Security Hub)"
    )


def test_sir07_no_managed_rules_fails_naming_both() -> None:
    (row,) = _sir07({_R1: {"Rules": []}})
    assert row.status is Status.FAIL
    assert row.actual_value == (
        "No SIR-managed EventBridge rule for GuardDuty and Security Hub findings"
    )
    assert "triage.security-ir.amazonaws.com" in row.remediation
    assert "aws iam create-service-linked-role" in row.remediation


def test_sir07_guardduty_only_fails_naming_security_hub() -> None:
    (row,) = _sir07({_R1: {"Rules": [_GD]}})
    assert row.status is Status.FAIL
    assert row.actual_value == "No SIR-managed EventBridge rule for Security Hub findings"


def test_sir07_disabled_rule_fails_naming_it_and_its_state() -> None:
    disabled = _rule("SIRGuardDutyRule", ["aws.guardduty"], state="DISABLED")
    (row,) = _sir07({_R1: {"Rules": [disabled, _SH]}})
    assert row.status is Status.FAIL
    assert row.actual_value == "SIR-managed rules not ENABLED: SIRGuardDutyRule (DISABLED)"


def test_sir07_missing_and_disabled_are_both_reported() -> None:
    disabled = _rule("SIRGuardDutyRule", ["aws.guardduty"], state="DISABLED")
    (row,) = _sir07({_R1: {"Rules": [disabled]}})
    assert row.actual_value == (
        "No SIR-managed EventBridge rule for Security Hub findings; "
        "not ENABLED: SIRGuardDutyRule (DISABLED)"
    )


def test_sir07_customer_rule_named_like_sir_is_not_counted() -> None:
    impostor = _rule("SIRGuardDutyRule", ["aws.guardduty"], managed=False)
    (row,) = _sir07({_R1: {"Rules": [impostor, _SH]}})
    assert row.status is Status.FAIL
    assert "GuardDuty" in row.actual_value


@pytest.mark.parametrize(
    "pattern", [_MISSING, "not json", "[1, 2]", '{"detail-type": ["x"]}', '{"source": 5}']
)
def test_sir07_bad_event_pattern_counts_as_neither(pattern: Any) -> None:
    rule = {"Name": "SIRGuardDutyRule", "State": "ENABLED", "ManagedBy": SIR_MANAGED_BY}
    if pattern is not _MISSING:
        rule["EventPattern"] = pattern
    (row,) = _sir07({_R1: {"Rules": [rule, _SH]}})
    assert row.status is Status.FAIL
    assert row.actual_value == "No SIR-managed EventBridge rule for GuardDuty findings"


def test_sir07_string_source_is_accepted() -> None:
    gd = {
        "Name": "SIRGuardDutyRule", "State": "ENABLED", "ManagedBy": SIR_MANAGED_BY,
        "EventPattern": '{"source": "aws.guardduty"}',
    }
    (row,) = _sir07({_R1: {"Rules": [gd, _SH]}})
    assert row.status is Status.PASS


def test_sir07_error_in_one_region_is_one_error_row_and_the_other_region_continues() -> None:
    rows = _sir07({_R1: _denied("ListRules"), _R2: {"Rules": [_GD, _SH]}})
    assert [r.status for r in rows] == [Status.ERROR, Status.PASS]
    assert rows[0].actual_value.startswith("ListRules failed: AccessDenied: ")


def test_sir07_resource_id_is_stable_across_states() -> None:
    ids = {
        _sir07({_R1: response})[0].resource_id
        for response in ({"Rules": [_GD, _SH]}, {"Rules": []}, _denied("ListRules"))
    }
    assert ids == {f"events:{_R1}:{_ACCOUNT}"}


@pytest.mark.parametrize(
    "rules",
    [
        None,
        [{"ManagedBy": SIR_MANAGED_BY, "State": "ENABLED",
          "EventPattern": '{"source":["aws.guardduty"]}'}, _SH],
        [_rule(None, ["aws.guardduty"]), _SH],
        [_rule("SIRGuardDutyRule", ["aws.guardduty"], state=_MISSING), _SH],
        ["not-a-dict", 7, _GD, _SH],
    ],
    ids=["rules-none", "no-name", "name-none", "no-state", "non-dict-elements"],
)
def test_sir07_malformed_shapes_yield_one_row_without_raising(rules: Any) -> None:
    (row,) = _sir07({_R1: {"Rules": rules}})
    assert row.status in (Status.PASS, Status.FAIL)


def test_sir07_unnamed_and_stateless_rules_render() -> None:
    (row,) = _sir07({_R1: {"Rules": [_rule(None, ["aws.guardduty"], state=_MISSING), _SH]}})
    assert row.actual_value == "SIR-managed rules not ENABLED: <unnamed> (None)"


_json_value = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=8),
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(st.sampled_from(["source", "detail-type", "x"]), children, max_size=3),
    max_leaves=10,
)


@given(
    st.one_of(
        st.none(),
        st.text(max_size=20),
        _json_value.map(json.dumps),
        st.integers(),
    )
)
@settings(max_examples=200, deadline=None)
def test_event_sources_never_raises(pattern: Any) -> None:
    result = SRA_SECURITYINCIDENTRESPONSE_07.event_sources({"EventPattern": pattern})
    assert isinstance(result, frozenset)
    assert all(isinstance(s, str) for s in result)


# --------------------------------------------------------------------------- #
# SRA-CLOUDTRAIL-15
# --------------------------------------------------------------------------- #

_TRAIL = f"arn:aws:cloudtrail:us-east-1:{_ACCOUNT}:trail/org"
_TRAIL2 = f"arn:aws:cloudtrail:us-east-1:{_ACCOUNT}:trail/org2"
_BASELINE = {
    "EventSelectors": [
        {
            "ReadWriteType": "All",
            "IncludeManagementEvents": True,
            "DataResources": [],
            "ExcludeManagementEventSources": [],
        }
    ]
}


def _org_trail(arn: Any = _TRAIL, home: Any = "us-east-1") -> dict[str, Any]:
    trail: dict[str, Any] = {"IsOrganizationTrail": True}
    if arn is not _MISSING:
        trail["TrailARN"] = arn
    if home is not _MISSING:
        trail["HomeRegion"] = home
    return trail


def _ct15(trails: Any, selectors: Callable[[str, str], Any]) -> tuple[list[Finding], dict]:
    rows, mocks = _run(
        SRA_CLOUDTRAIL_15,
        CloudTrailCheck,
        {
            "get_organization_trails": lambda: trails,
            "get_event_selectors": selectors,
        },
    )
    assert all(r.region == "global" for r in rows)
    return rows, mocks


def _one_trail(response: dict[str, Any]) -> Finding:
    rows, _ = _ct15({"trailList": [_org_trail()]}, lambda region, arn: response)
    (row,) = rows
    assert row.resource_id == _TRAIL
    return row


def _basic(*selectors: dict) -> dict:
    return {"EventSelectors": list(selectors)}


def _adv(*selectors: list[dict]) -> dict:
    return {
        "AdvancedEventSelectors": [
            {"Name": f"s{i}", "FieldSelectors": fields} for i, fields in enumerate(selectors)
        ]
    }


_MGMT = {"Field": "eventCategory", "Equals": ["Management"]}


def test_ct15_control_tower_baseline_passes() -> None:
    row = _one_trail(_BASELINE)
    assert row.status is Status.PASS
    assert row.actual_value == (
        "Organization trail logs all read and write management events from every event source"
    )


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (_basic({"ReadWriteType": "All", "IncludeManagementEvents": False}),
         "Management events are not included"),
        (_basic({"ReadWriteType": "ReadOnly", "IncludeManagementEvents": True}),
         "Only ReadOnly management events are recorded"),
        (_basic({"ReadWriteType": "ReadOnly", "IncludeManagementEvents": True},
                {"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True}),
         "Read and write management events are split across selectors "
         "(ReadOnly, WriteOnly); no single selector records both"),
        (_basic({"ReadWriteType": "All", "IncludeManagementEvents": True,
                 "ExcludeManagementEventSources": ["rdsdata.amazonaws.com", "kms.amazonaws.com"]}),
         "Management events from these sources are excluded: "
         "kms.amazonaws.com, rdsdata.amazonaws.com"),
        (_adv([_MGMT, {"Field": "readOnly", "Equals": ["true"]}]),
         "Only read-only management events are recorded"),
        (_adv([_MGMT, {"Field": "readOnly", "Equals": ["false"]}]),
         "Only write management events are recorded"),
        (_adv([_MGMT, {"Field": "readOnly", "Equals": ["true"]}],
              [_MGMT, {"Field": "readOnly", "Equals": ["false"]}]),
         "Read and write management events are split across advanced selectors "
         "(readOnly = false, true); no single selector records both"),
        (_adv([_MGMT, {"Field": "eventSource", "NotEquals": ["kms.amazonaws.com"]}]),
         "Management event sources are restricted: NotEquals kms.amazonaws.com"),
        (_adv([{"Field": "eventCategory", "Equals": ["Data"]},
               {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}]),
         "Management events are not included"),
        ({}, "Management events are not included"),
    ],
    ids=[
        "basic-excluded", "basic-readonly", "basic-split", "basic-sources",
        "adv-readonly-true", "adv-readonly-false", "adv-split", "adv-eventsource",
        "adv-data-only", "both-absent",
    ],
)
def test_ct15_coverage_gaps_fail_with_their_reason(response: dict, reason: str) -> None:
    row = _one_trail(response)
    assert row.status is Status.FAIL
    assert row.actual_value == reason
    assert "put-event-selectors" in row.remediation
    assert "replaces every existing selector" in row.remediation


def test_ct15_advanced_management_selector_passes() -> None:
    assert _one_trail(_adv([_MGMT])).status is Status.PASS


def test_ct15_advanced_list_takes_precedence_over_a_covering_basic_selector() -> None:
    response = {
        **_BASELINE,
        "AdvancedEventSelectors": [
            {"Name": "data", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}]}
        ],
    }
    row = _one_trail(response)
    assert row.status is Status.FAIL
    assert row.actual_value == "Management events are not included"


def test_ct15_no_org_trail_is_one_fail() -> None:
    rows, mocks = _ct15({"trailList": []}, lambda region, arn: _BASELINE)
    (row,) = rows
    assert row.status is Status.FAIL
    assert row.resource_id == f"organization/{_ACCOUNT}"
    mocks["get_event_selectors"].assert_not_called()


def test_ct15_trail_missing_arn_is_skipped() -> None:
    rows, _ = _ct15(
        {"trailList": [_org_trail(arn=_MISSING), _org_trail(arn=_TRAIL2)]},
        lambda region, arn: _BASELINE,
    )
    assert [r.resource_id for r in rows] == [_TRAIL2]


@pytest.mark.parametrize(
    "trail", [_org_trail(arn=_MISSING), _org_trail(home=_MISSING), _org_trail(arn=""), "x"]
)
def test_ct15_every_trail_unusable_is_the_single_no_trail_fail(trail: Any) -> None:
    rows, _ = _ct15({"trailList": [trail]}, lambda region, arn: _BASELINE)
    (row,) = rows
    assert row.status is Status.FAIL
    assert row.resource_id == f"organization/{_ACCOUNT}"


def test_ct15_describe_trails_error_is_one_error_row() -> None:
    rows, _ = _ct15(_denied("DescribeTrails"), lambda region, arn: _BASELINE)
    (row,) = rows
    assert row.status is Status.ERROR
    assert row.resource_id == f"organization/{_ACCOUNT}"
    assert row.actual_value.startswith("DescribeTrails failed: AccessDenied: ")


def test_ct15_trail_not_found_fails_that_trail_and_the_next_still_runs() -> None:
    def selectors(region: str, arn: str) -> Any:
        if arn == _TRAIL:
            return error_result(
                code="TrailNotFoundException", message="Unknown trail", operation="GetEventSelectors"
            )
        return _BASELINE

    rows, _ = _ct15({"trailList": [_org_trail(), _org_trail(arn=_TRAIL2)]}, selectors)
    assert [(r.resource_id, r.status) for r in rows] == [
        (_TRAIL, Status.FAIL), (_TRAIL2, Status.PASS)
    ]


def test_ct15_other_selector_error_is_error_and_continues() -> None:
    def selectors(region: str, arn: str) -> Any:
        return _denied("GetEventSelectors") if arn == _TRAIL else _BASELINE

    rows, _ = _ct15({"trailList": [_org_trail(), _org_trail(arn=_TRAIL2)]}, selectors)
    assert [r.status for r in rows] == [Status.ERROR, Status.PASS]


def test_ct15_selectors_are_read_in_the_home_region_with_the_full_arn() -> None:
    _, mocks = _ct15({"trailList": [_org_trail(home="eu-west-1")]}, lambda r, a: _BASELINE)
    mocks["get_event_selectors"].assert_called_once_with("eu-west-1", _TRAIL)


_basic_selector = st.fixed_dictionaries(
    {},
    optional={
        "IncludeManagementEvents": st.one_of(st.booleans(), st.none(), st.text(max_size=3)),
        "ReadWriteType": st.sampled_from(["All", "ReadOnly", "WriteOnly", "x"]) | st.none(),
        "ExcludeManagementEventSources": st.one_of(
            st.lists(st.sampled_from(["kms.amazonaws.com", "rdsdata.amazonaws.com"]), max_size=2),
            st.none(),
            st.text(max_size=3),
        ),
    },
)
_field_selector = st.fixed_dictionaries(
    {"Field": st.sampled_from(["eventCategory", "readOnly", "eventSource", "resources.type"])},
    optional={
        "Equals": st.one_of(
            st.lists(st.sampled_from(["Management", "Data", "true", "false", "x"]), max_size=3),
            st.none(),
        ),
        "NotEquals": st.lists(st.sampled_from(["kms.amazonaws.com", "x"]), max_size=2),
    },
)
_advanced_selector = st.fixed_dictionaries(
    {}, optional={"FieldSelectors": st.lists(_field_selector | st.integers(), max_size=4)}
)
_response = st.fixed_dictionaries(
    {},
    optional={
        "EventSelectors": st.lists(_basic_selector | st.integers(), max_size=3) | st.none(),
        "AdvancedEventSelectors": st.lists(_advanced_selector | st.none(), max_size=3) | st.none(),
    },
)
_COVERING_BASIC = {"IncludeManagementEvents": True, "ReadWriteType": "All"}
_COVERING_ADVANCED = {"FieldSelectors": [_MGMT]}


def _evaluated_is_advanced(response: dict) -> bool:
    return bool(response.get("AdvancedEventSelectors"))


@given(_response)
@settings(max_examples=300, deadline=None)
def test_management_event_gap_never_raises(response: dict) -> None:
    gap = SRA_CLOUDTRAIL_15.management_event_gap(response)
    assert gap is None or (isinstance(gap, str) and gap)


@given(_response, st.integers(min_value=0, max_value=3))
@settings(max_examples=300, deadline=None)
def test_a_covering_selector_in_the_evaluated_list_covers(response: dict, at: int) -> None:
    response = dict(response)
    if _evaluated_is_advanced(response):
        lst = list(response["AdvancedEventSelectors"])
        lst.insert(min(at, len(lst)), _COVERING_ADVANCED)
        response["AdvancedEventSelectors"] = lst
    else:
        lst = list(response.get("EventSelectors") or [])
        lst.insert(min(at, len(lst)), _COVERING_BASIC)
        response["EventSelectors"] = lst
    assert SRA_CLOUDTRAIL_15.management_event_gap(response) is None


def _covers_basic(s: Any) -> bool:
    return (
        isinstance(s, dict)
        and s.get("IncludeManagementEvents") is True
        and s.get("ReadWriteType") == "All"
        and not s.get("ExcludeManagementEventSources")
    )


def _covers_advanced(s: Any) -> bool:
    if not isinstance(s, dict):
        return False
    fields = [f for f in s.get("FieldSelectors") or [] if isinstance(f, dict)]
    names = {f.get("Field") for f in fields}
    return (
        any(f.get("Field") == "eventCategory" and "Management" in (f.get("Equals") or [])
            for f in fields)
        and "readOnly" not in names
        and "eventSource" not in names
    )


@given(_response)
@settings(max_examples=300, deadline=None)
def test_no_covering_selector_in_the_evaluated_list_is_a_reason(response: dict) -> None:
    if _evaluated_is_advanced(response):
        covered = any(_covers_advanced(s) for s in response["AdvancedEventSelectors"])
    else:
        covered = any(_covers_basic(s) for s in response.get("EventSelectors") or [])
    gap = SRA_CLOUDTRAIL_15.management_event_gap(response)
    assert (gap is None) == covered


# --------------------------------------------------------------------------- #
# SRA-EC2-02 and SRA-ROUTE53RESOLVER-01, shared fixtures
# --------------------------------------------------------------------------- #


def _vpc(vpc_id: Any, owner: str = _ACCOUNT, default: bool = False) -> dict:
    vpc: dict[str, Any] = {"OwnerId": owner, "IsDefault": default}
    if vpc_id is not _MISSING:
        vpc["VpcId"] = vpc_id
    return vpc


class _Flavour:
    """How one of the two VPC checks names its second listing."""

    def __init__(self, check_cls, base_cls, second, key, op, prefix, fail_text, make, cmds):
        self.check_cls = check_cls
        self.base_cls = base_cls
        self.second = second
        self.key = key
        self.op = op
        self.prefix = prefix
        self.fail_text = fail_text
        self.make = make
        self.cmds = cmds

    def run(self, vpcs: Any, entries: Any, regions: list[str] | None = None):
        def get_vpcs(region: str) -> Any:
            return vpcs

        def get_second(region: str) -> Any:
            return entries if isinstance(entries, dict) and "Error" in entries else {self.key: entries}

        return _run(
            self.check_cls,
            self.base_cls,
            {"get_vpcs": get_vpcs, self.second: get_second},
            regions=regions,
        )


def _flow_log(rid: Any, status: str = "ACTIVE", fl_id: str = "fl-1", **extra) -> dict:
    entry: dict[str, Any] = {"FlowLogId": fl_id, "FlowLogStatus": status, "TrafficType": "ALL", **extra}
    if rid is not _MISSING:
        entry["ResourceId"] = rid
    return entry


def _assoc(rid: Any, status: str = "ACTIVE", cfg: str = "rqlc-1", **extra) -> dict:
    entry: dict[str, Any] = {"ResolverQueryLogConfigId": cfg, "Status": status, **extra}
    if rid is not _MISSING:
        entry["ResourceId"] = rid
    return entry


_EC2 = _Flavour(
    SRA_EC2_02, EC2Check, "get_flow_logs", "FlowLogs", "DescribeFlowLogs", "ec2",
    "No active VPC-level flow log", _flow_log,
    ["aws ec2 create-flow-logs --resource-type VPC --resource-ids vpc-a --traffic-type ALL"],
)
_R53 = _Flavour(
    SRA_ROUTE53RESOLVER_01, Route53ResolverCheck, "get_query_log_config_associations",
    "ResolverQueryLogConfigAssociations", "ListResolverQueryLogConfigAssociations",
    "route53resolver", "No active Resolver query logging association", _assoc,
    [
        "aws route53resolver create-resolver-query-log-config",
        "aws route53resolver associate-resolver-query-log-config "
        "--resolver-query-log-config-id <id> --resource-id vpc-a",
    ],
)
_FLAVOURS = pytest.mark.parametrize("fl", [_EC2, _R53], ids=["ec2-02", "route53resolver-01"])


@_FLAVOURS
def test_vpc_with_active_entry_passes(fl: _Flavour) -> None:
    rows, _ = fl.run({"Vpcs": [_vpc("vpc-a")]}, [fl.make("vpc-a")])
    (row,) = rows
    assert row.status is Status.PASS
    assert row.resource_id == "vpc-a"
    if fl is _EC2:
        assert row.actual_value == "Active flow log fl-1 (traffic type ALL)"
    else:
        assert row.actual_value == "Active Resolver query logging association with rqlc-1"


@_FLAVOURS
def test_vpc_without_entry_fails_with_runnable_remediation(fl: _Flavour) -> None:
    rows, _ = fl.run({"Vpcs": [_vpc("vpc-a")]}, [])
    (row,) = rows
    assert row.status is Status.FAIL
    assert row.actual_value == fl.fail_text
    for cmd in fl.cmds:
        assert cmd in row.remediation
    assert f"--region {_R1}" in row.remediation


@_FLAVOURS
def test_default_vpc_fail_notes_it(fl: _Flavour) -> None:
    rows, _ = fl.run({"Vpcs": [_vpc("vpc-a", default=True)]}, [])
    assert rows[0].actual_value == f"{fl.fail_text} (default VPC)"


def test_ec2_subnet_and_eni_flow_logs_do_not_count() -> None:
    rows, _ = _EC2.run(
        {"Vpcs": [_vpc("vpc-a")]}, [_flow_log("subnet-1"), _flow_log("eni-1")]
    )
    assert rows[0].status is Status.FAIL


@_FLAVOURS
def test_non_active_entry_fails(fl: _Flavour) -> None:
    status = "ERROR" if fl is _EC2 else "FAILED"
    rows, _ = fl.run({"Vpcs": [_vpc("vpc-a")]}, [fl.make("vpc-a", status=status)])
    assert rows[0].status is Status.FAIL


@_FLAVOURS
def test_shared_vpc_yields_no_row(fl: _Flavour) -> None:
    rows, _ = fl.run({"Vpcs": [_vpc("vpc-a"), _vpc("vpc-shared", owner=_OTHER)]}, [])
    assert [r.resource_id for r in rows] == ["vpc-a"]


@_FLAVOURS
def test_no_owned_vpc_is_one_pass_and_no_second_call(fl: _Flavour) -> None:
    rows, mocks = fl.run({"Vpcs": [_vpc("vpc-shared", owner=_OTHER)]}, [])
    (row,) = rows
    assert row.status is Status.PASS
    assert row.resource_id == f"{fl.prefix}:{_R1}:{_ACCOUNT}"
    assert row.actual_value == "No VPC owned by this account in this Region"
    mocks[fl.second].assert_not_called()


@_FLAVOURS
def test_describe_vpcs_error_is_one_region_error(fl: _Flavour) -> None:
    rows, mocks = fl.run(_denied("DescribeVpcs"), [], regions=[_R1, _R2])
    assert [r.status for r in rows] == [Status.ERROR, Status.ERROR]
    assert [r.resource_id for r in rows] == [
        f"{fl.prefix}:{_R1}:{_ACCOUNT}", f"{fl.prefix}:{_R2}:{_ACCOUNT}"
    ]
    assert rows[0].actual_value.startswith("DescribeVpcs failed: AccessDenied: ")
    mocks[fl.second].assert_not_called()


@_FLAVOURS
def test_second_listing_error_fans_out_one_error_per_vpc(fl: _Flavour) -> None:
    rows, _ = fl.run(
        {"Vpcs": [_vpc("vpc-c"), _vpc("vpc-a"), _vpc("vpc-b")]}, _denied(fl.op)
    )
    assert [(r.resource_id, r.status) for r in rows] == [
        ("vpc-a", Status.ERROR), ("vpc-b", Status.ERROR), ("vpc-c", Status.ERROR)
    ]
    assert all(r.actual_value.startswith(f"{fl.op} failed: AccessDenied: ") for r in rows)


def test_route53resolver_config_ownership_is_ignored() -> None:
    shared = _assoc("vpc-a", cfg="rqlc-shared", OwnerId=_OTHER)
    rows, _ = _R53.run({"Vpcs": [_vpc("vpc-a")]}, [shared])
    assert rows[0].status is Status.PASS
    assert "rqlc-shared" in rows[0].actual_value


@_FLAVOURS
@pytest.mark.parametrize(
    "bad_vpc", [_vpc(_MISSING), _vpc(None), _vpc(""), "not-a-dict"],
    ids=["no-vpcid", "vpcid-none", "vpcid-empty", "non-dict"],
)
def test_malformed_vpcs_are_skipped(fl: _Flavour, bad_vpc: Any) -> None:
    rows, _ = fl.run({"Vpcs": [bad_vpc, _vpc("vpc-a")]}, [fl.make("vpc-a")])
    assert [(r.resource_id, r.status) for r in rows] == [("vpc-a", Status.PASS)]


@_FLAVOURS
def test_vpcs_none_is_one_region_pass(fl: _Flavour) -> None:
    rows, _ = fl.run({"Vpcs": None}, [])
    assert [r.status for r in rows] == [Status.PASS]


@_FLAVOURS
@pytest.mark.parametrize(
    "bad_entry", ["no-rid", "rid-none", "non-dict"],
)
def test_malformed_entries_are_ignored(fl: _Flavour, bad_entry: str) -> None:
    entry = {"no-rid": fl.make(_MISSING), "rid-none": fl.make(None), "non-dict": 42}[bad_entry]
    rows, _ = fl.run({"Vpcs": [_vpc("vpc-a")]}, [entry])
    assert rows[0].status is Status.FAIL


@_FLAVOURS
def test_second_list_none_fails_each_vpc(fl: _Flavour) -> None:
    rows, _ = fl.run({"Vpcs": [_vpc("vpc-a")]}, None)
    assert rows[0].status is Status.FAIL


# --------------------------------------------------------------------------- #
# Availability lookup (Requirements 2.9, 5.11)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "relative",
    [
        "securityincidentresponse/checks/sra_securityincidentresponse_07.py",
        "securityincidentresponse/base.py",
        "route53resolver/checks/sra_route53resolver_01.py",
        "route53resolver/base.py",
    ],
)
def test_full_coverage_services_issue_no_availability_lookup(relative: str) -> None:
    source = (_SERVICES_ROOT / relative).read_text(encoding="utf-8")
    assert "service_available_in_region" not in source
