from contextlib import ExitStack
from unittest.mock import MagicMock, patch
import pytest
from sraverify.core.aws_errors import error_result
from sraverify.core.enums import Status
from sraverify.core.scan_context import ScanContext
from sraverify.services.config.checks.sra_config_01 import SRA_CONFIG_01
from sraverify.services.config.checks.sra_config_02 import SRA_CONFIG_02
from sraverify.services.config.checks.sra_config_03 import SRA_CONFIG_03
from sraverify.services.config.checks.sra_config_04 import SRA_CONFIG_04
from sraverify.services.config.checks.sra_config_05 import SRA_CONFIG_05
from sraverify.services.config.checks.sra_config_06 import SRA_CONFIG_06
from sraverify.services.config.checks.sra_config_07 import SRA_CONFIG_07
from sraverify.services.config.checks.sra_config_08 import SRA_CONFIG_08
from sraverify.services.config.checks.sra_config_09 import SRA_CONFIG_09
from sraverify.services.config.checks.sra_config_10 import SRA_CONFIG_10


ACCOUNT = "111122223333"
REGION = "us-east-1"
RECORDER = f"arn:aws:config:{REGION}:{ACCOUNT}:configurationRecorder/main"
DEFAULT_RECORDER = f"arn:aws:config:{REGION}:{ACCOUNT}:configurationRecorder/default"
DEFAULT_CHANNEL = f"arn:aws:config:{REGION}:{ACCOUNT}:deliveryChannel/default"


def _run(check_cls, regions=None, responses=None, regional=False, archive=None, audit_accounts=None, delegation=None, statuses=None):
    regions = [REGION] if regions is None else regions
    session = MagicMock()
    session.region_name = REGION
    ctx = ScanContext(session=session, regions=regions,
                      log_archive_accounts=[ARCHIVE] if archive is None else archive,
                      audit_accounts=[AUDIT] if audit_accounts is None else list(audit_accounts))
    with ExitStack() as stack:
        stack.enter_context(patch.object(ScanContext, "get_account_info", return_value={"account_id": ACCOUNT, "account_name": "test"}))
        if not regions:
            stack.enter_context(patch.object(ctx, "get_enabled_regions", return_value=[]))
        if delegation is not None:
            stack.enter_context(patch.object(ctx.organization, "delegated_administrators", side_effect=delegation.__getitem__))
        check = check_cls()
        check.initialize(ctx)
        for name, response in (responses or {}).items():
            if regional:
                stack.enter_context(patch.object(check, name, side_effect=lambda region, values=response: values[region]))
            else:
                stack.enter_context(patch.object(check, name, return_value=response))
        if statuses is not None:
            class Wrapper:
                def __init__(self, region):
                    self.region = region

                def describe_configuration_aggregator_sources_status(self, name):
                    return statuses[(self.region, name)]

            stack.enter_context(patch.object(check, "get_client", side_effect=lambda region: Wrapper(region) if any(key[0] == region for key in statuses) else None))
        return list(check.execute())


def assert_row_a(rows, status, region, resource, *fragments):
    assert len(rows) == 1
    row = rows[0]
    assert (row.status, row.region, row.resource_id) == (status, region, resource)
    assert row.checked_value == "Config Configuration"
    for fragment in fragments:
        assert fragment in row.actual_value
    return row


def recorder_responses(recorders, statuses):
    return {
        "get_configuration_recorders": {"ConfigurationRecorders": recorders},
        "get_configuration_recorder_status": {"ConfigurationRecordersStatus": statuses},
    }


@pytest.mark.parametrize("check_cls", [
    pytest.param(SRA_CONFIG_01, id="config-01"),
    pytest.param(SRA_CONFIG_02, id="config-02"),
    pytest.param(SRA_CONFIG_03, id="config-03"),
])
def test_no_regions_a(check_cls):
    assert_row_a(_run(check_cls, responses={}, regions=[]), Status.ERROR, "global", "config:global", "No regions specified")


@pytest.mark.parametrize("check_cls", [
    pytest.param(SRA_CONFIG_01, id="config-01"),
    pytest.param(SRA_CONFIG_02, id="config-02"),
])
@pytest.mark.parametrize("statuses", [
    pytest.param([], id="empty"),
    pytest.param([{"name": "other", "recording": True, "lastStatus": "SUCCESS"}], id="different-name"),
])
def test_recorder_missing_status(check_cls, statuses):
    assert_row_a(_run(check_cls, responses=recorder_responses([{"name": "main"}], statuses)), Status.ERROR, REGION, RECORDER, "DescribeConfigurationRecorderStatus returned no status", "main")


@pytest.mark.parametrize("check_cls", [
    pytest.param(SRA_CONFIG_01, id="config-01"),
    pytest.param(SRA_CONFIG_02, id="config-02"),
])
def test_recorder_absent(check_cls):
    assert_row_a(_run(check_cls, responses=recorder_responses([], [])), Status.FAIL, REGION, DEFAULT_RECORDER, "No configuration recorder")


@pytest.mark.parametrize("recording,expected,fragment", [
    pytest.param(True, Status.PASS, "exists and is recording", id="recording"),
    pytest.param(False, Status.FAIL, "exists but is not recording", id="stopped"),
])
def test_config_01_recording(recording, expected, fragment):
    responses = recorder_responses([{"name": "main"}], [{"name": "main", "recording": recording}])
    assert_row_a(_run(SRA_CONFIG_01, responses=responses), expected, REGION, RECORDER, fragment)


@pytest.mark.parametrize("status,expected,resource,fragments", [
    pytest.param({"name": "main", "recording": True, "lastStatus": "SUCCESS", "arn": "arn:explicit"}, Status.PASS, "arn:explicit", ["lastStatus: SUCCESS"], id="healthy-explicit-arn"),
    pytest.param({"name": "main", "recording": False, "lastStatus": "SUCCESS"}, Status.FAIL, RECORDER, ["not recording"], id="stopped"),
    pytest.param({"name": "main", "recording": True, "lastStatus": "FAILURE", "lastErrorCode": "Denied", "lastErrorMessage": "missing permission"}, Status.FAIL, RECORDER, ["lastStatus: FAILURE", "errorCode: Denied", "errorMessage: missing permission"], id="failure-with-details"),
    pytest.param({"name": "main", "recording": True, "lastStatus": "FAILURE"}, Status.FAIL, RECORDER, ["lastStatus: FAILURE"], id="failure-without-details"),
    pytest.param({"name": "main", "recording": True}, Status.FAIL, RECORDER, ["lastStatus: UNKNOWN"], id="missing-last-status"),
])
def test_config_02_health(status, expected, resource, fragments):
    responses = recorder_responses([{"name": "main"}], [status])
    row = assert_row_a(_run(SRA_CONFIG_02, responses=responses), expected, REGION, resource, *fragments)
    if "lastErrorCode" not in status:
        assert "errorCode:" not in row.actual_value
        assert "errorMessage:" not in row.actual_value


@pytest.mark.parametrize("check_cls,listing,status_method,operation", [
    pytest.param(SRA_CONFIG_01, {"get_configuration_recorders": {"ConfigurationRecorders": [{"name": "main"}]}}, "get_configuration_recorder_status", "DescribeConfigurationRecorderStatus", id="config-01"),
    pytest.param(SRA_CONFIG_02, {"get_configuration_recorders": {"ConfigurationRecorders": [{"name": "main"}]}}, "get_configuration_recorder_status", "DescribeConfigurationRecorderStatus", id="config-02"),
    pytest.param(SRA_CONFIG_03, {"get_delivery_channels": {"DeliveryChannels": [{"name": "main"}]}}, "get_delivery_channel_status", "DescribeDeliveryChannelStatus", id="config-03"),
])
def test_status_denied_after_listing(check_cls, listing, status_method, operation):
    responses = {**listing, status_method: error_result(code="AccessDenied", message="not authorized", operation=operation)}
    assert_row_a(_run(check_cls, responses=responses), Status.ERROR, REGION, f"config:{ACCOUNT}:{REGION}", operation, "AccessDenied", "not authorized")


def channel_responses(channels, statuses):
    return {"get_delivery_channels": {"DeliveryChannels": channels}, "get_delivery_channel_status": {"DeliveryChannelsStatus": statuses}}


@pytest.mark.parametrize("channels,statuses,fragment", [
    pytest.param([], [], "No delivery channel found", id="no-channel"),
    pytest.param([{"name": "main"}], [], "No delivery channel status found", id="no-status"),
])
def test_config_03_absent(channels, statuses, fragment):
    assert_row_a(_run(SRA_CONFIG_03, responses=channel_responses(channels, statuses)), Status.FAIL, REGION, DEFAULT_CHANNEL, fragment)


@pytest.mark.parametrize("history,expected,fragments", [
    pytest.param({"lastStatus": "SUCCESS", "lastSuccessfulTime": "success-time", "lastAttemptTime": "attempt-time"}, Status.PASS, ["Config History: SUCCESS (Last success: success-time)"], id="success"),
    pytest.param({"lastStatus": "FAILURE", "lastAttemptTime": "attempt-time", "lastSuccessfulTime": "success-time"}, Status.FAIL, ["Config History: FAILURE (Last attempt: attempt-time)"], id="failure"),
    pytest.param({}, Status.FAIL, ["Config History: UNKNOWN (Last attempt: UNKNOWN)"], id="missing-history"),
])
def test_config_03_delivery_health(history, expected, fragments):
    status = {"name": "main", "configHistoryDeliveryInfo": history}
    if "lastStatus" in history:
        status["configSnapshotDeliveryInfo"] = {"lastStatus": history["lastStatus"]}
        status["configStreamDeliveryInfo"] = {"lastStatus": history["lastStatus"]}
    responses = channel_responses([{"name": "main"}], [status])
    row = assert_row_a(_run(SRA_CONFIG_03, responses=responses), expected, REGION, "config:deliveryChannel:main", *fragments)
    if "lastStatus" in history:
        assert f"Config Snapshot: {history['lastStatus']}" in row.actual_value
        assert f"Config Stream: {history['lastStatus']}" in row.actual_value


ARCHIVE = "444455556666"
R1 = "us-east-1"
R2 = "us-west-2"
ARN = f"arn:aws:config:{R2}:{ACCOUNT}:config-aggregator/config-aggregator-a1b2c3d4"
NONE = f"arn:aws:config:global:{ACCOUNT}:config-aggregator/none"
ORG_B = {"ConfigurationAggregatorName": "org", "ConfigurationAggregatorArn": ARN,
       "OrganizationAggregationSource": {"RoleArn": f"arn:aws:iam::{ACCOUNT}:role/config-aggregator", "AllAwsRegions": True}}
ACCOUNT_SOURCE = {"ConfigurationAggregatorName": "account", "AccountAggregationSources": [{"AccountIds": [ACCOUNT], "AllAwsRegions": True}]}
FINITE_ORG = {"ConfigurationAggregatorName": "org", "ConfigurationAggregatorArn": ARN, "OrganizationAggregationSource": {"RoleArn": f"arn:aws:iam::{ACCOUNT}:role/config-aggregator", "AllAwsRegions": False, "AwsRegions": [R1]}}
DENIED = error_result(code="AccessDenied", message="not authorized", operation="DescribeConfigurationAggregators")


def fields(rows):
    return [(r.status, r.region, r.resource_id, r.checked_value, r.actual_value) for r in rows]


@pytest.mark.parametrize("cls,checked", [
    pytest.param(SRA_CONFIG_04, "Configuration aggregator exists", id="config-04"),
    pytest.param(SRA_CONFIG_05, "AllAwsRegions: true", id="config-05"),
])
def test_aggregator_found_after_account_source_in_later_region(cls, checked):
    rows = _run(cls, responses={"get_configuration_aggregators": {
        R1: {"ConfigurationAggregators": [ACCOUNT_SOURCE]},
        R2: {"ConfigurationAggregators": [ACCOUNT_SOURCE, ORG_B]},
    }}, regional=True, regions=[R1, R2])
    assert len(rows) == 1
    assert fields(rows)[0][:4] == (Status.PASS, "global", ARN, checked)
    assert "org" in rows[0].actual_value and R2 in rows[0].actual_value


def test_config_04_finite_organization_source():
    rows = _run(SRA_CONFIG_04, regions=[R2], responses={"get_configuration_aggregators": {R2: {"ConfigurationAggregators": [FINITE_ORG]}}}, regional=True)
    assert fields(rows)[0][:4] == (Status.PASS, "global", ARN, "Configuration aggregator exists")
    assert len(rows) == 1
    assert "org" in rows[0].actual_value


@pytest.mark.parametrize("cls,aggregators,checked,actual", [
    pytest.param(SRA_CONFIG_04, [], "Configuration aggregator exists", "No organization aggregator found in any region", id="04-empty"),
    pytest.param(SRA_CONFIG_04, [ACCOUNT_SOURCE], "Configuration aggregator exists", "No organization aggregator found in any region", id="04-account-only"),
    pytest.param(SRA_CONFIG_05, [], "AllAwsRegions: true", "No organization aggregator with AllAwsRegions=true found in any region", id="05-empty"),
    pytest.param(SRA_CONFIG_05, [ACCOUNT_SOURCE], "AllAwsRegions: true", "No organization aggregator with AllAwsRegions=true found in any region", id="05-account-only"),
    pytest.param(SRA_CONFIG_05, [FINITE_ORG], "AllAwsRegions: true", "No organization aggregator with AllAwsRegions=true found in any region", id="05-finite-false"),
    pytest.param(SRA_CONFIG_05, [{"OrganizationAggregationSource": {"RoleArn": f"arn:aws:iam::{ACCOUNT}:role/config-aggregator", "AwsRegions": [R1]}}], "AllAwsRegions: true", "No organization aggregator with AllAwsRegions=true found in any region", id="05-finite-omitted"),
])
def test_aggregator_absent(cls, aggregators, checked, actual):
    rows = _run(cls, regions=[R2], responses={"get_configuration_aggregators": {R2: {"ConfigurationAggregators": aggregators}}}, regional=True)
    assert fields(rows) == [(Status.FAIL, "global", NONE, checked, actual)]


@pytest.mark.parametrize("cls,checked", [
    pytest.param(SRA_CONFIG_04, "Configuration aggregator exists", id="config-04"),
    pytest.param(SRA_CONFIG_05, "AllAwsRegions: true", id="config-05"),
])
@pytest.mark.parametrize("found", [pytest.param(False, id="empty"), pytest.param(True, id="found")])
def test_aggregator_denied_region_does_not_imply_absence(cls, checked, found):
    rows = _run(cls, responses={"get_configuration_aggregators": {
        R1: DENIED, R2: {"ConfigurationAggregators": [ORG_B] if found else []},
    }}, regional=True, regions=[R1, R2])
    assert len(rows) == 1 + int(found)
    assert (rows[0].status, rows[0].region, rows[0].resource_id) == (Status.ERROR, R1, f"config:{ACCOUNT}:{R1}")
    assert rows[0].actual_value == "DescribeConfigurationAggregators failed: AccessDenied: not authorized"
    if found:
        assert fields(rows)[1][:4] == (Status.PASS, "global", ARN, checked)
        assert "org" in rows[1].actual_value and R2 in rows[1].actual_value


@pytest.mark.parametrize("cls,accessor,checked", [
    pytest.param(SRA_CONFIG_04, "get_configuration_aggregators", "Configuration aggregator exists", id="config-04"),
    pytest.param(SRA_CONFIG_05, "get_configuration_aggregators", "AllAwsRegions: true", id="config-05"),
    pytest.param(SRA_CONFIG_06, "get_delivery_channels", f"S3 bucket owned by Log Archive account {ARCHIVE}", id="config-06"),
])
def test_no_regions_b(cls, accessor, checked):
    rows = _run(cls, responses={accessor: {}}, regional=True, regions=[])
    assert fields(rows) == [(Status.ERROR, "global", "config:global", checked, "No regions specified for check")]


@pytest.mark.parametrize("channels,status,resource,actual", [
    pytest.param([], Status.FAIL, "default", "No delivery channel found in this region", id="empty"),
    pytest.param([{"name": "central"}], Status.FAIL, "central", "No S3 bucket configured for delivery channel", id="missing-bucket"),
    pytest.param([{"name": "central", "s3BucketName": f"logs-{ARCHIVE}-{R1}-an"}], Status.PASS, "central", f"Delivery channel S3 bucket 'logs-{ARCHIVE}-{R1}-an' is owned by the Log Archive account {ARCHIVE}", id="regional-bucket"),
    pytest.param([{"name": "central", "s3BucketName": f"logs-999988887777-{R1}-an"}], Status.FAIL, "central", f"Delivery channel S3 bucket 'logs-999988887777-{R1}-an' does not appear to be owned by the Log Archive account {ARCHIVE} based on the bucket name", id="different-account-bucket"),
])
def test_delivery_channel_verdict(channels, status, resource, actual):
    rows = _run(SRA_CONFIG_06, responses={"get_delivery_channels": {R1: {"DeliveryChannels": channels}}}, regional=True)
    assert fields(rows) == [(status, R1, f"arn:aws:config:{R1}:{ACCOUNT}:deliveryChannel/{resource}", f"S3 bucket owned by Log Archive account {ARCHIVE}", actual)]


def test_delivery_channel_missing_archive_account():
    rows = _run(SRA_CONFIG_06, responses={"get_delivery_channels": {}}, regional=True, archive=[])
    assert fields(rows) == [(Status.ERROR, "global", "config:global", "S3 bucket owned by Log Archive account", "Log Archive Account ID not provided")]


def test_delivery_channel_denied_and_valid_region():
    bucket = f"logs-{ARCHIVE}-{R1}-an"
    denied = error_result(code="AccessDenied", message="not authorized", operation="DescribeDeliveryChannels")
    rows = _run(SRA_CONFIG_06, responses={"get_delivery_channels": {
        R1: denied, R2: {"DeliveryChannels": [{"name": "central", "s3BucketName": bucket}]},
    }}, regional=True, regions=[R1, R2])
    assert len(rows) == 2
    assert (rows[0].status, rows[0].region, rows[0].resource_id, rows[0].actual_value) == (Status.ERROR, R1, f"config:{ACCOUNT}:{R1}", "DescribeDeliveryChannels failed: AccessDenied: not authorized")
    assert fields(rows)[1] == (Status.PASS, R2, f"arn:aws:config:{R2}:{ACCOUNT}:deliveryChannel/central", f"S3 bucket owned by Log Archive account {ARCHIVE}", f"Delivery channel S3 bucket '{bucket}' is owned by the Log Archive account {ARCHIVE}")


AUDIT = "222233334444"
OTHER = "999988887777"
PRINCIPALS = ("config.amazonaws.com", "config-multiaccountsetup.amazonaws.com")


def _admin(account):
    return {"Id": account, "Name": f"account-{account}"}


def _response(*accounts):
    return {"DelegatedAdministrators": [_admin(account) for account in accounts]}


def _assert_rows(rows, expected):
    assert len(rows) == len(expected)
    for row, (status, resource, checked, actual) in zip(rows, expected):
        assert row.status is status
        assert row.region == "global"
        assert row.resource_id == resource
        assert checked in row.checked_value
        assert actual in row.actual_value


@pytest.mark.parametrize(
    "first,second,expected",
    [
        pytest.param(_response(AUDIT), _response(AUDIT), [(Status.PASS, f"delegated-admin/{AUDIT}", "exists for Config service", "for both service principals")], id="both-principals"),
        pytest.param(_response(), _response(), [(Status.FAIL, "delegated-admin/none", "exists for Config service", "No delegated administrator found")], id="none"),
        pytest.param(_response(AUDIT), _response(), [(Status.FAIL, f"delegated-admin/{AUDIT}", "all Config service principals", "not for all required service principals")], id="one-principal"),
        pytest.param(_response(AUDIT), _response(OTHER), [(Status.FAIL, f"delegated-admin/{AUDIT}", "all Config service principals", "not for all required service principals"), (Status.FAIL, f"delegated-admin/{OTHER}", "all Config service principals", "not for all required service principals")], id="different-accounts"),
    ],
)
def test_config_07_delegation(first, second, expected):
    _assert_rows(_run(SRA_CONFIG_07, delegation={PRINCIPALS[0]: first, PRINCIPALS[1]: second}), expected)


@pytest.mark.parametrize(
    "first,second,audit_accounts,expected",
    [
        pytest.param(_response(AUDIT), _response(AUDIT), (AUDIT,), [(Status.PASS, f"delegated-admin/{AUDIT}", AUDIT, "for both service principals")], id="audit-both-principals"),
        pytest.param(_response(), _response(), (AUDIT,), [(Status.FAIL, "delegated-admin/none", AUDIT, "No delegated administrator found")], id="none"),
        pytest.param(_response(OTHER), _response(OTHER), (AUDIT,), [(Status.FAIL, "delegated-admin/none", AUDIT, f"{OTHER} (account-{OTHER}) are not the audit account")], id="other-account"),
        pytest.param(_response(AUDIT), _response(), (AUDIT,), [(Status.FAIL, f"delegated-admin/{AUDIT}", "for both service principals", "not for all required service principals")], id="audit-one-principal"),
        pytest.param(_response(AUDIT), _response(AUDIT), (AUDIT, OTHER), [(Status.PASS, f"delegated-admin/{AUDIT}", AUDIT, "for both service principals")], id="one-matching-audit-of-two"),
        pytest.param(_response(), _response(), (), [(Status.ERROR, "delegated-admin/none", "audit account", "No audit account ID provided")], id="missing-audit-account"),
    ],
)
def test_config_08_audit_delegation(first, second, audit_accounts, expected):
    rows = _run(SRA_CONFIG_08, delegation={PRINCIPALS[0]: first, PRINCIPALS[1]: second}, audit_accounts=audit_accounts)
    _assert_rows(rows, expected)


@pytest.mark.parametrize("check_cls", [pytest.param(SRA_CONFIG_07, id="config-07"), pytest.param(SRA_CONFIG_08, id="config-08")])
def test_second_principal_denied_does_not_report_partial_results(check_cls):
    denied = error_result(code="AccessDenied", message="not authorized", operation="ListDelegatedAdministrators")
    rows = _run(check_cls, delegation={PRINCIPALS[0]: _response(AUDIT), PRINCIPALS[1]: denied})
    assert len(rows) == 1
    assert rows[0].status is Status.ERROR
    assert rows[0].region == "global"
    assert rows[0].resource_id == f"organization/{ACCOUNT}"
    assert rows[0].actual_value == "ListDelegatedAdministrators failed: AccessDenied: not authorized"


TYPES = [
    "AWS::Bedrock::DataSource",
    "AWS::BedrockAgentCore::BrowserCustom",
    "AWS::BedrockAgentCore::CodeInterpreterCustom",
    "AWS::BedrockAgentCore::Gateway",
    "AWS::BedrockAgentCore::Memory",
    "AWS::BedrockAgentCore::Runtime",
    "AWS::SageMaker::FeatureGroup",
    "AWS::SageMaker::InferenceExperiment",
    "AWS::SageMaker::Model",
    "AWS::SageMaker::ModelExplainabilityJobDefinition",
    "AWS::SageMaker::ModelQualityJobDefinition",
    "AWS::SageMaker::MonitoringSchedule",
    "AWS::SageMaker::NotebookInstance",
]


def denied(operation):
    return error_result(code="AccessDenied", message="not authorized", operation=operation)


def assert_row_d(row, status, region, resource, checked, actual):
    assert (row.status, row.region, row.resource_id) == (status, region, resource)
    assert row.checked_value == checked
    assert actual in row.actual_value


CHECKED_09 = "All source statuses are SUCCEEDED"
CHECKED_10 = "All 13 AI/ML resource types are recorded"
ORG_D = {"ConfigurationAggregatorName": "org", "ConfigurationAggregatorArn": ARN, "OrganizationAggregationSource": {"RoleArn": f"arn:aws:iam::{ACCOUNT}:role/config-aggregator"}}
EMPTY = {"ConfigurationAggregators": []}
MATCH = {"ConfigurationAggregators": [ORG_D]}


@pytest.mark.parametrize("cls,checked", [
    pytest.param(SRA_CONFIG_09, CHECKED_09, id="09"),
    pytest.param(SRA_CONFIG_10, CHECKED_10, id="10"),
])
def test_empty_regions(cls, checked):
    rows = _run(cls, regions=[])
    assert len(rows) == 1
    assert_row_d(rows[0], Status.ERROR, "global", "config:global", checked, "No regions specified")


@pytest.mark.parametrize("aggregators", [
    pytest.param({R1: EMPTY, R2: EMPTY}, id="empty"),
    pytest.param({R1: {"ConfigurationAggregators": [ACCOUNT_SOURCE]}, R2: EMPTY}, id="account-only"),
])
def test_09_no_organization_aggregator(aggregators):
    rows = _run(SRA_CONFIG_09, regions=[R1, R2], responses={'get_configuration_aggregators': aggregators}, regional=True)
    assert len(rows) == 1
    assert_row_d(rows[0], Status.FAIL, "global", f"arn:aws:config:global:{ACCOUNT}:config-aggregator/none", CHECKED_09, "No organization aggregator")


@pytest.mark.parametrize("second,expected", [
    pytest.param(EMPTY, False, id="later-empty"),
    pytest.param(MATCH, True, id="later-match"),
])
def test_09_discovery_denial_then_later_region(second, expected):
    rows = _run(SRA_CONFIG_09, regions=[R1, R2], responses={'get_configuration_aggregators': {R1: denied("DescribeConfigurationAggregators"), R2: second}}, regional=True, statuses={(R2, "org"): {"AggregatedSourceStatusList": [{"SourceId": "ok", "LastUpdateStatus": "SUCCEEDED"}]}})
    by_region = {row.region: row for row in rows}
    assert len(rows) == len(by_region) == (2 if expected else 1)
    assert_row_d(by_region[R1], Status.ERROR, R1, f"config:{ACCOUNT}:{R1}", "Config Configuration", "DescribeConfigurationAggregators failed: AccessDenied: not authorized")
    if expected:
        assert_row_d(by_region["global"], Status.PASS, "global", ARN, CHECKED_09, "all sources with status SUCCEEDED")


@pytest.mark.parametrize("response,status,fragment", [
    pytest.param({"AggregatedSourceStatusList": [{"SourceId": "ok", "LastUpdateStatus": "SUCCEEDED"}]}, Status.PASS, "all sources with status SUCCEEDED", id="succeeded"),
    pytest.param({"AggregatedSourceStatusList": []}, Status.FAIL, "No source statuses", id="empty"),
    pytest.param({"AggregatedSourceStatusList": [{"SourceType": "ACCOUNT", "SourceId": "ok", "LastUpdateStatus": "SUCCEEDED"}, {"SourceType": "ACCOUNT", "SourceId": "bad", "LastUpdateStatus": "FAILED"}, {"SourceType": "ACCOUNT", "SourceId": "old", "LastUpdateStatus": "OUTDATED"}, {"SourceType": "ACCOUNT", "SourceId": "unknown"}]}, Status.FAIL, "sources with status", id="mixed"),
    pytest.param(denied("DescribeConfigurationAggregatorSourcesStatus"), Status.ERROR, "DescribeConfigurationAggregatorSourcesStatus failed: AccessDenied: not authorized", id="denied"),
])
def test_09_source_status(response, status, fragment):
    rows = _run(SRA_CONFIG_09, regions=[R2], responses={'get_configuration_aggregators': {R2: MATCH}}, regional=True, statuses={(R2, "org"): response})
    assert len(rows) == 1
    row = rows[0]
    assert_row_d(row, status, "global", ARN, CHECKED_09, fragment)
    if "bad" in str(response):
        for fragment in ("ACCOUNT:bad (FAILED)", "ACCOUNT:old (OUTDATED)", "ACCOUNT:unknown (UNKNOWN)"):
            assert fragment in row.actual_value
        assert "ACCOUNT:ok" not in row.actual_value


def test_09_missing_client():
    rows = _run(SRA_CONFIG_09, regions=[R2], responses={'get_configuration_aggregators': {R2: MATCH}}, regional=True, statuses={})
    assert len(rows) == 1
    assert_row_d(rows[0], Status.ERROR, "global", ARN, CHECKED_09, f"No Config client available for region {R2}")


@pytest.mark.parametrize("group,status,missing", [
    pytest.param({"allSupported": True, "recordingStrategy": {"useOnly": "ALL_SUPPORTED_RESOURCE_TYPES"}}, Status.PASS, [], id="all-supported"),
    pytest.param({"recordingStrategy": {"useOnly": "INCLUSION_BY_RESOURCE_TYPES"}, "resourceTypes": TYPES}, Status.PASS, [], id="full-inclusion"),
    pytest.param({"recordingStrategy": {"useOnly": "EXCLUSION_BY_RESOURCE_TYPES"}, "resourceTypes": [], "exclusionByResourceTypes": {"resourceTypes": ["AWS::S3::Bucket"]}}, Status.PASS, [], id="exclusion-no-targets"),
    pytest.param({"allSupported": True}, Status.PASS, [], id="legacy-all"),
    pytest.param({"resourceTypes": TYPES}, Status.PASS, [], id="legacy-inclusion"),
    pytest.param({"recordingStrategy": {"useOnly": "INCLUSION_BY_RESOURCE_TYPES"}, "resourceTypes": TYPES[2:]}, Status.FAIL, TYPES[:2], id="partial-inclusion"),
    pytest.param({"recordingStrategy": {"useOnly": "INCLUSION_BY_RESOURCE_TYPES"}, "resourceTypes": []}, Status.FAIL, TYPES, id="empty-inclusion"),
    pytest.param({"recordingStrategy": {"useOnly": "EXCLUSION_BY_RESOURCE_TYPES"}, "exclusionByResourceTypes": {"resourceTypes": [TYPES[0], TYPES[8]]}}, Status.FAIL, [TYPES[0], TYPES[8]], id="excluded-targets"),
])
def test_10_recording_groups(group, status, missing):
    rows = _run(SRA_CONFIG_10, regions=[R1], responses={'get_configuration_recorders': {R1: {"ConfigurationRecorders": [{"name": "recorder", "recordingGroup": group}]}}}, regional=True)
    assert len(rows) == 1
    row = rows[0]
    arn = f"arn:aws:config:{R1}:{ACCOUNT}:configurationRecorder/recorder"
    assert_row_d(row, status, R1, arn, CHECKED_10, "records all 13" if not missing else f"does not record {len(missing)} of 13")
    if missing:
        assert set(row.actual_value.split("types: ", 1)[1].split(", ")) == set(missing)


def test_10_no_recorder():
    rows = _run(SRA_CONFIG_10, regions=[R1], responses={'get_configuration_recorders': {R1: {"ConfigurationRecorders": []}}}, regional=True)
    assert len(rows) == 1
    assert_row_d(rows[0], Status.FAIL, R1, f"arn:aws:config:{R1}:{ACCOUNT}:configurationRecorder/default", CHECKED_10, "No configuration recorder")


def test_10_denial_then_valid_region():
    rows = _run(SRA_CONFIG_10, regions=[R1, R2], responses={'get_configuration_recorders': {
        R1: denied("DescribeConfigurationRecorders"),
        R2: {"ConfigurationRecorders": [{"name": "recorder", "recordingGroup": {"allSupported": True}}]},
    }}, regional=True)
    by_region = {row.region: row for row in rows}
    assert len(rows) == len(by_region) == 2
    assert_row_d(by_region[R1], Status.ERROR, R1, f"config:{ACCOUNT}:{R1}", CHECKED_10, "DescribeConfigurationRecorders failed: AccessDenied: not authorized")
    assert_row_d(by_region[R2], Status.PASS, R2, f"arn:aws:config:{R2}:{ACCOUNT}:configurationRecorder/recorder", CHECKED_10, "records all 13")
