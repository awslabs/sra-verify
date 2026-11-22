from unittest.mock import MagicMock, patch

import pytest

from sraverify.core.enums import Status
from sraverify.core.scan_context import ScanContext
from sraverify.services.config.checks.sra_config_02 import SRA_CONFIG_02
from sraverify.services.config.checks.sra_config_03 import SRA_CONFIG_03


REGION = "us-east-1"


def run_check(cls, responses):
    ctx = ScanContext(session=MagicMock(region_name=REGION), regions=[REGION])
    with patch.object(ScanContext, "get_account_info", return_value={"account_id": "111122223333", "account_name": "test"}):
        check = cls()
        check.initialize(ctx)
        with patch.multiple(check, **{key: MagicMock(return_value=value) for key, value in responses.items()}):
            rows = list(check.execute())
    assert len(rows) == 1
    assert rows[0].region == REGION
    return rows[0]


def recorder(value, recording=True):
    status = {"name": "default", "recording": recording}
    if value is not ...:
        status["lastStatus"] = value
    return run_check(SRA_CONFIG_02, {"get_configuration_recorders": {"ConfigurationRecorders": [{"name": "default"}]}, "get_configuration_recorder_status": {"ConfigurationRecordersStatus": [status]}})


def channel(history="SUCCESS", snapshot=None, stream=None, config=None):
    status = {"name": "default", "configHistoryDeliveryInfo": {"lastStatus": history}}
    if snapshot is not None:
        status["configSnapshotDeliveryInfo"] = snapshot
    if stream is not None:
        status["configStreamDeliveryInfo"] = stream
    return run_check(SRA_CONFIG_03, {"get_delivery_channels": {"DeliveryChannels": [{"name": "default", **(config or {})}]}, "get_delivery_channel_status": {"DeliveryChannelsStatus": [status]}})


@pytest.mark.parametrize("value,expected", [("SUCCESS", Status.PASS), ("Success", Status.PASS), ("success", Status.FAIL), ("sUcCeSs", Status.FAIL), ("Failure", Status.FAIL), ("Pending", Status.FAIL), ("NotApplicable", Status.FAIL), (..., Status.FAIL), (42, Status.FAIL), (" Success ", Status.FAIL)])
def test_recorder_status(value, expected):
    row = recorder(value)
    assert row.status == expected
    if expected == Status.PASS:
        assert value in row.actual_value


def test_stopped_recorder():
    assert recorder("Success", False).status == Status.FAIL


@pytest.mark.parametrize("leg", ["history", "snapshot", "stream"])
@pytest.mark.parametrize("value,expected", [("SUCCESS", Status.PASS), ("Success", Status.PASS), ("success", None), ("sUcCeSs", None)])
def test_delivery_success_casing(leg, value, expected):
    args = {leg: value if leg == "history" else {"lastStatus": value}}
    row = channel(**args)
    assert row.status == (expected or (Status.FAIL if leg == "history" else Status.ERROR))


@pytest.mark.parametrize("leg,config", [("snapshot", {"configSnapshotDeliveryProperties": {"deliveryFrequency": "One_Hour"}}), ("stream", {"snsTopicARN": "arn:topic"})])
@pytest.mark.parametrize("info,expected", [(None, Status.ERROR), ({}, Status.ERROR), ({"lastStatus": "Not_Applicable"}, Status.ERROR), ({"lastStatus": "Failure"}, Status.FAIL), ({"lastStatus": "FAILURE"}, Status.FAIL), ({"lastStatus": ""}, Status.ERROR), ({"lastStatus": None}, Status.ERROR)])
def test_configured_optional_leg(leg, config, info, expected):
    row = channel(config=config, **{leg: info})
    assert row.status == expected
    assert leg.lower() in row.actual_value.lower()


@pytest.mark.parametrize("leg", ["snapshot", "stream"])
@pytest.mark.parametrize("info", [None, {}, {"lastStatus": "Not_Applicable"}])
def test_unconfigured_optional_leg_is_neutral(leg, info):
    assert channel(**{leg: info}).status == Status.PASS


@pytest.mark.parametrize("leg", ["snapshot", "stream"])
@pytest.mark.parametrize("field", ["lastErrorCode", "lastErrorMessage"])
def test_error_without_optional_verdict(leg, field):
    assert channel(**{leg: {field: "problem"}}).status == Status.ERROR


def test_snapshot_attempt_without_verdict():
    assert channel(snapshot={"lastAttemptTime": "today"}).status == Status.ERROR


def test_snapshot_failure_without_schedule():
    assert channel(snapshot={"lastStatus": "Failure"}).status == Status.FAIL


def test_stream_failure_without_topic_is_contradictory():
    assert channel(stream={"lastStatus": "Failure"}).status == Status.ERROR


def test_failure_wins_over_indeterminate():
    assert channel(snapshot={"lastStatus": "Failure"}, stream={"lastStatus": ""}).status == Status.FAIL


@pytest.mark.parametrize("value", ["Failure", "Not_Applicable", None])
def test_history_failure(value):
    assert channel(history=value).status == Status.FAIL


def test_conflicting_channel_name_is_unknown():
    row = run_check(SRA_CONFIG_03, {"get_delivery_channels": {"DeliveryChannels": [{"name": "other"}]}, "get_delivery_channel_status": {"DeliveryChannelsStatus": [{"name": "default", "configHistoryDeliveryInfo": {"lastStatus": "Success"}}]}})
    assert row.status == Status.ERROR
    assert row.resource_id == "config:deliveryChannel:default"


def test_stream_status_change_alone_is_not_attempt():
    assert channel(stream={"lastStatusChangeTime": "today"}).status == Status.PASS


@pytest.mark.parametrize("field", ["lastAttemptTime", "lastSuccessfulTime", "nextDeliveryTime"])
def test_snapshot_timestamp_without_status(field):
    assert channel(snapshot={field: "today"}).status == Status.ERROR


def test_no_channel_remediation_keeps_sns_optional():
    row = run_check(SRA_CONFIG_03, {"get_delivery_channels": {"DeliveryChannels": []}, "get_delivery_channel_status": {"DeliveryChannelsStatus": []}})
    assert row.status == Status.FAIL
    assert "SNS" not in row.remediation


@pytest.mark.parametrize("leg", ["snapshot", "stream"])
def test_lowercase_failure_is_recognized(leg):
    assert channel(config={"snsTopicARN": "arn:topic"}, **{leg: {"lastStatus": "failure"}}).status == Status.FAIL


@pytest.mark.parametrize("leg", ["snapshot", "stream"])
def test_lowercase_not_applicable_is_neutral(leg):
    assert channel(**{leg: {"lastStatus": "not_applicable"}}).status == Status.PASS


def test_not_applicable_with_old_snapshot_attempt_is_neutral():
    assert channel(snapshot={"lastStatus": "Not_Applicable", "lastAttemptTime": "today"}).status == Status.PASS


def test_empty_delivery_status_list_fails():
    row = run_check(SRA_CONFIG_03, {"get_delivery_channels": {"DeliveryChannels": [{"name": "default"}]}, "get_delivery_channel_status": {"DeliveryChannelsStatus": []}})
    assert row.status == Status.FAIL
    assert "No delivery channel status" in row.actual_value


def test_delivery_access_denied_is_error():
    row = run_check(SRA_CONFIG_03, {"get_delivery_channels": {"Error": {"Code": "AccessDeniedException", "Message": "denied", "Operation": "DescribeDeliveryChannels"}}})
    assert row.status == Status.ERROR
    assert "AccessDeniedException" in row.actual_value


def test_missing_history_fails():
    row = run_check(SRA_CONFIG_03, {"get_delivery_channels": {"DeliveryChannels": [{"name": "default"}]}, "get_delivery_channel_status": {"DeliveryChannelsStatus": [{"name": "default"}]}})
    assert row.status == Status.FAIL
    assert "History" in row.actual_value


def test_all_delivery_legs_succeed_with_documented_casing():
    row = channel(history="Success", snapshot={"lastStatus": "SUCCESS"}, stream={"lastStatus": "Success"}, config={"snsTopicARN": "arn:topic"})
    assert row.status == Status.PASS
    assert row.resource_id == "config:deliveryChannel:default"


@pytest.mark.parametrize("leg", ["snapshot", "stream"])
@pytest.mark.parametrize("value", [" Success ", "unexpected", 42])
def test_unknown_optional_status_is_error(leg, value):
    assert channel(**{leg: {"lastStatus": value}}).status == Status.ERROR


@pytest.mark.parametrize("leg", ["snapshot", "stream"])
def test_unconfigured_leg_with_empty_status_is_error(leg):
    row = channel(history="Success", **{leg: {"lastStatus": ""}})
    assert row.status == Status.ERROR
    assert leg.lower() in row.actual_value.lower()


def test_sns_remediation_is_conditional():
    row = run_check(SRA_CONFIG_03, {"get_delivery_channels": {"DeliveryChannels": [{"name": "default"}]}, "get_delivery_channel_status": {"DeliveryChannelsStatus": []}})
    assert "if configured" in row.remediation
    assert "if configured" in SRA_CONFIG_03.meta.remediation.console
