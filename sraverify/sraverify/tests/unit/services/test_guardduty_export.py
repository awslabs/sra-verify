from importlib import import_module
from unittest.mock import MagicMock, patch

import pytest

from sraverify.core.enums import Status
from sraverify.core.scan_context import ScanContext
from sraverify.services.guardduty.base import GuardDutyCheck

REGION = "us-east-1"
DETECTOR = "detector"
DESTINATION = {"DestinationId": "dest", "DestinationType": "S3", "Status": "PUBLISHING"}
DETAIL = {
    **DESTINATION,
    "DestinationProperties": {
        "DestinationArn": "arn:aws:s3:::valid-bucket/prefix",
        "KmsKeyArn": "arn:aws:kms:us-west-2:123456789012:key/mrk-0123456789abcdef0123456789abcdef",
    },
}


def run(detectors, details, pages, descriptions):
    cls = import_module(
        "sraverify.services.guardduty.checks.sra_guardduty_27"
    ).SRA_GUARDDUTY_27
    ctx = ScanContext(session=MagicMock(), regions=[REGION])
    with patch.object(
        ScanContext,
        "get_account_info",
        return_value={"account_id": "123456789012", "account_name": "test"},
    ):
        check = cls()
        check.initialize(ctx)
        with patch.object(
            GuardDutyCheck, "get_detector_id", return_value=detectors
        ), patch.object(
            GuardDutyCheck, "get_detector_details", return_value=details
        ), patch.object(
            GuardDutyCheck, "list_publishing_destinations", side_effect=pages
        ), patch.object(
            GuardDutyCheck, "describe_publishing_destination", side_effect=descriptions
        ):
            return list(check.execute())


@pytest.mark.parametrize(
    "detectors,expected",
    [
        ({"DetectorIds": []}, Status.FAIL),
        ({}, Status.ERROR),
        ({"DetectorIds": ["a", "b"]}, Status.ERROR),
        ({"DetectorIds": [None]}, Status.ERROR),
    ],
)
def test_detector_validation(detectors, expected):
    assert run(detectors, {}, [], [])[0].status == expected


@pytest.mark.parametrize(
    "details,expected",
    [
        ({"Status": "DISABLED"}, Status.FAIL),
        ({}, Status.ERROR),
        ({"Status": "UNKNOWN"}, Status.ERROR),
    ],
)
def test_detector_status(details, expected):
    assert run({"DetectorIds": [DETECTOR]}, details, [], [])[0].status == expected


@pytest.mark.parametrize(
    "pages,descriptions,expected",
    [
        ([{"Destinations": []}], [], Status.FAIL),
        ([{"Destinations": [], "NextToken": None}], [], Status.ERROR),
        ([{}], [], Status.ERROR),
        (
            [
                {"Destinations": [], "NextToken": "again"},
                {"Destinations": [], "NextToken": "again"},
            ],
            [],
            Status.ERROR,
        ),
        ([{"Destinations": [DESTINATION, None]}], [DETAIL], Status.PASS),
        (
            [{"Destinations": [DESTINATION]}],
            [
                {
                    **DETAIL,
                    "DestinationProperties": {
                        "DestinationArn": "arn:aws-eusc:s3:::valid-bucket/prefix with spaces",
                        "KmsKeyArn": "arn:aws-eusc:kms:eusc-de-east-1:999999999999:key/01234567-89ab-cdef-0123-456789abcdef",
                    },
                }
            ],
            Status.PASS,
        ),
        ([{"Destinations": [DESTINATION]}], [DETAIL], Status.PASS),
        (
            [{"Destinations": [DESTINATION]}],
            [
                {
                    **DETAIL,
                    "DestinationProperties": {
                        "DestinationArn": "arn:aws:s3:::valid-bucket",
                        "KmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/not-a-key",
                    },
                }
            ],
            Status.FAIL,
        ),
        (
            [{"Destinations": [DESTINATION]}],
            [{**DETAIL, "Status": "STOPPED"}],
            Status.FAIL,
        ),
        (
            [{"Destinations": [DESTINATION]}],
            [{**DETAIL, "Status": "FUTURE"}],
            Status.ERROR,
        ),
        ([{"Destinations": [DESTINATION]}], [{**DETAIL, "Status": []}], Status.ERROR),
        (
            [{"Destinations": [DESTINATION]}],
            [
                {
                    **DETAIL,
                    "DestinationProperties": {
                        "DestinationArn": "invalid",
                        "KmsKeyArn": "",
                    },
                }
            ],
            Status.FAIL,
        ),
        (
            [{"Destinations": [DESTINATION]}],
            [
                {
                    **DETAIL,
                    "DestinationProperties": {"DestinationArn": None, "KmsKeyArn": ""},
                }
            ],
            Status.ERROR,
        ),
        (
            [{"Destinations": [DESTINATION]}],
            [
                {
                    key: value
                    for key, value in DETAIL.items()
                    if key != "DestinationProperties"
                }
            ],
            Status.ERROR,
        ),
        (
            [{"Destinations": [DESTINATION]}],
            [{**DETAIL, "DestinationProperties": {}}],
            Status.FAIL,
        ),
        (
            [{"Destinations": [DESTINATION]}],
            [
                {
                    **DETAIL,
                    "DestinationProperties": {
                        "DestinationArn": "arn:aws:s3:::192.168.1.1",
                        "KmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/01234567-89ab-cdef-0123-456789abcdef",
                    },
                }
            ],
            Status.FAIL,
        ),
        (
            [{"Destinations": [DESTINATION]}],
            [{**DETAIL, "DestinationId": "other"}],
            Status.ERROR,
        ),
        (
            [{"Destinations": [{"DestinationId": "new", "DestinationType": "FUTURE"}]}],
            [],
            Status.FAIL,
        ),
    ],
)
def test_destination_outcomes(pages, descriptions, expected):
    row = run({"DetectorIds": [DETECTOR]}, {"Status": "ENABLED"}, pages, descriptions)[
        0
    ]
    assert row.status == expected
    assert row.resource_id == f"guardduty:{REGION}"


@pytest.mark.parametrize(
    "partition,region,bucket,expected",
    [
        ("aws", "us-east-1", "Legacy_BUCKET", Status.PASS),
        ("aws", "us-east-1", "a" * 64, Status.PASS),
        ("aws", "us-west-2", "Legacy_BUCKET", Status.FAIL),
        ("aws", "us-west-2", "a" * 64, Status.FAIL),
        ("aws-eusc", "eusc-de-east-1", "Legacy_BUCKET", Status.FAIL),
        ("aws-eusc", "eusc-de-east-1", "valid-bucket", Status.PASS),
    ],
)
def test_bucket_legacy_region_rules(partition, region, bucket, expected):
    detail = {
        **DETAIL,
        "DestinationProperties": {
            "DestinationArn": f"arn:{partition}:s3:::{bucket}/prefix with spaces",
            "KmsKeyArn": f"arn:{partition}:kms:{region}:999999999999:key/01234567-89ab-cdef-0123-456789abcdef",
        },
    }
    rows = run(
        {"DetectorIds": [DETECTOR]},
        {"Status": "ENABLED"},
        [{"Destinations": [DESTINATION]}],
        [detail],
    )
    assert rows[0].status == expected


@pytest.mark.parametrize(
    "envelope",
    [
        {"Error": None},
        {"Error": {}},
        {"Error": {"Code": 3, "Message": "x", "Operation": "x"}},
    ],
)
@pytest.mark.parametrize(
    "operation",
    ["list_detectors", "get_detector", "list_destinations", "describe_destination"],
)
def test_malformed_errors_are_regional_errors(envelope, operation):
    detectors = (
        envelope if operation == "list_detectors" else {"DetectorIds": [DETECTOR]}
    )
    details = envelope if operation == "get_detector" else {"Status": "ENABLED"}
    pages = [
        (
            envelope
            if operation == "list_destinations"
            else {"Destinations": [DESTINATION]}
        )
    ]
    descriptions = [envelope]
    row = run(detectors, details, pages, descriptions)[0]
    assert row.status == Status.ERROR
    assert row.resource_id == f"guardduty:{REGION}"


def test_malformed_describe_error_does_not_hide_pass():
    destinations = [DESTINATION, {"DestinationId": "other", "DestinationType": "S3"}]
    rows = run(
        {"DetectorIds": [DETECTOR]},
        {"Status": "ENABLED"},
        [{"Destinations": destinations}],
        [{"Error": None}, {**DETAIL, "DestinationId": "other"}],
    )
    assert rows[0].status == Status.PASS


def test_invalid_summary_without_passing_candidate_is_error():
    rows = run(
        {"DetectorIds": [DETECTOR]},
        {"Status": "ENABLED"},
        [{"Destinations": [None]}],
        [],
    )
    assert rows[0].status == Status.ERROR


def test_client_stubber_pagination_and_describe():
    import boto3
    from botocore.stub import Stubber
    from sraverify.services.guardduty.checks.sra_guardduty_27 import SRA_GUARDDUTY_27

    session = boto3.Session(
        aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION
    )
    ctx = ScanContext(session=session, regions=[REGION])
    check = SRA_GUARDDUTY_27()
    check.initialize(ctx)
    client = ctx.get_client("guardduty", region=REGION)
    first = {"DestinationId": "first", "DestinationType": "S3", "Status": "PUBLISHING"}
    second = {"DestinationId": "second", "DestinationType": "S3", "Status": "STOPPED"}
    second_detail = {
        **DETAIL,
        "DestinationId": "second",
        "DestinationProperties": {
            "DestinationArn": "arn:aws:s3:::valid-bucket/export prefix",
            "KmsKeyArn": "arn:aws:kms:us-west-2:999999999999:key/01234567-89ab-cdef-0123-456789abcdef",
        },
        "PublishingFailureStartTimestamp": 0,
    }
    first_detail = {
        **DETAIL,
        "DestinationId": "first",
        "Status": "STOPPED",
        "PublishingFailureStartTimestamp": 0,
    }
    with Stubber(client) as stubber:
        stubber.add_response(
            "list_publishing_destinations",
            {"Destinations": [first], "NextToken": "next"},
            {"DetectorId": DETECTOR},
        )
        stubber.add_response(
            "list_publishing_destinations",
            {"Destinations": [second]},
            {"DetectorId": DETECTOR, "NextToken": "next"},
        )
        stubber.add_response(
            "describe_publishing_destination",
            first_detail,
            {"DetectorId": DETECTOR, "DestinationId": "first"},
        )
        stubber.add_response(
            "describe_publishing_destination",
            second_detail,
            {"DetectorId": DETECTOR, "DestinationId": "second"},
        )
        with patch.object(
            ScanContext,
            "get_account_info",
            return_value={"account_id": "123456789012", "account_name": "test"},
        ), patch.object(
            GuardDutyCheck, "get_detector_id", return_value={"DetectorIds": [DETECTOR]}
        ), patch.object(
            GuardDutyCheck, "get_detector_details", return_value={"Status": "ENABLED"}
        ):
            rows = list(check.execute())
        assert rows[0].status == Status.PASS
        stubber.assert_no_pending_responses()


def test_pagination_pass_and_mixed_inconclusive():
    pages = [
        {"Destinations": [DESTINATION], "NextToken": "next"},
        {"Destinations": [{"DestinationId": "other", "DestinationType": "S3"}]},
    ]
    rows = run({"DetectorIds": [DETECTOR]}, {"Status": "ENABLED"}, pages, [DETAIL, {}])
    assert rows[0].status == Status.PASS


def test_list_error_after_first_page_overrides_candidate():
    from sraverify.core.aws_errors import error_result

    pages = [
        {"Destinations": [DESTINATION], "NextToken": "next"},
        error_result(
            code="AccessDenied",
            message="denied",
            operation="ListPublishingDestinations",
        ),
    ]
    rows = run({"DetectorIds": [DETECTOR]}, {"Status": "ENABLED"}, pages, [])
    assert rows[0].status == Status.ERROR
    assert "ListPublishingDestinations" in rows[0].actual_value


def test_describe_error_reports_operation_and_code():
    from sraverify.core.aws_errors import error_result

    rows = run(
        {"DetectorIds": [DETECTOR]},
        {"Status": "ENABLED"},
        [{"Destinations": [DESTINATION]}],
        [
            error_result(
                code="AccessDenied",
                message="denied",
                operation="DescribePublishingDestination",
            )
        ],
    )
    assert rows[0].status == Status.ERROR
    assert "DescribePublishingDestination failed: AccessDenied" in rows[0].actual_value


@pytest.mark.parametrize(
    "operation",
    ["list_detectors", "get_detector", "list_destinations", "describe_destination"],
)
def test_malformed_error_does_not_discard_later_region(operation):
    from sraverify.services.guardduty.checks.sra_guardduty_27 import SRA_GUARDDUTY_27

    ctx = ScanContext(session=MagicMock(), regions=[REGION, "us-west-2"])
    malformed = {"Error": {}}
    detectors = (
        [malformed, {"DetectorIds": [DETECTOR]}]
        if operation == "list_detectors"
        else [{"DetectorIds": [DETECTOR]}] * 2
    )
    details = (
        [malformed, {"Status": "ENABLED"}]
        if operation == "get_detector"
        else [{"Status": "ENABLED"}] * 2
    )
    pages = (
        [malformed, {"Destinations": [DESTINATION]}]
        if operation == "list_destinations"
        else [{"Destinations": [DESTINATION]}] * 2
    )
    descriptions = (
        [malformed, DETAIL] if operation == "describe_destination" else [DETAIL] * 2
    )
    with patch.object(
        ScanContext,
        "get_account_info",
        return_value={"account_id": "123456789012", "account_name": "test"},
    ):
        check = SRA_GUARDDUTY_27()
        check.initialize(ctx)
        with patch.object(
            GuardDutyCheck, "get_detector_id", side_effect=detectors
        ), patch.object(
            GuardDutyCheck, "get_detector_details", side_effect=details
        ), patch.object(
            GuardDutyCheck, "list_publishing_destinations", side_effect=pages
        ), patch.object(
            GuardDutyCheck, "describe_publishing_destination", side_effect=descriptions
        ):
            rows = list(check.execute())
    assert [(row.region, row.status, row.resource_id) for row in rows] == [
        (REGION, Status.ERROR, f"guardduty:{REGION}"),
        ("us-west-2", Status.PASS, "guardduty:us-west-2"),
    ]


def test_other_regions_survive_malformed_destination():
    from sraverify.services.guardduty.checks.sra_guardduty_27 import SRA_GUARDDUTY_27

    ctx = ScanContext(session=MagicMock(), regions=[REGION, "us-west-2"])
    with patch.object(
        ScanContext,
        "get_account_info",
        return_value={"account_id": "123456789012", "account_name": "test"},
    ):
        check = SRA_GUARDDUTY_27()
        check.initialize(ctx)
        with patch.object(
            GuardDutyCheck, "get_detector_id", return_value={"DetectorIds": [DETECTOR]}
        ), patch.object(
            GuardDutyCheck, "get_detector_details", return_value={"Status": "ENABLED"}
        ), patch.object(
            GuardDutyCheck,
            "list_publishing_destinations",
            return_value={"Destinations": [DESTINATION]},
        ), patch.object(
            GuardDutyCheck,
            "describe_publishing_destination",
            side_effect=[{**DETAIL, "Status": []}, DETAIL],
        ):
            rows = list(check.execute())
    assert [(row.region, row.status) for row in rows] == [
        (REGION, Status.ERROR),
        ("us-west-2", Status.PASS),
    ]
