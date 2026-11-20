from unittest.mock import MagicMock, patch

import pytest

from sraverify.core.aws_errors import error_result
from sraverify.core.enums import AccountType, Status
from sraverify.core.scan_context import ScanContext

ACCOUNT = "111122223333"
R1, R2 = "us-east-1", "us-west-2"


def run_check(trails, inventory, locks):
    from sraverify.services.cloudtrail.checks.sra_cloudtrail_16 import SRA_CLOUDTRAIL_16

    ctx = ScanContext(session=MagicMock(), regions=[R1, R2])
    with patch.object(
        ScanContext,
        "get_account_info",
        return_value={"account_id": ACCOUNT, "account_name": "test"},
    ):
        check = SRA_CLOUDTRAIL_16()
        check.initialize(ctx)
        with (
            patch.object(
                check, "describe_trails", side_effect=lambda **kw: trails[kw["region"]]
            ),
            patch.object(check, "_list_owned_buckets", return_value=inventory),
            patch.object(
                check,
                "_get_object_lock_configuration",
                side_effect=lambda region, bucket: locks[bucket],
            ) as calls,
        ):
            rows = list(check.execute())
    return check, rows, calls


def org(bucket):
    return {"IsOrganizationTrail": True, "S3BucketName": bucket}


def error(code, operation):
    return error_result(code=code, message="failure", operation=operation)


@pytest.mark.parametrize(
    "response,status",
    [
        (
            {
                "ObjectLockConfiguration": {
                    "ObjectLockEnabled": "Enabled",
                    "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}},
                }
            },
            Status.PASS,
        ),
        (
            {
                "ObjectLockConfiguration": {
                    "ObjectLockEnabled": "Enabled",
                    "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Years": 2}},
                }
            },
            Status.PASS,
        ),
        (
            error("ObjectLockConfigurationNotFoundError", "GetObjectLockConfiguration"),
            Status.FAIL,
        ),
        ({"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}, Status.FAIL),
        (error("AccessDenied", "GetObjectLockConfiguration"), Status.ERROR),
        (error("404", "GetObjectLockConfiguration"), Status.ERROR),
        ({}, Status.ERROR),
        (
            {
                "ObjectLockConfiguration": {
                    "ObjectLockEnabled": "Enabled",
                    "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 0}},
                }
            },
            Status.ERROR,
        ),
        (
            {
                "ObjectLockConfiguration": {
                    "ObjectLockEnabled": "Enabled",
                    "Rule": {
                        "DefaultRetention": {
                            "Mode": "GOVERNANCE",
                            "Days": 1,
                            "Years": 1,
                        }
                    },
                }
            },
            Status.ERROR,
        ),
    ],
)
def test_retention_results(response, status):
    check, rows, _ = run_check(
        {R1: {"trailList": [org("logs")]}, R2: {"trailList": []}},
        {"Buckets": [{"Name": "logs", "BucketRegion": R2}]},
        {"logs": response},
    )
    assert check.meta.account_type is AccountType.LOG_ARCHIVE
    assert len(rows) == 1
    assert rows[0].status is status
    assert rows[0].region == R2


def test_discovery_deduplicates_and_preserves_success_on_region_error():
    _, rows, calls = run_check(
        {
            R1: error("AccessDenied", "DescribeTrails"),
            R2: {
                "trailList": [
                    org("logs"),
                    org("logs"),
                    {"IsOrganizationTrail": False, "S3BucketName": "other"},
                ]
            },
        },
        {
            "Buckets": [
                {"Name": "logs", "BucketRegion": R1},
                {"Name": "other", "BucketRegion": R2},
            ]
        },
        {"logs": {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}},
    )
    assert {row.status for row in rows} == {Status.ERROR, Status.FAIL}
    calls.assert_called_once_with(R1, "logs")


@pytest.mark.parametrize(
    "trails,inventory",
    [
        ({R1: {"trailList": []}, R2: {"trailList": []}}, {"Buckets": []}),
        (
            {R1: {"trailList": [org("remote")]}, R2: {"trailList": []}},
            {"Buckets": [{"Name": "local", "BucketRegion": R1}]},
        ),
    ],
)
def test_no_owned_match_has_no_rows(trails, inventory):
    _, rows, calls = run_check(trails, inventory, {})
    assert rows == []
    calls.assert_not_called()


@pytest.mark.parametrize(
    "trails,inventory",
    [
        (
            {R1: {"trailList": [org("logs")]}, R2: {"trailList": []}},
            {"Buckets": [{"Name": "logs"}]},
        ),
        ({R1: {"trailList": [org("")]}, R2: {"trailList": []}}, {"Buckets": []}),
        ({R1: {}, R2: {"trailList": []}}, {"Buckets": []}),
        (
            {R1: {"trailList": [org("logs")]}, R2: {"trailList": []}},
            error("AccessDenied", "ListBuckets"),
        ),
    ],
)
def test_missing_evidence_is_error(trails, inventory):
    _, rows, _ = run_check(trails, inventory, {})
    assert any(row.status is Status.ERROR for row in rows)


def test_s3_inventory_pagination_and_owner_bound_regional_lookup():
    import boto3
    from botocore.stub import Stubber
    from sraverify.services.s3.client import S3Client

    session = boto3.Session(
        aws_access_key_id="synthetic", aws_secret_access_key="synthetic", region_name=R1
    )
    ctx = ScanContext(session=session, regions=[R1, R2])
    inventory_client = S3Client(R1, ctx=ctx)
    bucket_region = "eu-west-1"
    bucket_client = S3Client(bucket_region, ctx=ctx)
    trail1 = ctx.get_client("cloudtrail", region=R1)
    trail2 = ctx.get_client("cloudtrail", region=R2)
    with (
        Stubber(trail1) as trail1_stub,
        Stubber(trail2) as trail2_stub,
        Stubber(inventory_client.client) as inventory_stub,
        Stubber(bucket_client.client) as bucket_stub,
    ):
        trail1_stub.add_response(
            "describe_trails", {"trailList": []}, {"includeShadowTrails": True}
        )
        trail2_stub.add_response(
            "describe_trails",
            {"trailList": [org("logs")]},
            {"includeShadowTrails": True},
        )
        inventory_stub.add_response(
            "list_buckets",
            {
                "Buckets": [{"Name": "unrelated", "BucketRegion": R1}],
                "ContinuationToken": "next",
            },
            {"MaxBuckets": 1000},
        )
        inventory_stub.add_response(
            "list_buckets",
            {"Buckets": [{"Name": "logs", "BucketRegion": bucket_region}]},
            {"MaxBuckets": 1000, "ContinuationToken": "next"},
        )
        bucket_stub.add_response(
            "get_object_lock_configuration",
            {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}},
            {"Bucket": "logs", "ExpectedBucketOwner": ACCOUNT},
        )
        with patch.object(
            ScanContext,
            "get_account_info",
            return_value={"account_id": ACCOUNT, "account_name": "test"},
        ):
            from sraverify.services.cloudtrail.checks.sra_cloudtrail_16 import (
                SRA_CLOUDTRAIL_16,
            )

            check = SRA_CLOUDTRAIL_16()
            check.initialize(ctx)
            rows = list(check.execute())
        assert len(rows) == 1
        assert rows[0].status is Status.FAIL
        assert rows[0].region == bucket_region
        trail1_stub.assert_no_pending_responses()
        trail2_stub.assert_no_pending_responses()
        inventory_stub.assert_no_pending_responses()
        bucket_stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "trails, expected",
    [
        ({R1: {"trailList": []}, R2: {"trailList": []}}, []),
        (
            {
                R1: error("AccessDenied", "DescribeTrails"),
                R2: error("AccessDenied", "DescribeTrails"),
            },
            [Status.ERROR, Status.ERROR],
        ),
    ],
)
def test_no_destination_skips_inventory(trails, expected):
    from sraverify.services.cloudtrail.checks.sra_cloudtrail_16 import SRA_CLOUDTRAIL_16

    ctx = ScanContext(session=MagicMock(), regions=[R1, R2])
    with patch.object(
        ScanContext,
        "get_account_info",
        return_value={"account_id": ACCOUNT, "account_name": "test"},
    ):
        check = SRA_CLOUDTRAIL_16()
        check.initialize(ctx)
        with (
            patch.object(
                check, "describe_trails", side_effect=lambda **kw: trails[kw["region"]]
            ),
            patch.object(check, "_list_owned_buckets") as inventory,
        ):
            rows = list(check.execute())
    assert [row.status for row in rows] == expected
    inventory.assert_not_called()


@pytest.mark.parametrize("classification", [None, "true", 1])
def test_unknown_classification_preserves_valid_sibling(classification):
    unknown = {"S3BucketName": "unknown"}
    if classification is not None:
        unknown["IsOrganizationTrail"] = classification
    _, rows, _ = run_check(
        {R1: {"trailList": [unknown, org("logs")]}, R2: {"trailList": []}},
        {"Buckets": [{"Name": "logs", "BucketRegion": R1}]},
        {"logs": {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}},
    )
    assert {row.status for row in rows} == {Status.ERROR, Status.FAIL}


def test_invalid_bucket_region_preserves_other_findings():
    import boto3
    from botocore.stub import Stubber
    from sraverify.services.s3.client import S3Client
    from sraverify.services.cloudtrail.checks.sra_cloudtrail_16 import SRA_CLOUDTRAIL_16

    session = boto3.Session(
        aws_access_key_id="synthetic", aws_secret_access_key="synthetic", region_name=R1
    )
    ctx = ScanContext(session=session, regions=[R1, R2])
    client = S3Client(R1, ctx=ctx)
    with Stubber(client.client) as stub:
        stub.add_response(
            "list_buckets",
            {
                "Buckets": [
                    {"Name": "good", "BucketRegion": R1},
                    {"Name": "bad", "BucketRegion": "bad region"},
                ]
            },
            {"MaxBuckets": 1000},
        )
        stub.add_response(
            "get_object_lock_configuration",
            {
                "ObjectLockConfiguration": {
                    "ObjectLockEnabled": "Enabled",
                    "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}},
                }
            },
            {"Bucket": "good", "ExpectedBucketOwner": ACCOUNT},
        )
        with patch.object(
            ScanContext,
            "get_account_info",
            return_value={"account_id": ACCOUNT, "account_name": "test"},
        ):
            check = SRA_CLOUDTRAIL_16()
            check.initialize(ctx)
            with patch.object(
                check,
                "describe_trails",
                side_effect=[
                    {"trailList": [org("good"), org("bad")]},
                    {"trailList": []},
                ],
            ):
                rows = list(check.execute())
    assert {(row.resource_id, row.status) for row in rows} == {
        ("good", Status.PASS),
        ("bad", Status.ERROR),
    }


def test_aws_error_evidence_and_remediation():
    failure = error("AccessDenied", "GetObjectLockConfiguration")
    check, rows, _ = run_check(
        {R1: {"trailList": [org("logs")]}, R2: {"trailList": []}},
        {"Buckets": [{"Name": "logs", "BucketRegion": R1}]},
        {"logs": failure},
    )
    assert (
        rows[0].actual_value
        == "GetObjectLockConfiguration failed: AccessDenied: failure"
    )
    assert rows[0].remediation == check._remediation_for(failure["Error"])


def test_absent_lock_preserves_aws_evidence():
    failure = error(
        "ObjectLockConfigurationNotFoundError", "GetObjectLockConfiguration"
    )
    _, rows, _ = run_check(
        {R1: {"trailList": [org("logs")]}, R2: {"trailList": []}},
        {"Buckets": [{"Name": "logs", "BucketRegion": R1}]},
        {"logs": failure},
    )
    assert rows[0].actual_value == (
        "GetObjectLockConfiguration failed: ObjectLockConfigurationNotFoundError: failure"
    )
