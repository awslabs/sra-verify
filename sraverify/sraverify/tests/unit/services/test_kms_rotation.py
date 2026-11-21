from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.stub import Stubber

from sraverify.core.registry import all_checks
from sraverify.core.scan_context import ScanContext


ACCOUNT = "123456789012"
REGION = "us-east-1"
OTHER_REGION = "us-west-2"
KEY = "01234567-0123-0123-0123-012345678901"
OTHER_KEY = "11234567-0123-0123-0123-012345678901"


def _listing(region=REGION, key=KEY):
    return {"KeyId": key, "KeyArn": f"arn:aws:kms:{region}:{ACCOUNT}:key/{key}"}


def _metadata(region=REGION, key=KEY, **changes):
    return {"KeyMetadata": dict({
        "AWSAccountId": ACCOUNT, "KeyId": key, "Arn": _listing(region, key)["KeyArn"],
        "KeyManager": "CUSTOMER", "KeySpec": "SYMMETRIC_DEFAULT", "Origin": "AWS_KMS",
        "KeyState": "Enabled", "MultiRegion": False,
    }, **changes)}


def _stub(stack, region=REGION):
    client = boto3.client("kms", region_name=region, aws_access_key_id="test", aws_secret_access_key="test")
    return stack.enter_context(Stubber(client))


def _read_key(stub, *, region=REGION, key=KEY, **metadata):
    stub.add_response("describe_key", _metadata(region, key, **metadata), {"KeyId": _listing(region, key)["KeyArn"]})


def _findings(*stubs, regions=None):
    checks = all_checks()
    assert "SRA-KMS-01" in checks
    clients = {stub.client.meta.region_name: stub.client for stub in stubs}
    ctx = ScanContext(session=MagicMock(), regions=regions or list(clients))
    with patch.object(ctx, "get_client", side_effect=lambda _, region: clients[region]), patch.object(
        ctx, "get_account_info", return_value={"account_id": ACCOUNT, "account_name": "test"}
    ):
        check = checks["SRA-KMS-01"]()
        check.initialize(ctx)
        rows = list(check.execute())
    for stub in stubs:
        stub.assert_no_pending_responses()
    return rows


@pytest.mark.parametrize(("rotation", "verdict"), [
    ({"KeyRotationEnabled": False}, "FAIL"),
    ({"KeyRotationEnabled": True, "RotationPeriodInDays": 90}, "PASS"),
    ({"KeyRotationEnabled": True, "RotationPeriodInDays": 365}, "PASS"),
    ({"KeyRotationEnabled": True, "RotationPeriodInDays": 366}, "FAIL"),
    ({"KeyRotationEnabled": True, "RotationPeriodInDays": 2560}, "FAIL"),
    ({"KeyRotationEnabled": True}, "ERROR"),
    ({}, "ERROR"),
])
def test_reads_explicit_rotation_schedule(rotation, verdict):
    with ExitStack() as stack:
        stub = _stub(stack)
        listing = _listing()
        stub.add_response("list_keys", {"Keys": [listing], "Truncated": False}, {})
        _read_key(stub)
        stub.add_response("get_key_rotation_status", {"KeyId": listing["KeyArn"], **rotation}, {"KeyId": listing["KeyArn"]})
        (row,) = _findings(stub)
    assert (row.resource_id, row.status) == (listing["KeyArn"], verdict)


@pytest.mark.parametrize("metadata", [
    {"KeyManager": "AWS"}, {"KeyState": "Disabled"}, {"KeyState": "PendingDeletion"},
    {"KeySpec": "ECC_NIST_P256"}, {"KeySpec": "HMAC_256"}, {"Origin": "EXTERNAL"},
    {"Origin": "AWS_CLOUDHSM"}, {"Origin": "EXTERNAL_KEY_STORE"},
    {"MultiRegion": True, "MultiRegionConfiguration": {"MultiRegionKeyType": "REPLICA"}},
])
def test_ineligible_keys_produce_no_row(metadata):
    with ExitStack() as stack:
        stub = _stub(stack)
        stub.add_response("list_keys", {"Keys": [_listing()], "Truncated": False}, {})
        _read_key(stub, **metadata)
        assert _findings(stub) == []


def test_primary_has_a_finding_and_duplicate_entries_are_evaluated_once():
    listing = _listing()
    with ExitStack() as stack:
        stub = _stub(stack)
        stub.add_response("list_keys", {"Keys": [listing], "Truncated": True, "NextMarker": "more"}, {})
        stub.add_response("list_keys", {"Keys": [listing], "Truncated": False}, {"Marker": "more"})
        _read_key(stub, MultiRegion=True, MultiRegionConfiguration={"MultiRegionKeyType": "PRIMARY"})
        stub.add_response("get_key_rotation_status", {"KeyRotationEnabled": True, "RotationPeriodInDays": 365}, {"KeyId": listing["KeyArn"]})
        (row,) = _findings(stub)
    assert (row.resource_id, row.status) == (listing["KeyArn"], "PASS")


def test_later_inventory_page_error_does_not_discard_other_regions():
    with ExitStack() as stack:
        stub = _stub(stack)
        next_region = _stub(stack, OTHER_REGION)
        stub.add_response("list_keys", {"Keys": [_listing()], "Truncated": True, "NextMarker": "more"}, {})
        stub.add_client_error("list_keys", "AccessDeniedException", "denied", expected_params={"Marker": "more"})
        listing = _listing(OTHER_REGION)
        next_region.add_response("list_keys", {"Keys": [listing], "Truncated": False}, {})
        _read_key(next_region, region=OTHER_REGION)
        next_region.add_response("get_key_rotation_status", {"KeyRotationEnabled": False}, {"KeyId": listing["KeyArn"]})
        rows = _findings(stub, next_region)
    assert {(row.region, row.status) for row in rows} == {(REGION, "ERROR"), (OTHER_REGION, "FAIL")}


def test_key_read_error_and_missing_entry_arn_do_not_hide_valid_key():
    first = _listing()
    second = _listing(key=OTHER_KEY)
    with ExitStack() as stack:
        stub = _stub(stack)
        stub.add_response("list_keys", {"Keys": [first, second, {}], "Truncated": False}, {})
        stub.add_client_error("describe_key", "AccessDeniedException", "denied", expected_params={"KeyId": first["KeyArn"]})
        _read_key(stub, key=OTHER_KEY)
        stub.add_response("get_key_rotation_status", {"KeyRotationEnabled": False}, {"KeyId": second["KeyArn"]})
        rows = _findings(stub)
    assert sorted(row.status for row in rows) == ["ERROR", "ERROR", "FAIL"]
    assert any(row.resource_id == first["KeyArn"] and row.status == "ERROR" for row in rows)
    assert any(row.resource_id == second["KeyArn"] and row.status == "FAIL" for row in rows)


def test_list_marker_without_truncation_flag_is_an_error():
    with ExitStack() as stack:
        stub = _stub(stack)
        stub.add_response("list_keys", {"Keys": [], "NextMarker": "more"}, {})
        (row,) = _findings(stub)
    assert (row.region, row.status) == (REGION, "ERROR")


def test_repeating_scan_region_does_not_repeat_findings():
    listing = _listing()
    with ExitStack() as stack:
        stub = _stub(stack)
        stub.add_response("list_keys", {"Keys": [listing], "Truncated": False}, {})
        _read_key(stub)
        stub.add_response("get_key_rotation_status", {"KeyRotationEnabled": False}, {"KeyId": listing["KeyArn"]})
        (row,) = _findings(stub, regions=[REGION, REGION])
    assert (row.region, row.status) == (REGION, "FAIL")
