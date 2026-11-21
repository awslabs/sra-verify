from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timezone
from typing import Any, Callable
from unittest.mock import MagicMock, patch

import boto3
from botocore.stub import Stubber

import pytest

from sraverify.core.aws_errors import error_result
from sraverify.core.enums import Status
from sraverify.core.finding import Finding
from sraverify.core.scan_context import ScanContext
from sraverify.services.secretsmanager.base import SecretsManagerCheck
from sraverify.services.secretsmanager.checks.sra_secretsmanager_01 import (
    SRA_SECRETSMANAGER_01,
)

_ACCOUNT = "111122223333"
_R1 = "us-east-1"
_R2 = "us-west-2"
_MISSING = object()


def _arn(name: str = "app", region: str = _R1, account: str = _ACCOUNT) -> str:
    return f"arn:aws:secretsmanager:{region}:{account}:secret:{name}-AbCdEf"


def _listing(*entries: Any) -> dict[str, Any]:
    return {"SecretList": list(entries)}


def _described(arn: str, rotation: Any = True, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"ARN": arn, **extra}
    if rotation is not _MISSING:
        out["RotationEnabled"] = rotation
    return out


def _run(
    secrets: Callable[[str], Any],
    secret: Callable[[str, str], Any] = lambda region, arn: _described(arn),
    regions: list[str] | None = None,
) -> tuple[list[Finding], dict[str, MagicMock]]:
    ctx = ScanContext(session=MagicMock(name="session"), regions=regions or [_R1])
    with ExitStack() as stack:
        stack.enter_context(
            patch.object(
                ScanContext,
                "get_account_info",
                return_value={"account_id": _ACCOUNT, "account_name": "test"},
            )
        )
        check = SRA_SECRETSMANAGER_01()
        check.initialize(ctx)
        mocks = {
            "get_secrets": stack.enter_context(
                patch.object(SecretsManagerCheck, "get_secrets", side_effect=secrets)
            ),
            "get_secret": stack.enter_context(
                patch.object(SecretsManagerCheck, "get_secret", side_effect=secret)
            ),
        }
        rows = list(check.execute())
    return rows, mocks


def _statuses(rows: list[Finding]) -> list[Status]:
    return [r.status for r in rows]


def test_no_candidates_yields_no_rows_and_no_describe() -> None:
    rows, mocks = _run(lambda region: _listing())
    assert rows == []
    assert mocks["get_secret"].call_count == 0


def test_list_error_is_one_region_error_and_other_regions_continue() -> None:
    failure = error_result(code="AccessDeniedException", message="denied", operation="ListSecrets")
    rows, mocks = _run(
        lambda region: failure if region == _R1 else _listing({"ARN": _arn(region=region)}),
        regions=[_R1, _R2],
    )
    assert [(r.region, r.status) for r in rows] == [(_R1, Status.ERROR), (_R2, Status.PASS)]
    assert rows[0].resource_id == f"secretsmanager:{_R1}:{_ACCOUNT}"
    assert rows[0].actual_value.startswith("ListSecrets failed: AccessDeniedException: ")
    assert [c.args for c in mocks["get_secret"].call_args_list] == [(_R2, _arn(region=_R2))]


@pytest.mark.parametrize(
    "listing",
    [
        {"SecretList": "oops"},
        {"SecretList": None},
        [],
    ],
    ids=["str", "none", "not-a-mapping"],
)
def test_invalid_inventory_envelope_is_one_region_error(listing: Any) -> None:
    rows, mocks = _run(lambda region: listing)
    assert _statuses(rows) == [Status.ERROR]
    assert rows[0].resource_id == f"secretsmanager:{_R1}:{_ACCOUNT}"
    assert mocks["get_secret"].call_count == 0


def test_malformed_entries_are_one_aggregated_error_and_valid_arns_still_run() -> None:
    entries = [
        None,
        "x",
        {},
        {"ARN": 5},
        {"ARN": ""},
        {"ARN": "not-an-arn"},
        {"ARN": _arn(account="999988887777")},
        {"ARN": _arn(region=_R2)},
        {"ARN": "arn:aws:s3:::bucket"},
        {"ARN": _arn("good")},
    ]
    rows, mocks = _run(lambda region: _listing(*entries))
    assert sorted(_statuses(rows), key=lambda s: s.value) == sorted(
        [Status.ERROR, Status.PASS], key=lambda s: s.value
    )
    error = next(r for r in rows if r.status is Status.ERROR)
    assert error.resource_id == f"secretsmanager:{_R1}:{_ACCOUNT}"
    assert error.actual_value == (
        "ListSecrets failed: InvalidResponse: ListSecrets returned 9 entries that are not "
        "a secret ARN in this account and Region; they were not evaluated"
    )
    assert [c.args for c in mocks["get_secret"].call_args_list] == [(_R1, _arn("good"))]


def test_duplicate_arns_and_regions_are_described_once() -> None:
    rows, mocks = _run(
        lambda region: _listing({"ARN": _arn()}, {"ARN": _arn()}),
        regions=[_R1, _R1],
    )
    assert len(rows) == 1
    assert mocks["get_secrets"].call_count == 1
    assert mocks["get_secret"].call_count == 1


@pytest.mark.parametrize(
    ("value", "status"),
    [
        (True, Status.PASS),
        (False, Status.FAIL),
        (None, Status.FAIL),
        (_MISSING, Status.FAIL),
        ("false", Status.ERROR),
        ("true", Status.ERROR),
        (1, Status.ERROR),
    ],
    ids=["true", "false", "null", "missing", "str-false", "str-true", "int"],
)
def test_rotation_flag(value: Any, status: Status) -> None:
    rows, _ = _run(
        lambda region: _listing({"ARN": _arn()}),
        lambda region, arn: _described(arn, value),
    )
    assert _statuses(rows) == [status]
    assert rows[0].resource_id == _arn()
    assert rows[0].resource_type == "AWS::SecretsManager::Secret"


def test_describe_decides_not_the_stale_list() -> None:
    rows, _ = _run(
        lambda region: _listing({"ARN": _arn(), "RotationEnabled": True}),
        lambda region, arn: _described(arn, False),
    )
    assert _statuses(rows) == [Status.FAIL]


def test_describe_errors_are_per_arn() -> None:
    a, b, c = _arn("a"), _arn("b"), _arn("c")

    def describe(region: str, arn: str) -> Any:
        if arn == a:
            return error_result(
                code="ResourceNotFoundException", message="gone", operation="DescribeSecret"
            )
        if arn == b:
            return error_result(
                code="AccessDeniedException", message="denied", operation="DescribeSecret"
            )
        return _described(arn)

    rows, _ = _run(lambda region: _listing({"ARN": a}, {"ARN": b}, {"ARN": c}), describe)
    assert {r.resource_id: r.status for r in rows} == {
        a: Status.ERROR,
        b: Status.ERROR,
        c: Status.PASS,
    }


@pytest.mark.parametrize(
    "response",
    [
        _described(_arn("other")),
        {"RotationEnabled": True},
        {"ARN": 5, "RotationEnabled": True},
        None,
        "x",
    ],
    ids=["other-arn", "no-arn", "bad-arn-type", "none", "str"],
)
def test_describe_response_for_another_arn_or_wrong_shape_is_an_error(response: Any) -> None:
    rows, _ = _run(lambda region: _listing({"ARN": _arn()}), lambda region, arn: response)
    assert _statuses(rows) == [Status.ERROR]
    assert rows[0].resource_id == _arn()


_DELETED = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "extra",
    [
        {"DeletedDate": _DELETED},
        {"PrimaryRegion": _R2},
        {"CrossAccountPrimary": {"ReplicationStatus": "InSync"}},
        {"CrossAccountPrimary": {"ReplicationStatus": "Detached"}},
        {"CrossAccountPrimary": {}},
    ],
    ids=["deleted", "region-replica", "cross-account-replica", "detached", "empty-mapping"],
)
def test_deleted_and_replica_secrets_are_skipped(extra: dict[str, Any]) -> None:
    rows, _ = _run(
        lambda region: _listing({"ARN": _arn()}),
        lambda region, arn: _described(arn, False, **extra),
    )
    assert rows == []


@pytest.mark.parametrize(
    "extra",
    [
        {"PrimaryRegion": _R1},
        {"PrimaryRegion": None},
        {"DeletedDate": None},
        {"CrossAccountPrimary": None},
    ],
    ids=["primary", "null-primary-region", "null-deleted", "null-cross-account"],
)
def test_primary_and_null_markers_are_evaluated(extra: dict[str, Any]) -> None:
    rows, _ = _run(
        lambda region: _listing({"ARN": _arn()}),
        lambda region, arn: _described(arn, False, **extra),
    )
    assert _statuses(rows) == [Status.FAIL]


@pytest.mark.parametrize(
    "extra",
    [
        {"DeletedDate": "2026-01-01"},
        {"PrimaryRegion": 5},
        {"PrimaryRegion": ""},
        {"PrimaryRegion": "  "},
        {"PrimaryRegion": "US_EAST_1"},
        {"CrossAccountPrimary": "Detached"},
    ],
    ids=[
        "deleted", "primary-region-int", "primary-region-empty",
        "primary-region-blank", "primary-region-malformed", "cross-account",
    ],
)
def test_wrong_typed_markers_are_an_error(extra: dict[str, Any]) -> None:
    rows, _ = _run(
        lambda region: _listing({"ARN": _arn()}),
        lambda region, arn: _described(arn, True, **extra),
    )
    assert _statuses(rows) == [Status.ERROR]


def test_no_secret_metadata_reaches_a_finding() -> None:
    rows, _ = _run(
        lambda region: _listing({"ARN": _arn()}),
        lambda region, arn: _described(
            arn,
            False,
            Name="topsecretname",
            Description="topsecretdesc",
            KmsKeyId="topsecretkey",
            Tags=[{"Key": "k", "Value": "topsecrettag"}],
        ),
    )
    text = " ".join(f"{r.actual_value} {r.remediation} {r.checked_value}" for r in rows)
    assert "topsecret" not in text


def test_fail_remediation_does_not_assume_lambda_rotation() -> None:
    rows, _ = _run(
        lambda region: _listing({"ARN": _arn()}),
        lambda region, arn: _described(arn, False),
    )
    assert "lambda" not in rows[0].remediation.lower()
    assert "AutomaticallyAfterDays" not in rows[0].remediation


def test_eusc_primary_secret_is_evaluated_end_to_end() -> None:
    region = "eusc-de-east-1"
    arn = f"arn:aws-eusc:secretsmanager:{region}:{_ACCOUNT}:secret:app-AbCdEf"
    raw = boto3.client(
        "secretsmanager",
        region_name=region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    stub = Stubber(raw)
    stub.add_response("list_secrets", {"SecretList": [{"ARN": arn}]})
    stub.add_response(
        "describe_secret",
        {"ARN": arn, "PrimaryRegion": region, "RotationEnabled": True},
        {"SecretId": arn},
    )
    ctx = ScanContext(session=MagicMock(name="session"), regions=[region])
    ctx.get_client = MagicMock(return_value=raw)
    with patch.object(
        ScanContext,
        "get_account_info",
        return_value={"account_id": _ACCOUNT, "account_name": "test"},
    ), stub:
        check = SRA_SECRETSMANAGER_01()
        check.initialize(ctx)
        rows = list(check.execute())
    assert [(r.status, r.resource_id) for r in rows] == [(Status.PASS, arn)]


def test_trailing_newline_in_an_arn_or_primary_region_is_malformed() -> None:
    rows, mocks = _run(lambda region: _listing({"ARN": _arn() + "\n"}))
    assert _statuses(rows) == [Status.ERROR]
    assert mocks["get_secret"].call_count == 0
    rows, _ = _run(
        lambda region: _listing({"ARN": _arn()}),
        lambda region, arn: _described(arn, True, PrimaryRegion=_R1 + "\n"),
    )
    assert _statuses(rows) == [Status.ERROR]
