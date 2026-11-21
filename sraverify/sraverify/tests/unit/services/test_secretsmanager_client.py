from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.loaders import Loader
from botocore.model import ServiceModel
from botocore.parsers import create_parser
from botocore.stub import Stubber

from sraverify.core.scan_context import ScanContext
from sraverify.services.secretsmanager.client import SecretsManagerClient

_REGION = "us-east-1"
_ARN = "arn:aws:secretsmanager:us-east-1:111122223333:secret:app-AbCdEf"


def _client() -> tuple[SecretsManagerClient, Stubber]:
    raw = boto3.client(
        "secretsmanager",
        region_name=_REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    ctx = ScanContext(session=MagicMock(name="session"), regions=[_REGION])
    ctx.get_client = MagicMock(return_value=raw)
    return SecretsManagerClient(_REGION, ctx), Stubber(raw)


def test_list_secrets_follows_an_empty_page_with_a_token() -> None:
    client, stub = _client()
    stub.add_response("list_secrets", {"SecretList": [], "NextToken": "t1"})
    stub.add_response("list_secrets", {"SecretList": [{"ARN": _ARN, "Name": "app"}]})
    with stub:
        result = client.list_secrets()
    stub.assert_no_pending_responses()
    assert [s["ARN"] for s in result["SecretList"]] == [_ARN]


def test_list_secrets_error_on_a_later_page_is_one_error_result() -> None:
    client, stub = _client()
    stub.add_response("list_secrets", {"SecretList": [{"ARN": _ARN}], "NextToken": "t1"})
    stub.add_client_error("list_secrets", "AccessDeniedException", "denied")
    with stub:
        result = client.list_secrets()
    assert "SecretList" not in result
    assert result["Error"]["Code"] == "AccessDeniedException"
    assert result["Error"]["Operation"] == "ListSecrets"


@pytest.mark.parametrize(
    "pages",
    [
        [{"SecretList": "oops"}],
        [{"SecretList": None}],
        [None],
        ["x"],
        [{"SecretList": [{"ARN": _ARN}]}, {"SecretList": "oops"}],
        [{"SecretList": [{"ARN": _ARN}]}, None],
    ],
    ids=["str", "none", "null-page", "str-page", "valid-then-str", "valid-then-null"],
)
def test_list_secrets_malformed_page_is_one_error_result_without_partials(pages: list[Any]) -> None:
    client, _ = _client()
    client.client = MagicMock()
    client.client.get_paginator.return_value.paginate.return_value = pages
    result = client.list_secrets()
    assert set(result) == {"Error"}
    assert result["Error"]["Code"] == "PaginationError"


def test_describe_secret_returns_the_response_and_keeps_cross_account_primary() -> None:
    client, stub = _client()
    stub.add_response(
        "describe_secret",
        {
            "ARN": _ARN,
            "RotationEnabled": False,
            "CrossAccountPrimary": {"ReplicationStatus": "Detached"},
        },
        {"SecretId": _ARN},
    )
    with stub:
        result = client.describe_secret(_ARN)
    stub.assert_no_pending_responses()
    assert result["CrossAccountPrimary"] == {"ReplicationStatus": "Detached"}


def test_describe_secret_error_is_an_error_result() -> None:
    client, stub = _client()
    stub.add_client_error("describe_secret", "ResourceNotFoundException", "gone")
    with stub:
        result = client.describe_secret(_ARN)
    assert result["Error"]["Code"] == "ResourceNotFoundException"
    assert result["Error"]["Operation"] == "DescribeSecret"


def test_the_real_parser_keeps_cross_account_primary() -> None:
    model = ServiceModel(Loader().load_service_model("secretsmanager", "service-2"))
    body = {
        "ARN": _ARN,
        "RotationEnabled": True,
        "CrossAccountPrimary": {"ReplicationStatus": "Detached"},
    }
    parsed: dict[str, Any] = create_parser("json").parse(
        {"body": json.dumps(body).encode(), "headers": {}, "status_code": 200},
        model.operation_model("DescribeSecret").output_shape,
    )
    assert parsed["CrossAccountPrimary"] == {"ReplicationStatus": "Detached"}
    assert parsed["RotationEnabled"] is True
