"""
``InspectorCheck.batch_get_account_status`` batching (Property 22).

``BatchGetAccountStatus`` accepts at most 100 account IDs per request. The
accessor batches below that cap, merges every batch's ``accounts`` in input
order, and fails as a whole -- returning the failing batch's error result and
caching nothing -- if any batch fails.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from sraverify.core.aws_errors import error_result, is_error
from sraverify.core.scan_context import ScanContext
from sraverify.services.inspector.base import (
    BATCH_GET_ACCOUNT_STATUS_CAP,
    InspectorCheck,
)
from sraverify.tests.property.test_accessor_cache_property import _concrete

_REGION = "us-east-1"
_IDS = [f"{100000000000 + n}" for n in range(101)]


def _check_with(client: MagicMock) -> Any:
    """Return an initialized Inspector check whose us-east-1 client is ``client``."""
    ctx = ScanContext(session=MagicMock(name="session"), regions=[_REGION])
    check = _concrete(InspectorCheck)()
    check.initialize(ctx)
    check._clients[_REGION] = client
    return check


def _echo(batch: list[str]) -> dict[str, Any]:
    """Answer a batch with one status entry per ID, in order."""
    return {"accounts": [{"accountId": i, "state": {"status": "ENABLED"}} for i in batch]}


def test_101_accounts_are_batched_within_the_cap_and_merged_in_order() -> None:
    """Every request is within the cap, the batches partition the input, order holds."""
    client = MagicMock(name="InspectorClient")
    client.batch_get_account_status.side_effect = _echo
    check = _check_with(client)

    result = check.batch_get_account_status(_REGION, list(_IDS))

    batches = [c.args[0] for c in client.batch_get_account_status.call_args_list]
    assert len(batches) > 1
    assert all(len(b) <= BATCH_GET_ACCOUNT_STATUS_CAP for b in batches)
    assert [i for b in batches for i in b] == _IDS
    assert not is_error(result)
    assert [a["accountId"] for a in result["accounts"]] == _IDS


def test_a_failing_batch_fails_the_whole_call_and_caches_nothing() -> None:
    """The second batch's error result is returned unchanged; nothing is cached."""
    failure = error_result(
        code="AccessDeniedException",
        message="not allowed",
        operation="BatchGetAccountStatus",
    )
    calls = {"n": 0}

    def _answer(batch: list[str]) -> dict[str, Any]:
        calls["n"] += 1
        return failure if calls["n"] == 2 else _echo(batch)

    client = MagicMock(name="InspectorClient")
    client.batch_get_account_status.side_effect = _answer
    check = _check_with(client)

    result = check.batch_get_account_status(_REGION, list(_IDS))

    assert result is failure
    assert "accounts" not in result
    assert not check._ctx._has("inspector", f"batch_status:{_REGION}")
