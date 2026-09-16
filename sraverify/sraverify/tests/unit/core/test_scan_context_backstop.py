"""
Property 10: ``ScanContext._set`` refuses an error result.

The accessor discipline (Requirement 3) is the primary control: every base
accessor tests ``is_error`` before it writes, and the reflection tests hold that
per accessor. This four-line guard in the storage layer is defence in depth for
the accessor written later by someone who has not read that contract.

Why it matters concretely: a failure written into the per-scan cache is replayed
to every later check in that Region for the rest of the scan. In the 2026-09-12
baseline, ``SecurityLakeCheck.get_subscribers`` caching ``[]`` on an
``AccessDeniedException`` is what turned one denied call into 8 wrong FAIL rows
across ``SRA-SECURITYLAKE-16`` and ``-17``.

Two design decisions this module pins:

* **It skips rather than raising.** By the time the guard fires, the accessor has
  already returned the error result to its caller correctly; the only defect is the
  attempted write. Raising would abort the calling check and lose every row it
  had already yielded, trading a harmless redundancy for a synthetic ERROR row.
* **It does not guess.** The guard fires on ``is_error`` and nothing looser, so a
  malformed near-error result is stored. That is deliberate: ``error_result``
  cannot construct a malformed value and the client contract tests reject a
  non-dict return from any client method, so a half-built
  error result reaching ``_set`` means something upstream is already broken in a way
  this layer cannot diagnose. Widening the test here would only make the storage
  layer start second-guessing values it has no way to classify.

Uses a **real** ``ScanContext``, not a mock: the point is the interaction between
the guard and the lock, the lazy namespace creation, and ``_has``/``_get``.

Validates: Requirement 3.2 (backstop).
"""
from __future__ import annotations

import logging
from typing import Any

import pytest

from sraverify.core.aws_errors import (
    NO_CLIENT_CODE,
    error_result,
    no_client_result,
)
from sraverify.core.scan_context import ScanContext


class _NoAwsSession:
    """A session that refuses every client construction.

    ``ScanContext.__init__`` stores the session and builds no client, so nothing
    in this module should ever ask for one. Refusing loudly turns a future
    change that made construction eager into a failure here rather than an
    attempted AWS call.
    """

    region_name = "us-east-1"

    def client(self, *args: Any, **kwargs: Any) -> Any:
        """Refuse.

        Raises:
            AssertionError: Always.
        """
        raise AssertionError(
            f"the backstop tests must construct no AWS client; got {args} {kwargs}"
        )


@pytest.fixture
def ctx() -> ScanContext:
    """A real ``ScanContext`` with no credentials and no clients.

    Returns:
        A context whose cache is empty.
    """
    return ScanContext(session=_NoAwsSession(), regions=["us-east-1"])


@pytest.fixture
def cache_log() -> Any:
    """Capture records from the ``sraverify`` logger.

    ``caplog`` cannot be used: ``core/logging.py`` sets ``propagate = False``.

    Yields:
        The captured records, in emission order.
    """
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collector()
    target = logging.getLogger("sraverify")
    target.addHandler(handler)
    try:
        yield records
    finally:
        target.removeHandler(handler)


def _warnings(records: list[logging.LogRecord]) -> list[str]:
    """Return the messages of records at ``WARNING`` or above.

    Args:
        records: Captured records.

    Returns:
        Formatted messages.
    """
    return [r.getMessage() for r in records if r.levelno >= logging.WARNING]


# --------------------------------------------------------------------------- #
# The refusal
# --------------------------------------------------------------------------- #


def test_an_error_result_is_not_stored(ctx: ScanContext, cache_log: Any) -> None:
    """The slot is left empty, so a retry re-issues the call."""
    result = error_result(
        code="AccessDeniedException",
        message="not authorized to perform: securitylake:ListSubscribers",
        operation="ListSubscribers",
    )

    ctx._set("securitylake", "subscribers:us-east-1", result)

    assert ctx._has("securitylake", "subscribers:us-east-1") is False
    assert ctx._get("securitylake", "subscribers:us-east-1") is None


def test_the_refusal_logs_a_warning_naming_the_slot_and_the_code(
    ctx: ScanContext, cache_log: Any
) -> None:
    """The diagnostic has to be enough to find the offending accessor.

    Namespace and key identify the accessor; the code says what was being
    swallowed.
    """
    ctx._set(
        "securitylake",
        "subscribers:us-east-1",
        error_result(
            code="AccessDeniedException", message="m", operation="ListSubscribers"
        ),
    )

    warnings = _warnings(cache_log)
    assert len(warnings) == 1, f"expected exactly one warning, got {warnings}"
    assert "securitylake" in warnings[0]
    assert "subscribers:us-east-1" in warnings[0]
    assert "AccessDeniedException" in warnings[0]


def test_the_refusal_does_not_raise(ctx: ScanContext, cache_log: Any) -> None:
    """Skipping is the whole point: the caller keeps running.

    Raising would abort the check and cost every row it had already yielded, for
    a write whose value the accessor has already returned correctly.
    """
    ctx._set(
        "securitylake",
        "subscribers:us-east-1",
        error_result(code="C", message="m", operation="Op"),
    )
    # Still usable afterwards, with the same namespace.
    ctx._set("securitylake", "data_lakes:us-east-1", {"dataLakes": []})

    assert ctx._get("securitylake", "data_lakes:us-east-1") == {"dataLakes": []}


def test_a_no_client_result_is_also_refused(ctx: ScanContext, cache_log: Any) -> None:
    """``NoClient`` is an undetermined state like any other.

    Three ``SecurityLakeCheck`` accessors cached ``[]`` or ``None`` on the
    no-client path before this change; the error result form must not simply move the
    same defect into a new shape.
    """
    ctx._set(
        "securitylake",
        "subscribers:eu-west-3",
        no_client_result(service="Security Lake", region="eu-west-3"),
    )

    assert ctx._has("securitylake", "subscribers:eu-west-3") is False
    assert NO_CLIENT_CODE in _warnings(cache_log)[0]


def test_a_refused_write_does_not_create_the_namespace(
    ctx: ScanContext, cache_log: Any
) -> None:
    """The refusal is complete: no empty namespace is left behind.

    ``_set`` creates the inner dict lazily, and the guard returns before the
    lock, so a namespace whose only write was an error result never appears at all.
    """
    ctx._set(
        "brand_new_namespace",
        "k",
        error_result(code="C", message="m", operation="Op"),
    )

    assert ctx._has("brand_new_namespace", "k") is False
    assert ctx._get("brand_new_namespace", "k", "absent") == "absent"


def test_a_refused_write_does_not_overwrite_a_cached_success(
    ctx: ScanContext, cache_log: Any
) -> None:
    """A later failure must not evict an earlier good answer.

    ``_set`` is last-writer-wins, so without the guard a transient failure
    arriving after a success would replace it -- strictly worse than not caching
    the failure, because the good answer is gone too.
    """
    ctx._set("securitylake", "subscribers:us-east-1", {"subscribers": [{"id": "a"}]})

    ctx._set(
        "securitylake",
        "subscribers:us-east-1",
        error_result(code="C", message="m", operation="ListSubscribers"),
    )

    assert ctx._get("securitylake", "subscribers:us-east-1") == {
        "subscribers": [{"id": "a"}]
    }


# --------------------------------------------------------------------------- #
# What is still stored
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value",
    [
        {"subscribers": []},
        {"subscribers": [{"subscriberName": "audit"}]},
        {},
        {"DetectorIds": []},
        {"Error": {"Code": ""}},
        {"Error": {"Code": "C", "Message": "m"}},
        {"Error": None},
        {"Error": "AccessDenied"},
        {"Error": []},
        {"error": {"Code": "C", "Message": "m", "Operation": "Op"}},
    ],
    ids=[
        "empty-success-list", "populated-success", "empty-dict",
        "empty-detector-ids", "blank-code", "no-operation", "Error-None",
        "Error-str", "Error-list", "lowercase-error-key",
    ],
)
def test_a_non_error_result_is_stored_unchanged(
    ctx: ScanContext, cache_log: Any, value: Any
) -> None:
    """Property 10's third clause: the guard does not guess.

    The first four are ordinary successes and must be cached -- ``{}`` and
    ``{"subscribers": []}`` in particular, because "AWS answered with nothing"
    is a real answer and caching it is what keeps the call count unchanged
    (Requirement 3.6).

    The rest are malformed near-error results, and they are stored too. ``is_error``
    is ``False`` for every one of them, and widening the test would mean the
    storage layer guessing at values it cannot classify. They cannot arise in
    practice anyway: ``error_result`` rejects exactly the inputs ``is_error``
    rejects, and the client contract tests fail any client method that
    returning a non-dict.

    Note the last one especially -- a lowercase ``"error"`` key. Several AWS
    services use lowercase response members, so a case-insensitive guard would
    start silently discarding real responses.
    """
    ctx._set("ns", "k", value)

    assert ctx._has("ns", "k") is True
    assert ctx._get("ns", "k") == value
    assert _warnings(cache_log) == []


@pytest.mark.parametrize(
    "value",
    [None, [], "", 0, False, [1, 2], "a string"],
    ids=["None", "empty-list", "empty-str", "zero", "False", "list", "str"],
)
def test_a_legacy_erasing_value_walks_straight_past_the_guard(
    ctx: ScanContext, cache_log: Any, value: Any
) -> None:
    """The backstop's documented limitation, asserted rather than described.

    These are the shapes the pre-change accessors used to encode failure. The
    guard cannot see them -- they are not error result-shaped -- so it stores them
    silently. This is exactly why Requirement 3.4 names the nine sites that
    cached ``[]``/``{}``/``None``/``False`` deliberately and requires each to be
    changed, rather than relying on this guard to catch them.

    If this test ever fails because the guard started rejecting these, that is a
    real behaviour change: ``{}`` and ``[]`` are legitimate cached successes
    elsewhere, and refusing them here would stop caching real answers.
    """
    ctx._set("ns", "k", value)

    assert ctx._has("ns", "k") is True
    assert ctx._get("ns", "k") == value
    assert _warnings(cache_log) == []


def test_the_guard_is_the_only_change_to_the_storage_contract(
    ctx: ScanContext, cache_log: Any
) -> None:
    """Namespacing, lazy creation, and last-writer-wins are unchanged."""
    ctx._set("a", "k", 1)
    ctx._set("b", "k", 2)
    assert ctx._get("a", "k") == 1
    assert ctx._get("b", "k") == 2

    ctx._set("a", "k", 3)
    assert ctx._get("a", "k") == 3

    assert ctx._has("a", "missing") is False
    assert ctx._get("a", "missing", "default") == "default"
    assert ctx._has("missing-namespace", "k") is False
