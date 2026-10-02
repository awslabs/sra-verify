"""
``resolve_scan_region`` -- the scan Region rule (Property 32).

The first ``--regions`` value, else the session's Region, else
``PartitionUndeterminedError``. An unusable explicit first value is a usage
error and never falls through to the session. Pure: no client, no AWS call.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sraverify.core.errors import PartitionUndeterminedError, SRAVerifyError
from sraverify.core.regions import resolve_scan_region


def _session(region_name: Any) -> SimpleNamespace:
    """A session stand-in whose only attribute is ``region_name``."""
    return SimpleNamespace(region_name=region_name)


class _BareSession:
    """A session stand-in with no ``region_name`` attribute at all."""


# 1 -- precedence (a)
def test_the_first_explicit_region_wins_over_the_session() -> None:
    """``regions[0]`` is returned even when the session has another Region."""
    assert (
        resolve_scan_region(["us-gov-west-1", "us-east-1"], _session("us-east-1"))
        == "us-gov-west-1"
    )


# 2 -- precedence (b)
@pytest.mark.parametrize("regions", [None, []], ids=["none", "empty"])
def test_the_session_region_is_used_without_explicit_regions(regions: Any) -> None:
    """With no explicit Regions the session's Region is the scan Region."""
    assert resolve_scan_region(regions, _session("cn-north-1")) == "cn-north-1"


# 3 -- precedence (c), fail fast
@pytest.mark.parametrize(
    "session",
    [
        pytest.param(_session(None), id="none"),
        pytest.param(_BareSession(), id="missing"),
        pytest.param(_session(""), id="empty"),
        pytest.param(_session("  "), id="blank"),
        pytest.param(_session(" us-east-1 "), id="padded"),
        pytest.param(MagicMock(name="session"), id="magicmock"),
    ],
)
def test_no_determinable_region_raises_absent(session: Any) -> None:
    """Neither candidate supplies a usable Region: ``reason == "absent"``."""
    with pytest.raises(PartitionUndeterminedError) as info:
        resolve_scan_region(None, session)
    exc = info.value
    assert exc.reason == "absent"
    assert exc.bad_value is None
    assert "--regions" in str(exc)
    # The remedy names the variable boto3 actually reads: botocore maps
    # ``region`` to AWS_DEFAULT_REGION only, so advising AWS_REGION would send
    # the operator to a setting that still exits 2.
    assert "AWS_DEFAULT_REGION" in str(exc)
    assert "set AWS_REGION" not in str(exc)


# 4 -- a bad explicit value never falls through
@pytest.mark.parametrize(
    "regions",
    [
        pytest.param(["", "us-west-2"], id="empty-first"),
        pytest.param(["  "], id="blank"),
        pytest.param([" us-east-1 "], id="padded"),
        pytest.param(["us-east-1\n"], id="trailing-newline"),
        pytest.param([None], id="none"),
        pytest.param([123], id="int"),
    ],
)
def test_an_unusable_first_explicit_region_raises_invalid(regions: list[Any]) -> None:
    """``reason == "invalid"`` even though the session has a valid Region."""
    with pytest.raises(PartitionUndeterminedError) as info:
        resolve_scan_region(regions, _session("us-west-2"))
    exc = info.value
    element = regions[0]
    assert exc.reason == "invalid"
    if element is None:
        assert exc.bad_value is None
    else:
        assert exc.bad_value == element
    assert repr(element) in str(exc)
    assert "is not a Region name" in str(exc)
    assert "\n" not in str(exc)


# 5 -- hypothesis: any usable first element is returned as the same object
_usable_region = st.text(min_size=1).filter(lambda s: s == s.strip() and s.strip() != "")


@given(
    first=_usable_region,
    rest=st.lists(st.text(), max_size=3),
    session_value=st.one_of(st.none(), st.text(), st.integers()),
)
def test_any_usable_first_region_is_returned_unchanged(
    first: str, rest: list[str], session_value: Any
) -> None:
    """The result is ``regions[0]``, the same object, whatever the session holds."""
    regions = [first, *rest]
    assert resolve_scan_region(regions, _session(session_value)) is first


# 6 -- the error type
@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(PartitionUndeterminedError(), id="absent"),
        pytest.param(PartitionUndeterminedError(bad_value="bad\nvalue"), id="invalid"),
    ],
)
def test_the_error_is_a_one_line_sraverify_error(exc: PartitionUndeterminedError) -> None:
    """Subclasses ``SRAVerifyError``; ``args == (str(exc),)``; one line."""
    assert isinstance(exc, SRAVerifyError)
    assert exc.args == (str(exc),)
    assert "\n" not in str(exc)
