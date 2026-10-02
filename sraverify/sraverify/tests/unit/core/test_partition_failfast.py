"""
``SRAVerify`` refuses a scan whose partition cannot be determined (failfast
tests 17, 18, 18a).

``run_checks`` resolves the scan Region first -- before selection, before a
``ScanContext`` exists, and before any AWS call -- and ``SRAVerify.__init__``
hands the first explicit Region to ``get_session`` so the session's Region and
the scan Region agree by construction.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from sraverify.core.errors import PartitionUndeterminedError
from sraverify.scanner import SRAVerify

ROLE = "arn:aws:iam::999988887777:role/SRAMemberRole"


class _RefusingSession:
    """Records and refuses every client build."""

    def __init__(self, region_name: Any) -> None:
        self.region_name = region_name
        self.client_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def client(self, *args: Any, **kwargs: Any) -> None:
        self.client_calls.append((args, kwargs))
        raise AssertionError(f"no client may be built; asked for {args!r} {kwargs!r}")


# 17
def test_run_checks_refuses_before_any_context_or_call(monkeypatch) -> None:
    """No Region anywhere: ``run_checks`` raises, builds no context, calls nothing."""
    session = _RefusingSession(region_name=None)

    def _no_context(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("ScanContext must not be constructed")

    monkeypatch.setattr("sraverify.scanner.ScanContext", _no_context)
    sra = SRAVerify(session=session)  # type: ignore[arg-type]

    with pytest.raises(PartitionUndeterminedError):
        sra.run_checks()

    assert session.client_calls == []


# 18
@pytest.mark.parametrize(
    "regions,session_region,expected",
    [
        pytest.param(["us-gov-west-1", "us-east-1"], "us-east-1", "us-gov-west-1", id="explicit"),
        pytest.param(None, "cn-north-1", "cn-north-1", id="session"),
    ],
)
def test_resolve_scan_region_applies_the_precedence(
    regions: list[str] | None, session_region: str, expected: str
) -> None:
    """The public preflight returns the same answer ``run_checks`` will use."""
    sra = SRAVerify(regions=regions, session=_RefusingSession(session_region))  # type: ignore[arg-type]
    assert sra.resolve_scan_region() == expected


def test_resolve_scan_region_raises_with_neither() -> None:
    """Neither source: the preflight raises."""
    sra = SRAVerify(session=_RefusingSession(None))  # type: ignore[arg-type]
    with pytest.raises(PartitionUndeterminedError):
        sra.resolve_scan_region()


# 18a
@pytest.mark.parametrize(
    "regions,expected_region",
    [
        pytest.param(["us-gov-west-1", "us-east-1"], "us-gov-west-1", id="explicit"),
        pytest.param(None, None, id="none"),
    ],
)
def test_the_first_explicit_region_is_handed_to_get_session(
    monkeypatch, regions: list[str] | None, expected_region: str | None
) -> None:
    """``SRAVerify(regions=..., role_arn=R)`` calls ``get_session(region=regions[0])``."""
    calls: list[dict[str, Any]] = []

    def _recorder(**kwargs: Any) -> SimpleNamespace:
        calls.append(kwargs)
        return SimpleNamespace(region_name="us-east-1")

    monkeypatch.setattr("sraverify.scanner.get_session", _recorder)

    SRAVerify(regions=regions, role_arn=ROLE)

    assert len(calls) == 1
    assert calls[0]["region"] == expected_region
    assert calls[0]["role_arn"] == ROLE
