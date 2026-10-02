"""
``get_session`` and the scan Region (failfast tests 14-16b).

``sts:AssumeRole`` goes to the scan Region's STS, the assumed session keeps that
Region, an undetermined Region is refused before any STS call, and every other
failure keeps today's wrapped ``Exception``. ``boto3.Session`` is replaced with
a recording fake, so nothing reaches AWS.
"""
from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError, ProfileNotFound

import sraverify.core.session as session_module
from sraverify.core.errors import PartitionUndeterminedError
from sraverify.core.session import get_session

ROLE = "arn:aws:iam::999988887777:role/SRAMemberRole"

#: Profile name -> the Region its config would supply.
_PROFILE_REGIONS = {"with-region": "eu-west-1"}


class _Recorder:
    """Shared record of every fake session built and every client requested."""

    def __init__(self) -> None:
        self.sessions: list[dict[str, Any]] = []
        self.client_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.assume_role_error: Exception | None = None
        self.session_error: Exception | None = None


def _install(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    """Replace ``boto3.Session`` as ``core/session.py`` sees it."""
    rec = _Recorder()

    class _FakeSts:
        def assume_role(self, **kwargs: Any) -> dict[str, Any]:
            if rec.assume_role_error is not None:
                raise rec.assume_role_error
            return {
                "Credentials": {
                    "AccessKeyId": "AKIDEXAMPLE",
                    "SecretAccessKey": "secret-example",  # pragma: allowlist secret -- fake value returned by a stub STS client; never a credential
                    "SessionToken": "token-example",
                }
            }

    class _FakeSession:
        def __init__(self, **kwargs: Any) -> None:
            if rec.session_error is not None and "aws_access_key_id" not in kwargs:
                raise rec.session_error
            rec.sessions.append(kwargs)
            region = kwargs.get("region_name")
            if region is None:
                region = _PROFILE_REGIONS.get(kwargs.get("profile_name") or "")
            self.region_name = region

        def client(self, *args: Any, **kwargs: Any) -> _FakeSts:
            rec.client_calls.append((args, kwargs))
            return _FakeSts()

    monkeypatch.setattr(session_module.boto3, "Session", _FakeSession)
    return rec


# 14
def test_an_undetermined_region_is_refused_before_assume_role(monkeypatch) -> None:
    """No Region anywhere: the typed error propagates unwrapped and STS is never built."""
    rec = _install(monkeypatch)

    with pytest.raises(PartitionUndeterminedError) as info:
        get_session(role_arn=ROLE)

    assert type(info.value) is PartitionUndeterminedError
    assert rec.client_calls == []


# 15
def test_an_explicit_region_selects_the_sts_endpoint_and_the_assumed_region(
    monkeypatch,
) -> None:
    """``region="us-gov-west-1"`` binds STS there and the assumed session keeps it."""
    rec = _install(monkeypatch)

    session = get_session(region="us-gov-west-1", role_arn=ROLE)

    assert rec.client_calls == [(("sts",), {"region_name": "us-gov-west-1"})]
    assert rec.sessions[-1]["region_name"] == "us-gov-west-1"
    assert session.region_name == "us-gov-west-1"


# 16
def test_the_profile_region_is_kept_through_assume_role(monkeypatch) -> None:
    """The profile's Region binds STS and survives into the assumed session."""
    rec = _install(monkeypatch)

    session = get_session(profile="with-region", role_arn=ROLE)

    assert rec.client_calls == [(("sts",), {"region_name": "eu-west-1"})]
    assert rec.sessions[-1]["region_name"] == "eu-west-1"
    assert session.region_name == "eu-west-1"


# 16a
def test_an_assume_role_failure_keeps_the_wrapped_exception(monkeypatch) -> None:
    """``AccessDenied`` from AssumeRole surfaces exactly as before."""
    rec = _install(monkeypatch)
    rec.assume_role_error = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "AssumeRole"
    )

    with pytest.raises(Exception) as info:
        get_session(region="us-east-1", role_arn=ROLE)

    assert type(info.value) is Exception
    assert str(info.value).startswith("Failed to create AWS session: ")


@pytest.mark.parametrize("role_arn", [None, ROLE], ids=["no-role", "role"])
def test_a_profile_failure_keeps_the_wrapped_exception(monkeypatch, role_arn) -> None:
    """``ProfileNotFound`` surfaces exactly as before, with or without a role."""
    rec = _install(monkeypatch)
    rec.session_error = ProfileNotFound(profile="missing")

    with pytest.raises(Exception) as info:
        get_session(profile="missing", role_arn=role_arn)

    assert type(info.value) is Exception
    assert str(info.value).startswith("Failed to create AWS session: ")
    assert rec.client_calls == []


# 16b
def test_without_a_role_no_region_is_required(monkeypatch) -> None:
    """The no-role path returns the base session untouched and never raises."""
    rec = _install(monkeypatch)

    session = get_session(region=None, profile=None)

    assert session.region_name is None
    assert rec.client_calls == []
    assert len(rec.sessions) == 1
