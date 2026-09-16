"""
A control the scanner *did* determine to be absent must be FAIL, not ERROR.

This is the mirror image of Property 14, and it needs its own module because the
Property 14 harness cannot reach the branch. That harness makes every accessor
return an error result, which drives each check down its ``"Error" in ...`` path;
the branch here is reached only when an accessor returns a **successful but empty**
response. AWS answered, the answer is that nothing is configured, and the row must
say FAIL -- an ERROR there claims an inability to determine something the scan had
in fact determined, which is exactly as wrong as a confessing FAIL and invisible to
every other property in the suite.

Found in production, not by the suite: 24 GuardDuty checks reported a Region with
no detector as ERROR, with the wording "Unable to access GuardDuty in this region".
14 of them produced a row in a single Region of a single account on the 2026-09-16
organization scan; the other 10 were audit-scoped and simply did not reach that
Region. ``GuardDutyCheck.detector_id_of``'s docstring already said the ``None`` it
returns "can only mean 'GuardDuty is not enabled in this Region', because a failure
could not have reached it" -- the helper was right and the callers disagreed with
it.

Scoped to GuardDuty deliberately. A general form would need a plausible empty
success shape per accessor rather than per client method, which is the same table
that does not exist and blocks the reachability gap recorded in
``test_check_classification_property``. What is cheap and exact is the one service
where an empty enumeration has a single unambiguous meaning, so that is what this
asserts.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sraverify.core.enums import Status
from sraverify.core.registry import all_checks
from sraverify.core.scan_context import ScanContext

_TEST_REGION = "us-east-1"
_TEST_ACCOUNT = "111122223333"

#: Every registered GuardDuty check, ascending. Read from the real registry rather
#: than listed, so a new GuardDuty check is covered the day it is written.
_GUARDDUTY = sorted(
    (check_id, cls)
    for check_id, cls in all_checks().items()
    if cls.__module__.split(".")[-3] == "guardduty"
)


def _context() -> MagicMock:
    """Return a mock ``ScanContext`` warm enough for ``execute()`` to run.

    Returns:
        The mock context.
    """
    ctx = MagicMock(spec=ScanContext)
    ctx.regions = [_TEST_REGION]
    ctx.audit_accounts = [_TEST_ACCOUNT]
    ctx.log_archive_accounts = [_TEST_ACCOUNT]
    ctx.get_account_info.return_value = {
        "account_id": _TEST_ACCOUNT,
        "account_name": "probe-account",
    }
    ctx.get_management_account_id.return_value = _TEST_ACCOUNT
    ctx.get_enabled_regions.return_value = [_TEST_REGION]
    ctx._has.return_value = False
    ctx._get.return_value = None
    return ctx


def test_the_guardduty_catalog_is_not_empty() -> None:
    """Guards against the reflection silently finding nothing."""
    assert len(_GUARDDUTY) >= 25, (
        f"found {len(_GUARDDUTY)} GuardDuty checks; the registry holds 25 and the "
        f"module-path filter is broken"
    )


@pytest.mark.parametrize("check_id,cls", _GUARDDUTY, ids=[c for c, _ in _GUARDDUTY])
def test_a_region_with_no_detector_is_a_fail_not_an_error(check_id, cls) -> None:
    """A successful ``ListDetectors`` naming no detector means the control is absent.

    ``get_detector_id`` is patched to answer ``{"DetectorIds": []}`` -- a genuine
    success, not an error result -- which is what GuardDuty returns for a Region
    where it has never been enabled. No check may report that as ERROR, and none
    may PASS on it either.
    """
    check = cls()
    check._ctx = _context()
    check._clients[_TEST_REGION] = MagicMock(name="GuardDutyClient")

    with patch.object(cls, "get_detector_id", lambda self, region: {"DetectorIds": []}):
        findings = list(check.execute())

    if not findings:
        pytest.skip(f"{check_id} yields no row for a Region with no detector")

    statuses = {f.status for f in findings}

    assert Status.ERROR not in statuses, (
        f"{check_id} reported a Region with no GuardDuty detector as ERROR: "
        f"{[f.actual_value[:90] for f in findings if f.status is Status.ERROR]}. "
        f"ListDetectors succeeded and named no detector, so the control is absent "
        f"and the row is a FAIL."
    )
    assert Status.PASS not in statuses, (
        f"{check_id} PASSed a Region with no GuardDuty detector: "
        f"{[f.actual_value[:90] for f in findings if f.status is Status.PASS]}"
    )
    assert statuses == {Status.FAIL}, f"{check_id} yielded {statuses}"


@pytest.mark.parametrize("check_id,cls", _GUARDDUTY, ids=[c for c, _ in _GUARDDUTY])
def test_that_row_does_not_confess(check_id, cls) -> None:
    """And its wording states the absence rather than admitting an inability.

    The confessing-wording property in
    ``test_no_confessing_fail_property`` is static over ``failed()`` calls, so it
    would not have caught the original defect: the wording lived on an ``error()``
    call, where "Unable to access" is legitimate. Once the status is corrected the
    static rule covers it, and this is the runtime belt to that braces.
    """
    check = cls()
    check._ctx = _context()
    check._clients[_TEST_REGION] = MagicMock(name="GuardDutyClient")

    with patch.object(cls, "get_detector_id", lambda self, region: {"DetectorIds": []}):
        findings = list(check.execute())

    if not findings:
        pytest.skip(f"{check_id} yields no row for a Region with no detector")

    offenders = [
        f.actual_value
        for f in findings
        if "unable to" in f.actual_value.lower() or "could not" in f.actual_value.lower()
    ]
    assert offenders == [], (
        f"{check_id} describes an established absence as an inability to "
        f"determine: {offenders}"
    )
