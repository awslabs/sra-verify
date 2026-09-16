"""
Unit tests for ``core/availability.py`` -- Property 15.

These run against the **real** botocore endpoint data rather than a mock, which
is the point: the function's whole job is to report what that data says, and a
mocked answer would test the plumbing while leaving the actual claims
(``apprunner`` is absent from ``us-west-1``; ``shield`` answers ``[]``
everywhere) unverified. The data ships with botocore, so this needs no
credentials and issues no call.

Figures below were measured against botocore 1.43.6, ``aws`` partition,
34 Regions: ``apprunner`` 11, ``auditmanager`` 12, ``securitylake`` 17,
``amplify`` 20, ``macie2`` 22, ``appsync`` 31, ``inspector2`` 32,
``accessanalyzer`` 34, ``s3control`` 29. A botocore upgrade that adds an
App Runner Region in ``us-west-1`` would fail
:func:`test_apprunner_is_absent_from_us_west_1`, which is correct -- the
suppression the WAF check relies on would have genuinely changed.

Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.8, 5.11, 7.8.
"""
from __future__ import annotations

import logging
from typing import Any

import boto3
import pytest

from sraverify.core import availability
from sraverify.core.availability import service_available_in_region

#: Every commercial Region botocore knows, used for the "non-regionalized
#: services are available everywhere" sweep.
_COMMERCIAL_REGIONS: tuple[str, ...] = tuple(
    boto3.Session().get_available_regions("ec2", partition_name="aws")
)


@pytest.fixture
def cold_cache() -> Any:
    """Drop the ``lru_cache`` around a test that must observe a real lookup.

    Requested explicitly rather than autouse. The warning, fail-open, cache-hit,
    and no-network tests each need a cold entry, because a warm one would serve
    the answer without running the body and they would pass vacuously. Every
    other test in this module only cares about the *answer*, and letting those
    share the cache keeps the module from rebuilding a ``boto3.Session`` for each
    of the 34 Regions in the non-regionalized sweep -- which is the difference
    between roughly 14 seconds and under 1.

    Yields:
        ``None``.
    """
    service_available_in_region.cache_clear()
    yield
    service_available_in_region.cache_clear()


@pytest.fixture
def availability_log() -> Any:
    """Capture records from the ``sraverify`` logger.

    ``caplog`` cannot be used: ``core/logging.py`` sets ``propagate = False``.

    Yields:
        The list of captured records, in emission order.
    """
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collector()
    handler.setLevel(logging.DEBUG)
    target = logging.getLogger("sraverify")
    previous = target.level
    target.setLevel(logging.DEBUG)
    target.addHandler(handler)
    try:
        yield records
    finally:
        target.removeHandler(handler)
        target.setLevel(previous)


def _at_least(records: list[logging.LogRecord], level: int) -> list[str]:
    """Return the messages of records at or above ``level``.

    Args:
        records: Captured records.
        level: A ``logging`` level.

    Returns:
        Formatted messages.
    """
    return [r.getMessage() for r in records if r.levelno >= level]


def _exactly(records: list[logging.LogRecord], level: int) -> list[str]:
    """Return the messages of records at exactly ``level``.

    Args:
        records: Captured records.
        level: A ``logging`` level.

    Returns:
        Formatted messages.
    """
    return [r.getMessage() for r in records if r.levelno == level]


# --------------------------------------------------------------------------- #
# The one path that returns False
# --------------------------------------------------------------------------- #


def test_apprunner_is_absent_from_us_west_1() -> None:
    """The only positive absence in the four-Region baseline scan.

    App Runner has 11 of 34 commercial Regions and ``us-west-1`` is not one of
    them. ``SRA-WAF-06`` relies on this to emit no row there.
    """
    assert service_available_in_region("apprunner", "us-west-1") is False


def test_apprunner_is_present_in_us_east_1() -> None:
    """The same service in a Region it does serve, so the test is not vacuous."""
    assert service_available_in_region("apprunner", "us-east-1") is True


@pytest.mark.parametrize(
    "service_id,region",
    [
        ("auditmanager", "us-west-1"),
        ("securitylake", "us-west-1"),
        ("macie2", "us-east-1"),
        ("inspector2", "us-east-1"),
        ("appsync", "us-east-1"),
        ("amplify", "us-east-1"),
    ],
    ids=[
        "auditmanager.us-west-1", "securitylake.us-west-1", "macie2.us-east-1",
        "inspector2.us-east-1", "appsync.us-east-1", "amplify.us-east-1",
    ],
)
def test_the_other_candidate_services_answer_in_the_four_region_scan(
    service_id: str, region: str
) -> None:
    """Every candidate service is present in the Regions the baseline scanned.

    Pinned so that adding an availability guard to a check cannot silently delete
    rows from the report. If any of these ever answers ``False``, the guard for that
    service starts suppressing a Region the baseline has rows for, and the rows
    simply vanish rather than reporting anything.
    """
    assert service_available_in_region(service_id, region) is True


# --------------------------------------------------------------------------- #
# Requirement 5.8 -- the empty-list rule
# --------------------------------------------------------------------------- #


#: The non-regionalized services the scanner consults. Each answers ``[]`` from
#: ``get_available_regions`` for the ``aws`` partition because it resolves
#: through ``aws-global``.
_NON_REGIONALIZED: tuple[str, ...] = (
    "shield",
    "organizations",
    "iam",
    "account",
    "cloudfront",
)


def test_shield_is_available_in_every_commercial_region() -> None:
    """A partition-endpoint service answers ``[]`` and must read as available.

    ``get_available_regions`` returns ``[]`` for ``shield`` because it resolves
    through ``aws-global`` rather than per Region. A naive ``region in regional``
    reads that as "available nowhere" and would suppress every one of the 14
    Shield rows in the catalog -- the one input on which a fail-closed reading is
    wrong for every Region at once.

    Swept across all 34 commercial Regions for one service rather than for all
    five: the claim is about the *rule*, and one service exercising every Region
    plus the four spot-checks below covers it without paying 34 endpoint lookups
    five times over.
    """
    for region in _COMMERCIAL_REGIONS:
        assert service_available_in_region("shield", region) is True, (
            f"shield in {region} must be available: an empty regional list "
            f"means 'not resolvable per Region', not 'reachable from nowhere'"
        )


@pytest.mark.parametrize("service_id", _NON_REGIONALIZED)
def test_every_non_regionalized_service_answers_an_empty_list_and_reads_available(
    service_id: str,
) -> None:
    """The premise and the answer, for each non-regionalized service.

    Asserting the empty list explicitly matters: it is what makes this a test of
    the empty-list *rule* rather than an incidental pass. If botocore ever gives
    one of these per-Region endpoints, the first assertion fails and tells the
    next reader the premise moved, instead of the rule silently ceasing to be
    exercised.
    """
    session = boto3.Session()
    assert (
        session.get_available_regions(service_id, partition_name="aws") == []
    ), f"{service_id} now has per-Region endpoint data; this rule's premise changed"

    for region in ("us-east-1", "us-west-1", "eu-west-1", "ap-southeast-2"):
        assert service_available_in_region(service_id, region) is True


def test_security_ir_has_no_endpoint_data_and_is_available() -> None:
    """``security-ir`` answers ``[]`` because botocore ships no data for it.

    Indistinguishable from the non-regionalized case above, which is exactly
    why the rule is "empty means yes" rather than a list of known-global
    services. Security Incident Response is also home-Region-pinned, so
    endpoint presence would not predict where its data lives even if the data
    existed -- Requirement 5.7 rejects it as a candidate for that reason.
    """
    assert service_available_in_region("security-ir", "us-east-1") is True


# --------------------------------------------------------------------------- #
# Requirement 5.3 -- unknown service id
# --------------------------------------------------------------------------- #


def test_an_unknown_service_id_is_available_and_warns(availability_log: Any, cold_cache: Any) -> None:
    """A typo must produce a diagnostic, not silence.

    ``get_available_regions`` answers ``[]`` rather than raising for an
    unrecognized name, so without the explicit ``get_available_services()``
    check a mis-typed id would disable the calling check in every Region with
    nothing in the log to say why.
    """
    assert service_available_in_region("no-such-service", "us-east-1") is True

    warnings = _exactly(availability_log, logging.WARNING)
    assert len(warnings) == 1, f"expected one warning, got {warnings}"
    assert "no-such-service" in warnings[0]
    assert "us-east-1" in warnings[0]


def test_the_unknown_service_warning_goes_to_the_logger_not_to_stdout(
    availability_log: Any, capsys: Any, cold_cache: Any
) -> None:
    """Requirement 8.1: the diagnostic this feature adds is a log record.

    Property 21 forbids ``print`` and ``warnings.warn`` statically; this is the
    dynamic counterpart for the one new warning path in this module.
    """
    service_available_in_region("no-such-service", "us-east-1")

    captured = capsys.readouterr()
    assert captured.out == "", f"availability wrote to stdout: {captured.out!r}"
    assert _exactly(availability_log, logging.WARNING), "the warning was not logged"


# --------------------------------------------------------------------------- #
# Requirement 5.2 -- partition derivation
# --------------------------------------------------------------------------- #


def test_a_govcloud_region_is_measured_against_the_govcloud_partition() -> None:
    """``organizations`` in GovCloud is available, not measured against ``aws``.

    If the partition defaulted to ``aws`` this would still answer ``True`` via
    the empty-list rule, so the discriminating case is the one below.
    """
    assert service_available_in_region("organizations", "us-gov-west-1") is True


def test_securitylake_in_govcloud_uses_the_govcloud_region_list() -> None:
    """The discriminating partition case.

    ``securitylake`` has 17 Regions in ``aws`` and 2 in ``aws-us-gov``, and
    ``us-gov-west-1`` is in the second list and not the first. Measured against
    the commercial partition this would answer ``False``; measured correctly it
    answers ``True``. This is the assertion that actually proves the partition
    is derived rather than assumed.
    """
    session = boto3.Session()
    gov_regions = session.get_available_regions(
        "securitylake", partition_name="aws-us-gov"
    )
    aws_regions = session.get_available_regions("securitylake", partition_name="aws")

    assert "us-gov-west-1" in gov_regions, (
        "botocore's GovCloud data for securitylake changed; this test's premise "
        "no longer holds"
    )
    assert "us-gov-west-1" not in aws_regions

    assert service_available_in_region("securitylake", "us-gov-west-1") is True


def test_apprunner_in_govcloud_is_available_which_differs_from_the_waf_original(
    availability_log: Any,
) -> None:
    """A deliberate behaviour change from ``WAFCheck.region_supports_service``.

    App Runner genuinely has no GovCloud endpoints, so the old ``False`` was
    factually right, and ``.tmp/verify_waf06.py`` asserted it.

    But the *data* that produces it -- an empty regional list for a recognized
    service -- is the same data ``security-ir`` produces in every partition
    because botocore ships no endpoint entry for it at all, and
    ``shield``/``organizations``/``iam`` produce in every partition because they
    are non-regionalized. The three cases are indistinguishable at this layer.
    Reading the empty list as "absent" would suppress every Security Incident
    Response and Shield row in every Region.

    So: fail-open costs one ERROR row per Region for ``SRA-WAF-06`` in a
    GovCloud scan. Fail-closed would cost five checks' worth of silence in every
    scan, commercial included. The trade is not close.
    """
    session = boto3.Session()
    assert (
        session.get_available_regions("apprunner", partition_name="aws-us-gov") == []
    ), "botocore now has GovCloud data for apprunner; this test's premise changed"

    assert service_available_in_region("apprunner", "us-gov-west-1") is True

    # The empty-list path is not an error condition, so it stays quiet. Only the
    # unknown-id path warns and only the exception path debugs.
    assert _at_least(availability_log, logging.WARNING) == []


# --------------------------------------------------------------------------- #
# Requirement 5.4 -- fail open on any exception
# --------------------------------------------------------------------------- #


def test_a_session_that_raises_still_answers_available(
    monkeypatch: Any, availability_log: Any, cold_cache: Any
) -> None:
    """A lookup defect costs an honest ERROR row, never silent suppression.

    ``boto3.Session()`` is patched rather than one of the three lookup methods
    because the requirement is explicit that session *construction* is inside
    the handler: a broken botocore install raises there, and criterion 4 has to
    hold for the whole function.
    """

    def _explode() -> Any:
        raise RuntimeError("botocore install is broken")

    monkeypatch.setattr(availability.boto3, "Session", _explode)

    assert service_available_in_region("apprunner", "us-west-1") is True

    debugs = _exactly(availability_log, logging.DEBUG)
    assert any("apprunner" in m and "us-west-1" in m for m in debugs), (
        f"the fail-open path must leave a debug record, got {debugs}"
    )


@pytest.mark.parametrize(
    "region",
    ["", "not-a-region", "us-east", "US-EAST-1", "  ", "us-east-1-extra-segments"],
    ids=["empty", "garbage", "truncated", "uppercase", "whitespace", "over-long"],
)
def test_an_unparseable_region_answers_available(region: str) -> None:
    """``get_partition_for_region`` raises on these; the handler covers it."""
    assert service_available_in_region("apprunner", region) is True


# --------------------------------------------------------------------------- #
# Requirement 5.11 -- the cache
# --------------------------------------------------------------------------- #


def test_a_repeated_lookup_does_not_rebuild_the_session(monkeypatch: Any, cold_cache: Any) -> None:
    """Requirement 5.11: cached per ``(service_id, region)`` for the process.

    A full-organization scan asks the same question once per check per Region --
    for Security Lake alone that is 17 checks times the Region count -- and the
    bundled data cannot change under it.
    """
    calls: list[int] = []
    real_session = boto3.Session

    def _counting_session(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        return real_session(*args, **kwargs)

    monkeypatch.setattr(availability.boto3, "Session", _counting_session)

    first = service_available_in_region("apprunner", "us-west-1")
    assert len(calls) == 1, "the first call must do the lookup"

    second = service_available_in_region("apprunner", "us-west-1")
    assert len(calls) == 1, (
        f"the second identical call must be served from the cache, "
        f"but Session was built {len(calls)} times"
    )
    assert first == second is False


def test_the_cache_key_includes_the_region() -> None:
    """Two Regions for one service are two entries, not one.

    A cache keyed on the service alone would answer ``us-east-1``'s ``True`` for
    ``us-west-1`` and silently stop suppressing anything.
    """
    assert service_available_in_region("apprunner", "us-east-1") is True
    assert service_available_in_region("apprunner", "us-west-1") is False


def test_the_cache_key_includes_the_service() -> None:
    """Two services in one Region are two entries."""
    assert service_available_in_region("apprunner", "us-west-1") is False
    assert service_available_in_region("securitylake", "us-west-1") is True


# --------------------------------------------------------------------------- #
# Requirement 5.1 -- the signature and the offline promise
# --------------------------------------------------------------------------- #


def test_the_signature_takes_no_session_parameter() -> None:
    """A parameter the implementation ignored would mislead the reader.

    The endpoint data is process-global and shipped with botocore, so the answer
    cannot depend on which session asks.
    """
    import inspect

    params = list(
        inspect.signature(service_available_in_region.__wrapped__).parameters
    )
    assert params == ["service_id", "region"], (
        f"expected exactly (service_id, region), got {params}"
    )


def test_the_lookup_issues_no_http_request(monkeypatch: Any, cold_cache: Any) -> None:
    """Requirement 5.1: offline and credential-free.

    Patching botocore's transport is a stronger statement than asserting no
    credentials were needed: if any path here resolved an endpoint over the
    network, this raises.
    """
    import botocore.httpsession

    def _no_network(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the availability lookup issued an HTTP request")

    monkeypatch.setattr(
        botocore.httpsession.URLLib3Session, "send", _no_network
    )

    assert service_available_in_region("apprunner", "us-west-1") is False
    assert service_available_in_region("shield", "us-east-1") is True
