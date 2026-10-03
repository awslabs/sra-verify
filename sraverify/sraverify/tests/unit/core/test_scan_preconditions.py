"""
Property 45: a failed identity or Region lookup costs exactly the rows it cost
before, and each of them names the failed call.

``ScanContext.get_account_info`` and ``get_enabled_regions`` return an error
result for a failed ``sts:GetCallerIdentity`` / ``ec2:DescribeRegions``.
``SecurityCheck``'s identity properties, ``_finding`` and ``regions`` raise
``ScanPreconditionError`` when they read one, and ``run_checks``' per-check guard
turns it into one ERROR row per check that read the failed fact:
``Region`` ``global``, empty ``ResourceId``, the check's own severity, the scan's
fallback account, ``ActualValue`` ``<Operation> failed: <Code>: <Message>`` and a
scan-environment remediation chosen by the code first and then by the lookup.
A check that reads neither fact yields its genuine rows.

Every scan here runs against a stand-in session; no request is sent.
"""
from __future__ import annotations

import ast
import contextlib
import gc
import logging
import re
import weakref
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError, NoCredentialsError

import sraverify
import sraverify.scanner as scanner
from sraverify.core import registry
from sraverify.core.aws_errors import is_error
from sraverify.core.check import SecurityCheck
from sraverify.core.enums import AccountType, Severity, Status
from sraverify.core.errors import ScanPreconditionError
from sraverify.core.finding import GLOBAL_REGION
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.core.scan_context import ScanContext

_SERVICES_ROOT = Path(sraverify.__file__).resolve().parent / "services"

_ERROR_VALUE_RE = re.compile(r"^\S+ failed: \S+: ")
_CREDENTIALS = scanner._CREDENTIALS_REMEDIATION
_GRANT = (
    "Pass --regions explicitly, or grant the scanning role ec2:DescribeRegions "
    "(1-sraverify-member-roles.yaml), then re-run the scan"
)


# --------------------------------------------------------------------------- #
# Probe checks
# --------------------------------------------------------------------------- #


def _meta(index: int, severity: Severity) -> CheckMeta:
    return CheckMeta(
        check_id=f"SRA-PROBE-{index:02d}",
        title=f"Probe control {index} is configured",
        description="Synthetic check for the scan-precondition property; reaches no AWS API.",
        check_logic="Yields fixed rows from the identity and Region it reads",
        severity=severity,
        account_type=AccountType.APPLICATION,
        service="Probe",
        resource_type="AWS::Probe::Resource",
        remediation=Remediation(text="Control-level remediation for the probe."),
    )


def _reads_identity(self: SecurityCheck) -> Iterator[Any]:
    """One global PASS: reads identity through ``_finding``, never ``regions``."""
    yield self.passed(region=GLOBAL_REGION, resource_id="probe/global", actual_value="ok")


def _reads_regions_execute(self: SecurityCheck) -> Iterator[Any]:
    for region in self.regions:
        yield self.passed(region=region, resource_id=f"probe/{region}", actual_value="ok")


def _reads_regions_setup(self: SecurityCheck) -> None:
    """Reads ``self.regions`` in ``initialize``, as every regional base does."""
    self._clients.clear()
    if hasattr(self, "regions") and self.regions:
        for region in self.regions:
            self._clients[region] = object()


def _reads_neither(self: SecurityCheck) -> Iterator[Any]:
    """Returns before its first row, so it reads neither fact."""
    return
    yield  # pragma: no cover - makes this a generator


def _setup_none(self: SecurityCheck) -> None:
    self._clients.clear()


def _probe(index: int, severity: Severity, execute: Any, setup: Any) -> type[SecurityCheck]:
    meta = _meta(index, severity)
    return type(
        meta.check_id.replace("-", "_"),
        (SecurityCheck,),
        {"__module__": __name__, "meta": meta, "execute": execute, "_setup_clients": setup},
    )


IDENTITY = _probe(1, Severity.HIGH, _reads_identity, _setup_none)
REGIONS = _probe(2, Severity.LOW, _reads_regions_execute, _reads_regions_setup)
NEITHER = _probe(3, Severity.CRITICAL, _reads_neither, _setup_none)


@contextlib.contextmanager
def _isolated_registry(*classes: type[SecurityCheck]) -> Iterator[None]:
    """Replace the catalog with ``classes`` for the block, restoring it in place."""
    saved = dict(registry._REGISTRY)
    registry._REGISTRY.clear()
    try:
        for cls in classes:
            registry.register(cls.meta.check_id, cls)
        yield
    finally:
        registry._REGISTRY.clear()
        registry._REGISTRY.update(saved)


class _Session:
    """A stand-in session: one mock per service, failing the named lookup."""

    def __init__(self, *, fail: str | None = None, exc: Exception | None = None):
        self.region_name = "us-east-1"
        self.mocks: dict[str, MagicMock] = {}
        sts = self.client("sts")
        sts.get_caller_identity.return_value = {"Account": "111122223333"}
        self.client("account").get_account_information.return_value = {"AccountName": "probe"}
        self.client("ec2").describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}, {"RegionName": "us-west-2"}]
        }
        if fail == "identity":
            sts.get_caller_identity.side_effect = exc
        elif fail == "regions":
            self.client("ec2").describe_regions.side_effect = exc

    def client(self, service_name: str, region_name: Any = None, config: Any = None) -> MagicMock:
        return self.mocks.setdefault(service_name, MagicMock(name=service_name))


def _invalid_token() -> ClientError:
    return ClientError(
        {"Error": {"Code": "InvalidClientTokenId", "Message": "The security token is invalid."}},
        "GetCallerIdentity",
    )


def _auth_failure() -> ClientError:
    return ClientError(
        {"Error": {"Code": "AuthFailure", "Message": "AWS was not able to validate it."}},
        "DescribeRegions",
    )


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    """Every ``sraverify`` record at ``DEBUG`` (the suite runs ``-p no:logging``)."""
    captured: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    handler = _Collector()
    target = logging.getLogger("sraverify")
    previous = target.level
    target.setLevel(logging.DEBUG)
    target.addHandler(handler)
    try:
        yield captured
    finally:
        target.removeHandler(handler)
        target.setLevel(previous)


def _scan(session: _Session, regions: list[str] | None) -> list[Any]:
    with _isolated_registry(IDENTITY, REGIONS, NEITHER):
        sra = scanner.SRAVerify(session=session, regions=regions)  # type: ignore[arg-type]
        return sra.run_checks()


def _rows(findings: list[Any], cls: type[SecurityCheck]) -> list[Any]:
    return [f for f in findings if f.check_id == cls.meta.check_id]


def _assert_precondition_row(
    row: Any, cls: type[SecurityCheck], remediation: str, account: tuple[str, str]
) -> None:
    """The precondition row's cells; ``account`` is the scan's fallback account."""
    assert row.status is Status.ERROR
    assert row.region == GLOBAL_REGION
    assert row.resource_id is None
    assert row.to_row()["ResourceId"] == ""
    assert row.severity is cls.meta.severity
    assert (row.account_id, row.account_name) == account
    assert _ERROR_VALUE_RE.match(row.actual_value), row.actual_value
    assert row.remediation == remediation


# --------------------------------------------------------------------------- #
# The row set
# --------------------------------------------------------------------------- #


def test_a_failed_identity_lookup_costs_one_row_per_reading_check(
    records: list[logging.LogRecord],
) -> None:
    """Identity fails: the two checks that read it get one row each; the third none."""
    session = _Session(fail="identity", exc=_invalid_token())

    findings = _scan(session, ["us-east-1"])

    for cls in (IDENTITY, REGIONS):
        rows = _rows(findings, cls)
        assert len(rows) == 1, rows
        # Identity is what failed, so the fallback account is empty.
        _assert_precondition_row(rows[0], cls, _CREDENTIALS, ("", ""))
        assert rows[0].actual_value.startswith("GetCallerIdentity failed: InvalidClientTokenId: ")
    assert _rows(findings, NEITHER) == []
    precondition_errors = [
        r for r in records if r.levelno >= logging.ERROR and "could not run" in r.getMessage()
    ]
    assert len(precondition_errors) == 2
    assert [r for r in records if r.levelno >= logging.ERROR] == precondition_errors
    session.mocks["ec2"].describe_regions.assert_not_called()


def test_a_failed_region_lookup_costs_one_row_per_reading_check(
    records: list[logging.LogRecord],
) -> None:
    """Regions fail with no explicit list: only the Region reader loses its rows."""
    session = _Session(fail="regions", exc=_auth_failure())

    findings = _scan(session, None)

    rows = _rows(findings, REGIONS)
    assert len(rows) == 1
    # Identity resolved, so the row carries the scan's real account.
    _assert_precondition_row(rows[0], REGIONS, _CREDENTIALS, ("111122223333", "probe"))
    assert rows[0].actual_value.startswith("DescribeRegions failed: AuthFailure: ")
    assert "ec2:DescribeRegions" not in rows[0].remediation

    genuine = _rows(findings, IDENTITY)
    assert [(r.status, r.region, r.account_id) for r in genuine] == [
        (Status.PASS, GLOBAL_REGION, "111122223333")
    ]
    assert _rows(findings, NEITHER) == []
    # One DescribeRegions per check that reads the list, which is what the
    # merged tree issued: a failure is never cached, so each reader re-asks.
    assert session.mocks["ec2"].describe_regions.call_count == 1
    assert len([r for r in records if r.levelno >= logging.ERROR]) == 1


def test_no_credentials_reach_the_row_end_to_end() -> None:
    """A real ``NoCredentialsError`` passes through ``aws_error`` to the remediation."""
    session = _Session(fail="regions", exc=NoCredentialsError())
    ctx = ScanContext(session=session, regions=None)  # type: ignore[arg-type]
    result = ctx.get_enabled_regions()
    assert is_error(result)
    assert result["Error"]["Code"] == "NoCredentialsError"
    assert result["Error"]["Operation"] == "Request"

    findings = _scan(_Session(fail="regions", exc=NoCredentialsError()), None)
    row = _rows(findings, REGIONS)[0]
    assert row.actual_value.startswith("Request failed: NoCredentialsError: ")
    assert row.remediation == _CREDENTIALS
    assert "ec2:DescribeRegions" not in row.remediation


def test_a_row_builder_failure_costs_that_row_and_the_scan_continues(
    records: list[logging.LogRecord],
) -> None:
    """A defect building the row is logged with ``exc_info`` and the loop goes on."""
    session = _Session(fail="regions", exc=_auth_failure())
    with patch.object(scanner, "_precondition_error", side_effect=RuntimeError("builder")):
        findings = _scan(session, None)

    assert _rows(findings, REGIONS) == []
    assert [r.status for r in _rows(findings, IDENTITY)] == [Status.PASS]
    secondary = [r for r in records if "Could not build precondition ERROR row" in r.getMessage()]
    assert len(secondary) == 1
    assert secondary[0].levelno == logging.ERROR
    assert secondary[0].exc_info is not None


def test_the_context_is_released() -> None:
    """``del ctx`` still frees the context after a precondition row."""
    refs: list[weakref.ref] = []
    real = scanner.ScanContext

    def _recording(*args: Any, **kwargs: Any) -> ScanContext:
        ctx = real(*args, **kwargs)
        refs.append(weakref.ref(ctx))
        return ctx

    with patch.object(scanner, "ScanContext", side_effect=_recording):
        findings = _scan(_Session(fail="identity", exc=_invalid_token()), ["us-east-1"])

    assert findings
    gc.collect()
    assert len(refs) == 1
    assert refs[0]() is None


# --------------------------------------------------------------------------- #
# The remediation, pinned per order-table row
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "lookup,code,operation,expected",
    [
        pytest.param(
            "identity", "EndpointConnectionError", "Request",
            "Confirm the STS endpoint for eu-west-1 is reachable from the scanner's "
            "network, then re-run the scan",
            id="identity-transport",
        ),
        pytest.param(
            "regions", "EndpointConnectionError", "Request",
            "Confirm the EC2 endpoint for eu-west-1 is reachable from the scanner's "
            "network, or pass --regions",
            id="regions-transport",
        ),
        pytest.param("identity", "InvalidClientTokenId", "GetCallerIdentity", _CREDENTIALS,
                     id="identity-InvalidClientTokenId"),
        pytest.param("regions", "AuthFailure", "DescribeRegions", _CREDENTIALS,
                     id="regions-AuthFailure"),
        pytest.param("identity", "SomeUnlistedCode", "GetCallerIdentity", _CREDENTIALS,
                     id="identity-unlisted"),
        pytest.param("regions", "UnauthorizedOperation", "DescribeRegions", _GRANT,
                     id="regions-UnauthorizedOperation"),
        pytest.param("regions", "NoCredentialsError", "Request", _CREDENTIALS,
                     id="regions-NoCredentialsError"),
        pytest.param("not-a-lookup", "SomeUnlistedCode", "Request", _CREDENTIALS,
                     id="unknown-lookup"),
    ],
)
def test_the_precondition_remediation_is_chosen_by_code_then_lookup(
    lookup: str, code: str, operation: str, expected: str
) -> None:
    """Every row of the design's order table, through the real row builder."""
    exc = ScanPreconditionError(
        check_id=REGIONS.meta.check_id,
        lookup=lookup,
        error={"Code": code, "Message": "probe message", "Operation": operation},
    )

    row = scanner._precondition_error(REGIONS, exc, ("111122223333", "probe"), "eu-west-1")

    assert row.remediation == expected
    assert row.actual_value == f"{operation} failed: {code}: probe message"
    assert (row.account_id, row.account_name) == ("111122223333", "probe")
    assert row.checked_value == "Probe Configuration"
    if code in {"AuthFailure", "NoCredentialsError"}:
        assert "ec2:DescribeRegions" not in row.remediation


def test_the_credential_set_is_the_two_server_codes_and_the_six_botocore_classes() -> None:
    """A code joins ``_CREDENTIAL_ERROR_CODES`` only by a reviewed edit."""
    classes = scanner._LOCAL_CREDENTIAL_EXCEPTIONS
    assert len(classes) == 6
    assert all(issubclass(c, BotoCoreError) for c in classes)
    assert scanner._REJECTED_CREDENTIAL_CODES == {"AuthFailure", "InvalidClientTokenId"}
    assert scanner._CREDENTIAL_ERROR_CODES == {"AuthFailure", "InvalidClientTokenId"} | {
        c.__name__ for c in classes
    }
    assert {c.__name__ for c in classes} == {
        "NoCredentialsError",
        "PartialCredentialsError",
        "CredentialRetrievalError",
        "UnauthorizedSSOTokenError",
        "TokenRetrievalError",
        "SSOTokenLoadError",
    }


def test_a_transport_failure_is_not_a_credential_failure() -> None:
    """The two sets are disjoint, so the order table's first two rows cannot overlap."""
    assert not scanner._CREDENTIAL_ERROR_CODES & scanner.TRANSPORT_ERROR_CODES
    assert "EndpointConnectionError" in scanner.TRANSPORT_ERROR_CODES
    assert isinstance(EndpointConnectionError(endpoint_url="x"), BotoCoreError)


# --------------------------------------------------------------------------- #
# No check names the exception
# --------------------------------------------------------------------------- #


def _names_precondition_error(source: str) -> list[int]:
    lines = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name) and node.id == "ScanPreconditionError":
            lines.append(node.lineno)
        elif isinstance(node, ast.Attribute) and node.attr == "ScanPreconditionError":
            lines.append(node.lineno)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            lines += [
                node.lineno
                for a in node.names
                if a.name.split(".")[-1] == "ScanPreconditionError"
                or a.asname == "ScanPreconditionError"
            ]
    return lines


_CHECK_MODULES = sorted(_SERVICES_ROOT.glob("*/checks/sra_*.py"))


@pytest.mark.parametrize("path", _CHECK_MODULES, ids=lambda p: p.name)
def test_no_check_module_names_the_precondition_error(path: Path) -> None:
    """The orchestrator catches it; a check never does (and never names it)."""
    assert _names_precondition_error(path.read_text(encoding="utf-8")) == []


def test_the_precondition_name_rule_is_not_vacuous() -> None:
    """Code is caught; prose is not."""
    assert _names_precondition_error(
        "from sraverify.core.errors import ScanPreconditionError\n"
        "try:\n    pass\nexcept errors.ScanPreconditionError:\n    pass\n"
    ) == [1, 4]
    assert _names_precondition_error('"""ScanPreconditionError is never caught here."""\n') == []
    assert len(_CHECK_MODULES) >= 150
