from contextlib import ExitStack
from importlib import import_module
from unittest.mock import MagicMock, patch

import pytest

from sraverify.core.aws_errors import error_result
from sraverify.core.enums import Status
from sraverify.core.scan_context import ScanContext


A = "111122223333"
B = "444455556666"
AUDIT = "222233334444"
R1, R2 = "us-east-1", "us-west-2"
ROSTER = {"Accounts": [{"Id": A, "State": "ACTIVE"}, {"Id": B, "State": "ACTIVE"}, {"Id": AUDIT, "State": "SUSPENDED"}]}
SOURCES = [
    pytest.param(6, "ROUTE53", "Route 53 log source enabled with version 2.0", True, id="06-route53"),
    pytest.param(7, "S3_DATA", "CloudTrail S3 data events enabled with version 2.0", True, id="07-s3"),
    pytest.param(8, "SH_FINDINGS", "Security Hub findings enabled with version 2.0", True, id="08-findings"),
    pytest.param(9, "EKS_AUDIT", "EKS Audit logs enabled with version 2.0", False, id="09-eks"),
    pytest.param(10, "LAMBDA_EXECUTION", "Lambda execution logs enabled with version 2.0", True, id="10-lambda"),
    pytest.param(11, "CLOUD_TRAIL_MGMT", "CloudTrail management logs enabled with version 2.0", True, id="11-cloudtrail"),
    pytest.param(12, "WAF", "WAF logs enabled with version 2.0", False, id="12-waf"),
    pytest.param(13, "VPC_FLOW", "VPC Flow logs enabled with version 2.0", True, id="13-vpc"),
]


def run(number, responses=None, roster=None, delegation=None, regions=(R1,), archive=(B,), audit=(AUDIT,)):
    session = MagicMock()
    session.region_name = R1
    session.client.return_value = object()
    ctx = ScanContext(session=session, regions=list(regions), log_archive_accounts=list(archive), audit_accounts=list(audit))
    cls = getattr(import_module(f"sraverify.services.securitylake.checks.sra_securitylake_{number:02}"), f"SRA_SECURITYLAKE_{number:02}")
    with ExitStack() as stack:
        stack.enter_context(patch.object(ctx, "get_account_info", return_value={"account_id": A, "account_name": "test"}))
        stack.enter_context(patch.object(ctx.organization, "accounts", side_effect=AssertionError("unexpected account lookup") if roster is None else None, return_value=roster))
        if delegation is not None:
            stack.enter_context(patch.object(ctx.organization, "delegated_administrators", side_effect={"securitylake.amazonaws.com": delegation}.__getitem__))
        check = cls()
        check.initialize(ctx)
        for name, response in (responses or {}).items():
            stack.enter_context(patch.object(check, name, side_effect=response.__getitem__))
        return list(check.execute())


def rows_by_key(rows, count):
    result = {(row.region, row.resource_id): row for row in rows}
    assert len(rows) == len(result) == count
    return result


def assert_row(row, status, checked, actual):
    assert row.status == status and row.checked_value == checked
    assert actual in row.actual_value


def source(name, version="2.0"):
    return {"awsLogSource": {"sourceName": name, "sourceVersion": version}}


def entry(account, region, sources):
    return {"account": account, "region": region, "sources": sources}


def arn(region, account, resource):
    return f"arn:aws:securitylake:{region}:{account}:{resource}"


@pytest.mark.parametrize("number,name,checked,v1", SOURCES)
def test_source_mixed_accounts_regions(number, name, checked, v1):
    responses = {}
    for region, enabled in [(R1, A), (R2, B)]:
        other = B if enabled == A else A
        decoy = "ROUTE53" if name == "WAF" else "WAF"
        responses[region] = {"sources": [entry(enabled, region, [source(decoy), source(name, "1.0" if v1 else "2.0"), source(name)]), entry(other, region, [source(decoy)])]}
    rows = rows_by_key(run(number, {"get_log_sources": responses}, regions=(R1, R2), roster=ROSTER), 4)
    for region, enabled in [(R1, A), (R2, B)]:
        for account in (A, B):
            row = rows[(region, arn(region, account, f"log-source/{name}"))]
            assert row.status == (Status.PASS if account == enabled else Status.FAIL)
            assert row.checked_value == checked
            assert account in row.actual_value
            assert ("is configured" if number == 6 and account == enabled else "enabled with version 2.0" if account == enabled else "not configured") in row.actual_value


@pytest.mark.parametrize("number,name,checked,kind", [
    pytest.param(*case.values[:3], kind, id=f"{case.id}-{kind}")
    for case in SOURCES for kind in (("empty", "v1") if case.values[3] else ("empty",))
])
def test_source_versions(number, name, checked, kind):
    entries = [] if kind == "empty" else [entry(A, R1, [source(name, "1.0")])]
    rows = rows_by_key(run(number, {"get_log_sources": {R1: {"sources": entries}}}, roster=ROSTER), 2)
    row = rows[(R1, arn(R1, A, f"log-source/{name}"))]
    assert row.status == Status.FAIL and row.checked_value == checked
    assert A in row.actual_value
    assert ("not configured" if kind == "empty" else "1.0 instead of 2.0") in row.actual_value
    other = rows[(R1, arn(R1, B, f"log-source/{name}"))]
    assert other.status == Status.FAIL and other.checked_value == checked
    assert B in other.actual_value and "not configured" in other.actual_value


@pytest.mark.parametrize("number,name,checked,v1", SOURCES)
@pytest.mark.parametrize("code,status", [pytest.param("ResourceNotFoundException", Status.FAIL, id="lake-absent"), pytest.param("AccessDeniedException", Status.ERROR, id="denied")])
def test_source_read_error_continues(number, name, checked, v1, code, status):
    error = error_result(code=code, message="fixture denied", operation="ListLogSources")
    rows = rows_by_key(run(number, {"get_log_sources": {R1: error, R2: {"sources": [entry(A, R2, [source(name)])]}}}, regions=(R1, R2), roster=ROSTER), 4)
    for account in (A, B):
        row = rows[(R1, arn(R1, account, f"log-source/{name}"))]
        assert row.status == status and row.checked_value == f"{name} log source configured"
        assert (account if status == Status.FAIL else "ListLogSources failed: AccessDeniedException: fixture denied") in row.actual_value
    assert_row(rows[(R2, arn(R2, A, f"log-source/{name}"))], Status.PASS, checked, f"{'is configured' if number == 6 else 'are enabled with version 2.0'} in {R2} for account {A}")
    assert_row(rows[(R2, arn(R2, B, f"log-source/{name}"))], Status.FAIL, checked, f"not configured for account {B}")


def test_lake_mixed_accounts_regions():
    responses = {R1: {"dataLakeSources": [{"account": A}, {"account": A}]}, R2: {"dataLakeSources": [{"account": B}]}}
    rows = rows_by_key(run(1, {"get_data_lake_sources": responses}, regions=(R1, R2), roster=ROSTER), 4)
    for region, enabled in [(R1, A), (R2, B)]:
        for account in (A, B):
            row = rows[(region, arn(region, account, "datalake/default"))]
            assert row.status == (Status.PASS if account == enabled else Status.FAIL)
            assert row.checked_value == "Security Lake enabled"
            assert row.actual_value == f"Security Lake is {'enabled' if account == enabled else 'not enabled'} for account {account}"


@pytest.mark.parametrize("code,status", [pytest.param("ResourceNotFoundException", Status.FAIL, id="lake-absent"), pytest.param("AccessDeniedException", Status.ERROR, id="denied")])
def test_lake_read_error_continues(code, status):
    error = error_result(code=code, message="fixture denied", operation="GetDataLakeSources")
    rows = rows_by_key(run(1, {"get_data_lake_sources": {R1: error, R2: {"dataLakeSources": [{"account": A}]}}}, regions=(R1, R2), roster=ROSTER), 4)
    for account in (A, B):
        row = rows[(R1, arn(R1, account, "datalake/default"))]
        assert row.status == status and row.checked_value == "Security Lake enabled"
        assert (account if status == Status.FAIL else "GetDataLakeSources failed: AccessDeniedException: fixture denied") in row.actual_value
    assert_row(rows[(R2, arn(R2, A, "datalake/default"))], Status.PASS, "Security Lake enabled", f"is enabled for account {A}")
    assert_row(rows[(R2, arn(R2, B, "datalake/default"))], Status.FAIL, "Security Lake enabled", f"is not enabled for account {B}")


@pytest.mark.parametrize("number", [pytest.param(n, id=f"check-{n:02}") for n in (1, 6, 7, 8, 9, 10, 11, 12, 13)])
def test_no_organization(number):
    error = error_result(code="AWSOrganizationsNotInUseException", message="not in use", operation="ListAccounts")
    rows = rows_by_key(run(number, roster=error, regions=(R1, R2)), 2)
    for region in (R1, R2):
        row = rows[(region, arn(region, A, "datalake/default"))]
        assert row.status == Status.FAIL
        assert row.checked_value == ("Security Lake enabled" if number == 1 else "Log source configured for every active account")
        assert "No AWS Organization exists" in row.actual_value


DEFAULTS = ["CLOUD_TRAIL_MGMT", "LAMBDA_EXECUTION", "EKS_AUDIT", "ROUTE53", "SH_FINDINGS", "VPC_FLOW"]


def config(region, names):
    return {"region": region, "sources": [{"sourceName": name, "sourceVersion": "2.0"} for name in names]}


@pytest.mark.parametrize("number,slug,checked", [pytest.param(4, "default", "Organization configuration enabled", id="04"), pytest.param(5, "auto-enable", "Auto-enable configured with AWS defaults: " + ", ".join(sorted(DEFAULTS)), id="05")])
def test_configuration_missing(number, slug, checked):
    error = error_result(code="ResourceNotFoundException", message="absent", operation="GetDataLakeOrganizationConfiguration")
    rows = run(number, {"get_organization_configuration": {R1: error}})
    assert len(rows) == 1
    row = rows[0]
    assert (row.status, row.region, row.resource_id, row.checked_value) == (Status.FAIL, R1, arn(R1, A, f"organization-configuration/{slug}"), checked)
    assert "control is not configured" in row.actual_value


def test_configuration_enabled():
    rows = run(4, {"get_organization_configuration": {R1: {"autoEnableNewAccount": [config(R1, ["ROUTE53"])]}}})
    assert len(rows) == 1
    row = rows[0]
    assert (row.status, row.region, row.resource_id, row.checked_value) == (Status.PASS, R1, arn(R1, A, "organization-configuration/default"), "Organization configuration enabled")
    assert "configuration is enabled" in row.actual_value


@pytest.mark.parametrize("configs,status,configured,missing", [
    pytest.param([config(R1, DEFAULTS)], Status.PASS, DEFAULTS, [], id="defaults"),
    pytest.param([config(R1, DEFAULTS + ["WAF", "S3_DATA"])], Status.PASS, DEFAULTS + ["WAF", "S3_DATA"], [], id="optional"),
    pytest.param([config(R2, DEFAULTS), config(R1, DEFAULTS[:-1] + ["WAF"])], Status.FAIL, DEFAULTS[:-1] + ["WAF"], ["VPC_FLOW"], id="missing-one"),
    pytest.param([config(R2, DEFAULTS)], Status.FAIL, [], DEFAULTS, id="missing-region"),
])
def test_configuration_defaults(configs, status, configured, missing):
    rows = run(5, {"get_organization_configuration": {R1: {"autoEnableNewAccount": configs}}})
    assert len(rows) == 1
    row = rows[0]
    assert (row.status, row.region, row.resource_id, row.checked_value) == (status, R1, arn(R1, A, "organization-configuration/auto-enable"), "Auto-enable configured with AWS defaults: " + ", ".join(sorted(DEFAULTS)))
    expected = "Currently configured: " + (", ".join(sorted(configured)) if configured else "None")
    if missing:
        expected += ". Missing: " + ", ".join(sorted(missing))
    assert row.actual_value == expected


@pytest.mark.parametrize("number,delegation,archive,status,checked,actual", [
    pytest.param(14, {"DelegatedAdministrators": [{"Id": B}]}, (B,), Status.PASS, "Delegated administrator configured", B, id="14-delegated"),
    pytest.param(14, {"DelegatedAdministrators": []}, (B,), Status.FAIL, "Delegated administrator configured", "No delegated administrator", id="14-empty"),
    pytest.param(15, {"DelegatedAdministrators": [{"Id": B}]}, (B,), Status.PASS, f"Delegated administrator is Log Archive account {B}", B, id="15-match"),
    pytest.param(15, {"DelegatedAdministrators": [{"Id": AUDIT}]}, (B,), Status.FAIL, f"Delegated administrator is Log Archive account {B}", f"{AUDIT} is not the Log Archive account {B}", id="15-different"),
    pytest.param(15, {"DelegatedAdministrators": []}, (B,), Status.FAIL, f"Delegated administrator is Log Archive account {B}", "No delegated administrator", id="15-empty"),
    pytest.param(15, None, (), Status.ERROR, "Delegated administrator is Log Archive account", "Log Archive Account ID not provided", id="15-no-archive"),
    *[pytest.param(n, error_result(code="AWSOrganizationsNotInUseException", message="not in use", operation="ListDelegatedAdministrators"), (B,), Status.FAIL, "Delegated administrator configured" if n == 14 else f"Delegated administrator is Log Archive account {B}", "No AWS Organization exists", id=f"{n}-no-organization") for n in (14, 15)],
])
def test_delegation(number, delegation, archive, status, checked, actual):
    rows = run(number, delegation=delegation, archive=archive, regions=(R1, R2))
    assert len(rows) == 1
    row = rows[0]
    assert (row.status, row.region, row.resource_id, row.checked_value) == (status, "global", "arn:aws:organizations::global:delegatedadministrator/securitylake", checked)
    assert actual in row.actual_value


@pytest.mark.parametrize("number,access,slug", [pytest.param(16, "LAKEFORMATION", "query", id="16-query"), pytest.param(17, "S3", "data", id="17-data")])
@pytest.mark.parametrize("kind", [pytest.param(x, id=x) for x in ("match", "wrong-principal", "wrong-access", "empty", "lake-absent", "no-audit")])
def test_subscribers(number, access, slug, kind):
    def subscriber(identity, types, identifier):
        return {"subscriberIdentity": {"principal": identity}, "accessTypes": types, "subscriberId": identifier, "subscriberStatus": "ACTIVE"}
    decoy = subscriber(B, [access], "11111111-1111-1111-1111-111111111111")
    match = subscriber(AUDIT, [access], "22222222-2222-2222-2222-222222222222")
    wrong_access = subscriber(AUDIT, ["S3" if access == "LAKEFORMATION" else "LAKEFORMATION"], "33333333-3333-3333-3333-333333333333")
    entries = {"match": [decoy, match], "wrong-principal": [decoy], "wrong-access": [decoy, wrong_access], "empty": []}
    response = error_result(code="ResourceNotFoundException", message="absent", operation="ListSubscribers") if kind == "lake-absent" else {"subscribers": entries.get(kind, [])}
    responses = {} if kind == "no-audit" else {"get_subscribers": {R1: response}}
    rows = run(number, responses, regions=(R1, R2) if kind == "no-audit" else (R1,), audit=() if kind == "no-audit" else (AUDIT,))
    assert len(rows) == 1
    row = rows[0]
    if kind == "no-audit":
        assert (row.status, row.region, row.resource_id, row.checked_value) == (Status.ERROR, "global", f"arn:aws:securitylake::global:subscriber/{slug}-access", f"Security tooling account has {slug} access")
        assert "Audit account ID not provided" in row.actual_value
    else:
        resource = match["subscriberId"] if kind == "match" else f"{slug}-access"
        assert (row.status, row.region, row.resource_id, row.checked_value) == (Status.PASS if kind == "match" else Status.FAIL, R1, arn(R1, A, f"subscriber/{resource}"), f"Audit account {AUDIT} has {slug} access")
        if kind == "lake-absent":
            assert "control is not configured" in row.actual_value
        else:
            assert row.actual_value == f"Audit account {AUDIT} is {'set up' if kind == 'match' else 'not set up'} as {slug} access subscriber"


def test_lake_empty_sources():
    rows = rows_by_key(run(1, {"get_data_lake_sources": {R1: {"dataLakeSources": []}}}, roster=ROSTER), 2)
    for account in (A, B):
        row = rows[(R1, arn(R1, account, "datalake/default"))]
        assert row.status == Status.FAIL
        assert row.checked_value == "Security Lake enabled"
        assert row.actual_value == f"Security Lake is not enabled for account {account}"
