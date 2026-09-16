"""
Unit tests for ``util/gate.py``.

Requirement 6.15 requires the gate to be tested against synthetic CSV pairs and
stderr sets covering every admitted and every rejected transition, "so that the
gate is not the one untested component in the change".

That is the right instinct and worth stating plainly: the gate is what decides
whether a batch that changes 120 rows has left the other 2943 alone. An untested
gate that admits too much would let a regression through with a green tick, and
one that rejects too much would burn a full reference/candidate scan pair per
false alarm.

Every fixture here is synthetic. There is no fixed baseline CSV to drift against
and no AWS access; the two scans and the log evidence are constructed per test so
each case isolates one rule.
"""
from __future__ import annotations

import csv
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

import pytest

import sraverify

_REPO_ROOT: Path = Path(sraverify.__file__).resolve().parent.parent.parent
_GATE_PATH: Path = _REPO_ROOT / "util" / "gate.py"


def _load_gate() -> Any:
    """Import ``util/gate.py`` by path.

    ``util/`` is not a package; the gate is a script run from the repository root.

    Returns:
        The imported module.
    """
    spec = importlib.util.spec_from_file_location("_sraverify_gate", _GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gate() -> Any:
    """The gate module.

    Returns:
        The imported module.
    """
    if not _GATE_PATH.is_file():
        pytest.skip(f"{_GATE_PATH} not present")
    return _load_gate()


# --------------------------------------------------------------------------- #
# Fixture builders
# --------------------------------------------------------------------------- #

_ACCOUNT = "111122223333"
_TYPE = "application"
_REGION = "us-east-1"

#: A complete, valid row. Tests override only the cells they care about, so a
#: failure is attributable to the cell under test rather than to a malformed row.
_BASE_ROW: dict[str, str] = {
    "AccountId": _ACCOUNT,
    "AccountName": "probe-account",
    "Region": _REGION,
    "CheckId": "SRA-GUARDDUTY-01",
    "Status": "PASS",
    "Severity": "HIGH",
    "Title": "SRA-GUARDDUTY-01 GuardDuty detector exists",
    "Description": "A description.",
    "ResourceId": "guardduty:us-east-1:detector-1",
    "ResourceType": "AWS::GuardDuty::Detector",
    "CheckedValue": "GuardDuty Configuration",
    "ActualValue": "Detector detector-1 present",
    "Remediation": "",
    "Service": "GuardDuty",
    "CheckLogic": "Some logic.",
    "AccountType": _TYPE,
}


def row(**overrides: str) -> dict[str, str]:
    """Return a complete findings row with the given cells overridden.

    Args:
        **overrides: Cells to change.

    Returns:
        A full 16-cell row.
    """
    merged = dict(_BASE_ROW)
    merged.update(overrides)
    return merged


def write_csv(path: Path, rows: Iterable[dict[str, str]], gate: Any) -> Path:
    """Write rows to a findings CSV with the contract's columns.

    Args:
        path: Where to write.
        rows: The rows.
        gate: The gate module, for ``FIELDS``.

    Returns:
        ``path``.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(gate.FIELDS))
        writer.writeheader()
        for item in rows:
            writer.writerow(item)
    return path


def write_stderr(
    directory: Path,
    *,
    account: str = _ACCOUNT,
    account_type: str = _TYPE,
    entries: Iterable[tuple[str, list[tuple[str, str, str, str]]]] = (),
) -> Path:
    """Write one per-invocation stderr file.

    Args:
        directory: The ``stderr/`` directory.
        account: Account ID, for the file name.
        account_type: Account type, for the file name.
        entries: ``(check_id, [(operation, region, code, message)])`` in execution
            order. Each check's failures are written *before* its ``check_done``
            marker, which is the ordering the gate's positional attribution
            depends on.

    Returns:
        The written file.
    """
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{account}-{account_type}.log"
    lines: list[str] = []
    for check_id, failures in entries:
        for operation, region, code, message in failures:
            lines.append(
                f"2026-09-15 12:00:00,000 - sraverify - ERROR - "
                f"aws_call_failed operation={operation} region={region} "
                f"code={code} message={json.dumps(message)}"
            )
        rows_value = "synthetic" if check_id.endswith("!synthetic") else "1"
        clean_id = check_id.removesuffix("!synthetic")
        lines.append(
            f"2026-09-15 12:00:00,000 - sraverify - INFO - "
            f"check_done check_id={clean_id} rows={rows_value}"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def scan(tmp_path: Path, gate: Any) -> Any:
    """Return a helper that builds a two-scan pair and runs the gate.

    Returns:
        A callable taking reference rows, candidate rows, and optional evidence,
        and returning the gate's report.
    """

    def _run(
        reference_rows: Iterable[dict[str, str]],
        candidate_rows: Iterable[dict[str, str]],
        *,
        reference_entries: Iterable[Any] = (),
        candidate_entries: Iterable[Any] = (),
        services: set[str] | None = None,
        wording_changed: set[str] | None = None,
        dependencies: dict[str, set[str]] | None = None,
    ) -> Any:
        reference_csv = write_csv(tmp_path / "ref" / "c.csv", reference_rows, gate)
        candidate_csv = write_csv(tmp_path / "cand" / "c.csv", candidate_rows, gate)
        reference_stderr = tmp_path / "ref" / "stderr"
        candidate_stderr = tmp_path / "cand" / "stderr"
        write_stderr(reference_stderr, entries=reference_entries)
        write_stderr(candidate_stderr, entries=candidate_entries)

        # Dependencies are normally derived by AST from the package. Injecting
        # them keeps each test about one rule rather than about the derivation,
        # which has its own tests below.
        original = gate.derive_dependencies
        if dependencies is not None:
            gate.derive_dependencies = lambda _root: dependencies
        try:
            return gate.run_gate(
                reference_csv=reference_csv,
                reference_stderr=reference_stderr,
                candidate_csv=candidate_csv,
                candidate_stderr=candidate_stderr,
                services=services or set(),
                wording_changed=wording_changed or set(),
                package_root=Path("/nonexistent") if dependencies is None else Path("."),
            )
        finally:
            gate.derive_dependencies = original

    return _run


def rejections(report: Any) -> list[str]:
    """Return the rejection details.

    Args:
        report: A gate report.

    Returns:
        One detail string per rejection.
    """
    return [v.detail for v in report.rejections]


# --------------------------------------------------------------------------- #
# The null case
# --------------------------------------------------------------------------- #


def test_a_scan_compared_against_itself_finds_nothing(scan: Any) -> None:
    """The harness's own null case, and Phase 0 step 0.11's self-comparison.

    If this ever fails, every other test in this module is suspect: the gate would
    be reporting differences that do not exist.
    """
    rows = [
        row(),
        row(CheckId="SRA-GUARDDUTY-02", Status="FAIL", ActualValue="No detector"),
        row(CheckId="SRA-GUARDDUTY-03", Status="ERROR", ActualValue="GetDetector failed: AccessDeniedException: no"),
    ]

    report = scan(rows, list(rows))

    assert report.verdicts == [], f"a self-comparison reported {rejections(report)}"
    assert report.totals["reference_rows"] == report.totals["candidate_rows"] == 3


def test_the_gate_records_a_digest_for_every_input(scan: Any) -> None:
    """Requirement 6.12: a decision must be re-derivable from immutable inputs."""
    report = scan([row()], [row()])

    assert len(report.digests) >= 4, (
        f"expected digests for two CSVs and two stderr files, got "
        f"{sorted(report.digests)}"
    )
    for digest in report.digests.values():
        assert len(digest) == 64, f"not a SHA-256 digest: {digest!r}"


# --------------------------------------------------------------------------- #
# Criterion 5 -- Status transitions
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "before,after",
    [("PASS", "FAIL"), ("PASS", "ERROR"), ("FAIL", "PASS"), ("ERROR", "PASS")],
)
def test_every_pass_transition_is_rejected(
    scan: Any, before: str, after: str
) -> None:
    """Criterion 5: this feature touches only the failure and no-client paths.

    A row that passed must still pass. Rejecting all four directions rather than
    only the two that lose a PASS matters: a FAIL becoming a PASS would mean the
    check stopped detecting something, which is worse than a noisy ERROR.

    ``SRA-GUARDDUTY-01`` is deliberately *not* in ``ADMITTED_PASS_TO_FAIL``, so
    this remains the default for every check that has not been declared.
    """
    report = scan(
        [row(Status=before, ActualValue="before")],
        [row(Status=after, ActualValue="after")],
    )

    assert len(report.rejections) == 1
    assert "not admitted unless the check is declared" in rejections(report)[0]


def test_fail_to_error_is_admitted_with_matching_evidence(scan: Any) -> None:
    """Criterion 3: the transition this whole feature is *for*.

    A FAIL becoming an ERROR is the intended correction -- the row used to assert
    the control was absent and now admits the question went unanswered. It is
    admitted only where the log proves the underlying call failed with a
    non-semantic code, because otherwise the check has simply stopped detecting
    something.
    """
    report = scan(
        [row(Status="FAIL", ActualValue="No detector in this Region")],
        [
            row(
                Status="ERROR",
                ActualValue="GetDetector failed: AccessDeniedException: not authorized",
                Remediation="Grant the member role permission to call GetDetector",
            )
        ],
        candidate_entries=[
            (
                "SRA-GUARDDUTY-01",
                [("GetDetector", _REGION, "AccessDeniedException", "not authorized")],
            )
        ],
        dependencies={"SRA-GUARDDUTY-01": {"GetDetector"}},
    )

    assert report.rejections == [], rejections(report)
    assert any(v.admitted and v.kind == "status" for v in report.verdicts)


def test_fail_to_error_is_rejected_without_evidence(scan: Any) -> None:
    """Criterion 3: no log record means the row is unexplained.

    Marked for re-run rather than dismissed, because an absent record can also
    mean the buildspec failed to capture that invocation's stderr -- and
    criterion 9 requires a re-run before an unexplained difference counts.
    """
    report = scan(
        [row(Status="FAIL", ActualValue="No detector in this Region")],
        [row(Status="ERROR", ActualValue="GetDetector failed: AccessDeniedException: x")],
        candidate_entries=[("SRA-GUARDDUTY-01", [])],
        dependencies={"SRA-GUARDDUTY-01": {"GetDetector"}},
    )

    assert len(report.rejections) == 1
    assert "NO aws_call_failed record" in rejections(report)[0]
    assert report.reruns, "an unexplained ERROR must be marked for re-run"


def test_fail_to_error_is_rejected_when_the_evidence_is_semantic(scan: Any) -> None:
    """Criterion 3: a semantic code means AWS reported the control absent.

    That is a FAIL. If the candidate turned it into an ERROR, the discriminator
    table is missing the entry -- the row has become *less* informative, not more.
    """
    report = scan(
        [row(Status="FAIL", ActualValue="No public access block configuration found")],
        [
            row(
                Status="ERROR",
                ActualValue="GetPublicAccessBlock failed: NoSuchPublicAccessBlockConfiguration: none",
            )
        ],
        candidate_entries=[
            (
                "SRA-GUARDDUTY-01",
                [
                    (
                        "GetPublicAccessBlock",
                        _REGION,
                        "NoSuchPublicAccessBlockConfiguration",
                        "none",
                    )
                ],
            )
        ],
        dependencies={"SRA-GUARDDUTY-01": {"GetPublicAccessBlock"}},
    )

    assert len(report.rejections) == 1
    assert "every record in the window is semantic" in rejections(report)[0]


def test_fail_to_error_is_rejected_when_the_operation_is_not_a_dependency(
    scan: Any,
) -> None:
    """Criterion 3: the failure must be on an operation *this check* uses.

    Otherwise an unrelated failure elsewhere in the same check window would
    launder any FAIL-to-ERROR transition.
    """
    report = scan(
        [row(Status="FAIL", ActualValue="No detector")],
        [row(Status="ERROR", ActualValue="GetDetector failed: AccessDeniedException: x")],
        candidate_entries=[
            (
                "SRA-GUARDDUTY-01",
                [("SomeOtherOperation", _REGION, "AccessDeniedException", "x")],
            )
        ],
        dependencies={"SRA-GUARDDUTY-01": {"GetDetector"}},
    )

    assert len(report.rejections) == 1


def test_fail_to_error_requires_the_evidence_to_name_the_same_region(
    scan: Any,
) -> None:
    """A failure in another Region does not explain this Region's row.

    The most likely way a wrong admission would slip through: a scan with four
    Regions logs four failures in one check's window, and matching on operation
    alone would admit a transition in the Region that actually succeeded.
    """
    report = scan(
        [row(Status="FAIL", ActualValue="No detector")],
        [row(Status="ERROR", ActualValue="GetDetector failed: AccessDeniedException: x")],
        candidate_entries=[
            (
                "SRA-GUARDDUTY-01",
                [("GetDetector", "us-west-2", "AccessDeniedException", "x")],
            )
        ],
        dependencies={"SRA-GUARDDUTY-01": {"GetDetector"}},
    )

    assert len(report.rejections) == 1
    assert "NO aws_call_failed record" in rejections(report)[0]


def test_error_to_fail_is_admitted_only_for_the_listed_checks(scan: Any) -> None:
    """Criterion 5: the one declared flip, and nothing else.

    ``SRA-SECURITYINCIDENTRESPONSE-04`` reports "no active memberships" as an
    ERROR today where the project rule makes it a FAIL: AWS answered, and the
    answer is that the control is absent.
    """
    listed = "SRA-SECURITYINCIDENTRESPONSE-04"
    assert listed in _load_gate().ADMITTED_ERROR_TO_FAIL

    admitted_report = scan(
        [row(CheckId=listed, Service="Security Incident Response", Status="ERROR", ActualValue="no memberships")],
        [row(CheckId=listed, Service="Security Incident Response", Status="FAIL", ActualValue="no active memberships found")],
    )
    assert admitted_report.rejections == [], rejections(admitted_report)

    rejected_report = scan(
        [row(Status="ERROR", ActualValue="x")],
        [row(Status="FAIL", ActualValue="y")],
    )
    assert len(rejected_report.rejections) == 1
    assert "not in the Requirement 4.10 list" in rejections(rejected_report)[0]


# --------------------------------------------------------------------------- #
# Criterion 5 -- cell changes with the Status unchanged
# --------------------------------------------------------------------------- #


def test_an_error_row_reformatted_to_the_contract_shape_is_admitted(
    scan: Any,
) -> None:
    """Criterion 5: every existing ERROR row's wording changes in Batch 6.

    Normalising ``Message`` from botocore's ``str(e)`` wrapper to the response's
    own message rewrites the ``ActualValue`` of every ERROR row from ``shield``,
    ``account``, ``auditmanager``, and ``guardduty``. Admitted where the new value
    takes the contract's shape.
    """
    report = scan(
        [
            row(
                Status="ERROR",
                ActualValue="Error: An error occurred (AccessDeniedException) when calling the GetDetector operation: nope",
            )
        ],
        [row(Status="ERROR", ActualValue="GetDetector failed: AccessDeniedException: nope")],
    )

    assert report.rejections == [], rejections(report)


def test_an_error_row_reformatted_to_some_other_shape_is_rejected(
    scan: Any,
) -> None:
    """The admission is conditional on the shape, not on the Status.

    Otherwise "it's an ERROR either way" would admit any rewording, including one
    that dropped the operation and code the row is required to name.
    """
    report = scan(
        [row(Status="ERROR", ActualValue="Error: something")],
        [row(Status="ERROR", ActualValue="Something else entirely")],
    )

    assert len(report.rejections) == 1
    assert "does not match" in rejections(report)[0], (
        f"expected a shape-specific rejection, got {rejections(report)[0]!r}"
    )


def test_a_fail_wording_change_is_admitted_only_when_declared(scan: Any) -> None:
    """Criterion 5: a discriminated FAIL's new wording must be declared per batch.

    A FAIL's ``ActualValue`` is what a reader acts on, so changing it silently is
    how a correct verdict acquires a wrong explanation.
    """
    declared = scan(
        [row(Status="FAIL", ActualValue="Unable to retrieve detector details")],
        [row(Status="FAIL", ActualValue="GuardDuty is not the delegated administrator")],
        wording_changed={"SRA-GUARDDUTY-01"},
    )
    assert declared.rejections == [], rejections(declared)

    undeclared = scan(
        [row(Status="FAIL", ActualValue="Unable to retrieve detector details")],
        [row(Status="FAIL", ActualValue="GuardDuty is not the delegated administrator")],
    )
    assert len(undeclared.rejections) == 1
    assert "not declared in --wording-changed" in rejections(undeclared)[0], (
        f"expected a declaration-specific rejection, got "
        f"{rejections(undeclared)[0]!r}"
    )


def test_a_resource_id_change_alone_is_rejected(scan: Any) -> None:
    """Criterion 5: ``ResourceId`` may move only alongside an admitted change.

    It is the cell the pairing depends on, so a silent change to it would also
    quietly re-pair rows on the next run.
    """
    report = scan(
        [row(ResourceId="guardduty:us-east-1:detector-1")],
        [row(ResourceId="guardduty:us-east-1:detector-2")],
    )

    assert len(report.rejections) == 1
    assert "ResourceId changed with no other admitted change" in rejections(report)[0]


@pytest.mark.parametrize(
    "cell,value",
    [
        ("Severity", "LOW"),
        ("Title", "SRA-GUARDDUTY-01 Something else"),
        ("Description", "A different description."),
        ("ResourceType", "AWS::Other::Thing"),
        ("CheckedValue", "Other Configuration"),
        ("CheckLogic", "Different logic."),
        ("AccountName", "other-account"),
    ],
)
def test_any_other_cell_change_is_rejected(scan: Any, cell: str, value: str) -> None:
    """Criterion 5: only ``Status``, ``ActualValue``, ``Remediation``, and
    ``ResourceId`` may move.

    Everything else comes from ``CheckMeta``, which this feature does not touch --
    so a change here means metadata moved, and ``docs/checks.txt`` would be stale
    too.
    """
    report = scan([row()], [row(**{cell: value})])

    assert len(report.rejections) == 1, (
        f"changing {cell} was not rejected: {rejections(report)}"
    )


# --------------------------------------------------------------------------- #
# Criterion 2 -- multiset pairing
# --------------------------------------------------------------------------- #


def test_a_multi_row_group_pairs_by_resource_id(scan: Any) -> None:
    """Criterion 2: the reason this is a multiset and not a keyed dict.

    ``SRA-WAF-02`` emits one row per load balancer. Three rows share the logical
    key, so a dict keyed on it keeps one and a join produces nine.
    """
    reference = [
        row(CheckId="SRA-WAF-02", Service="WAF", ResourceId=f"alb-{n}", ActualValue=f"acl for alb-{n}")
        for n in (1, 2, 3)
    ]
    candidate = [
        row(CheckId="SRA-WAF-02", Service="WAF", ResourceId=f"alb-{n}", ActualValue=f"acl for alb-{n}")
        for n in (3, 1, 2)  # different file order
    ]

    report = scan(reference, candidate)

    assert report.verdicts == [], (
        f"three rows under one logical key were mis-paired: {rejections(report)}"
    )


def test_a_multi_row_group_with_one_added_row_reports_only_the_addition(
    scan: Any,
) -> None:
    """Pairing must isolate the new row rather than reporting three changes.

    A third load balancer appearing between the two scans is a real possibility in
    a same-window pair, and it must not cascade.
    """
    reference = [
        row(CheckId="SRA-WAF-02", Service="WAF", ResourceId=f"alb-{n}", ActualValue=f"acl for alb-{n}")
        for n in (1, 2)
    ]
    candidate = reference + [
        row(CheckId="SRA-WAF-02", Service="WAF", ResourceId="alb-3", ActualValue="acl for alb-3")
    ]

    report = scan(reference, candidate)

    assert len(report.verdicts) == 1
    assert report.verdicts[0].kind == "added"


def test_pairing_is_deterministic_across_runs_with_blank_resource_ids(
    scan: Any,
) -> None:
    """Criterion 2: the same inputs must produce the same pairing, twice.

    Blank and duplicate ``ResourceId`` values are the case where an
    implementation could fall back on dict or file ordering. The final pass sorts
    on ``(ResourceId, Status, ActualValue, Remediation)`` for exactly this reason.
    """
    reference = [
        row(ResourceId="", Status="FAIL", ActualValue="first"),
        row(ResourceId="", Status="FAIL", ActualValue="second"),
        row(ResourceId="dup", Status="FAIL", ActualValue="third"),
        row(ResourceId="dup", Status="FAIL", ActualValue="fourth"),
    ]
    candidate = [
        row(ResourceId="", Status="FAIL", ActualValue="second"),
        row(ResourceId="dup", Status="FAIL", ActualValue="fourth"),
        row(ResourceId="", Status="FAIL", ActualValue="first"),
        row(ResourceId="dup", Status="FAIL", ActualValue="third"),
    ]

    first = scan(reference, candidate)
    second = scan(reference, candidate)

    assert [(v.kind, v.detail) for v in first.verdicts] == [
        (v.kind, v.detail) for v in second.verdicts
    ]
    assert first.verdicts == [], (
        f"identical rows in a different order were reported as changes: "
        f"{rejections(first)}"
    )


# --------------------------------------------------------------------------- #
# Criterion 6 -- added and removed rows
# --------------------------------------------------------------------------- #


def test_an_added_row_is_admitted_when_the_reference_check_went_synthetic(
    scan: Any,
) -> None:
    """Criterion 6: rows recovered from a generator a transport failure aborted.

    This is the ``SRA-WAF-06`` case from commit ``bdad609``: a transport failure
    escaped the client, unwound ``list(check.execute())``, and discarded three rows
    that had already been yielded. Once the client catches it, those rows come
    back -- and ``rows=synthetic`` on the reference side is the proof.
    """
    report = scan(
        [],
        [row(Status="FAIL", ActualValue="No detector")],
        reference_entries=[("SRA-GUARDDUTY-01!synthetic", [])],
    )

    assert report.rejections == [], rejections(report)
    assert any(v.admitted and v.kind == "added" for v in report.verdicts)


def test_an_added_row_is_rejected_when_the_reference_check_completed(
    scan: Any,
) -> None:
    """A new row with no explanation is a rejection, pending re-run."""
    report = scan(
        [],
        [row(Status="FAIL", ActualValue="No detector")],
        reference_entries=[("SRA-GUARDDUTY-01", [])],
    )

    assert len(report.rejections) == 1
    assert "no synthetic-row condition" in rejections(report)[0]
    assert report.reruns


def test_a_removed_row_is_rejected_when_the_service_serves_the_region(
    scan: Any,
) -> None:
    """Criterion 6: a row must not simply disappear.

    The availability lookup is the *only* admitted reason, and GuardDuty serves
    every commercial Region -- so this row vanishing means the check stopped
    emitting it.
    """
    report = scan([row(Status="FAIL", ActualValue="No detector")], [])

    assert len(report.rejections) == 1
    assert "reference-only row" in rejections(report)[0]


def test_a_removed_row_is_admitted_where_the_service_has_no_endpoint(
    scan: Any, gate: Any
) -> None:
    """Criterion 6: the availability guard's intended effect.

    ``apprunner`` has 11 of 34 commercial Regions and ``us-west-1`` is not one of
    them, so ``SRA-WAF-06`` should emit nothing there once the guard is in place.
    The gate consults the real lookup, which is why this uses the real absent pair.
    """
    report = scan(
        [
            row(
                CheckId="SRA-WAF-06",
                Service="WAF",
                Region="us-west-1",
                Status="ERROR",
                ActualValue="ListServices failed: EndpointConnectionError: unreachable",
            )
        ],
        [],
    )

    admitted = [v for v in report.verdicts if v.admitted and v.kind == "removed"]
    assert admitted, (
        f"the suppressed us-west-1 App Runner row was not admitted: "
        f"{rejections(report)}"
    )


# --------------------------------------------------------------------------- #
# Criterion 7 -- scope and schema
# --------------------------------------------------------------------------- #


def test_an_out_of_scope_difference_is_rejected(scan: Any) -> None:
    """Criterion 7: out-of-scope rows exercise the shared code.

    ``AWSClient.aws_error``, the ``_set`` backstop, and ``is_not_configured`` are shared by
    every service, so a difference in a service this batch did not touch is a
    regression in one of them -- which is precisely what a per-batch gate would
    otherwise miss.
    """
    report = scan(
        [row(CheckId="SRA-MACIE-01", Service="Macie", Status="FAIL", ActualValue="before")],
        [row(CheckId="SRA-MACIE-01", Service="Macie", Status="FAIL", ActualValue="after")],
        services={"GuardDuty"},
    )

    assert report.rejections, "an out-of-scope change was not rejected"
    assert any("not in this batch's scope" in d for d in rejections(report))


def test_an_out_of_scope_row_that_is_identical_is_ignored(scan: Any) -> None:
    """The scope filter must not report rows that did not change."""
    macie = row(CheckId="SRA-MACIE-01", Service="Macie", Status="FAIL", ActualValue="same")
    report = scan([macie, row()], [macie, row()], services={"GuardDuty"})

    assert report.verdicts == [], rejections(report)


def test_a_reordered_column_is_rejected(scan: Any, tmp_path: Path) -> None:
    """Criterion 7: the 16 names and their order are a public contract.

    Two standalone HTML dashboards parse that order. A reordering would render
    them silently wrong rather than broken, which is worse.
    """
    reordered = list(gate_fields_swapped(_load_gate()))
    path = tmp_path / "bad.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=reordered)
        writer.writeheader()
        writer.writerow(row())

    module = _load_gate()
    good = write_csv(tmp_path / "good.csv", [row()], module)
    stderr = tmp_path / "stderr"
    write_stderr(stderr)

    report = module.run_gate(
        reference_csv=good,
        reference_stderr=stderr,
        candidate_csv=path,
        candidate_stderr=stderr,
        services=set(),
        wording_changed=set(),
        package_root=None,
    )

    assert len(report.rejections) == 1
    assert "16 contract columns in order" in rejections(report)[0]


def gate_fields_swapped(gate: Any) -> list[str]:
    """Return the contract columns with two swapped.

    Args:
        gate: The gate module.

    Returns:
        The reordered column names.
    """
    fields = list(gate.FIELDS)
    fields[4], fields[5] = fields[5], fields[4]
    return fields


# --------------------------------------------------------------------------- #
# Criterion 6 -- the masked-FAIL sweep
# --------------------------------------------------------------------------- #


def test_the_masked_fail_sweep_catches_a_fail_with_a_non_semantic_failure(
    scan: Any,
) -> None:
    """Criterion 6: the check that the CSV alone cannot make.

    This is the measured defect: ``SRA-SECURITYLAKE-16`` says "is not set up as
    query access subscriber" while the same invocation's log records
    ``AccessDenied`` on ``ListSubscribers``. The row asserts absence; the log says
    nobody could look. Eight such rows in the 2026-09-12 baseline, and none of them
    detectable from the report.
    """
    report = scan(
        [
            row(
                CheckId="SRA-SECURITYLAKE-16",
                Service="SecurityLake",
                Status="FAIL",
                ActualValue="Audit account is not set up as query access subscriber",
            )
        ],
        [
            row(
                CheckId="SRA-SECURITYLAKE-16",
                Service="SecurityLake",
                Status="FAIL",
                ActualValue="Audit account is not set up as query access subscriber",
            )
        ],
        candidate_entries=[
            (
                "SRA-SECURITYLAKE-16",
                [("ListSubscribers", _REGION, "AccessDeniedException", "not authorized")],
            )
        ],
        dependencies={"SRA-SECURITYLAKE-16": {"ListSubscribers"}},
    )

    assert len(report.rejections) == 1
    assert "masked FAIL" in rejections(report)[0]


def test_the_masked_fail_sweep_admits_a_fail_with_a_semantic_failure(
    scan: Any,
) -> None:
    """A semantic code behind a FAIL is exactly right.

    ``ResourceNotFoundException`` from ``ListSubscribers`` means the data lake does
    not exist in that Region -- AWS answered, and the answer is that the control is
    absent. The sweep must not flag it, or every discriminated FAIL would reject.
    """
    fail_row = row(
        CheckId="SRA-SECURITYLAKE-16",
        Service="SecurityLake",
        Status="FAIL",
        ActualValue="Security Lake is not enabled in this Region",
    )
    report = scan(
        [fail_row],
        [fail_row],
        candidate_entries=[
            (
                "SRA-SECURITYLAKE-16",
                [("ListSubscribers", _REGION, "ResourceNotFoundException", "no lake")],
            )
        ],
        dependencies={"SRA-SECURITYLAKE-16": {"ListSubscribers"}},
    )

    assert report.rejections == [], rejections(report)


def test_the_masked_fail_sweep_only_applies_to_the_named_checks(scan: Any) -> None:
    """The sweep is scoped to Requirement 4.9's list.

    A FAIL elsewhere with an unrelated failure in its window is a different
    question, judged by the pairing rules.
    """
    fail_row = row(Status="FAIL", ActualValue="No detector in this Region")
    report = scan(
        [fail_row],
        [fail_row],
        candidate_entries=[
            (
                "SRA-GUARDDUTY-01",
                [("GetDetector", _REGION, "AccessDeniedException", "denied")],
            )
        ],
        dependencies={"SRA-GUARDDUTY-01": {"GetDetector"}},
    )

    assert not any(v.kind == "masked_fail" for v in report.verdicts)


# --------------------------------------------------------------------------- #
# Criterion 8 -- totals
# --------------------------------------------------------------------------- #


def test_an_increase_in_confessing_fails_is_rejected(scan: Any) -> None:
    """Criterion 8: the count must be non-increasing per batch.

    Necessary and not sufficient, and worth stating: it detects the rows whose
    wording admits uncertainty and none of the masked FAILs. The sweep above is
    the other half.
    """
    report = scan(
        [row(Status="FAIL", ActualValue="No detector in this Region")],
        [row(Status="FAIL", ActualValue="Unable to retrieve detector details")],
        wording_changed={"SRA-GUARDDUTY-01"},
    )

    assert any("confessing FAIL rows increased" in d for d in rejections(report))


def test_a_synthetic_row_in_the_candidate_scan_is_rejected(scan: Any) -> None:
    """Requirement 2.5: after the sweep a synthetic row means a defect.

    It also means the check lost every row it had already yielded for its other
    Regions, so one synthetic row is worth more than one row of noise.
    """
    report = scan(
        [row()],
        [
            row(
                Status="ERROR",
                ActualValue="Error running SRA-GUARDDUTY-01: AttributeError: 'NoneType' object has no attribute 'get'",
            )
        ],
    )

    assert any("synthetic ERROR row" in d for d in rejections(report))


def test_the_totals_are_reported_even_when_nothing_is_rejected(scan: Any) -> None:
    """The gate notes carry the counts a reviewer compares against the baseline."""
    report = scan([row()], [row()])

    for expected in (
        "candidate_rows",
        "candidate_confessing_fail",
        "candidate_check_ids",
        "candidate_synthetic_rows",
        "candidate_pass",
        "candidate_fail",
        "candidate_error",
    ):
        assert expected in report.totals, f"{expected} missing from the totals"


# --------------------------------------------------------------------------- #
# Criterion 3 -- log parsing
# --------------------------------------------------------------------------- #


def test_a_message_with_an_embedded_newline_parses(gate: Any, tmp_path: Path) -> None:
    """The reason ``message`` is JSON-encoded and last.

    An AWS message containing a newline would otherwise split the record across
    two lines, and this parser would read the tail as a separate malformed record --
    dropping the evidence that admits a FAIL-to-ERROR transition.
    """
    directory = tmp_path / "stderr"
    write_stderr(
        directory,
        entries=[
            (
                "SRA-GUARDDUTY-01",
                [
                    (
                        "GetDetector",
                        _REGION,
                        "AccessDeniedException",
                        'line one\nline two with "quotes"\r\nand a CRLF',
                    )
                ],
            )
        ],
    )

    evidence = gate.load_evidence(directory)
    invocation = evidence[(_ACCOUNT, _TYPE)]
    failures = invocation.windows["SRA-GUARDDUTY-01"]

    assert len(failures) == 1
    assert failures[0].message == 'line one\nline two with "quotes"\r\nand a CRLF'


def test_failures_are_attributed_to_the_check_whose_marker_follows_them(
    gate: Any, tmp_path: Path
) -> None:
    """Criterion 3: positional attribution, which single-threading makes sound.

    The record ordering is the whole mechanism. Two checks, one failure each, and
    each failure must land in its own window -- if attribution slipped by one, every
    FAIL-to-ERROR admission would be evidenced by the wrong check's failure.
    """
    directory = tmp_path / "stderr"
    write_stderr(
        directory,
        entries=[
            ("SRA-GUARDDUTY-01", [("GetDetector", _REGION, "CodeOne", "first")]),
            ("SRA-GUARDDUTY-02", [("ListDetectors", _REGION, "CodeTwo", "second")]),
        ],
    )

    invocation = gate.load_evidence(directory)[(_ACCOUNT, _TYPE)]

    assert [f.code for f in invocation.windows["SRA-GUARDDUTY-01"]] == ["CodeOne"]
    assert [f.code for f in invocation.windows["SRA-GUARDDUTY-02"]] == ["CodeTwo"]
    assert invocation.order == ["SRA-GUARDDUTY-01", "SRA-GUARDDUTY-02"]


def test_a_failure_after_the_last_marker_is_kept_as_an_orphan(
    gate: Any, tmp_path: Path
) -> None:
    """A record with no following marker is not silently dropped.

    It means the scan ended mid-check -- a crash, or a truncated artefact -- and
    that is worth knowing rather than losing.
    """
    directory = tmp_path / "stderr"
    path = directory
    path.mkdir(parents=True, exist_ok=True)
    (path / f"{_ACCOUNT}-{_TYPE}.log").write_text(
        "check_done check_id=SRA-GUARDDUTY-01 rows=1\n"
        "aws_call_failed operation=GetDetector region=us-east-1 code=Late "
        'message="after the last marker"\n',
        encoding="utf-8",
    )

    invocation = gate.load_evidence(directory)[(_ACCOUNT, _TYPE)]

    assert [f.code for f in invocation.orphans] == ["Late"]


def test_a_synthetic_marker_is_recorded(gate: Any, tmp_path: Path) -> None:
    """``rows=synthetic`` is what admits a recovered row on the candidate side."""
    directory = tmp_path / "stderr"
    write_stderr(directory, entries=[("SRA-GUARDDUTY-01!synthetic", [])])

    invocation = gate.load_evidence(directory)[(_ACCOUNT, _TYPE)]

    assert invocation.rows["SRA-GUARDDUTY-01"] == "synthetic"


def test_a_missing_stderr_directory_is_a_usage_error(gate: Any, tmp_path: Path) -> None:
    """Silently proceeding with no evidence would admit or reject arbitrarily."""
    with pytest.raises(SystemExit):
        gate.load_evidence(tmp_path / "does-not-exist")


# --------------------------------------------------------------------------- #
# The semantic-code table
# --------------------------------------------------------------------------- #


def test_the_gate_keeps_its_own_semantic_code_table(gate: Any) -> None:
    """The gate must not trust the candidate tree's discriminator tables.

    If it imported them, a *wrong* table entry would admit exactly the rows that
    entry caused -- the code under test would be grading its own answer. The local
    copy is deliberately conservative and deliberately duplicated.
    """
    assert gate.is_semantic("DescribeOrganization", "AWSOrganizationsNotInUseException")
    assert gate.is_semantic("GetPublicAccessBlock", "NoSuchPublicAccessBlockConfiguration")
    # The operation dimension, in the gate too.
    assert not gate.is_semantic("ListOrganizationAdminAccounts", "BadRequestException")
    assert gate.is_semantic("DescribeOrganizationConfiguration", "BadRequestException")


@pytest.mark.parametrize(
    "code",
    ["EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError", "NoClient",
     "AccessDenied", "ThrottlingException", "SomeFutureException"],
)
def test_no_transport_or_unknown_code_is_semantic(gate: Any, code: str) -> None:
    """These can never establish absence, for any operation.

    Which is what makes them the codes that *admit* a FAIL-to-ERROR transition and
    *reject* a masked FAIL.
    """
    for operation in list(gate.SEMANTIC_CODES) + ["AnyOperation"]:
        assert not gate.is_semantic(operation, code), (
            f"{operation}/{code} was classified as semantic"
        )


# --------------------------------------------------------------------------- #
# Dependency derivation
# --------------------------------------------------------------------------- #


def test_dependencies_are_derived_from_the_real_tree(gate: Any) -> None:
    """Criterion 3: the check-to-operation map is derived, not maintained.

    A hand-maintained map would be wrong within a batch, and the gate would then
    admit or reject on a stale dependency set.
    """
    package_root = Path(sraverify.__file__).resolve().parent
    dependencies = gate.derive_dependencies(package_root)

    assert len(dependencies) >= 150, (
        f"only {len(dependencies)} checks got a dependency set; the catalog holds 158"
    )
    assert "SRA-GUARDDUTY-01" in dependencies
    # GuardDuty's detector lookup, however it is currently spelled.
    guardduty = dependencies["SRA-GUARDDUTY-01"]
    assert guardduty, "SRA-GUARDDUTY-01 has an empty dependency set"


def test_an_absent_package_root_yields_no_dependencies(gate: Any) -> None:
    """The gate runs against artefacts, possibly without the package present.

    With no dependency information the operation filter is skipped rather than
    applied wrongly, which keeps the gate usable on an archived artefact pair.
    """
    assert gate.derive_dependencies(Path("/nonexistent")) == {}


# --------------------------------------------------------------------------- #
# normalise_volatile -- the two reproducibly-volatile cell forms
#
# Added after the Batch 1 gate rejected 20 rows across CloudTrail, Config, Macie,
# and Security Hub. None was in the batch's scope and none was a regression: four
# carried a live AWS delivery timestamp and eight an account list built by joining
# a set. Both vary between two scans of the same tree, so the gate was measuring
# the organization rather than the code.
#
# The risk of a normalisation is that it hides a real difference, so each test
# below pairs an "equal despite" case with the "still differs" case that bounds
# it.
# --------------------------------------------------------------------------- #


def test_two_scans_differing_only_in_a_delivery_timestamp_compare_equal(
    gate: Any,
) -> None:
    """CloudTrail's ``LatestDeliveryTime`` advances between the two scans.

    ``SRA-CLOUDTRAIL-08``, ``-09``, ``-10``, and ``SRA-CONFIG-03`` interpolate an
    AWS-supplied timestamp into ``ActualValue``. Two scans an hour apart differ by
    construction, and no code change is involved.
    """
    before = (
        "Organization trail 'aws-controltower-BaselineCloudTrail' is publishing "
        "logs to S3 bucket 'aws-controltower-logs-555566667777-us-east-1', "
        "latest delivery time: 2026-09-15 14:52:28.453000-05:00"
    )
    after = before.replace(
        "2026-09-15 14:52:28.453000-05:00", "2026-09-15 16:30:57.994000-05:00"
    )

    assert before != after
    assert gate.normalise_volatile(before) == gate.normalise_volatile(after)


def test_a_change_around_the_timestamp_is_still_visible(gate: Any) -> None:
    """The bound on the timestamp rule.

    Only the timestamp is neutralised. A regression that dropped the bucket name,
    or pointed the trail at a different bucket, changes the surrounding text and
    must still be reported.
    """
    before = "publishing logs to S3 bucket 'a-logs', latest delivery time: 2026-09-15 14:52:28.453000-05:00"
    after = "publishing logs to S3 bucket 'b-logs', latest delivery time: 2026-09-15 16:30:57.994000-05:00"

    assert gate.normalise_volatile(before) != gate.normalise_volatile(after)


@pytest.mark.parametrize(
    "stamp",
    [
        "2026-09-15 14:52:28.453000-05:00",
        "2026-09-15T14:52:28.453000-05:00",
        "2026-09-15 14:52:28-05:00",
        "2026-09-15T14:52:28Z",
        "2026-09-15 14:52:28",
    ],
    ids=["space-micros-offset", "T-micros-offset", "space-offset", "T-Z", "naive"],
)
def test_every_timestamp_spelling_the_checks_emit_is_recognized(
    gate: Any, stamp: str
) -> None:
    """The pattern covers the shapes ``str(datetime)`` produces.

    boto3 hands back timezone-aware ``datetime`` objects and the checks interpolate
    them with ``str()`` or an f-string, so the separator is a space and the offset
    is present. The ISO ``T`` and ``Z`` forms are accepted too rather than
    discovering in Batch 5 that one check formats its own.
    """
    assert gate.normalise_volatile(f"at {stamp} ok") == "at <TS> ok"


def test_an_account_list_in_a_different_order_compares_equal(gate: Any) -> None:
    """``SRA-MACIE-07`` and ``SRA-SECURITYHUB-08`` join a ``set``.

    Set iteration order varies per process, so the same finding renders in a
    different order each scan. This is a known defect the migration deliberately
    does not touch -- it is recorded in ``creating_checks_best_practices.md`` --
    and the gate must not report it as a difference in every batch from here on.
    """
    before = "Missing accounts: 333344445555, 555566667777, 222233334444"
    after = "Missing accounts: 222233334444, 333344445555, 555566667777"

    assert before != after
    assert gate.normalise_volatile(before) == gate.normalise_volatile(after)


def test_a_changed_account_membership_is_still_visible(gate: Any) -> None:
    """The bound on the ordering rule, and the distinction that matters.

    Ordering is a defect in how the row is *rendered*. Membership is the finding
    itself. An account that appears, disappears, or is substituted must still be
    reported, because that is a real change in what the scan found.
    """
    before = "Missing accounts: 333344445555, 555566667777, 222233334444"
    gained = "Missing accounts: 333344445555, 555566667777, 222233334444, 111122223333"
    lost = "Missing accounts: 333344445555, 555566667777"
    swapped = "Missing accounts: 333344445555, 555566667777, 999988887777"

    for other in (gained, lost, swapped):
        assert gate.normalise_volatile(before) != gate.normalise_volatile(other), (
            f"a membership change was normalised away: {other!r}"
        )


def test_a_single_account_id_is_left_alone(gate: Any) -> None:
    """One account ID is an identity, not a list, and its position is meaningful.

    Reordering cannot apply to a single value, so the rule is off below two. This
    keeps the common case -- a ``ResourceId`` or a message naming one account --
    compared as written.
    """
    assert gate.normalise_volatile("account 123456789012 is not a member") == (
        "account 123456789012 is not a member"
    )


def test_two_account_lists_with_the_same_ids_in_different_text_still_differ(
    gate: Any,
) -> None:
    """The ordering rule does not collapse different sentences.

    The surrounding text is compared with the IDs tokenised, so a verdict flip
    that kept the same account list is still a difference.
    """
    before = "The following accounts are not members: 333344445555, 555566667777"
    after = "The following accounts are now members: 333344445555, 555566667777"

    assert gate.normalise_volatile(before) != gate.normalise_volatile(after)


def test_normalisation_is_idempotent(gate: Any) -> None:
    """Applying it twice changes nothing.

    ``row_tuple`` is called on both sides of every comparison and on leftover
    pairing, so a normalisation that drifted on a second application would make
    pairing depend on how many times a row had been considered.

    This test found a real defect on first run: the account multiset was appended
    as raw IDs, which the second application re-tokenised and re-appended. It is
    why the suffix is a digest.
    """
    value = (
        "Missing accounts: 333344445555, 555566667777 at "
        "2026-09-15 14:52:28.453000-05:00"
    )
    once = gate.normalise_volatile(value)

    assert gate.normalise_volatile(once) == once
    assert not re.search(r"\b\d{12}\b", once), (
        f"the suffix leaks raw account IDs, so a second application would "
        f"re-tokenise them: {once!r}"
    )


def test_an_empty_cell_normalises_to_itself(gate: Any) -> None:
    """Total over its input.

    ``ResourceId`` is empty on most rows and ``Remediation`` is empty on every
    PASS, so the common input to this function is the empty string.
    """
    assert gate.normalise_volatile("") == ""


def test_row_tuple_pairs_rows_that_differ_only_volatilely(gate: Any) -> None:
    """The integration point: ``row_tuple`` is what the comparison uses.

    Testing ``normalise_volatile`` alone would not catch it being applied to only
    one side, or to the key fields but not the value fields.
    """
    before = row(
        CheckId="SRA-CLOUDTRAIL-08",
        Status="PASS",
        ActualValue="delivered at 2026-09-15 14:52:28.453000-05:00",
    )
    after = row(
        CheckId="SRA-CLOUDTRAIL-08",
        Status="PASS",
        ActualValue="delivered at 2026-09-15 16:30:57.994000-05:00",
    )

    assert gate.row_tuple(before) == gate.row_tuple(after)


def test_row_tuple_still_separates_a_status_change(gate: Any) -> None:
    """The bound on the integration: normalisation never touches ``Status``.

    A FAIL becoming a PASS is the one transition the gate never admits, so it must
    not be reachable through a normalisation.
    """
    before = row(CheckId="SRA-CLOUDTRAIL-08", Status="FAIL", ActualValue="x")
    after = row(CheckId="SRA-CLOUDTRAIL-08", Status="PASS", ActualValue="x")

    assert gate.row_tuple(before) != gate.row_tuple(after)


def test_an_out_of_scope_row_differing_only_volatilely_is_not_rejected(
    scan: Any,
) -> None:
    """Criterion 7 end to end, against the case that produced this function.

    The Batch 1 gate rejected exactly this shape 20 times. Criterion 7 is right to
    be strict about out-of-scope rows -- they are what proves the shared code did
    not regress -- but a live timestamp is not evidence of anything.
    """
    report = scan(
        [
            row(
                CheckId="SRA-CLOUDTRAIL-08",
                Service="CloudTrail",
                Status="PASS",
                ActualValue="delivered at 2026-09-15 14:52:28.453000-05:00",
            )
        ],
        [
            row(
                CheckId="SRA-CLOUDTRAIL-08",
                Service="CloudTrail",
                Status="PASS",
                ActualValue="delivered at 2026-09-15 16:30:57.994000-05:00",
            )
        ],
        services={"GuardDuty"},
    )

    assert report.rejections == [], (
        f"a volatile out-of-scope difference was rejected: {rejections(report)}"
    )


# --------------------------------------------------------------------------- #
# Criterion 5: a declared FAIL wording change may move Remediation with it
#
# Added in Batch 2. Batch 1's seven declared checks each kept their remediation
# text byte-identical, so ActualValue moved alone and the narrower rule sufficed.
# Batch 2 is where the two come apart for every declared check, because a
# discriminated FAIL states a different *reason* and the advice follows it.
# --------------------------------------------------------------------------- #


def test_a_declared_fail_wording_change_may_move_remediation(scan: Any) -> None:
    """The reason and the advice change together, and that has to be admissible.

    ``SRA-MACIE-09`` is the live example: it stopped saying "Failed to retrieve
    Macie members" and started saying "Macie is not enabled in us-east-1". Keeping
    the old remediation ("ensure you have permissions to call ListMembers") would
    have meant shipping advice that describes a cause the row no longer claims,
    purely to satisfy the gate.
    """
    report = scan(
        [
            row(
                Status="FAIL",
                ActualValue="Failed to retrieve Macie members",
                Remediation="Ensure you have permissions to call ListMembers",
            )
        ],
        [
            row(
                Status="FAIL",
                ActualValue="Macie is not enabled in us-east-1",
                Remediation="Enable Macie in this Region",
            )
        ],
        wording_changed={"SRA-GUARDDUTY-01"},
    )

    assert report.rejections == [], (
        f"a declared FAIL wording change was rejected for moving Remediation: "
        f"{rejections(report)}"
    )


def test_an_undeclared_fail_wording_change_is_still_rejected_with_remediation(
    scan: Any,
) -> None:
    """The bound: the declaration is what admits it, not the field set.

    Without this, widening the admissible field set would have quietly made every
    FAIL rewording admissible as long as it dragged Remediation along.
    """
    report = scan(
        [row(Status="FAIL", ActualValue="before", Remediation="old advice")],
        [row(Status="FAIL", ActualValue="after", Remediation="new advice")],
    )

    assert len(report.rejections) == 1
    assert "not declared in --wording-changed" in rejections(report)[0]


def test_a_declared_check_may_not_change_a_field_outside_the_trio(scan: Any) -> None:
    """``CheckedValue`` is not covered by a wording declaration.

    It names the control being tested, not the outcome, so it should be identical
    either side of a migration that only changes how a failure is reported. This
    caught three real defects in Batch 2: the ``SRA-SECURITYHUB-04``, ``-10``, and
    ``-11`` guards had invented new ``checked_value`` text rather than reusing each
    check's existing string.
    """
    report = scan(
        [row(Status="FAIL", ActualValue="before", CheckedValue="autoEnable: true")],
        [
            row(
                Status="FAIL",
                ActualValue="after",
                CheckedValue="AutoEnable is true or central config",
            )
        ],
        wording_changed={"SRA-GUARDDUTY-01"},
    )

    assert len(report.rejections) == 1, (
        f"a CheckedValue change was admitted under a wording declaration: "
        f"{rejections(report)}"
    )
    assert "CheckedValue" in rejections(report)[0]


def test_a_declared_check_may_not_change_status(scan: Any) -> None:
    """A wording declaration never admits a verdict change.

    The declaration says "this check's FAIL text changed". It must not become a
    way to wave through FAIL becoming PASS, which is the transition criterion 5
    exists to forbid.
    """
    report = scan(
        [row(Status="FAIL", ActualValue="before")],
        [row(Status="PASS", ActualValue="after")],
        wording_changed={"SRA-GUARDDUTY-01"},
    )

    assert len(report.rejections) == 1
    assert "PASS" in rejections(report)[0]


# --------------------------------------------------------------------------- #
# ADMITTED_PASS_TO_FAIL -- correcting a fabricated PASS
#
# Added in Batch 2, and it amends the design's Non-Goal 2. That non-goal assumed
# erasure could only manufacture false negatives; it also manufactures false
# PASSes wherever a check reads an accessor's emptiness as "nothing here, so
# nothing wrong". SRA-SECURITYHUB-09 reported PASS for two Regions with no hub at
# all. A false PASS is worse than a false FAIL because nobody investigates a pass.
# --------------------------------------------------------------------------- #


def _declared(gate: Any, check_id: str) -> Any:
    """Temporarily add ``check_id`` to ``ADMITTED_PASS_TO_FAIL``.

    Args:
        gate: The gate module.
        check_id: The check to declare.

    Returns:
        A context manager restoring the original frozenset.
    """
    import contextlib

    @contextlib.contextmanager
    def _cm() -> Any:
        original = gate.ADMITTED_PASS_TO_FAIL
        gate.ADMITTED_PASS_TO_FAIL = frozenset(original | {check_id})
        try:
            yield
        finally:
            gate.ADMITTED_PASS_TO_FAIL = original

    return _cm()


def test_a_declared_pass_to_fail_is_admitted_with_semantic_evidence(
    scan: Any, gate: Any
) -> None:
    """The SRA-SECURITYHUB-09 case: a PASS that was never evaluated becomes a FAIL.

    Admitted only with a **semantic** record. That is stricter than the
    FAIL-to-ERROR rule, which wants a *non*-semantic one, and the asymmetry is the
    point: turning a PASS into a FAIL asserts that AWS established the control is
    absent, so the evidence has to be AWS saying exactly that. A permission denial
    would justify an ERROR, never a FAIL.
    """
    with _declared(gate, "SRA-GUARDDUTY-01"):
        report = scan(
            [row(Status="PASS", ActualValue="No members found")],
            [row(Status="FAIL", ActualValue="Security Hub is not enabled")],
            candidate_entries=[
                (
                    "SRA-GUARDDUTY-01",
                    [("ListMembers", _REGION, "BadRequestException", "no such resource found.")],
                )
            ],
            dependencies={"SRA-GUARDDUTY-01": {"ListMembers"}},
        )

    assert report.rejections == [], (
        f"a declared, evidenced PASS correction was rejected: {rejections(report)}"
    )


def test_a_declared_pass_to_fail_without_semantic_evidence_is_rejected(
    scan: Any, gate: Any
) -> None:
    """The bound. A declaration is not a blanket pass for the check.

    If the only record in the window is a throttle, the scan did not
    establish that the control is absent, so FAIL is the wrong verdict and the row
    is a regression -- exactly the mistake this whole feature exists to stop, just
    pointing the other way.
    """
    with _declared(gate, "SRA-GUARDDUTY-01"):
        report = scan(
            [row(Status="PASS", ActualValue="No members found")],
            [row(Status="FAIL", ActualValue="Security Hub is not enabled")],
            candidate_entries=[
                (
                    "SRA-GUARDDUTY-01",
                    [("ListMembers", _REGION, "ThrottlingException", "rate exceeded")],
                )
            ],
            dependencies={"SRA-GUARDDUTY-01": {"ListMembers"}},
        )

    assert len(report.rejections) == 1
    assert "no **semantic** aws_call_failed record" in rejections(report)[0]


def test_a_declared_check_may_not_turn_a_pass_into_an_error(
    scan: Any, gate: Any
) -> None:
    """The declaration covers PASS-to-FAIL only.

    A PASS becoming an ERROR means the control still cannot be evaluated, so there
    was nothing to correct -- the row went from a confident wrong answer to no
    answer, and that is a regression in coverage worth reporting.
    """
    with _declared(gate, "SRA-GUARDDUTY-01"):
        report = scan(
            [row(Status="PASS", ActualValue="No members found")],
            [row(Status="ERROR", ActualValue="ListMembers failed: X: y")],
        )

    assert len(report.rejections) == 1
    assert "not admitted unless the check is declared" in rejections(report)[0]


def test_a_declared_check_may_not_turn_a_fail_into_a_pass(scan: Any, gate: Any) -> None:
    """And never in the direction that loses a finding.

    ``ADMITTED_PASS_TO_FAIL`` is named for its direction. A FAIL becoming a PASS
    means the check stopped detecting something, which no declaration in this
    feature should be able to wave through.
    """
    with _declared(gate, "SRA-GUARDDUTY-01"):
        report = scan(
            [row(Status="FAIL", ActualValue="something is wrong")],
            [row(Status="PASS", ActualValue="all good")],
        )

    assert len(report.rejections) == 1
    assert "not admitted unless the check is declared" in rejections(report)[0]


def test_securityhub_09_is_the_only_declared_pass_correction(gate: Any) -> None:
    """The list stays short and reviewed.

    22 sites across 8 services test an accessor's return for emptiness and yield
    PASS, so later batches will add to this. Pinning it here means each addition
    shows up in a diff beside its evidence rather than accumulating quietly.
    """
    assert gate.ADMITTED_PASS_TO_FAIL == frozenset({"SRA-SECURITYHUB-09"}), (
        f"ADMITTED_PASS_TO_FAIL is now {sorted(gate.ADMITTED_PASS_TO_FAIL)}; add "
        f"the new entry to this test with a note on which batch declared it"
    )
