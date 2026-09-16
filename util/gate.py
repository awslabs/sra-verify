#!/usr/bin/env python3
"""
The acceptance gate for the client error contract migration.

Compares two full-organization scans -- a **reference** tree and a **candidate**
tree, run back to back -- and admits or rejects the candidate. Reconciles every
changed row against the scanner's own structured log records, because the CSV
alone cannot distinguish a corrected row from a regression.

Usage::

    python util/gate.py \\
        --reference-csv  gate/batch-1/reference/consolidated.csv \\
        --reference-stderr gate/batch-1/reference/stderr/ \\
        --candidate-csv  gate/batch-1/candidate/consolidated.csv \\
        --candidate-stderr gate/batch-1/candidate/stderr/ \\
        --services GuardDuty \\
        --notes .tmp/gate/batch-1.md

Exits ``0`` when every difference is admitted, ``1`` on any rejection, ``2`` on a
usage or input error.

Why it is built this way
------------------------

**Two scans, not a comparison against the 2026-09-12 baseline.** Any resource
that changed in the organization between then and a gate run would show up as a
verdict change with no code cause. Running both trees in the same window narrows
the drift window from weeks to minutes. It does not close it, so an unexplained
difference is reported for re-run, never waved through as noise. The baseline
scan keeps one job: supplying the aggregate counts in criteria 8.

**Multisets, not a keyed dict.** ``SRA-WAF-02`` emits one row per load balancer,
``SRA-SHIELD-03`` one per protection, ``SRA-IAM-01`` one per IAM user. Under the
logical key ``(AccountId, AccountType, Region, CheckId)`` those are several rows:
a dict keyed that way silently overwrites them, and a join cross-multiplies them.

**Structured logs, not free text.** The buildspec fans accounts out with
``parallel -j5``, so one CloudWatch stream interleaves five processes -- in the
archived baseline export a progress bar and a diagnostic share a single line with
no boundary between them. Two things fix it at the source: each invocation's
stderr goes to its own file, and the scanner emits two machine-readable records,
``aws_call_failed`` from the client guard and ``check_done`` from the
orchestrator. Execution within one invocation is single-threaded, so every
failure logged since the previous marker belongs to the check whose marker comes
next.

**Dependencies derived, not maintained.** Which operations a check depends on is
computed by AST: check module -> accessor names -> base accessor -> client method
-> boto3 method name, PascalCased into its AWS operation. A hand-maintained map
would be wrong within a batch.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Set, Tuple

# --------------------------------------------------------------------------- #
# The CSV contract
# --------------------------------------------------------------------------- #

#: The 16 columns, in order. Duplicated from ``Finding.FIELDS`` on purpose: this
#: script is run against artefacts produced by *another* commit's code, so
#: importing the package would check the wrong tree's idea of the schema. Criterion
#: 7 rejects any change to these names or their order.
FIELDS: Tuple[str, ...] = (
    "AccountId",
    "AccountName",
    "Region",
    "CheckId",
    "Status",
    "Severity",
    "Title",
    "Description",
    "ResourceId",
    "ResourceType",
    "CheckedValue",
    "ActualValue",
    "Remediation",
    "Service",
    "CheckLogic",
    "AccountType",
)

#: The logical key rows are grouped under. Several rows may share it.
LOGICAL_KEY: Tuple[str, ...] = ("AccountId", "AccountType", "Region", "CheckId")

#: Requirement 4.7's confessing patterns, for the criterion 8 total.
CONFESSING_RE = re.compile(
    r"failed to (retrieve|get|fetch|access|determine|check)"
    r"|unable to (retrieve|get|fetch|access|determine|check)"
    r"|could not (be )?(determine|determined|retrieve|retrieved|access|accessed)"
    r"|error (retrieving|getting|fetching|checking|accessing|determining)",
    re.IGNORECASE,
)

#: The shape an ERROR row's ``ActualValue`` takes after migration.
ERROR_VALUE_RE = re.compile(r"^\S+ failed: \S+: ")

#: The orchestrator's synthetic-row prefix.
SYNTHETIC_PREFIX = "Error running SRA-"

#: ``aws_call_failed operation=... region=... code=... message=<json>``
AWS_CALL_FAILED_RE = re.compile(
    r"aws_call_failed operation=(?P<operation>\S+) region=(?P<region>\S+) "
    r"code=(?P<code>\S+) message=(?P<message>.*)$"
)

#: ``check_done check_id=... rows=...``
CHECK_DONE_RE = re.compile(
    r"check_done check_id=(?P<check_id>\S+) rows=(?P<rows>\S+)"
)

#: Requirement 4.10's intended ERROR-to-FAIL flips, by check ID. Any other
#: ERROR-to-FAIL transition rejects. Kept here rather than passed on the command
#: line so the list is reviewed in a diff.
ADMITTED_ERROR_TO_FAIL: frozenset[str] = frozenset(
    {
        # "no active Security Incident Response memberships found" is an answer
        # from AWS, not an inability to determine, so the project rule makes it a
        # FAIL. Batch 6.
        "SRA-SECURITYINCIDENTRESPONSE-04",
    }
)

#: Checks whose **PASS** becomes a FAIL because the PASS was fabricated: an
#: erased client error reached a branch written for an empty answer.
#:
#: This amends the design's Non-Goal 2 ("Any PASS verdict change"). That non-goal
#: was written on the assumption that erasure could only manufacture false
#: *negatives* -- the 120 confessing FAIL rows the feature was sized against, all
#: of them FAILs. It cannot: where a check reads an accessor's emptiness as "there
#: is nothing here, so nothing is wrong", the same erased error manufactures a
#: false **PASS**, and a false PASS is strictly worse because nobody investigates
#: a pass. 22 sites across 8 services test an accessor's return for emptiness and
#: yield PASS, so this is a class rather than an accident.
#:
#: Declared here rather than on the command line, exactly as
#: :data:`ADMITTED_ERROR_TO_FAIL` is, so each entry is reviewed in a diff and
#: carries its evidence. Any PASS transition **not** listed here still rejects,
#: and a listed one is still checked for supporting evidence in the log -- the
#: declaration says "this check's PASS was unsound", not "trust this row".
ADMITTED_PASS_TO_FAIL: frozenset[str] = frozenset(
    {
        # Reported PASS "No Security Hub member accounts found in region X" for
        # us-east-2 and us-west-1, where Security Hub is not enabled at all.
        # SecurityHubClient.list_members returned [] on any ClientError and
        # `if not securityhub_members: yield self.passed(...)` read that as an
        # empty answer. Verified 2026-09-15 in a controlled account: DescribeHub
        # returns InvalidAccessException in both Regions, and ListMembers returns
        # BadRequestException "no such resource found" -- now declared semantic in
        # SecurityHubCheck.NOT_CONFIGURED_ERRORS, so the row is a FAIL. Batch 2.
        "SRA-SECURITYHUB-09",
    }
)

#: Requirement 4.9's masked-FAIL sites: checks whose confident FAIL wording could
#: be sitting on an erased error. Criterion 6's sweep applies to these.
MASKED_FAIL_CHECKS: frozenset[str] = frozenset(
    {
        "SRA-S3-01",
        "SRA-S3-02",
        "SRA-S3-03",
        "SRA-S3-04",
        "SRA-INSPECTOR-01",
        "SRA-INSPECTOR-02",
        "SRA-INSPECTOR-03",
        "SRA-INSPECTOR-04",
        "SRA-ACCESSANALYZER-01",
        "SRA-SECURITYLAKE-16",
        "SRA-SECURITYLAKE-17",
    }
)

#: Error codes that mean "the control is not configured" for the operation that
#: produced them, used by the gate to decide whether an ``aws_call_failed`` record
#: is *semantic*. Deliberately a local, conservative copy rather than an import:
#: the gate must judge the candidate tree's rows without trusting the candidate
#: tree's own table, or a wrong table entry would admit the very rows it caused.
SEMANTIC_CODES: Dict[str, frozenset[str]] = {
    "DescribeOrganization": frozenset({"AWSOrganizationsNotInUseException"}),
    "ListPolicies": frozenset({"PolicyTypeNotEnabledException"}),
    "DescribeOrganizationConfiguration": frozenset({"BadRequestException"}),
    "GetClassificationExportConfiguration": frozenset(
        {"ResourceNotFoundException", "AccessDeniedException"}
    ),
    "GetFindingsPublicationConfiguration": frozenset(
        {"ResourceNotFoundException", "AccessDeniedException"}
    ),
    "GetAdministratorAccount": frozenset(
        {"ResourceNotFoundException", "AccessDeniedException"}
    ),
    # Two services reach ListMembers, and each contributes a semantic code. This
    # table is keyed by operation alone -- deliberately coarser than the per-service
    # NOT_CONFIGURED_ERRORS tables, because it is an independent sanity check on
    # the candidate rather than a second copy of the classifier -- so the set is
    # the union. macie2 answers AccessDeniedException "Macie is not enabled";
    # securityhub answers BadRequestException "no such resource found" when no hub
    # exists (Batch 2, SRA-SECURITYHUB-09's fabricated PASS).
    "ListMembers": frozenset(
        {
            "ResourceNotFoundException",
            "AccessDeniedException",
            "BadRequestException",
        }
    ),
    "GetEnabledStandards": frozenset({"InvalidAccessException"}),
    "ListEnabledProductsForImport": frozenset({"InvalidAccessException"}),
    "GetSubscriptionState": frozenset({"ResourceNotFoundException"}),
    "DescribeSubscription": frozenset({"ResourceNotFoundException"}),
    "ListProtections": frozenset({"ResourceNotFoundException"}),
    "DescribeDRTAccess": frozenset({"ResourceNotFoundException"}),
    "GetFunction": frozenset({"ResourceNotFoundException"}),
    "GetWebACLForResource": frozenset({"WAFNonexistentItemException"}),
    "GetLoggingConfiguration": frozenset({"WAFNonexistentItemException"}),
    "GetAlternateContact": frozenset({"ResourceNotFoundException"}),
    "GetAdminAccount": frozenset({"ResourceNotFoundException"}),
    "GetRole": frozenset({"NoSuchEntity"}),
    "GetPublicAccessBlock": frozenset({"NoSuchPublicAccessBlockConfiguration"}),
    "ListDelegatedAdministrators": frozenset({"AWSOrganizationsNotInUseException"}),
    "ListSubscribers": frozenset({"ResourceNotFoundException"}),
    "ListDataLakes": frozenset({"ResourceNotFoundException"}),
    "GetDataLakeOrganizationConfiguration": frozenset({"ResourceNotFoundException"}),
    "ListLogSources": frozenset({"ResourceNotFoundException"}),
    "GetDataLakeSources": frozenset({"ResourceNotFoundException"}),
    "GetOrganizationAdminAccount": frozenset({"ResourceNotFoundException"}),
}


def is_semantic(operation: str, code: str) -> bool:
    """Return whether ``code`` from ``operation`` means "not configured".

    Args:
        operation: AWS operation name.
        code: AWS error code.

    Returns:
        ``True`` only for a declared pair. Everything else -- every transport
        code, ``NoClient``, and anything undeclared -- is non-semantic, which is
        the conservative direction: a non-semantic code is what *admits* a
        FAIL-to-ERROR transition and what *rejects* a masked FAIL.
    """
    return code in SEMANTIC_CODES.get(operation, frozenset())


#: The ``Operation`` an error result carries when botocore attached none -- every
#: ``BotoCoreError``, and the no-client case. Declared here rather than imported
#: from the candidate tree, for the same reason ``SEMANTIC_CODES`` is: the gate
#: judges the candidate and must not take its definitions from it.
#:
#: A record carrying this cannot be attributed to a particular operation, so it
#: is treated as evidence for *any* operation the check depends on. That is sound
#: because it is only ever attached to a transport or no-client failure, and
#: :func:`is_semantic` has no entry for it -- so it can admit a FAIL-to-ERROR
#: transition, which is the reporting direction, and can never make a masked FAIL
#: look explained away as semantic.
UNKNOWN_OPERATION = "Request"


def explains(failure: "Failure", wanted: Set[str]) -> bool:
    """Return whether ``failure`` is evidence for a check depending on ``wanted``.

    Two departures from a plain ``failure.operation in wanted``, both needed for
    the comparison to mean anything:

    * A failure carrying :data:`UNKNOWN_OPERATION` matches whatever the check
      depends on. Nothing was sent, so no operation can be named -- and the
      alternative is discarding exactly the transport records that are the
      commonest legitimate cause of a FAIL becoming an ERROR.
    * The comparison is case-insensitive. ``wanted`` is derived from boto3 method
      names, so ``get_web_acl_for_resource`` yields ``GetWebAclForResource`` while
      botocore reports AWS's own ``GetWebACLForResource``. ``DescribeDRTAccess``
      and ``GetWebACLForResource`` are the two live instances; a case-sensitive
      compare silently drops every Shield and WAF record and the gate would demand
      a rerun for rows it had perfectly good evidence for.

    An empty ``wanted`` means the derivation found nothing for this check, in
    which case every record in the window counts -- erring toward admitting a
    transition rather than toward a spurious rejection.

    Args:
        failure: A parsed ``aws_call_failed`` record.
        wanted: Operations the check depends on, from :func:`derive_dependencies`.

    Returns:
        ``True`` if this record could describe a call this check makes.
    """
    if not wanted:
        return True
    if failure.operation == UNKNOWN_OPERATION:
        return True
    return failure.operation.casefold() in {w.casefold() for w in wanted}


# --------------------------------------------------------------------------- #
# Rows
# --------------------------------------------------------------------------- #

Row = Dict[str, str]


def read_csv(path: Path) -> Tuple[List[str], List[Row]]:
    """Read a findings CSV.

    Args:
        path: The CSV path.

    Returns:
        ``(fieldnames, rows)``.

    Raises:
        SystemExit: If the file cannot be read.
    """
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            return list(reader.fieldnames or []), [dict(row) for row in reader]
    except OSError as exc:
        raise SystemExit(f"gate: cannot read {path}: {exc}") from exc


#: An ISO-ish timestamp as the checks interpolate one, e.g.
#: ``2026-09-15 14:52:28.453000-05:00``. Four checks put a live AWS timestamp in
#: their ``ActualValue`` -- CloudTrail's ``LatestDeliveryTime`` and
#: ``LatestDigestDeliveryTime``, and Config's delivery-channel last-success time.
_TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?"
)

#: A bare 12-digit AWS account ID.
_ACCOUNT_RE = re.compile(r"\b\d{12}\b")


def normalise_volatile(value: str) -> str:
    """Return ``value`` with its reproducibly-volatile parts neutralised.

    Two scans of a live organization minutes apart differ in ways no code change
    caused, and both causes are in the *reference* tree as much as the candidate:

    * **Live timestamps.** Four checks interpolate an AWS-supplied delivery time
      into ``ActualValue``. It advances between the two scans by construction.
    * **Set iteration order.** ``SRA-MACIE-07`` and ``SRA-SECURITYHUB-08`` build
      their account list by joining a ``set``, so the order varies per process.
      This is a known defect the migration deliberately does not touch, recorded
      in ``creating_checks_best_practices.md``.

    Both normalisations are deliberately *narrow*, and the narrowness is what
    makes them safe rather than a way of waving differences through:

    * The timestamps are replaced by a token, so a difference anywhere else in the
      cell still shows. A regression that dropped the bucket name or flipped the
      verdict changes the surrounding text.
    * Account IDs are replaced by a token **and** a digest of the sorted multiset
      of IDs is appended, so a cell listing the same accounts in a different order
      compares equal while a cell that gained, lost, or substituted an account does
      not. That is the distinction that matters: ordering is a defect in how the
      row is rendered, membership is a finding.

    The multiset is appended as a **digest** rather than as the IDs themselves so
    the function is idempotent: raw IDs in the suffix would be re-tokenised and
    re-appended on a second application. ``row_tuple`` is called on both sides of
    every comparison and again during leftover pairing, and a normalisation whose
    result depended on how many times it had been applied would make pairing
    depend on evaluation order.

    Args:
        value: A cell value.

    Returns:
        The normalised value. Not human-readable; only ever compared.
    """
    text = _TIMESTAMP_RE.sub("<TS>", value)
    accounts = _ACCOUNT_RE.findall(text)
    if len(accounts) > 1:
        digest = hashlib.sha256(",".join(sorted(accounts)).encode()).hexdigest()[:16]
        text = _ACCOUNT_RE.sub("<ACCT>", text) + f"|accts:{digest}"
    return text


def row_tuple(row: Row) -> Tuple[str, ...]:
    """Return a row's 16 cells as a tuple, for exact pairing.

    Cells are passed through :func:`normalise_volatile` first, so a pair that
    differs only in a live timestamp or in set-iteration order pairs exactly and
    is never reported. Without it the Batch 1 gate rejected 20 rows across
    CloudTrail, Config, Macie, and Security Hub -- none of them touched by the
    batch, and none of them a regression.

    Args:
        row: A findings row.

    Returns:
        The normalised cell values in ``FIELDS`` order.
    """
    return tuple(normalise_volatile(row.get(field, "")) for field in FIELDS)


def logical_key(row: Row) -> Tuple[str, ...]:
    """Return the row's logical key.

    Args:
        row: A findings row.

    Returns:
        ``(AccountId, AccountType, Region, CheckId)``.
    """
    return tuple(row.get(field, "") for field in LOGICAL_KEY)


def sort_key(row: Row) -> Tuple[str, str, str, str]:
    """Return the deterministic ordering used for leftover pairing.

    Requirement 6.2 requires the whole pairing to be reproducible, so the final
    pass sorts rather than relying on file order.

    Args:
        row: A findings row.

    Returns:
        ``(ResourceId, Status, ActualValue, Remediation)``.
    """
    return (
        row.get("ResourceId", ""),
        row.get("Status", ""),
        row.get("ActualValue", ""),
        row.get("Remediation", ""),
    )


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #


@dataclass
class Failure:
    """One ``aws_call_failed`` record."""

    operation: str
    region: str
    code: str
    message: str

    @property
    def semantic(self) -> bool:
        """Whether this failure means "not configured" for its operation."""
        return is_semantic(self.operation, self.code)


@dataclass
class Invocation:
    """The evidence from one ``sraverify`` process's stderr.

    Attributes:
        path: The stderr file.
        windows: ``check_id -> [Failure]`` -- the failures logged between the
            previous ``check_done`` marker and this check's.
        rows: ``check_id -> rows=`` value, so ``synthetic`` is detectable.
        order: The check IDs in execution order.
        orphans: Failures logged after the last marker, or before the first.
    """

    path: Path
    windows: Dict[str, List[Failure]] = field(default_factory=dict)
    rows: Dict[str, str] = field(default_factory=dict)
    order: List[str] = field(default_factory=list)
    orphans: List[Failure] = field(default_factory=list)


def parse_invocation(path: Path) -> Invocation:
    """Parse one per-invocation stderr file into check windows.

    Attribution is positional, which is sound because execution within one
    invocation is single-threaded: every ``aws_call_failed`` record since the
    previous ``check_done`` marker belongs to the check whose marker comes next.
    That is the whole reason the buildspec gives each invocation its own file --
    a merged ``parallel -j5`` stream interleaves five processes and destroys the
    ordering this depends on.

    Args:
        path: The stderr file.

    Returns:
        The parsed invocation.
    """
    invocation = Invocation(path=path)
    pending: List[Failure] = []

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        failure_match = AWS_CALL_FAILED_RE.search(line)
        if failure_match:
            raw = failure_match.group("message")
            try:
                message = json.loads(raw)
            except (ValueError, TypeError):
                # A message that does not decode is still evidence that the call
                # failed; keep it rather than dropping the record.
                message = raw
            pending.append(
                Failure(
                    operation=failure_match.group("operation"),
                    region=failure_match.group("region"),
                    code=failure_match.group("code"),
                    message=str(message),
                )
            )
            continue

        done_match = CHECK_DONE_RE.search(line)
        if done_match:
            check_id = done_match.group("check_id")
            invocation.order.append(check_id)
            invocation.rows[check_id] = done_match.group("rows")
            invocation.windows.setdefault(check_id, []).extend(pending)
            pending = []

    invocation.orphans.extend(pending)
    return invocation


def load_evidence(directory: Path) -> Dict[Tuple[str, str], Invocation]:
    """Parse every stderr file in a directory, keyed by account and account type.

    File names are expected to be ``<account_id>-<account_type>.log``, which is
    what the buildspec produces. A name that does not parse is still loaded, under
    a key derived from the stem, so a partial rename does not silently drop
    evidence.

    Args:
        directory: The ``stderr/`` directory.

    Returns:
        ``{(account_id, account_type): Invocation}``.

    Raises:
        SystemExit: If the directory is missing.
    """
    if not directory.is_dir():
        raise SystemExit(f"gate: stderr directory not found: {directory}")

    evidence: Dict[Tuple[str, str], Invocation] = {}
    for path in sorted(directory.glob("*.log")):
        stem = path.stem
        account_id, _, account_type = stem.partition("-")
        evidence[(account_id, account_type or "")] = parse_invocation(path)
    return evidence


def failures_for(
    evidence: Dict[Tuple[str, str], Invocation], row: Row
) -> List[Failure]:
    """Return the failures logged in this row's check window, for its Region.

    Args:
        evidence: Parsed invocations.
        row: A findings row.

    Returns:
        Matching failures, empty when there is no evidence file or no window.
    """
    invocation = evidence.get((row.get("AccountId", ""), row.get("AccountType", "")))
    if invocation is None:
        return []
    window = invocation.windows.get(row.get("CheckId", ""), [])
    region = row.get("Region", "")
    # A `global` row is not attributable to one Region, so accept any.
    if region in ("", "global"):
        return list(window)
    return [failure for failure in window if failure.region == region]


def check_done_rows(
    evidence: Dict[Tuple[str, str], Invocation], row: Row
) -> str | None:
    """Return the ``rows=`` value of this row's check marker, if any.

    Args:
        evidence: Parsed invocations.
        row: A findings row.

    Returns:
        e.g. ``"3"`` or ``"synthetic"``, or ``None`` when unavailable.
    """
    invocation = evidence.get((row.get("AccountId", ""), row.get("AccountType", "")))
    if invocation is None:
        return None
    return invocation.rows.get(row.get("CheckId", ""))


# --------------------------------------------------------------------------- #
# Static check -> operation dependencies
# --------------------------------------------------------------------------- #


def derive_dependencies(package_root: Path) -> Dict[str, Set[str]]:
    """Derive, per check ID, the AWS operations it depends on.

    Four hops, all by AST, so nothing is maintained by hand:

    1. check module -> the accessor names it calls on ``self``
    2. service base -> for each accessor, the client methods it calls
    3. client -> for each client method, every boto3 method it calls, converted
       to its PascalCase operation name
    4. compose

    Step 3 has one source, the boto3 method name, and that is a deliberate
    narrowing. An earlier draft preferred an ``operation=`` string literal in the
    method's ``except`` clause and fell back to the method name. The literal is
    gone from the tree -- ``AWSClient.aws_error`` reads the operation from
    ``ClientError.operation_name`` -- and it should not be missed here: the gate
    is meant to be an *independent* derivation of what a check depends on, and a
    literal written by the same author in the same file was never independent of
    the code it described. The boto3 method name is what actually determines the
    wire operation.

    Deliberately over-inclusive at steps 1 and 3. Any ``self.<name>(...)`` call is
    taken as a candidate accessor, and *every* boto3 call in a client method
    contributes an operation rather than only the first. A false positive widens a
    check's dependency set, which can only make criterion 3 *more* willing to
    admit a FAIL-to-ERROR transition -- and criterion 6's masked-FAIL sweep
    stricter. Both err toward reporting rather than hiding.

    Args:
        package_root: The ``sraverify`` package directory.

    Returns:
        ``{check_id: {operation, ...}}``.
    """
    services_root = package_root / "services"
    if not services_root.is_dir():
        return {}

    # Step 3: client method -> operations, per service.
    client_ops: Dict[str, Dict[str, Set[str]]] = {}
    for client_path in sorted(services_root.rglob("client.py")):
        if "__pycache__" in client_path.parts:
            continue
        service = client_path.parent.name
        tree = ast.parse(client_path.read_text(encoding="utf-8"))
        methods: Dict[str, Set[str]] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            boto_methods: Set[str] = set()
            for sub in ast.walk(node):
                # `self.<attr>.<boto_method>(...)` -- the receiver being itself an
                # attribute is what distinguishes a boto3 call from `self.foo()`.
                if not (
                    isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Attribute)
                    and isinstance(sub.func.value, ast.Attribute)
                ):
                    continue
                if sub.func.attr == "get_paginator":
                    if sub.args and isinstance(sub.args[0], ast.Constant):
                        boto_methods.add(str(sub.args[0].value))
                elif sub.func.attr != "get_waiter":
                    boto_methods.add(sub.func.attr)
            operations = {
                "".join(part.capitalize() for part in boto_method.split("_"))
                for boto_method in boto_methods
            }
            if operations:
                methods[node.name] = operations
        client_ops[service] = methods

    # Step 2: base accessor -> operations, per service.
    base_ops: Dict[str, Dict[str, Set[str]]] = {}
    for base_path in sorted(services_root.rglob("base.py")):
        if "__pycache__" in base_path.parts:
            continue
        service = base_path.parent.name
        tree = ast.parse(base_path.read_text(encoding="utf-8"))
        accessors: Dict[str, Set[str]] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            operations: Set[str] = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                    operations |= client_ops.get(service, {}).get(sub.func.attr, set())
            accessors[node.name] = operations
        base_ops[service] = accessors

    # Step 1 and 4: check module -> accessors -> operations.
    dependencies: Dict[str, Set[str]] = {}
    for check_path in sorted(services_root.rglob("checks/sra_*.py")):
        if "__pycache__" in check_path.parts:
            continue
        service = check_path.parent.parent.name
        stem = check_path.stem
        parts = stem.split("_")
        check_id = f"SRA-{parts[1].upper()}-{parts[-1]}"

        tree = ast.parse(check_path.read_text(encoding="utf-8"))
        operations: Set[str] = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "self"
            ):
                operations |= base_ops.get(service, {}).get(node.func.attr, set())
        dependencies[check_id] = operations

    return dependencies


# --------------------------------------------------------------------------- #
# Judgement
# --------------------------------------------------------------------------- #


@dataclass
class Verdict:
    """One admitted or rejected difference."""

    admitted: bool
    kind: str
    key: Tuple[str, ...]
    detail: str
    rerun: bool = False


@dataclass
class Report:
    """Everything the gate concluded."""

    verdicts: List[Verdict] = field(default_factory=list)
    totals: Dict[str, object] = field(default_factory=dict)
    digests: Dict[str, str] = field(default_factory=dict)

    @property
    def rejections(self) -> List[Verdict]:
        """Every rejected difference."""
        return [v for v in self.verdicts if not v.admitted]

    @property
    def reruns(self) -> List[Verdict]:
        """Every difference needing a re-run before it counts."""
        return [v for v in self.verdicts if v.rerun]


def pair_group(
    reference: List[Row], candidate: List[Row]
) -> Tuple[List[Tuple[Row, Row]], List[Row], List[Row]]:
    """Pair the rows of one logical key, deterministically.

    Three passes, in order:

    1. exact on all 16 cells
    2. on a non-blank ``ResourceId`` occurring exactly once on each side
    3. by the sorted ``(ResourceId, Status, ActualValue, Remediation)`` order

    Pass 2's uniqueness condition matters: a check emitting three rows with the
    same blank ``ResourceId`` must not have them paired arbitrarily, or the gate's
    output would differ between runs on identical inputs.

    Args:
        reference: Reference rows for one logical key.
        candidate: Candidate rows for the same key.

    Returns:
        ``(pairs, unpaired_reference, unpaired_candidate)``.
    """
    pairs: List[Tuple[Row, Row]] = []

    # Pass 1: exact.
    remaining_candidate = list(candidate)
    remaining_reference: List[Row] = []
    candidate_by_tuple: Dict[Tuple[str, ...], List[Row]] = defaultdict(list)
    for row in remaining_candidate:
        candidate_by_tuple[row_tuple(row)].append(row)
    for row in reference:
        bucket = candidate_by_tuple.get(row_tuple(row))
        if bucket:
            pairs.append((row, bucket.pop(0)))
        else:
            remaining_reference.append(row)
    remaining_candidate = [r for rows in candidate_by_tuple.values() for r in rows]

    # Pass 2: unique non-blank ResourceId on both sides.
    reference_ids = defaultdict(list)
    for row in remaining_reference:
        reference_ids[row.get("ResourceId", "")].append(row)
    candidate_ids = defaultdict(list)
    for row in remaining_candidate:
        candidate_ids[row.get("ResourceId", "")].append(row)

    matched_reference: Set[int] = set()
    matched_candidate: Set[int] = set()
    for resource_id, reference_rows in reference_ids.items():
        if not resource_id.strip():
            continue
        candidate_rows = candidate_ids.get(resource_id, [])
        if len(reference_rows) == 1 and len(candidate_rows) == 1:
            pairs.append((reference_rows[0], candidate_rows[0]))
            matched_reference.add(id(reference_rows[0]))
            matched_candidate.add(id(candidate_rows[0]))

    remaining_reference = [
        r for r in remaining_reference if id(r) not in matched_reference
    ]
    remaining_candidate = [
        r for r in remaining_candidate if id(r) not in matched_candidate
    ]

    # Pass 3: sorted order.
    remaining_reference.sort(key=sort_key)
    remaining_candidate.sort(key=sort_key)
    overlap = min(len(remaining_reference), len(remaining_candidate))
    for index in range(overlap):
        pairs.append((remaining_reference[index], remaining_candidate[index]))

    return pairs, remaining_reference[overlap:], remaining_candidate[overlap:]


def judge_pair(
    reference: Row,
    candidate: Row,
    *,
    dependencies: Dict[str, Set[str]],
    candidate_evidence: Dict[Tuple[str, str], Invocation],
    wording_changed: Set[str],
) -> Verdict | None:
    """Judge one paired row. Returns ``None`` when the row is unchanged.

    Args:
        reference: The reference row.
        candidate: The candidate row.
        dependencies: Check ID -> operations it depends on.
        candidate_evidence: Parsed candidate stderr.
        wording_changed: Check IDs whose discriminated FAIL wording this batch
            declares as changed.

    Returns:
        A verdict, or ``None``.
    """
    key = logical_key(reference)
    check_id = reference.get("CheckId", "")

    if row_tuple(reference) == row_tuple(candidate):
        return None

    before = reference.get("Status", "")
    after = candidate.get("Status", "")

    # --- Status transitions (criterion 5) --------------------------------- #
    if before != after:
        # A declared false PASS becoming a FAIL, and only in that direction.
        # Evidence is still required: the declaration says the check's PASS branch
        # was reachable from an erased error, not that any row it emits is right.
        if (
            before == "PASS"
            and after == "FAIL"
            and check_id in ADMITTED_PASS_TO_FAIL
        ):
            wanted = dependencies.get(check_id, set())
            failures = failures_for(candidate_evidence, candidate)
            supporting = [f for f in failures if explains(f, wanted) and f.semantic]
            if supporting:
                first = supporting[0]
                return Verdict(
                    True,
                    "status",
                    key,
                    f"{check_id}: PASS -> FAIL, declared as a fabricated PASS and "
                    f"evidenced by the semantic {first.operation}/{first.code} in "
                    f"{candidate.get('Region','')}",
                )
            return Verdict(
                False,
                "status",
                key,
                f"{check_id}: PASS -> FAIL is declared in ADMITTED_PASS_TO_FAIL, "
                f"but no **semantic** aws_call_failed record explains it in this "
                f"check's window for {candidate.get('Region','')}. A declared PASS "
                f"correction still has to show that AWS established the control is "
                f"absent; without that the row is a regression.\n"
                f"    reference ActualValue: {reference.get('ActualValue','')[:120]!r}\n"
                f"    candidate ActualValue: {candidate.get('ActualValue','')[:120]!r}",
                rerun=not failures,
            )

        if before == "PASS" or after == "PASS":
            return Verdict(
                False,
                "status",
                key,
                f"{check_id}: {before} -> {after}. A PASS transition is not "
                f"admitted unless the check is declared in "
                f"ADMITTED_PASS_TO_FAIL: this feature touches only the failure "
                f"and no-client paths, so a row that passed must still pass "
                f"unless its PASS was reachable from an erased error.\n"
                f"    reference ActualValue: {reference.get('ActualValue','')[:120]!r}\n"
                f"    candidate ActualValue: {candidate.get('ActualValue','')[:120]!r}",
            )

        if before == "FAIL" and after == "ERROR":
            wanted = dependencies.get(check_id, set())
            failures = failures_for(candidate_evidence, candidate)
            supporting = [
                f
                for f in failures
                if explains(f, wanted) and not f.semantic
            ]
            if supporting:
                first = supporting[0]
                return Verdict(
                    True,
                    "status",
                    key,
                    f"{check_id}: FAIL -> ERROR, evidenced by "
                    f"{first.operation}/{first.code} in "
                    f"{candidate.get('Region','')}",
                )
            if not failures:
                return Verdict(
                    False,
                    "status",
                    key,
                    f"{check_id}: FAIL -> ERROR with NO aws_call_failed record in "
                    f"this check's window for {candidate.get('Region','')}. Either "
                    f"the row is a regression, or the evidence is missing -- check "
                    f"that the buildspec captured this invocation's stderr.",
                    rerun=True,
                )
            return Verdict(
                False,
                "status",
                key,
                f"{check_id}: FAIL -> ERROR but every record in the window is "
                f"semantic ("
                + ", ".join(f"{f.operation}/{f.code}" for f in failures[:3])
                + "). A semantic code means AWS reported the control absent, "
                "which is a FAIL.",
            )

        if before == "ERROR" and after == "FAIL":
            if check_id in ADMITTED_ERROR_TO_FAIL:
                return Verdict(
                    True,
                    "status",
                    key,
                    f"{check_id}: ERROR -> FAIL, declared under Requirement 4.10",
                )
            return Verdict(
                False,
                "status",
                key,
                f"{check_id}: ERROR -> FAIL is not in the Requirement 4.10 list. "
                f"If it is intended, add it to ADMITTED_ERROR_TO_FAIL in this "
                f"script and record it in the batch's gate notes.\n"
                f"    candidate ActualValue: {candidate.get('ActualValue','')[:120]!r}",
            )

        return Verdict(
            False, "status", key, f"{check_id}: unhandled transition {before} -> {after}"
        )

    # --- Unchanged Status, changed cells (criterion 5) -------------------- #
    changed = [
        field
        for field in FIELDS
        if reference.get(field, "") != candidate.get(field, "")
    ]

    # An ERROR row's ActualValue is admitted when it takes the canonical
    # "{Operation} failed: {Code}: {Message}" shape, with Remediation and
    # ResourceId allowed to move alongside it.
    if set(changed) <= {"ActualValue", "Remediation", "ResourceId"} and after == "ERROR":
        if ERROR_VALUE_RE.match(candidate.get("ActualValue", "")):
            return Verdict(
                True,
                "actual_value",
                key,
                f"{check_id}: ERROR row reformatted (ActualValue"
                + (", Remediation" if "Remediation" in changed else "")
                + (", ResourceId" if "ResourceId" in changed else "")
                + ")",
            )

    # A FAIL row's ActualValue is admitted only for a check declared in
    # --wording-changed, and `Remediation` is allowed to move with it.
    #
    # That pairing is not a loosening for convenience: a discriminated FAIL states
    # a *different reason* for the same verdict, and the advice has to follow the
    # reason. When SRA-MACIE-09 stops saying "Failed to retrieve Macie members" and
    # starts saying "Macie is not enabled in us-east-1", the old remediation
    # ("ensure you have permissions to call ListMembers") is no longer the right
    # instruction -- it describes a cause the row no longer claims.
    #
    # Batch 1 did not need this. Each of GuardDuty's seven declared checks passed a
    # `remediation=` that happened to be identical before and after, so ActualValue
    # moved alone and the narrower rule was sufficient. Batch 2 is where the two
    # come apart, and requiring them not to would force an author to preserve advice
    # they know to be wrong in order to pass the gate.
    #
    # `Status` is pinned by the transition branches above -- FAIL stays FAIL, and a
    # PASS transition is still never admitted -- which is the property criterion 5
    # exists to protect. The per-check declaration is the control on the rest.
    if (
        after == "FAIL"
        and "ActualValue" in changed
        and set(changed) <= {"ActualValue", "Remediation", "ResourceId"}
    ):
        if check_id in wording_changed:
            return Verdict(
                True,
                "actual_value",
                key,
                f"{check_id}: FAIL wording changed (ActualValue"
                + (", Remediation" if "Remediation" in changed else "")
                + (", ResourceId" if "ResourceId" in changed else "")
                + "), declared for this batch",
            )
        return Verdict(
            False,
            "actual_value",
            key,
            f"{check_id}: FAIL ActualValue changed but the check is not declared "
            f"in --wording-changed.\n"
            f"    before: {reference.get('ActualValue','')[:120]!r}\n"
            f"    after:  {candidate.get('ActualValue','')[:120]!r}",
        )

    # An ERROR row whose ActualValue changed to something that is *not* the
    # canonical shape is a regression in the row's own format.
    if changed and after == "ERROR" and "ActualValue" in changed:
        return Verdict(
            False,
            "actual_value",
            key,
            f"{check_id}: ERROR ActualValue changed but does not match "
            f"{ERROR_VALUE_RE.pattern!r}.\n"
            f"    before: {reference.get('ActualValue','')[:120]!r}\n"
            f"    after:  {candidate.get('ActualValue','')[:120]!r}",
        )

    if changed == ["ResourceId"]:
        return Verdict(
            False,
            "resource_id",
            key,
            f"{check_id}: ResourceId changed with no other admitted change: "
            f"{reference.get('ResourceId','')!r} -> "
            f"{candidate.get('ResourceId','')!r}",
        )

    return Verdict(
        False,
        "cells",
        key,
        f"{check_id}: {after} row changed in {changed}, which criterion 5 does "
        f"not admit",
    )


def judge_unpaired(
    rows: Iterable[Row],
    *,
    side: str,
    reference_evidence: Dict[Tuple[str, str], Invocation],
    unavailable: Set[Tuple[str, str]],
) -> List[Verdict]:
    """Judge rows left unpaired on one side (criterion 6).

    Args:
        rows: The unpaired rows.
        side: ``"added"`` or ``"removed"``.
        reference_evidence: Parsed reference stderr, for the added case.
        unavailable: ``(service, region)`` pairs the availability lookup answers
            ``False`` for, for the removed case.

    Returns:
        One verdict per row.
    """
    verdicts: List[Verdict] = []
    for row in rows:
        key = logical_key(row)
        check_id = row.get("CheckId", "")

        if side == "added":
            marker = check_done_rows(reference_evidence, row)
            if marker == "synthetic":
                verdicts.append(
                    Verdict(
                        True,
                        "added",
                        key,
                        f"{check_id}: row recovered -- the reference invocation "
                        f"reports rows=synthetic for this check, so a transport "
                        f"failure was aborting its generator",
                    )
                )
                continue
            verdicts.append(
                Verdict(
                    False,
                    "added",
                    key,
                    f"{check_id}: candidate-only row with no synthetic-row "
                    f"condition in the reference invocation "
                    f"(check_done rows={marker!r}).\n"
                    f"    {row.get('Status','')}: "
                    f"{row.get('ActualValue','')[:120]!r}",
                    rerun=True,
                )
            )
            continue

        service_region = (row.get("Service", ""), row.get("Region", ""))
        if service_region in unavailable:
            verdicts.append(
                Verdict(
                    True,
                    "removed",
                    key,
                    f"{check_id}: row suppressed -- {row.get('Service','')} has no "
                    f"endpoint in {row.get('Region','')}",
                )
            )
            continue
        verdicts.append(
            Verdict(
                False,
                "removed",
                key,
                f"{check_id}: reference-only row, and "
                f"{row.get('Service','')} does have an endpoint in "
                f"{row.get('Region','')}. A row must not simply disappear.\n"
                f"    {row.get('Status','')}: "
                f"{row.get('ActualValue','')[:120]!r}",
                rerun=True,
            )
        )
    return verdicts


def unavailable_pairs(rows: Sequence[Row]) -> Set[Tuple[str, str]]:
    """Return ``(Service, Region)`` pairs whose service has no endpoint there.

    Consults the availability lookup if the package is importable, and otherwise
    returns an empty set -- in which case every removed row rejects and is
    reported, which is the safe direction.

    Args:
        rows: Rows to consider.

    Returns:
        The unavailable pairs.
    """
    try:
        from sraverify.core.availability import service_available_in_region
    except Exception:  # noqa: BLE001 - the gate must run without the package
        return set()

    # `Service` is a display name; map it to a boto3 service id where the two
    # differ for a candidate-set service.
    display_to_id = {
        "Security Lake": "securitylake",
        "Macie": "macie2",
        "Inspector": "inspector2",
        "Audit Manager": "auditmanager",
        "WAF": "apprunner",
    }

    unavailable: Set[Tuple[str, str]] = set()
    for row in rows:
        service = row.get("Service", "")
        region = row.get("Region", "")
        service_id = display_to_id.get(service)
        if not service_id or not region or region == "global":
            continue
        if not service_available_in_region(service_id, region):
            unavailable.add((service, region))
    return unavailable


def sha256(path: Path) -> str:
    """Return a file's SHA-256 hex digest.

    Args:
        path: The file.

    Returns:
        The digest.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def run_gate(
    *,
    reference_csv: Path,
    reference_stderr: Path,
    candidate_csv: Path,
    candidate_stderr: Path,
    services: Set[str],
    wording_changed: Set[str],
    package_root: Path | None,
) -> Report:
    """Compare the two scans and return the report.

    Args:
        reference_csv: Reference consolidated CSV.
        reference_stderr: Reference ``stderr/`` directory.
        candidate_csv: Candidate consolidated CSV.
        candidate_stderr: Candidate ``stderr/`` directory.
        services: ``Service`` values in scope. Empty means every service.
        wording_changed: Check IDs whose discriminated FAIL wording changed.
        package_root: The ``sraverify`` package, for dependency derivation.

    Returns:
        The report.
    """
    report = Report()

    reference_fields, reference_rows = read_csv(reference_csv)
    candidate_fields, candidate_rows = read_csv(candidate_csv)

    for path in (reference_csv, candidate_csv):
        report.digests[str(path)] = sha256(path)
    for directory in (reference_stderr, candidate_stderr):
        if directory.is_dir():
            for path in sorted(directory.glob("*.log")):
                report.digests[str(path)] = sha256(path)

    # --- Criterion 7: the schema ----------------------------------------- #
    if tuple(candidate_fields) != FIELDS:
        report.verdicts.append(
            Verdict(
                False,
                "schema",
                (),
                f"the candidate CSV's columns are not the 16 contract columns in "
                f"order.\n    expected: {FIELDS}\n    found:    "
                f"{tuple(candidate_fields)}",
            )
        )
        return report
    if tuple(reference_fields) != FIELDS:
        report.verdicts.append(
            Verdict(
                False,
                "schema",
                (),
                f"the reference CSV's columns are not the 16 contract columns in "
                f"order: {tuple(reference_fields)}",
            )
        )
        return report

    dependencies = derive_dependencies(package_root) if package_root else {}
    reference_evidence = load_evidence(reference_stderr)
    candidate_evidence = load_evidence(candidate_stderr)

    def in_scope(row: Row) -> bool:
        return not services or row.get("Service", "") in services

    # --- Criterion 7: out-of-scope rows must be identical ---------------- #
    out_reference = sorted(row_tuple(r) for r in reference_rows if not in_scope(r))
    out_candidate = sorted(row_tuple(r) for r in candidate_rows if not in_scope(r))
    if services and out_reference != out_candidate:
        only_reference = [t for t in out_reference if t not in set(out_candidate)]
        only_candidate = [t for t in out_candidate if t not in set(out_reference)]
        for cells in (only_reference[:20] + only_candidate[:20]):
            row = dict(zip(FIELDS, cells))
            report.verdicts.append(
                Verdict(
                    False,
                    "out_of_scope",
                    logical_key(row),
                    f"{row.get('CheckId','')} ({row.get('Service','')}) is not in "
                    f"this batch's scope but its row differs between the two "
                    f"scans. Out-of-scope rows exercise the shared code -- "
                    f"AWSClient.aws_error, the _set backstop, is_not_configured -- "
                    f"so a "
                    f"difference here is a regression in it.\n"
                    f"    {row.get('Status','')}: "
                    f"{row.get('ActualValue','')[:120]!r}",
                )
            )

    # --- Criteria 4-6: group, pair, judge -------------------------------- #
    reference_groups: Dict[Tuple[str, ...], List[Row]] = defaultdict(list)
    candidate_groups: Dict[Tuple[str, ...], List[Row]] = defaultdict(list)
    for row in reference_rows:
        if in_scope(row):
            reference_groups[logical_key(row)].append(row)
    for row in candidate_rows:
        if in_scope(row):
            candidate_groups[logical_key(row)].append(row)

    unavailable = unavailable_pairs(
        [r for rows in reference_groups.values() for r in rows]
    )

    for key in sorted(set(reference_groups) | set(candidate_groups)):
        pairs, unpaired_reference, unpaired_candidate = pair_group(
            reference_groups.get(key, []), candidate_groups.get(key, [])
        )
        for reference_row, candidate_row in pairs:
            verdict = judge_pair(
                reference_row,
                candidate_row,
                dependencies=dependencies,
                candidate_evidence=candidate_evidence,
                wording_changed=wording_changed,
            )
            if verdict is not None:
                report.verdicts.append(verdict)
        report.verdicts.extend(
            judge_unpaired(
                unpaired_candidate,
                side="added",
                reference_evidence=reference_evidence,
                unavailable=unavailable,
            )
        )
        report.verdicts.extend(
            judge_unpaired(
                unpaired_reference,
                side="removed",
                reference_evidence=reference_evidence,
                unavailable=unavailable,
            )
        )

    # --- Criterion 6: the masked-FAIL sweep ------------------------------ #
    for row in candidate_rows:
        if row.get("Status") != "FAIL" or row.get("CheckId") not in MASKED_FAIL_CHECKS:
            continue
        wanted = dependencies.get(row.get("CheckId", ""), set())
        offending = [
            f
            for f in failures_for(candidate_evidence, row)
            if explains(f, wanted) and not f.semantic
        ]
        if offending:
            first = offending[0]
            report.verdicts.append(
                Verdict(
                    False,
                    "masked_fail",
                    logical_key(row),
                    f"{row.get('CheckId','')}: FAIL in {row.get('Region','')} while "
                    f"{first.operation} failed with the non-semantic code "
                    f"{first.code}. This is a masked FAIL -- the row asserts the "
                    f"control is absent and the log says nobody could look.\n"
                    f"    ActualValue: {row.get('ActualValue','')[:120]!r}\n"
                    f"    message: {first.message[:160]!r}",
                )
            )

    # --- Criterion 8: totals -------------------------------------------- #
    confessing = [
        row
        for row in candidate_rows
        if row.get("Status") == "FAIL" and CONFESSING_RE.search(row.get("ActualValue", ""))
    ]
    synthetic = [
        row
        for row in candidate_rows
        if row.get("ActualValue", "").startswith(SYNTHETIC_PREFIX)
    ]
    reference_confessing = [
        row
        for row in reference_rows
        if row.get("Status") == "FAIL" and CONFESSING_RE.search(row.get("ActualValue", ""))
    ]

    report.totals = {
        "reference_rows": len(reference_rows),
        "candidate_rows": len(candidate_rows),
        "reference_confessing_fail": len(reference_confessing),
        "candidate_confessing_fail": len(confessing),
        "candidate_check_ids": len({row.get("CheckId", "") for row in candidate_rows}),
        "candidate_synthetic_rows": len(synthetic),
        "candidate_pass": sum(1 for r in candidate_rows if r.get("Status") == "PASS"),
        "candidate_fail": sum(1 for r in candidate_rows if r.get("Status") == "FAIL"),
        "candidate_error": sum(1 for r in candidate_rows if r.get("Status") == "ERROR"),
    }

    if len(confessing) > len(reference_confessing):
        report.verdicts.append(
            Verdict(
                False,
                "totals",
                (),
                f"confessing FAIL rows increased: {len(reference_confessing)} -> "
                f"{len(confessing)}. This count must be non-increasing per batch.",
            )
        )

    if synthetic:
        by_check = sorted({row.get("CheckId", "") for row in synthetic})
        report.verdicts.append(
            Verdict(
                False,
                "totals",
                (),
                f"{len(synthetic)} synthetic ERROR row(s) in the candidate scan, "
                f"from {by_check}. After this feature a synthetic row means a "
                f"programming defect in a check, a base class, or a client.",
            )
        )

    return report


def write_notes(report: Report, path: Path, *, argv: Sequence[str]) -> None:
    """Write the gate notes for a batch.

    Args:
        report: The report.
        path: Where to write.
        argv: The invocation, recorded verbatim.
    """
    lines: List[str] = [
        "# Acceptance gate run",
        "",
        "Generated by `util/gate.py`. Every input's SHA-256 is recorded below, so",
        "this decision can be re-derived from immutable artefacts.",
        "",
        "## Invocation",
        "",
        "```",
        " ".join(argv),
        "```",
        "",
        "## Totals",
        "",
        "| Figure | Value |",
        "| --- | --- |",
    ]
    for name, value in report.totals.items():
        lines.append(f"| `{name}` | {value} |")

    lines += ["", "## Verdicts", ""]
    admitted = [v for v in report.verdicts if v.admitted]
    lines.append(
        f"{len(admitted)} admitted, {len(report.rejections)} rejected, "
        f"{len(report.reruns)} needing a re-run before they count."
    )

    if report.rejections:
        lines += ["", "### Rejections", ""]
        for verdict in report.rejections:
            lines += [f"- **{verdict.kind}** `{'/'.join(verdict.key)}`", ""]
            for line in verdict.detail.splitlines():
                lines.append(f"  {line}")
            lines.append("")

    if admitted:
        lines += ["", "### Admitted", ""]
        for verdict in admitted:
            lines.append(f"- {verdict.kind}: {verdict.detail.splitlines()[0]}")

    lines += ["", "## Input digests", ""]
    for name, digest in sorted(report.digests.items()):
        lines.append(f"- `{digest}`  {name}")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, run the gate, print the outcome.

    Args:
        argv: Command line, for testing.

    Returns:
        ``0`` when every difference is admitted, ``1`` on a rejection.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-csv", type=Path, required=True)
    parser.add_argument("--reference-stderr", type=Path, required=True)
    parser.add_argument("--candidate-csv", type=Path, required=True)
    parser.add_argument("--candidate-stderr", type=Path, required=True)
    parser.add_argument(
        "--services",
        default="",
        help="comma-separated Service values in scope; omit for every service",
    )
    parser.add_argument(
        "--wording-changed",
        default="",
        help="comma-separated check IDs whose discriminated FAIL wording changed "
        "in this batch",
    )
    parser.add_argument(
        "--package-root",
        type=Path,
        default=None,
        help="the sraverify package directory, for deriving check->operation "
        "dependencies (default: inferred from this script's location)",
    )
    parser.add_argument("--notes", type=Path, default=None)
    args = parser.parse_args(argv)

    package_root = args.package_root
    if package_root is None:
        candidate = Path(__file__).resolve().parent.parent / "sraverify" / "sraverify"
        package_root = candidate if candidate.is_dir() else None

    report = run_gate(
        reference_csv=args.reference_csv,
        reference_stderr=args.reference_stderr,
        candidate_csv=args.candidate_csv,
        candidate_stderr=args.candidate_stderr,
        services={s.strip() for s in args.services.split(",") if s.strip()},
        wording_changed={
            s.strip() for s in args.wording_changed.split(",") if s.strip()
        },
        package_root=package_root,
    )

    print("=== Totals ===")
    for name, value in report.totals.items():
        print(f"  {name:<32} {value}")

    admitted = [v for v in report.verdicts if v.admitted]
    print(
        f"\n=== {len(admitted)} admitted, {len(report.rejections)} rejected, "
        f"{len(report.reruns)} needing re-run ==="
    )

    for verdict in report.rejections:
        print(f"\nREJECT [{verdict.kind}] {'/'.join(verdict.key)}")
        for line in verdict.detail.splitlines():
            print(f"  {line}")

    if report.reruns:
        print(
            "\nRe-run each of the above marked for re-run against both trees for "
            "that account only, before counting it as a rejection (criterion 9), "
            "and record the outcome in the gate notes."
        )

    if args.notes:
        write_notes(report, args.notes, argv=["util/gate.py", *(argv or sys.argv[1:])])
        print(f"\nGate notes written to {args.notes}")

    if report.rejections:
        print(f"\nGATE REJECTED: {len(report.rejections)} difference(s) not admitted.")
        return 1
    print("\nGATE ADMITTED: every difference is accounted for.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
