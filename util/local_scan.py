#!/usr/bin/env python3
"""
Produce a gate-able scan from the working tree, using local AWS profiles.

The local equivalent of ``2-sraverify-codebuild-deploy.yaml``'s inline buildspec:
one ``sraverify`` invocation per account type, each with its stderr captured to
its own file, and the resulting CSVs consolidated into one. The output directory
is laid out exactly as ``util/gate.py`` expects::

    <out>/consolidated.csv
    <out>/stderr/<account_id>-<account_type>.log
    <out>/raw/<per-invocation csv>

Why this exists
---------------

The acceptance gate needs two scans of the same accounts from two commits, run
back to back. The CodeBuild project can supply them, but its buildspec does
``git clone -b $GIT_BRANCH https://github.com/awslabs/sra-verify.git`` -- so every
scan runs code that has been pushed to a public repository. Twelve of those (a
reference and a candidate per batch) is a lot of public pushes for a
work-in-progress refactor.

The gate does not care where its inputs came from. It needs a consolidated CSV
and a directory of per-invocation stderr files, and this produces both from the
working tree. It also makes the reference/candidate window *tighter* than
CodeBuild can: two runs minutes apart on one machine rather than two builds that
each re-clone and re-install.

Two honest limitations
----------------------

**Credentials are broader than production.** The deployed scan assumes
``SRAMemberRole``, whose trust policy is conditioned on
``SRAVerifyCodeBuildServiceRole`` and therefore cannot be assumed from a local
Admin profile. So these scans run with whatever the profile grants, which is
normally more. Fewer calls are denied, so fewer ERROR rows appear -- including,
specifically, the ``securitylake:ListSubscribers`` denial behind the 8 measured
masked-FAIL rows. A reference/candidate comparison is still sound, because both
sides use the same credentials; but a batch whose point is a permission-denied
path needs the targeted run the design's Manual Validation section describes.

**Coverage is the accounts you have profiles for**, not all 13. That is usually
enough -- the gate compares like with like, and one account per account type
exercises every check's selection path -- but a check that only fails in an account
you have no profile for will not be exercised.

Usage::

    python util/local_scan.py --out .tmp/gate/batch-1/reference \\
        --regions us-east-1,us-east-2,us-west-1,us-west-2 \\
        --audit-account <audit-account-id> \\
        --log-archive-account <log-archive-account-id> \\
        --scan management=schiefj+codemain-Admin \\
        --scan audit=schiefj+codeaudit-Admin \\
        --scan log-archive=schiefj+codelog-Admin \\
        --scan application=schiefj+codeprod-Admin
"""

from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

#: The 16 columns, in order. Duplicated rather than imported for the same reason
#: ``util/gate.py`` duplicates it: this runs against whatever tree is checked out.
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


@dataclass(frozen=True)
class ScanTarget:
    """One ``sraverify`` invocation: an account type scanned through a profile."""

    account_type: str
    profile: str


def account_id_for(profile: str) -> str:
    """Return the account ID a profile authenticates to.

    Args:
        profile: An AWS profile name.

    Returns:
        The 12-digit account ID.

    Raises:
        SystemExit: If the profile cannot be resolved, which is almost always an
            expired SSO session.
    """
    result = subprocess.run(
        [
            "aws",
            "sts",
            "get-caller-identity",
            "--profile",
            profile,
            "--query",
            "Account",
            "--output",
            "text",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"local_scan: profile {profile!r} could not be resolved. If the "
            f"session has expired, refresh it and re-run.\n{result.stderr.strip()}"
        )
    return result.stdout.strip()


def run_one(
    target: ScanTarget,
    *,
    account_id: str,
    out: Path,
    regions: str,
    audit_accounts: str,
    log_archive_accounts: str,
    sraverify: str,
) -> Tuple[ScanTarget, int, Path]:
    """Run one invocation, capturing its stderr to its own file.

    Mirrors the buildspec's ``run_scan``: stderr to a per-invocation file, then
    the file replayed so the operator still sees it. Deliberately **not** passing
    ``--debug``, because the two records the gate reads -- ``check_done`` at
    ``info`` and ``aws_call_failed`` at ``error`` -- are visible at the default
    level, and ``--debug`` would bury them.

    Args:
        target: The account type and profile.
        account_id: The resolved account ID, for the file names.
        out: The output directory.
        regions: Comma-separated Region list.
        audit_accounts: Value for ``--audit-account``.
        log_archive_accounts: Value for ``--log-archive-account``.
        sraverify: Path to the console script.

    Returns:
        ``(target, exit_status, csv_path)``.
    """
    raw = out / "raw"
    stderr_dir = out / "stderr"
    raw.mkdir(parents=True, exist_ok=True)
    stderr_dir.mkdir(parents=True, exist_ok=True)

    csv_path = raw / f"{account_id}-{target.account_type}.csv"
    log_path = stderr_dir / f"{account_id}-{target.account_type}.log"

    command = [
        sraverify,
        "--profile",
        target.profile,
        "--account-type",
        target.account_type,
        "--regions",
        regions,
        "--output",
        str(csv_path),
    ]
    if audit_accounts:
        command += ["--audit-account", audit_accounts]
    if log_archive_accounts:
        command += ["--log-archive-account", log_archive_accounts]

    with log_path.open("w", encoding="utf-8") as log_handle:
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=log_handle, text=True
        )

    print(
        f"  {target.account_type:<12} {account_id}  exit={result.returncode}  "
        f"stderr={log_path.name}"
    )
    return target, result.returncode, csv_path


def consolidate(out: Path) -> Tuple[Path, int]:
    """Merge every per-invocation CSV into one consolidated file.

    Every cell is read and written as a string. The buildspec's pandas step needs
    ``dtype=str`` for the same reason: without it a 12-digit ``AccountId`` is
    type-inferred as ``int64`` and loses a leading zero, and a single blank cell in
    the column makes it ``float64`` so every ID gains a ``.0``. Using the ``csv``
    module sidesteps the question entirely and drops the pandas dependency.

    Args:
        out: The output directory.

    Returns:
        ``(consolidated_path, row_count)``.

    Raises:
        SystemExit: If a per-invocation CSV has unexpected columns.
    """
    raw = out / "raw"
    consolidated = out / "consolidated.csv"
    rows: List[Dict[str, str]] = []

    for path in sorted(raw.glob("*.csv")):
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != FIELDS:
                raise SystemExit(
                    f"local_scan: {path} does not carry the 16 contract columns "
                    f"in order.\n  expected: {FIELDS}\n  found:    "
                    f"{tuple(reader.fieldnames or ())}"
                )
            rows.extend(dict(row) for row in reader)

    with consolidated.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=list(FIELDS), lineterminator="\r\n"
        )
        writer.writeheader()
        writer.writerows(rows)

    return consolidated, len(rows)


def main(argv: Sequence[str] | None = None) -> int:
    """Run every requested invocation and consolidate.

    Args:
        argv: Command line, for testing.

    Returns:
        ``0`` when every invocation exited ``0`` and rows were produced.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--regions", default="us-east-1,us-east-2,us-west-1,us-west-2"
    )
    parser.add_argument("--audit-account", default="")
    parser.add_argument("--log-archive-account", default="")
    parser.add_argument(
        "--scan",
        action="append",
        default=[],
        metavar="ACCOUNT_TYPE=PROFILE",
        help="repeatable; e.g. --scan audit=schiefj+codeaudit-Admin",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=4,
        help="concurrent invocations, mirroring the buildspec's parallel -j",
    )
    parser.add_argument(
        "--sraverify",
        default=str(Path(sys.executable).parent / "sraverify"),
        help="path to the sraverify console script (default: alongside this "
        "interpreter, so the working tree's editable install is used)",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="remove --out first, so a re-run cannot mix artefacts from two scans",
    )
    args = parser.parse_args(argv)

    targets: List[ScanTarget] = []
    for spec in args.scan:
        account_type, _, profile = spec.partition("=")
        if not account_type or not profile:
            raise SystemExit(f"local_scan: --scan expects TYPE=PROFILE, got {spec!r}")
        targets.append(ScanTarget(account_type.strip(), profile.strip()))

    if not targets:
        raise SystemExit("local_scan: at least one --scan is required")

    if not Path(args.sraverify).is_file():
        raise SystemExit(
            f"local_scan: {args.sraverify} not found. Install the working tree "
            f"with `pip install -e ./sraverify` so the scan runs the code under test."
        )

    if args.clean and args.out.exists():
        shutil.rmtree(args.out)
    args.out.mkdir(parents=True, exist_ok=True)

    print("Resolving profiles...")
    resolved = {target: account_id_for(target.profile) for target in targets}
    for target, account_id in resolved.items():
        print(f"  {target.account_type:<12} {target.profile} -> {account_id}")

    print(f"\nScanning {len(targets)} invocation(s), regions={args.regions}")
    failures: List[Tuple[ScanTarget, int]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = [
            pool.submit(
                run_one,
                target,
                account_id=resolved[target],
                out=args.out,
                regions=args.regions,
                audit_accounts=args.audit_account,
                log_archive_accounts=args.log_archive_account,
                sraverify=args.sraverify,
            )
            for target in targets
        ]
        for future in futures:
            target, status, _ = future.result()
            if status != 0:
                failures.append((target, status))

    consolidated, count = consolidate(args.out)
    print(f"\nConsolidated {count} rows -> {consolidated}")

    stderr_files = sorted((args.out / "stderr").glob("*.log"))
    markers = sum(
        line.count("check_done ")
        for path in stderr_files
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
    )
    failures_logged = sum(
        line.count("aws_call_failed ")
        for path in stderr_files
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
    )
    print(
        f"{len(stderr_files)} stderr file(s), {markers} check_done marker(s), "
        f"{failures_logged} aws_call_failed record(s)"
    )

    if failures:
        for target, status in failures:
            print(
                f"WARNING: {target.account_type} via {target.profile} exited "
                f"{status}",
                file=sys.stderr,
            )
        # Exit 1 rather than 0: a missing invocation means the consolidated CSV
        # is short, and gating on a short CSV would read every absent row as a
        # removed row.
        return 1

    if count == 0:
        print("ERROR: no rows were produced", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
