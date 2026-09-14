"""CSV output for scan findings."""

from __future__ import annotations

import csv
from pathlib import Path

from sraverify.core.finding import Finding


def write_csv_output(findings: list[Finding], output_file: str) -> None:
    """Write *findings* to *output_file* as the 16-column contract CSV.

    The file is always created, even for an empty findings list, so a
    downstream consumer can distinguish "scan ran, nothing found" from
    "scan did not run". Column order comes from ``Finding.FIELDS`` and is a
    public contract parsed by sra-verify-dashboard.html and
    sra-verify-comparison-dashboard.html.

    Dialect is pinned explicitly -- encoding, line terminator, and quoting --
    so the emitted bytes do not vary with the host platform or locale.
    Raises OSError if the path cannot be opened; no directory is created.

    Args:
        findings: Findings to render, in output order. Left unmodified, as is
            every element: there is no missing-field backfill and no legacy
            ``CheckType`` migration, because a ``Finding`` has no uncertain
            shape.
        output_file: Complete path to the CSV file to write. Any existing
            content at that path is replaced.
    """
    with Path(output_file).open(
        "w",
        newline="",              # csv owns line endings; no universal-newline translation
        encoding="utf-8",        # explicit, NOT the locale default
        errors="strict",         # never silently substitute a character
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=Finding.FIELDS,
            lineterminator="\r\n",   # the csv module default, pinned
            quoting=csv.QUOTE_MINIMAL,
            quotechar='"',
            doublequote=True,        # an embedded " is written as ""
        )
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding.to_row())
