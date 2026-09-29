---
inclusion: always
---

# Testing checks against live AWS

This file is authoritative for **validating new or changed checks against a real organization**: the order of work, what counts as a pass, how to mutate and restore safely, and how to exercise the CodeBuild path. `creating_checks_best_practices.md` owns how a check is written; this file owns how it is proven. A green unit suite proves nothing about AWS facts, so no check is done until it has been through this.

## The test environment

The accounts, AWS profiles, and what may be changed live in **`sratester/accounts.md`**. That directory is gitignored, so account IDs and profile names never belong in this file or anywhere else under `.kiro/`, which is tracked and published. Read it before starting:

#[[file:sratester/accounts.md]]

Resolve account IDs at run time with `aws sts get-caller-identity --profile <profile>`; do not hard-code them in scripts that might be committed.

## Two modes, both legitimate

- **Validate** — the checks are believed correct; prove they detect and clear.
- **Build and validate** — a test run that exposes a defect is expected to fix it, re-run the suite, and **re-test the affected check from Phase 1**. A fix is not done until the live run agrees.

Report every defect found, including ones you fixed, with the observed AWS behaviour that exposed it.

## Order of work

Do these in order. Each step is cheaper than the next and usually settles something the next one would otherwise waste time on.

1. **Probe the API live, read-only, before trusting a draft.** Response shapes, error codes, and enum values in botocore and the docs are frequently incomplete. Write a small probe that calls each operation the check uses from each account type it can run in, and record what came back. Every `NOT_CONFIGURED_ERRORS` entry needs an observed error from this step or an API reference page; never declare a code you inferred.
2. **Read-only negative runs.** Most FAIL and ERROR arms can be reached without changing anything:
   - Regions the org does not use (a service genuinely absent there).
   - `--regions` narrowed to exclude a home Region (trips home-Region guards).
   - The check run from the wrong account type (e.g. audit checks with the management profile).
   - A required flag omitted, or given a wrong account ID.
3. **Snapshot** every resource you are about to change into `.tmp/sratester/snapshot.json`, byte for byte (policy content, rule state, targets, linked Regions, finding status).
4. **Mutate → detect → fix → validate**, one check at a time (the five phases below).
5. **Verify restoration** with a script that re-reads every snapshotted resource and compares it, and include its output in the report. "I reverted it" is not evidence.
6. **IAM.** Simulate every new action against the deployed member role with `aws iam simulate-principal-policy` (the role cannot be assumed from an Admin profile), and the edited template with `simulate-custom-policy`. Deploy `1-sraverify-member-roles.yaml` (StackSet and the management-account stack) before any CodeBuild run.
7. **CodeBuild end to end** (below).

## The five phases

| Phase          | Action                                                        | Expected                                                           |
| -------------- | ------------------------------------------------------------- | ------------------------------------------------------------------ |
| 1 Baseline     | Run the check unchanged                                       | Record the verdict and *why*; question a PASS as hard as a FAIL    |
| 2 Misconfigure | Smallest reversible change that breaks exactly this control   | —                                                                  |
| 3 Detect       | Re-run                                                        | FAIL, naming the resource and the reason; unrelated rows unchanged |
| 4 Fix          | Apply the correct configuration (often: restore the snapshot) | —                                                                  |
| 5 Validate     | Re-run                                                        | PASS, or back to the Phase 1 verdict                               |

If the baseline is FAIL, invert 2–5: fix to reach PASS, then restore to the baseline FAIL. Either way the check must be seen producing **both** verdicts.

Prefer a **scoped** mutation that flips one account or one Region (a child policy on one account, suppressing one account's findings) over an org-wide one, and confirm in Phase 3 that only that row moved. Where AWS state needs time to propagate (Organizations effective policies, finding status), wait and say how long.

**Run mutation sequences strictly sequentially per check.** Drive each check's phases from one script that finishes each mutation and wait before starting the scan. Parallel runs on the same resource interleave and produce results that look valid and are not. Independent checks touching different resources may run in parallel.

## Gates for every scan

Run with `--debug` and keep stderr. A scan passes only if:

- 0 synthetic rows (an ERROR whose `ActualValue` names a Python exception rather than `"<Operation> failed: <Code>: …"`).
- 0 `- ERROR -` log records, and no `No client available`.
- Every ERROR row is explained: wrong account, missing flag, home Region not scanned, or a known permission gap.
- `aws_call_failed` count is plausible for the scan (count it; a jump means something new is failing).

Also run `pytest` after any code change, and `cmp` a regenerated `sraverify --list-checks` against `docs/checks.txt`.

## Do not mutate without explicit sign-off, even in the test org

- **The Security Hub / GuardDuty / other delegated administrator.** Deregistering the Security Hub DA removes it from CSPM *and* V2 and opts the org out of central configuration. Exercise the comparison through `--audit-account` instead.
- **Control Tower baseline resources** (`aws-controltower-*` recorders, trails, StackSets). Changes cause drift that needs a landing-zone re-baseline.
- **Org-wide enablement of billable features** (Macie discovery, GuardDuty plans, Shield Advanced, support plans).
- **Disabling a service** in a Region, which discards its findings and inventory.

When one of these is the only way to reach an arm, say so in the report and mark the check 🔄 with the reason.

## CodeBuild end to end, without editing the project

The deployed project clones the public repo, so it tests `main`, not the working tree. To test local code, run one build with a `buildspecOverride` whose only change replaces the `git clone -b $GIT_BRANCH …` line with a copy of a tarball uploaded to the findings bucket:

- Tar the repo paths the buildspec uses — `sraverify/` **and** `sra-verify-dashboard.html` (POST_BUILD copies it; omit it and the build reports FAILED after a successful scan).
- Exclude `.venv`, `build`, `dist`, `*.egg-info`, `__pycache__`, `.hypothesis`.
- Delete the tarball afterwards.

Judge the result from the consolidated CSV in `sraverify/reports/consolidated/`, not the build status: new checks' row counts per account, **0 ERROR rows from the new checks**, and the total ERROR count compared with the previous consolidated report (a change should be explainable by the new rows alone).

## Lessons that were expensive to learn

- **A baseline PASS can be the defect.** SRA-SECURITYHUB-20 first passed on an EventBridge rule filtering on the CSPM (ASFF) schema that no V2 event can match. Read what a PASS matched.
- **Aggregated views hide what they don't aggregate.** Reading only an aggregation home Region misses Regions that are not linked to it. Read every scanned Region.
- **Remediation text is testable — test it.** Run the CLI a FAIL row recommends during Phase 4; `UpdateAggregatorV2` rejected the `ALL_REGIONS` mode the first draft suggested.
- **IAM action names are not always operation names.** `GetFindingsV2` is authorized by `securityhub:GetFindings`; check the API reference and `simulate-principal-policy` rather than trusting the generator.
- **Inferred error codes are wrong often enough to matter.** Declare only what was observed.

## Report

Write the final report to **`sratester/<feature>-test-report.md`** (e.g. `sratester/ai-coverage-checks-test-report.md`, `sratester/securityhub-v2-checks-test-report.md`), next to `accounts.md`. `sratester/` is gitignored, so the report can name real account IDs and resources. Keep the raw CSVs, stderr, probes and mutation scripts in `.tmp/sratester/`, and reference them from the report by path. Include:

- A status table per check: ✅ TESTED (both verdicts seen), 🔄 ATTEMPTED (reason), ❌ BLOCKED (only for an actual IAM/SCP denial).
- Per check: the phase table with the exact mutation and the observed row text.
- Gate results, IAM simulation results, and the CodeBuild comparison.
- Defects found and how they were fixed.
- The restoration verification output.

Only the final report goes in `sratester/`; all scratch output goes under `.tmp/sratester/`. Both are gitignored, and nothing test-specific is written into the tracked tree.
