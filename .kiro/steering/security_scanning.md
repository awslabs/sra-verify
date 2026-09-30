---
inclusion: always
---

# Security scanning before commit

This file is authoritative for **scanning a change with ASH before it is committed**: when to run it, what counts as clean, and how a finding is fixed or dispositioned. It covers every change: checks, clients, the CLI, tests, and the two CloudFormation templates. `testing_checks.md` owns proving a check against live AWS; this file owns proving the tree is clean.

The scanner configuration lives in `.ash.yaml` at the repo root. Its header carries the pinned ASH version and the reasoning behind each scanner's pin. Read it before changing scanner settings.

## When and how

Run ASH after the unit suite is green and before proposing a commit message:

```bash
uv tool run --from automated-security-helper==3.7.0 ash --source-dir . --mode local
```

Keep the ASH version in this command identical to the one in the `.ash.yaml` header. A different ASH version brings different rules and scanner versions, so its results cannot be compared.

Read the result from `.ash/ash_output/reports/ash.summary.md`. The `.ash/` directory is gitignored. A scan is **clean** only when:

- every enabled scanner reports **PASSED**, with 0 actionable findings at the `MEDIUM` global threshold;
- no scanner reports **ERROR** or **MISSING**. MISSING means the scanner never ran; it is not a pass.
- the only **SKIPPED** scanners are the ones disabled deliberately (below).

Low and Info findings do not fail the scan, but do not let a new category of them accumulate unexamined.

## Scanner selection

| Scanner        | State    | Covers / reason                                          |
| -------------- | -------- | -------------------------------------------------------- |
| bandit         | enabled  | The Python package and tests                             |
| checkov        | enabled  | The two CloudFormation templates                         |
| cfn-nag        | enabled  | The same templates, different rule set                   |
| detect-secrets | enabled  | Secrets in any tracked file                              |
| grype          | enabled  | Known vulnerabilities in `sraverify/uv.lock`             |
| opengrep       | enabled  | Pattern rules over the source                            |
| cdk-nag        | disabled | No CDK app; templates are covered by checkov and cfn-nag |
| npm-audit      | disabled | No npm lockfile                                          |
| semgrep        | disabled | Duplicates opengrep, which needs no account or metrics   |
| syft           | disabled | SBOM only; grype does the vulnerability scan             |

**Omitting a scanner from `.ash.yaml` does not disable it.** Every built-in scanner defaults to enabled, so a scanner is turned off only by `enabled: false`. Re-enable one when the repo gains what it scans, for example a `package.json` for npm-audit.

## Fixing or dispositioning a finding

Fix the code first. Suppress only a finding that has been confirmed to be a false positive, or an accepted design decision. Every suppression covers **one line or one resource** and carries its reason next to it. There is no global allowlist, no rule excluded across a directory, and no rule-level `suppressions:` block in `.ash.yaml`.

- **bandit.** Prefer a code change. `exec` of a literal string in the registration tests was replaced with `type(name, (SecurityCheck,), {"__module__": ...})`, which `__init_subclass__` reads identically. If a line genuinely needs the construct, write `# nosec B<NNN>` on that line with the reason. B101 (`assert`) findings are Low and do not fail the scan.
- **checkov** (CloudFormation). Add a `checkov` block under the resource's `Metadata`, alongside any `cfn_nag` block:

  ```yaml
  Metadata:
    cfn_nag:
      rules_to_suppress:
        - id: W35
          reason: No bucket logging needed.
    checkov:
      skip:
        - id: CKV_AWS_18
          comment: No bucket logging needed.
  ```

  The key names differ from cfn_nag's: `skip` rather than `rules_to_suppress`, and `comment` rather than `reason`. Where a checkov ID and a cfn_nag ID flag the same control, give them the same justification.
- **cfn-nag.** Add a `Metadata.cfn_nag.rules_to_suppress` entry with an `id` and a `reason`.
- **detect-secrets.** Put `# pragma: allowlist secret` on the flagged line, followed by the reason. This is detect-secrets' own marker, so it applies to that line only.
- **A generated or cache directory**: add it to `global_settings.ignore_paths` in `.ash.yaml` with a `reason`. Use this only for content that is never committed.

A template change must also pass `aws cloudformation validate-template`.

## Known false positives

Each of these has been checked and is not a secret:

- **`.pytest_cache/CACHEDIR.TAG`**: pytest's fixed signature constant. Handled by the `**/.pytest_cache/**` ignore path.
- **The access key and secret key in `test_availability_property.py`**: AWS's published documentation example credentials, both ending in `EXAMPLE`. Deliberately not quoted here, because quoting them would make this file a detect-secrets finding too. `tests/conftest.py` refuses all outbound HTTP, so they are never sent.
- **Hypothesis alphabets** (`"abcdef...z_"`, `"ABC...Z0123456789-_"`): these trip the high-entropy detectors.
- **ARN segments** such as `log-source/LAMBDA_EXECUTION`: also high-entropy by the detector's measure.

When one of these moves, its inline pragma must move with it.

## Commit message

Only once the scan is clean, propose the one-line commit message. If a finding was dispositioned rather than fixed, say which one and why in the reply.
