# Product

## What this is

**SRA Verify** is a read-only security assessment tool that audits an AWS Organization against the [AWS Security Reference Architecture (SRA)](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html). The SRA is AWS prescriptive guidance describing a multi-account security layout: a management account, a dedicated Audit / Security Tooling account, a Log Archive account, and application (member) accounts, with services like GuardDuty, Security Hub, Macie, and Config delegated-administered out of the Audit account.

The SRA is a document, not a control. SRA Verify turns its recommendations into executable checks and produces an auditable report, so a team can answer "are we actually implementing the SRA?"

## Scope and boundaries

- **Read-only.** Checks call `Describe*` / `Get*` / `List*` APIs only. They never remediate, never mutate. Remediation is emitted as text in the finding, not performed.
- **Assessment, not enforcement.** Output is a report. There is no blocking, no policy deployment.
- Currently **158 checks across 18 AWS services** (guardduty 25, securitylake 17, shield 14, cloudtrail 13, inspector 11, securityhub 11, firewallmanager 10, macie 10, config 9, organizations 9, waf 9, securityincidentresponse 5, accessanalyzer 4, s3 4, account 3, auditmanager 2, ec2 1, iam 1).

## Users

AWS Worldwide Public Sector security teams and their customers running AWS Organizations. The tool is normally run from the Audit (Security Tooling) account, assuming a member role into each account in the org.

## Output

- **CSV** — the primary artifact, `sraverify_findings_YYYYMMDD_HHMMSS.csv`, with a fixed 16-column schema. One row per finding. `Status` is `PASS`, `FAIL`, or `ERROR` — nothing else is legal. The single authoritative declaration of the column names and their order is `Finding.FIELDS` in `core/finding.py`; `structure.md` carries the detail.
- **HTML dashboard** — `sra-verify-dashboard.html` and `sra-verify-comparison-dashboard.html` are standalone single-file viewers. Typical flow: upload the dashboard to S3, open it, and paste an S3 presigned URL of the findings CSV into it. The dashboard can also emit a markdown digest for pasting into an LLM.

A report is always written when the scan runs, even with zero findings, so a consumer can tell "scan ran, nothing found" from "scan did not run". A usage error writes no file at all. See `tech.md` for the exit codes that distinguish these.

## Delivery models

1. **CodeBuild** (primary) — CloudFormation-deployed project that walks the whole org and consolidates results into S3.
2. **Local CLI** — `sraverify --regions us-east-1,us-west-2`.
3. **Python library** — `from sraverify import SRAVerify`.
4. **MCP server** — `sra-verify-mcp/` wraps the library as an MCP tool surface.

## Product principles for check authors

- **Security-first.** Fail on a misconfiguration even when the feature is nominally "enabled" (e.g. a WAF rule set to Count rather than Block is a FAIL).

- **FAIL vs ERROR is a real distinction, and it is the most load-bearing rule here.** FAIL means AWS told us the control is not in place. ERROR means we could not determine whether it is. Never report an ERROR as a FAIL.

  - A semantic AWS error code meaning "the thing isn't configured" — `AWSOrganizationsNotInUseException` and its kin — is a **FAIL**. A permission or transport failure is an **ERROR**.
  - **Missing required input is an ERROR, not a FAIL.** Six checks used to report an absent `--audit-account` or `--log-archive-account` as FAIL; all six are fixed. The cost of getting this wrong is double: the dashboards count a FAIL as a finding, so a phantom FAIL sends someone chasing a misconfiguration that does not exist, *and* it hides the fact that the control was never evaluated at all.
  - The illustration worth remembering: `SRA-AUDITMANAGER-02` used to emit FAIL with `Expected audit accounts: []` when the flag was absent. Supply the flag and the same check PASSes — so the FAIL was reporting a misconfiguration that was not there.
  - **A non-regional condition is reported once**, with `region="global"`, not fanned out one row per region. A missing CLI flag is not a property of us-west-2.
  - `WARN` was never a legal `Status`. The three former `status="WARN"` sites now emit FAIL, on the reasoning that a partially configured control is a finding, not an inability to determine.

- **Remediation must be actionable.** Name the concrete step or console/CLI action, not "configure the service correctly." When the blocker is a missing input, the remediation names the flag to re-run with.
