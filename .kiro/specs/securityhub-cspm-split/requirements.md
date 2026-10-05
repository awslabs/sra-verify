# Requirements Document

**Feature:** Security Hub CSPM split and missing CSPM checks

**Spec directory:** `.kiro/specs/securityhub-cspm-split/`

**Inputs:** the user request ("split security hub / security hub cspm into two different services (if that makes sense), and add the missing checks from the check-report.md for security hub cspm (where it makes sense)"); `docs/check-report.md` (the SRA checklist coverage map, 2026-09-25 revision); the twenty modules under `sraverify/sraverify/services/securityhub/`; the six steering files; and the AWS Security Hub CSPM API reference, read for every operation this document cites.

## Introduction

AWS now ships two products behind one boto3 service id. **AWS Security Hub CSPM** is the classic product: the hub resource, the ASFF finding format, security standards and controls, finding aggregators, central configuration policies, and the `Security Hub Findings - Imported` EventBridge event. **AWS Security Hub** (internally V2, the console at `securityhub/v2`) is the unified product: `DescribeSecurityHubV2`, the OCSF finding format, the `SecurityHubV2` delegated-administrator feature, the `SECURITYHUB_POLICY` Organizations policy type, the `AggregatorV2` resource, coverage findings, and the `Findings Imported V2` event. Both are reached through `boto3.client("securityhub")`, both are authorized by `securityhub:*` IAM actions, and both are enabled, delegated and aggregated independently of each other: the 2026-09-16 probe found V2 enabled in a Region where CSPM was not subscribed.

The scanner's `services/securityhub/` package already covers both. `SRA-SECURITYHUB-01` through `-13` read the CSPM surface and `SRA-SECURITYHUB-14` through `-20` read the V2 surface, and `docs/check-report.md` records that classification. But every one of the twenty declares `service="SecurityHub"`, so the report's `Service` column, the dashboards' service grouping, `--list-services` and the `--service` filter present them as one service. An operator who wants only the CSPM rows, or only the V2 rows, has no filter that gives them that.

`docs/check-report.md` also lists seventeen checklist items under *AWS Security Hub CSPM*: six Covered, five Partial, six Missing. The Partial and Missing items that are read-only verifiable through the CSPM API and are not already asserted by another check are: findings from all Regions aggregated to a single home Region (item 9); all OUs and member accounts designated centrally managed (item 6); the FSBP standard enabled for all member accounts (item 11); the CIS AWS Foundations Benchmark standard enabled for all member accounts (item 12); and custom EventBridge rules for automated response (item 16). The remaining Partial and Missing items are either a different service's API (Detective, CloudWatch telemetry), a judgement about customer-authored content (automation rule enrichment), a restatement of controls other checks already hold (member aggregation, "other standards"), or a V2 fact already covered by `SRA-SECURITYHUB-19` (CSPM consumed for exposure correlation). Requirement 13 lists each with its reason.

This feature answers both halves of the request. For the split, the design chooses a **soft split**: the twenty existing checks keep their IDs, their modules, their package and their rows, and only `meta.service` changes — `"Security Hub CSPM"` on the thirteen CSPM checks and `"Security Hub"` on the seven V2 checks — because `--service` is a full-value, case-insensitive match on `meta.service`, so two display names already give the filter boundary the user asked for. A full split that relocated checks into a second package would renumber existing check IDs, and `CheckId` is the first component of the comparison dashboard's join key (`CheckId||AccountId||Region||ResourceId`): every row of a renumbered check would appear as one removal and one addition in every comparison against a prior report. Steering defers even a `Region` or `ActualValue` cell move for that reason; a `CheckId` move is strictly worse. The design document's decision record weighs four options and records why the others were not taken. For the gaps, five new checks, `SRA-SECURITYHUB-21` through `-25`, are added to the existing package with `service="Security Hub CSPM"`.

The one cell this feature moves on existing rows is `Service`, on every Security Hub row. It is not part of any join key, the dashboards derive their service lists from the data rather than from a hard-coded list, and the `CheckedValue` default `f"{service} Configuration"` is never reached by a Security Hub check (every one of the twenty passes `checked_value` explicitly on every helper call). The ERROR-row `Remediation` text that `_remediation_for` composes from `self.service` does change wording, and an operator script that passes `--service SecurityHub` — which today selects all twenty checks — will after this change exit 2 with `NoChecksSelectedError` and create no file, the existing contract for a real-but-empty filter (exit 2 rather than the header-only report the CLI used to write). Requirement 2 pins exactly which cells may move and which may not.

Two `NOT_CONFIGURED_ERRORS` entries this feature could plausibly need — `ListFindingAggregators` and `ListConfigurationPolicyAssociations` answering the overloaded codes the table already declares for their sibling operations — are **not declared on inference**. The design names the exact entry and the exact golden row for each, and Requirement 9 makes adding either conditional on observing the error from a controlled account during the read-only API probe. That probe is the first step of the work, ahead of any code, as `testing_checks.md` orders it: it also settles whether `GetFindingAggregator` answers from a non-home Region and whether inherited accounts are listed as their own `ACCOUNT` association summaries, both of which shape code the implementer would otherwise write twice. Until an entry is observed, its pair resolves to ERROR, which is the conservative default the contract is built on.

## Glossary

### Domain terms

- **Security Hub CSPM**: The classic product. Operations without a `V2` suffix: `DescribeHub`, `GetEnabledStandards`, `DescribeOrganizationConfiguration`, `ListMembers`, `ListFindingAggregators`, `GetFindingAggregator`, `ListConfigurationPolicies`, `GetConfigurationPolicy`, `ListConfigurationPolicyAssociations`, `ListOrganizationAdminAccounts` without `Feature`. Findings are ASFF; the EventBridge detail-type is `Security Hub Findings - Imported`.
- **Security Hub (V2)**: The unified product. `DescribeSecurityHubV2`, `ListAggregatorsV2`, `GetAggregatorV2`, `GetFindingsV2`, `ListOrganizationAdminAccounts` with `Feature=SecurityHubV2`, the `SECURITYHUB_POLICY` Organizations policy type. Findings are OCSF; the detail-type is `Findings Imported V2`.
- **CSPM check**: `SRA-SECURITYHUB-01` – `-13`, and the five new checks `-21` – `-25`.
- **V2 check**: `SRA-SECURITYHUB-14` – `-20`.
- **Soft split**: Changing `meta.service` so the two groups carry different display names, with no change to check IDs, modules, package, base class, client, cache namespace or row keys.
- **Display name**: The `meta.service` string. `"Security Hub CSPM"` for CSPM checks, `"Security Hub"` for V2 checks. The convention in the catalog drops the `AWS`/`Amazon` prefix (`"GuardDuty"`, `"Security Lake"`, `"IAM Access Analyzer"`).
- **Home Region**: The Region a CSPM finding aggregator designates as the aggregation Region (`FindingAggregationRegion`). The configuration-policy and association operations may only be called there, by the delegated administrator. Resolved from the aggregator ARN by `SecurityHubCheck.home_region_of`.
- **Finding aggregator**: The CSPM resource that establishes the home Region and linked Regions. `RegionLinkingMode` is one of `ALL_REGIONS`, `ALL_REGIONS_EXCEPT_SPECIFIED`, `SPECIFIED_REGIONS`, `NO_REGIONS`; `Regions` is the excluded or included list depending on the mode.
- **Configuration policy association**: The record, per account, OU or root, of which configuration policy (or `SELF_MANAGED_SECURITY_HUB`) governs it, whether `APPLIED` directly or `INHERITED`, and whether the association is `PENDING`, `SUCCESS` or `FAILED`. `ListConfigurationPolicyAssociations` accepts an `AssociationType` filter (`API_AssociationFilters.html`) and each summary carries `AssociationType` (`API_ConfigurationPolicyAssociationSummary.html`), which is the documented basis for the design's reading that inherited targets are listed; the probe confirms it.
- **Disassociation**: `StartConfigurationPolicyDisassociation` (`API_StartConfigurationPolicyDisassociation.html`). Removes a directly applied configuration from a target, which then inherits the configuration of its closest parent. It is the only operation that restores an `INHERITED` association after a direct `APPLIED` mutation; re-associating the parent's policy to the account would leave it `APPLIED`.
- **Centrally managed**: An account whose association names a configuration policy (not `SELF_MANAGED_SECURITY_HUB`) with `AssociationStatus` `SUCCESS`.
- **Standards subscription**: One entry of `GetEnabledStandards`, carrying `StandardsArn` and `StandardsStatus` (`PENDING`, `READY`, `FAILED`, `DELETING`, `INCOMPLETE`). Only `READY` is evaluating.
- **FSBP**: The AWS Foundational Security Best Practices standard, `arn:aws:securityhub:<region>::standards/aws-foundational-security-best-practices/v/1.0.0`.
- **CIS**: The CIS AWS Foundations Benchmark. Four versions are current: `…::standards/cis-aws-foundations-benchmark/v/5.0.0`, `/v/3.0.0`, `/v/1.4.0`, and the legacy `arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0`, whose ARN uses `ruleset/` rather than `standards/`.
- **Cell-stable**: For every existing row joined on (`CheckId`, `AccountId`, `Region`, `ResourceId`), every column except the ones Requirement 2 names is byte-identical between the tree before and after this feature.
- **Probe-gated entry**: A `NOT_CONFIGURED_ERRORS` entry whose text is written in the design but is added to the table only once the live probe has observed the exact code and message from a controlled account.

### System names used in acceptance criteria

- **Check_Catalog**: The registered checks, 182 before this feature and 187 after.
- **SecurityHub_Package**: `sraverify/sraverify/services/securityhub/` — `base.py`, `client.py`, `checks/`.
- **SecurityHub_Base**: `SecurityHubCheck` in `base.py`, with its `NAMESPACE`, `NOT_CONFIGURED_ERRORS`, accessors and static helpers.
- **SecurityHub_Client**: `SecurityHubClient` in `client.py`.
- **New_Checks**: `SRA_SECURITYHUB_21` – `SRA_SECURITYHUB_25`.
- **Contract_Tests**: the property and unit suite under `sraverify/sraverify/tests/`, in particular `test_client_contract_property.py`, `test_accessor_cache_property.py`, `test_discriminator_property.py`, `test_check_classification_property.py`, `test_layering_property.py`, `test_catalog_identity_property.py`, `test_registry_bijection_property.py`.
- **IAM_Generator**: `util/generate_iam_policy.py` and its two artefacts.
- **Member_Role_Template**: `1-sraverify-member-roles.yaml`.
- **Catalog_Inventory**: `docs/checks.txt`.
- **Coverage_Report**: `docs/check-report.md`.
- **Steering_Docs**: `.kiro/steering/*.md` and `sraverify/README.md`.
- **Acceptance_Gate**: the live validation under `testing_checks.md`: read-only negative runs, scoped mutations, restoration proof, IAM simulation, CodeBuild run. The read-only **probe** that precedes it is Requirement 12.1 but runs at the start of the work, before any code is written, and is re-run as the Acceptance_Gate's first step only to confirm nothing moved.

## Non-Goals

1. **A second service package.** No `services/securityhubcspm/` or `services/securityhubv2/`, no new `<Service>Check` base, no new `NAMESPACE`, no new client module. The decision record in `design.md` says why; the short version is that two bases cannot share accessors without violating the layering rule that a base inherits only `SecurityCheck`, and two tables classifying the same `(operation, code)` pairs is the drift the single-table design exists to prevent.
2. **Renumbering or relocating any existing check.** No `CheckId`, module path, class name or package changes for `SRA-SECURITYHUB-01` – `-20`.
3. **Fixing known defects in the existing checks.** `sra_securityhub_01`'s dead `"/standards/"` split and `sra_securityhub_08`'s set-built `ActualValue` stay as `structure.md` records them.
4. **Checks that need a service package this repository does not have**: Amazon Detective (checklist item 4's other half), CloudWatch Observability Admin telemetry rules (item 17).
5. **An automation-rule check** (item 15). `ListAutomationRules` and `BatchGetAutomationRules` are read-only and could establish that an ENABLED rule exists, but "enriches findings with resource context" is a judgement about the rule's `FindingFieldsUpdate` content that the scanner has no basis to make; an existence check would PASS a rule that suppresses findings.
6. **Renaming the `no_client_result(service="SecurityHub", …)` message** in `SecurityHubCheck._cached_call`. It is the `Message` of a `NoClient` ERROR result, not a `Service` cell, and leaving it keeps the diff to the one field the feature is about.
7. **Dashboard edits.** Both dashboards build their service lists from the CSV; nothing is hard-coded.
8. **Declaring `AWSOrganizationsNotInUseException` from `ListAccounts` differently.** The new association check reads `self.organization.accounts()` and uses the provider's existing classification.

## Requirements

### Requirement 1: Two display names, one package

**User Story:** As an operator, I want `--service "Security Hub CSPM"` and `--service "Security Hub"` to select the two products separately, so that a CSPM-only or V2-only scan and a per-product dashboard grouping are possible without renumbering anything.

#### Acceptance Criteria

1. THE SecurityHub_Package SHALL set `meta.service` to `"Security Hub CSPM"` on `SRA-SECURITYHUB-01` through `-13` and on the New_Checks, and to `"Security Hub"` on `SRA-SECURITYHUB-14` through `-20`. Both values satisfy `CheckMeta` rule 4 (whitespace-normalized) and the 60-character cap.
2. THE Check_Catalog SHALL keep every existing `check_id`, class name, module path and package unchanged, so that `__init_subclass__`'s four-way identity cross-check passes with no edit outside the `meta.service` line in each of the twenty modules.
3. WHEN `sraverify --service "Security Hub CSPM"` runs, THE scanner SHALL select exactly the eighteen CSPM checks (thirteen existing plus five new), and WHEN `--service "Security Hub"` runs it SHALL select exactly the seven V2 checks; neither value SHALL match the other's checks, because `select_checks` compares the full lowercased value.
4. WHEN `sraverify --service SecurityHub` runs after this change, THE CLI SHALL exit 2 with `NoChecksSelectedError` and create no file, which is the existing behaviour for a real-but-empty filter. The README's `--service` example (`--service CloudTrail`, `README.md:231`) is unaffected and SHALL NOT be changed; the README's service list (`README.md:5`) SHALL name `Security Hub CSPM` and `Security Hub` in place of `Security Hub`, and its stale "158 automated security checks" count SHALL be corrected to 187 in the same edit.
5. THE scanner's `--list-services` SHALL list `Security Hub` and `Security Hub CSPM` as two entries and SHALL no longer list `SecurityHub`.
6. THE SecurityHub_Base, SecurityHub_Client, `NAMESPACE`, cache keys and `NOT_CONFIGURED_ERRORS` SHALL be shared by both groups unchanged; the split is a metadata fact and nothing else.

### Requirement 2: Cell stability on existing rows

**User Story:** As a consumer diffing two consolidated reports, I want to know exactly which cells this feature moves, so that a diff between the tree before and after it measures the feature and nothing else.

#### Acceptance Criteria

1. FOR every row an existing check emitted before this feature, joined on (`CheckId`, `AccountId`, `Region`, `ResourceId`), THE Check_Catalog SHALL emit a row after this feature with identical `Status`, `Severity`, `Title`, `Description`, `ResourceType`, `CheckedValue`, `ActualValue`, `CheckLogic` and `AccountType`.
2. THE `Service` cell SHALL change on every Security Hub row, and on no other row; `"SecurityHub"` SHALL appear in no row's `Service` cell. (It legitimately remains in `ResourceType` cells such as `AWS::SecurityHub::Hub`, in `CheckLogic` text that names an operation, and in the `Message` of a `NoClient` ERROR result, per Non-Goal 6; a gate that greps the whole row for the token is the wrong gate.)
3. THE `Remediation` cell SHALL change only on ERROR rows whose remediation `_remediation_for` composed from `self.service` (the transport, `NoClient`, access-denied and generic buckets name the service); FAIL and PASS rows SHALL be unchanged, because no Security Hub check's FAIL or PASS remediation interpolates `self.service`.
4. THE `CheckedValue` cell SHALL be unchanged on every existing row: all twenty checks pass `checked_value` explicitly on every `passed()` / `failed()` / `error()` call, so the `f"{service} Configuration"` default is reached only by the orchestrator's synthetic and precondition rows, which report a defect or a failed identity lookup rather than a verdict.
5. THE row count per existing check per account SHALL be unchanged; the five New_Checks SHALL be the only source of new rows.
6. THE Acceptance_Gate SHALL demonstrate criteria 1–5 by diffing the consolidated CSV of a CodeBuild run on this tree against the previous consolidated report, with the Security Hub rows' `Service` column normalized, and SHALL report the number of rows that differ for any other reason (expected: zero).

### Requirement 3: SRA-SECURITYHUB-21 — CSPM cross-Region aggregation links every scanned Region

**User Story:** As a security operator, I want to know that the CSPM finding aggregator links every Region to the home Region, so that findings from all Regions are triaged in one place (checklist item 9).

#### Acceptance Criteria

1. THE New_Checks SHALL include `SRA_SECURITYHUB_21` in `checks/sra_securityhub_21.py`, `account_type=AccountType.AUDIT`, `severity=Severity.MEDIUM`, `resource_type="AWS::SecurityHub::FindingAggregator"`, with a title whose first token is not `Ensure`/`Check`.
2. THE check SHALL call `self.get_finding_aggregators(self.regions[0])` first, then resolve the home Region with `self.home_region_of(...)`, then call a new accessor `self.get_finding_aggregator(home_region, aggregator_arn)` that wraps `securityhub:GetFindingAggregator`.
3. WHEN `ListFindingAggregators` succeeds and names no aggregator, THE check SHALL yield one FAIL with `region="global"`.
4. WHEN the home Region is not in `self.regions`, THE check SHALL yield one ERROR with `region="global"` naming the home Region and the scanned Regions, before any `GetFindingAggregator` call, with a remediation that names `--regions`.
5. WHEN `GetFindingAggregator` succeeds, THE check SHALL compute the scanned Regions the aggregator does not link, using `FindingAggregationRegion`, `RegionLinkingMode` and `Regions` with the CSPM semantics (`ALL_REGIONS` links all; `ALL_REGIONS_EXCEPT_SPECIFIED` links all but `Regions`; `SPECIFIED_REGIONS` links only `Regions`; `NO_REGIONS` links none; the home Region is always covered), and SHALL yield one row labelled with the home Region: PASS when the uncovered list is empty, FAIL naming the uncovered Regions otherwise.
6. WHEN any accessor returns an error result, THE check SHALL decide FAIL versus ERROR through `self.is_not_configured(error)` and compose every ERROR `ActualValue` as `f"{Operation} failed: {Code}: {Message}"` with `remediation=self._remediation_for(error)`.

### Requirement 4: SRA-SECURITYHUB-22 — every active account is centrally managed

**User Story:** As a security operator, I want to know that every active account in the organization is governed by a configuration policy with a successful association, so that no account is self-managed or left in a failed association (checklist item 6).

#### Acceptance Criteria

1. THE New_Checks SHALL include `SRA_SECURITYHUB_22` in `checks/sra_securityhub_22.py`, `account_type=AccountType.AUDIT`, `severity=Severity.HIGH`, `resource_type="AWS::SecurityHub::PolicyAssociation"`.
2. THE check SHALL call `self.get_finding_aggregators(self.regions[0])` **first**, resolve the home Region, apply the same not-scanned guard as Requirement 3.4, then call a new accessor `self.get_configuration_policy_associations(home_region)` wrapping `securityhub:ListConfigurationPolicyAssociations` (every page merged), then `self.organization.accounts()`.
3. THE check SHALL filter the organization's accounts with `is_active_account` and SHALL evaluate every active account, including the delegated administrator and the management account, because the API reference states the delegated administrator can itself be a self-managed target.
4. FOR each active account, THE check SHALL yield one row labelled with the home Region, `resource_id` the account ID: PASS when an association summary with `TargetType` `ACCOUNT` and `TargetId` equal to the account names a `ConfigurationPolicyId` other than `SELF_MANAGED_SECURITY_HUB` and `AssociationStatus` `SUCCESS`; FAIL otherwise, with an `ActualValue` that says which of the three conditions failed — no association listed, self-managed, or a `PENDING`/`FAILED` status with its `AssociationStatusMessage` when present. This rests on `ListConfigurationPolicyAssociations` listing accounts governed through inheritance as their own `ACCOUNT` summaries with `AssociationType` `INHERITED`, which the API reference supports (`API_AssociationFilters.html` offers an `AssociationType` filter on this list operation; `API_ConfigurationPolicyAssociationSummary.html` documents `AssociationType` as "directly applied … or inherited from a parent") and which the probe in Requirement 12.1 SHALL confirm before the check is written.
5. WHEN `ListConfigurationPolicyAssociations` succeeds with an empty list, THE check SHALL still yield one FAIL per active account (no association listed) rather than one global row, because coverage is asserted per account.
5a. IF the probe shows that inherited accounts are **not** listed as `ACCOUNT` summaries, THE check SHALL instead resolve each account's governing association by walking `ROOT` and `ORGANIZATIONAL_UNIT` summaries against `self.organization.roots()`, `self.organization.ous_for_parent(parent_id)` and `self.organization.accounts_for_parent(parent_id)`, and the design's `association_of` helper SHALL be replaced by a resolver that takes the organization tree; this is a design change and SHALL be recorded in `design.md` before `sra_securityhub_22.py` is written.
6. WHEN `self.organization.accounts()` returns an error result, THE check SHALL use the two-arm shape — FAIL when `self.is_not_configured(error)` (the provider declares `ListAccounts` / `AWSOrganizationsNotInUseException`), ERROR otherwise — as one row with `region=home_region`.
7. THE check SHALL read the account list exactly once as `self.organization.accounts()`, so `test_layering_property.py`'s consumer list gains `securityhub/checks/sra_securityhub_22.py` and its count moves from fifteen to sixteen.
8. WHEN the account under evaluation is the organization management account (`self.organization.management_account_id()`, an existing provider accessor over the cached `DescribeOrganization` result; an error result from it means "unknown" and adds nothing), THE no-association and `FAILED`-status remediations SHALL additionally say that Security Hub CSPM must be enabled in the management account first so it becomes a member, because the Security Hub user guide ("Troubleshooting association failure", `view-policy.html`) states that an association with the management account fails otherwise. The verdict SHALL NOT depend on this lookup.

### Requirement 5: SRA-SECURITYHUB-23 — the FSBP standard is enabled and READY

**User Story:** As a security operator, I want each account and Region to have the AWS Foundational Security Best Practices standard enabled and evaluating, not merely some standard (checklist item 11; `SRA-SECURITYHUB-01` passes on any standard).

#### Acceptance Criteria

1. THE New_Checks SHALL include `SRA_SECURITYHUB_23` in `checks/sra_securityhub_23.py`, `account_type=AccountType.APPLICATION`, `severity=Severity.HIGH`, `resource_type="AWS::SecurityHub::Standard"`.
2. THE check SHALL reuse `self.get_enabled_standards(region)` per Region and SHALL add no client method, accessor or IAM action.
3. FOR each scanned Region, THE check SHALL yield one row: PASS when a subscription's `StandardsArn` ends with `standards/aws-foundational-security-best-practices/v/1.0.0` and its `StandardsStatus` is `READY`; FAIL when the subscription is absent, or present with any other status, naming the status and `StandardsStatusReason.StatusReasonCode` when present; FAIL when Security Hub CSPM is not subscribed in the Region (the declared `GetEnabledStandards` / `InvalidAccessException` needle); ERROR for every other error result.
4. THE check SHALL mirror `SRA-SECURITYHUB-12`'s transient-status wording: a `PENDING` or `DELETING` subscription earns a remediation that says to wait and re-run, not to re-enable.
5. THE check SHALL list the Region's enabled standards in `ActualValue` through `self.standard_name_of`, sorted, so the cell is diffable.

### Requirement 6: SRA-SECURITYHUB-24 — a CIS AWS Foundations Benchmark standard is enabled and READY

**User Story:** As a security operator, I want each account and Region to have a version of the CIS AWS Foundations Benchmark enabled and evaluating (checklist item 12).

#### Acceptance Criteria

1. THE New_Checks SHALL include `SRA_SECURITYHUB_24` in `checks/sra_securityhub_24.py`, `account_type=AccountType.APPLICATION`, `severity=Severity.MEDIUM`, `resource_type="AWS::SecurityHub::Standard"`.
2. THE check SHALL reuse `self.get_enabled_standards(region)` and SHALL add no client method, accessor or IAM action.
3. THE check SHALL accept any version: a subscription counts when its `StandardsArn` contains `cis-aws-foundations-benchmark/v/`, which matches the three `standards/…` ARNs and the legacy `ruleset/…/v/1.2.0` ARN alike. WHEN more than one version is subscribed, THE check SHALL PASS if at least one is `READY` and SHALL name every subscribed version and status in `ActualValue`.
4. THE verdict and wording rules of Requirement 5.3–5.5 SHALL apply with the CIS marker in place of the FSBP suffix.

### Requirement 7: SRA-SECURITYHUB-25 — an EventBridge rule routes CSPM findings to a response target

**User Story:** As a security operator, I want an ENABLED EventBridge rule with a target that matches `Security Hub Findings - Imported` events in the home Region, so that CSPM findings drive automated response (checklist item 16; `SRA-SECURITYHUB-20` deliberately rejects CSPM-filtered rules).

#### Acceptance Criteria

1. THE New_Checks SHALL include `SRA_SECURITYHUB_25` in `checks/sra_securityhub_25.py`, `account_type=AccountType.AUDIT`, `severity=Severity.MEDIUM`, `resource_type="AWS::Events::Rule"`.
2. THE check SHALL resolve the home Region from `self.get_finding_aggregators(self.regions[0])` and `self.home_region_of(...)`; WHEN an aggregator exists it SHALL evaluate the home Region only, and WHEN none exists it SHALL evaluate every scanned Region, mirroring `SRA-SECURITYHUB-20`.
3. THE check SHALL reuse `self.get_event_rules(region)` and `self.get_rule_targets(region, name)` and SHALL add no client method, accessor or IAM action.
4. THE check SHALL use a new static helper `SecurityHubCheck.matches_cspm_findings(rule)` that returns `True` when the rule's `EventPattern` is valid JSON, names `aws.securityhub` in `source`, and either names `Security Hub Findings - Imported` in `detail-type` or omits `detail-type` altogether (a source-only pattern, or a `detail`-filtered pattern — the only `detail.findings` schema Security Hub emits is the CSPM ASFF schema, so a `detail` filter without a `detail-type` is a CSPM rule). A rule matching only `Findings Imported V2` or only `Security Hub Findings - Custom Action` SHALL NOT count: the first is V2, the second needs a human to trigger it.
5. THE check SHALL yield PASS for the first matching rule that is `ENABLED` and has at least one target, naming the rule ARN as `resource_id`; otherwise one FAIL per evaluated Region whose `ActualValue` distinguishes "no matching rule", "matching rule(s) DISABLED" and "matching rule(s) have no target"; and ERROR when `ListRules` fails, or when at least one ENABLED candidate rule's `ListTargetsByRule` returned an error result and no candidate PASSed (the first error result is the one reported, even if other ENABLED candidates were merely targetless), mirroring `SRA-SECURITYHUB-20._evaluate_region`, composed as Requirement 3.6 requires.

### Requirement 8: Client and base additions honour the existing contracts

**User Story:** As a maintainer, I want the two new client methods and two new accessors to be indistinguishable in shape from the ninety-six and the existing accessors, so that the contract suite tests them the day they land.

#### Acceptance Criteria

1. THE SecurityHub_Client SHALL gain `get_finding_aggregator(aggregator_arn)` calling `self.client.get_finding_aggregator(FindingAggregatorArn=aggregator_arn)` and returning the response unchanged, and `list_configuration_policy_associations()` iterating `self.client.get_paginator("list_configuration_policy_associations").paginate()` and returning `{"ConfigurationPolicyAssociationSummaries": [...]}` with every page merged; both with the handler `except AWS_EXCEPTIONS as e: return self.aws_error(e)` and the whole paginator loop inside the `try`.
2. THE SecurityHub_Client SHALL acquire no new boto3 client; both methods use `self.client`, bound in `__init__` to `ctx.get_client('securityhub', region=region)`.
3. THE SecurityHub_Base SHALL gain `get_finding_aggregator(region, aggregator_arn)` caching under `f"finding_aggregator:{region}:{aggregator_arn}"` and `get_configuration_policy_associations(region)` caching under `f"configuration_policy_associations:{region}"`, both through the existing `_cached_call`, so an error result is returned unchanged and never cached and the no-client path returns `no_client_result(...)`.
4. THE SecurityHub_Base SHALL gain three static helpers — `cspm_unlinked_regions(aggregator, regions)`, `association_of(summaries, account_id)` and `matches_cspm_findings(rule)` — and two module constants beside `V2_FINDINGS_DETAIL_TYPE`: `CSPM_FINDINGS_DETAIL_TYPE = "Security Hub Findings - Imported"` and `SELF_MANAGED_POLICY_ID = "SELF_MANAGED_SECURITY_HUB"`, the latter imported by `sra_securityhub_22.py`.
5. THE SecurityHub_Base SHALL keep every existing accessor's cache key unchanged; `test_accessor_cache_property.py`'s key assertions SHALL pass without edit for the existing rows.
6. NO New_Check SHALL touch `self._ctx`, `_has`, `_get` or `_set`, declare `NOT_CONFIGURED_ERRORS`, define `__init__`, override `initialize`, or read `_audit_accounts` / `_log_archive_accounts` by any spelling; `test_layering_property.py`'s reach-through rule and `__init_subclass__` SHALL hold without edit.

### Requirement 9: Error classification stays declared, and is not inferred

**User Story:** As a consumer of the report, I want a FAIL from a new check to rest on an observed AWS answer and an ERROR to mean the scan could not tell, so that the FAIL-versus-ERROR contract is as sound for the five new checks as for the twenty.

#### Acceptance Criteria

1. THE SecurityHub_Base's `NOT_CONFIGURED_ERRORS` SHALL be edited by this feature only through the two probe-gated entries below; no entry SHALL be added for `GetFindingAggregator`, because its documented `ResourceNotFoundException` would only arrive for an ARN `ListFindingAggregators` had just returned, which is a race or a defect rather than an absent control.
2. **Probe-gated entry A** — `"ListFindingAggregators": {"InvalidAccessException": NotConfigured(evidence=…, message="not subscribed to aws security hub")}` — SHALL be added only if the read-only probe (Requirement 12.1, run before any code is written) observes `list-finding-aggregators` refused with `InvalidAccessException` and that message from an account not subscribed to Security Hub CSPM in the probed Region. Its `evidence` SHALL cite the observation (date, account role, Region) and the CommonErrors URL. If not observed, the entry SHALL stay out and the pair SHALL remain ERROR.
3. **Probe-gated entry B** — `"ListConfigurationPolicyAssociations": {"AccessDeniedException": NotConfigured(evidence=…, message="with central configuration enabled")}` — SHALL be added only if the probe observes that message from the raw CLI call `aws securityhub list-configuration-policy-associations` issued with a non-delegated-administrator profile in the home Region, mirroring the existing `ListConfigurationPolicies` entry. The raw CLI call is the observation route because the check itself may never issue the operation from such an account (Requirement 12.2). The "can only be called from the aggregation region" message SHALL stay undeclared so a wrong-Region call remains an ERROR.
4. WHEN either entry is added, THE `_NON_OWNED_NOT_CONFIGURED_ENTRIES` golden in `test_discriminator_property.py` SHALL gain the matching `('SecurityHubCheck', <operation>, <code>, <needle>, <sha256 of evidence>)` row in the same commit, AND the module's `assert len(_NON_OWNED_NOT_CONFIGURED_ENTRIES) == 46` (line 671) SHALL be bumped to 47 or 48 to match, and `test_a_declared_semantic_error_result_reaches_failed` SHALL observe the new check reaching `failed()` for the pair (for entry A through `SRA-SECURITYHUB-21`, `-22` and `-25`, whose first accessor is `get_finding_aggregators`). The decision SHALL be made in the base-class task, from the probe output, not after the suite and the security scan have run.
5. EVERY ERROR row from a New_Check SHALL carry `ActualValue` in the shape `f"{Operation} failed: {Code}: {Message}"` and `remediation=self._remediation_for(error)`; `test_every_error_row_names_the_failed_operation_and_code` SHALL hold over the 187-check catalog.
6. NO New_Check SHALL compare an error code inline; the only classification call SHALL be `self.is_not_configured(error)`.

### Requirement 10: Test and artefact obligations

**User Story:** As a maintainer, I want every table, golden, count and generated artefact the catalog depends on to be updated in the same change, so that the suite is green on the commit that adds the checks and no artefact drifts.

#### Acceptance Criteria

1. THE Contract_Tests' `ClientAdapter` table for `securityhub` in `test_client_contract_property.py` SHALL gain two rows — `get_finding_aggregator` (`operation="GetFindingAggregator"`, `args=(<aggregator ARN>,)`, `success={...FindingAggregationRegion, FindingAggregatorArn, RegionLinkingMode, Regions}`) and `list_configuration_policy_associations` (`operation="ListConfigurationPolicyAssociations"`, `paginated=True`, `success=({"ConfigurationPolicyAssociationSummaries": [...]},)`) — so `test_the_adapter_table_is_complete_and_exact` passes. The module holds no literal method count; the "96 client methods" figure lives in `structure.md` and `tech.md` and becomes 98 (Requirement 11.1).
2. THE Contract_Tests' `AccessorAdapter` table for `securityhub` in `test_accessor_cache_property.py` SHALL gain two `accessor` rows (`get_finding_aggregator` with its `client_method` and `cache_key`; `get_configuration_policy_associations` likewise) and three `helper` rows (`cspm_unlinked_regions`, `association_of`, `matches_cspm_findings`) with representative `args`, so `test_every_public_base_method_is_classified` passes.
3. THE `EXPECTED_CHECK_COUNT` constants in `test_catalog_identity_property.py` and `test_registry_bijection_property.py` SHALL move from 182 to 187.
4. THE `_CONSUMERS` tuple in `test_layering_property.py` SHALL gain `"securityhub/checks/sra_securityhub_22.py"` and `test_there_are_exactly_fifteen_consumers` SHALL assert sixteen (and be renamed accordingly).
5. THE three `== 18` service-count assertions (`test_client_contract_property.py`, `test_accessor_cache_property.py`, `tests/unit/util/test_generate_iam_policy.py`) SHALL be unchanged, because no package is added.
6. THE IAM_Generator SHALL be re-run and its artefacts SHALL gain exactly `securityhub:GetFindingAggregator` and `securityhub:ListConfigurationPolicyAssociations`; the Member_Role_Template's `SRAVerifyLeastPrivilege` policy SHALL gain the same two actions in sorted position; the template SHALL pass `aws cloudformation validate-template`.
7. THE Catalog_Inventory SHALL be regenerated with `sraverify/.venv/bin/sraverify --list-checks > docs/checks.txt` and verified with `cmp`; the twenty existing Security Hub lines change their `(Service)` token and five lines are added.
8. THE full suite SHALL pass with `cd sraverify && uv run pytest -q -p no:logging`, with the new passed and skipped totals recorded in `tech.md` and `structure.md`.
9. THE ASH scan SHALL be clean per `security_scanning.md` before a commit message is proposed.

### Requirement 11: Documentation and steering

**User Story:** As the next author, I want the steering files and coverage report to describe the catalog that exists, so that the counts and the Security Hub classification they state are true.

#### Acceptance Criteria

1. THE Steering_Docs SHALL update every count this feature moves: `product.md` (187 checks; `securityhub 25`; the two display names), `structure.md` and `tech.md` (187 checks, 98 client methods, the new pytest totals), `creating_checks_best_practices.md` (the two `182` mentions).
2. THE `product.md` scope section SHALL state the soft split: both products share one package and one base, differ in `meta.service`, and `--service` selects either.
3. THE Coverage_Report SHALL move checklist items 6 and 9 (Missing) and 11, 12 and 16 (Missing or Partial) to Covered, leaving Partial = {4, 10, 13} and Missing = {14, 15, 17}, so the CSPM summary row moves from 17 / 6 / 5 / 6 to **17 / 11 / 3 / 3**; the total row SHALL be recomputed from the per-service rows (224 / 124 / 13 / 87 if no other row changes); its header SHALL say 187 checks.
4. THE README's service list (`README.md:5`) SHALL name `Security Hub CSPM` and `Security Hub` and SHALL state 187 checks; the `--service CloudTrail` example SHALL be left as it is.
5. THE `sraverify/README.md` developer guide SHALL mention that two display names may coexist in one package and that `meta.service` is the filter boundary.

### Requirement 12: Live validation and acceptance gate

**User Story:** As the repository owner, I want each new check seen producing both verdicts against the test organization, with every mutation snapshotted and restored, before the change is proposed for commit.

#### Acceptance Criteria

1. A read-only probe SHALL run **before any code is written** (it is the first task after the baseline, per `testing_checks.md`'s order of work) and SHALL be re-run unchanged as the Acceptance_Gate's first step to confirm nothing moved. It SHALL call `list-finding-aggregators`, `get-finding-aggregator`, `list-configuration-policy-associations` and `get-enabled-standards` from the audit, management and one application profile, in the home Region and in one non-home scanned Region, plus `list-finding-aggregators` from an application profile in a Region where CSPM is not subscribed, and SHALL record every response shape, error code and message to `.tmp/sratester/securityhub-cspm-split/probe.txt`. It SHALL settle four facts the design depends on: (i) whether `get-finding-aggregator` answers from a non-home Region; (ii) whether the number of `TargetType=ACCOUNT` summaries from the delegated administrator equals the number of active organization accounts, with every gap explained (Requirement 4.4; a mismatch triggers Requirement 4.5a); (iii) whether entry A is observable (Requirement 9.2); (iv) whether entry B is observable from the raw CLI with the management profile (Requirement 9.3). It SHALL also record what `list-finding-aggregators` returns from the management profile, which decides the expected row in criterion 2.
2. THE Acceptance_Gate SHALL reach the read-only negative arms: `--regions` excluding the home Region → the not-scanned ERROR (`-21`, `-22`, `-25`); a Region where CSPM is not subscribed → the not-enabled FAIL (`-23`, `-24`). Running `-22` with the management profile SHALL be recorded for what it produces rather than asserted in advance: `-22` calls `ListFindingAggregators` first, so if the management account lists no aggregator the row is the no-aggregator FAIL (`global`, "so central configuration is not in use") and `ListConfigurationPolicyAssociations` is never issued; only if the probe (criterion 1) shows the management account does list an aggregator will the run reach the `ListConfigurationPolicyAssociations` ERROR arm (or FAIL, if entry B landed). WHERE no read-only route to that ERROR arm exists in the test organization, the report SHALL mark it 🔄 ATTEMPTED with this reason; the arm is held offline by `test_check_classification_property.py`.
3. THE Acceptance_Gate SHALL reach the FAIL arm of `-22` through one scoped mutation — associating one application account directly with `SELF_MANAGED_SECURITY_HUB` via `start-configuration-policy-association --target AccountId=<id>` in the home Region — after snapshotting that account's summary **including its `AssociationType`**. Restoration SHALL be chosen by the snapshotted `AssociationType`: WHEN it is `INHERITED`, restore with `aws securityhub start-configuration-policy-disassociation --configuration-policy-identifier SELF_MANAGED_SECURITY_HUB --target AccountId=<id> --region <home>` (`API_StartConfigurationPolicyDisassociation.html`: the target "inherits the configuration of the closest parent"; `disassociate-policy.html`: "Provide SELF_MANAGED_SECURITY_HUB for this field to disassociate self-managed behavior"), because re-associating the parent's policy to the account would leave it `APPLIED` and no longer following root/OU changes; WHEN it is `APPLIED`, restore with `start-configuration-policy-association` back to the snapshotted policy ARN. In both cases poll `get-configuration-policy-association` until `AssociationStatus` is `SUCCESS` and `ConfigurationPolicyId` and `AssociationType` equal the snapshot, saying how long it took, and confirm only that account's row moved. The restoration comparison in criterion 10 SHALL compare `ConfigurationPolicyId`, `TargetId`, `TargetType`, `AssociationType` and `AssociationStatus`, and SHALL exclude `UpdatedAt`, which a successful restore necessarily changes.
4. THE Acceptance_Gate SHALL reach the FAIL arm of `-25` by disabling (or, if none exists, creating and then deleting) one rule matching `Security Hub Findings - Imported` in the home Region, after snapshotting its state. THE rule chosen for `disable-rule` SHALL NOT be named `aws-controltower-*` and SHALL NOT be owned by a CloudFormation stack (`aws events describe-rule` reports no `ManagedBy`, and `aws events list-tags-for-resource` shows no `aws:cloudformation:stack-name` tag), because `testing_checks.md` forbids changing Control Tower baseline resources and a stack-owned rule (for example an automated-response solution's) would drift its stack. WHEN every matching rule is managed by that test, THE gate SHALL use the create-then-delete route with a rule named `sraverify-test-cspm` instead of disabling any existing rule.
5. THE Acceptance_Gate SHALL reach the FAIL arm of `-21` either read-only (a scanned Region the aggregator does not link) or through `update-finding-aggregator` narrowing the linked Regions by one, with the snapshot of `RegionLinkingMode` and `Regions` taken first; the report SHALL note that unlinking a Region also removes it from central configuration's scope for the duration of the mutation.
6. WHERE a FAIL arm of `-23` or `-24` cannot be reached without an organization-wide policy change (every account centrally managed and every policy enabling the standard), THE report SHALL mark that arm 🔄 ATTEMPTED with the reason and SHALL rely on the not-subscribed FAIL arm as the observed FAIL.
7. THE Acceptance_Gate SHALL NOT deregister, change or re-designate the Security Hub CSPM or V2 delegated administrator, disable Security Hub in any Region, or change any Control Tower resource.
8. THE Acceptance_Gate SHALL simulate `securityhub:GetFindingAggregator` and `securityhub:ListConfigurationPolicyAssociations` against the deployed member role with `simulate-principal-policy`, deploy the Member_Role_Template before the CodeBuild run, and judge the CodeBuild result from the consolidated CSV: five new checks' row counts per account, zero ERROR rows from them, and a total-ERROR delta explainable by the new rows alone.
9. THE Acceptance_Gate SHALL apply every scan gate from `testing_checks.md`: `--debug` stderr kept, zero synthetic rows, zero `- ERROR -` records, no `No client available`, every ERROR row explained, a plausible `aws_call_failed` count.
10. THE final report SHALL be written to `sratester/securityhub-cspm-split-test-report.md` with the status table, phase tables, gate results, IAM simulation, CodeBuild comparison, defects, and restoration verification output. The restoration verification SHALL be a script that re-reads every snapshotted resource and compares it field by field against `.tmp/sratester/securityhub-cspm-split/snapshot.json`, excluding only fields that a correct restore necessarily changes (`UpdatedAt` on an association summary), and its output SHALL appear in the report verbatim.

### Requirement 13: Gaps deliberately not added

**User Story:** As the user who asked for the missing checks "where it makes sense", I want to see which checklist items were not turned into checks and why, so the decision is reviewable rather than silent.

#### Acceptance Criteria

1. THE design SHALL record, one line each, why these `docs/check-report.md` CSPM items gain no check: item 4 (GuardDuty and Detective share the DA — Detective has no package; the GuardDuty half is `SRA-GUARDDUTY-14` versus `SRA-SECURITYHUB-07`), item 10 (member aggregation — `-07`, `-08`, `-09` already hold the delegated administrator and membership facts it restates), item 13 ("other standards as applicable" — no objective criterion), item 14 (CSPM consumed by Security Hub for exposure correlation — a V2 fact `SRA-SECURITYHUB-19`'s coverage findings already assess), item 15 (automation rule enrichment — customer-content judgement, Non-Goal 5), item 17 (CloudWatch telemetry rule — the `observabilityadmin` service, no package).
2. THE Coverage_Report SHALL keep those items at their current status with a note pointing at this spec.
