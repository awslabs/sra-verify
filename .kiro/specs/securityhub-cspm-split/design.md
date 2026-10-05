# Design Document

**Feature:** Security Hub CSPM split and missing CSPM checks

**Spec directory:** `.kiro/specs/securityhub-cspm-split/`

**Reads:** `requirements.md` in this directory; the six steering files; `docs/check-report.md`; `services/securityhub/{base,client}.py` and `checks/sra_securityhub_01.py` – `_20.py`; the contract tests named in Requirement 10; the AWS Security Hub CSPM API reference and user guide pages cited inline. Every operation name, response field and enum value below was read from the API reference or confirmed against botocore 1.43.105's service model; nothing is assumed from memory. Every URL was fetched and answered 200 on 2026-10-05.

## Overview

This feature does two things to one package. It gives the thirteen Security Hub CSPM checks and the seven unified Security Hub (V2) checks different `meta.service` display names so that `--service`, `--list-services`, the `Service` column and the dashboards' service grouping separate the two products, and it adds five CSPM checks for the checklist items `docs/check-report.md` lists as Partial or Missing and that the CSPM API can establish read-only: the finding aggregator links every scanned Region (`SRA-SECURITYHUB-21`), every active account is centrally managed with a successful association (`-22`), the FSBP standard is enabled and READY (`-23`), a CIS AWS Foundations Benchmark version is enabled and READY (`-24`), and an ENABLED EventBridge rule with a target matches `Security Hub Findings - Imported` events (`-25`).

Nothing moves. No check ID, module, class, package, base class, client, cache namespace or `NOT_CONFIGURED_ERRORS` entry changes. The `Service` cell changes on every Security Hub row, and that is the whole of the diff on existing rows apart from the ERROR-row remediation text that `_remediation_for` builds from `self.service`. The design chose this deliberately over a package split, and the decision record below says why.

The stack is the one `tech.md` locks: Python 3.11+, boto3/botocore ≥ 1.43.96 (both new operations, `GetFindingAggregator` and `ListConfigurationPolicyAssociations`, are in the 1.43.105 service model, and `list_configuration_policy_associations` has a botocore paginator), pytest + hypothesis, hatchling/uv. No new dependency.

## Decision record: split Security Hub into two services?

### The question

AWS markets two products on one boto3 service id. They differ in their delegated-administrator feature (`ListOrganizationAdminAccounts` with or without `Feature=SecurityHubV2`), their organization-wide enablement (central configuration policies versus the `SECURITYHUB_POLICY` Organizations type), their aggregation resource (`FindingAggregator` versus `AggregatorV2`), their finding format (ASFF versus OCSF) and their EventBridge detail-type. The repository already treats them as two surfaces inside one package — `docs/check-report.md` splits the twenty checks 13/7 — but the catalog metadata does not. The user asked for a split "if that makes sense".

### Where `meta.service` is read

Before choosing, every consumer of the field was checked, because changing a display name is only cheap if nothing keys on it.

| Reader                                                                            | Effect of a display-name change                                                                                                                                                                                                                                                                        |
| --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `scanner.select_checks` — `cls.meta.service.lower() == wanted`                    | `--service` is a full-value case-insensitive match. Two names give two filters; `--service SecurityHub` becomes a `NoChecksSelectedError`, exit 2, no file.                                                                                                                                            |
| `SRAVerify.list_services` and `--list-services`                                   | Two entries instead of one.                                                                                                                                                                                                                                                                            |
| `SRAVerify.run_checks` — groups by `meta.service` for the progress bar            | Two groups. No behavioural effect.                                                                                                                                                                                                                                                                     |
| `SecurityCheck._finding` — `checked_value` default `f"{m.service} Configuration"` | Reached only when a helper is called without `checked_value`. Counted: all 20 Security Hub checks pass `checked_value` on every one of their 121 helper calls. The default is reached only by `scanner._synthetic_error` and `_precondition_error`, which report a defect or a failed identity lookup. |
| `SecurityCheck._remediation_for` — names `self.service` in all four buckets       | ERROR rows' `Remediation` wording changes ("Confirm the Security Hub CSPM endpoint …"). ERROR rows only.                                                                                                                                                                                               |
| `Finding.service` → the `Service` CSV column                                      | Changes on every Security Hub row.                                                                                                                                                                                                                                                                     |
| `sra-verify-dashboard.html`                                                       | Builds its service filter and per-service issue groups from `new Set(allData.map(row => row.Service))`. No hard-coded names.                                                                                                                                                                           |
| `sra-verify-comparison-dashboard.html`                                            | Join key is `CheckId                                                                                                                                                                                                                                                                                   |  | AccountId |  | Region |  | ResourceId` (`findingKey`, line 1027). `Service` is displayed and filterable, not joined on. |
| `util/generate_iam_policy.py`                                                     | Does not read `meta` at all; attribution is by `ctx.get_client('<id>')` bindings in `__init__`. Unaffected.                                                                                                                                                                                            |
| `__init_subclass__` identity rules                                                | Check the module stem, `check_id`, class name and package. `meta.service` is not an identity input. Unaffected.                                                                                                                                                                                        |
| `CheckMeta` validation                                                            | `service` must be whitespace-normalized and ≤ 60 characters. Both new values pass.                                                                                                                                                                                                                     |
| `docs/checks.txt`                                                                 | Each line carries `(Service)`; the twenty lines change. Regenerated anyway for the five new checks.                                                                                                                                                                                                    |
| Tests                                                                             | No test asserts the literal `"SecurityHub"` as a `meta.service` value. `test_exit_codes.py` uses `CloudTrail` for its empty-combination case.                                                                                                                                                          |

The buildspec in `2-sraverify-codebuild-deploy.yaml` passes `--account-type`, `--regions` and `--role` and never `--service`, so the CodeBuild path is unaffected.

### Options

**(a) Full split with new check IDs.** Create `services/securityhubcspm/` (or `securityhubv2/`) and move the thirteen (or seven) checks into it, which under the identity rules means `SRA-SECURITYHUBCSPM-NN` IDs, new module names and new class names. Cost: every moved check's `CheckId` changes, and `CheckId` is the first component of the comparison dashboard's join key, so every row of a moved check appears as one removal and one addition against every prior consolidated CSV in S3. `structure.md` defers even a `Region` or `ActualValue` cell move because it cannot be separated from a regression in a two-scan diff; a `CheckId` move loses the join entirely. It also needs a second `<Service>Check` base, which cannot inherit `SecurityHubCheck` (`test_no_service_base_inherits_anything_but_security_check`), so the sixteen cached accessors, six `derived` delegators to the Organizations provider, eight static helpers and the ten-pair `NOT_CONFIGURED_ERRORS` table in `vars(SecurityHubCheck)` would be duplicated or re-homed, with three `== 18` service-count assertions and `product.md`'s inventory to move. Rejected.

**(b) Soft split: two display names, one package.** Change `meta.service` on the twenty modules and nothing else. Cost: the `Service` cell on every Security Hub row, the ERROR-row remediation wording, `docs/checks.txt`, and `--service SecurityHub` turning into exit 2. Gain: `--service` separates the products, the dashboards group them separately, `--list-services` lists both, and the catalog's naming matches AWS's. Everything the join key, the identity rules and the contract tests care about is untouched. **Chosen.**

**(c) New package for new checks only.** Leave `-01` – `-20` alone and put the five new checks in `services/securityhubcspm/` as `SRA-SECURITYHUBCSPM-01` – `-05`. Cost: the new base must inherit `SecurityCheck` directly, so it either duplicates `_cached_call`, `get_enabled_standards`, `get_finding_aggregators`, `home_region_of`, `standard_name_of`, `get_event_rules`, `get_rule_targets` and the `GetEnabledStandards` / `InvalidAccessException` table entry — two tables classifying one pair is exactly the drift the single-table design removes, and `_NON_OWNED_NOT_CONFIGURED_ENTRIES` would carry the duplicate — or it imports `SecurityHubClient` from the sibling package, which `test_layering_property.py` does not forbid (it bans `core → services` imports, bases inheriting below `SecurityCheck`, and `OrganizationsClient` in a base) but which the IAM generator cannot attribute unless the new `client.py` re-binds `self.client = ctx.get_client('securityhub', …)` in its own `__init__`. A second cache namespace would re-issue `GetEnabledStandards` once per Region per package. And the result splits CSPM across two ID prefixes — `-01` – `-13` under one, the new five under another — which is a worse boundary than today's none. Rejected.

**(d) No split.** Add the five checks with `service="SecurityHub"`. Cheapest, and it leaves the operator without the filter the request asked for. Rejected because (b) delivers the boundary at the cost of one non-key column.

### Choice and its two sub-decisions

**(b)**, with both groups renamed rather than only the CSPM group. Renaming only the thirteen would leave `"SecurityHub"` meaning "V2", which no reader would guess, and would move thirteen checks' `Service` cells now and seven later; moving all twenty in one change costs the same review and ends with names that match AWS's. The display names drop the vendor prefix as every other entry in the catalog does: `"Security Hub CSPM"` and `"Security Hub"`.

The `no_client_result(service="SecurityHub", region=…)` string in `_cached_call` is left alone. It is the `Message` field of a `NoClient` error result that becomes an ERROR `ActualValue`, not a `Service` cell, and it is shared by both groups.

### Can the shared client and base serve both groups?

Yes, because nothing about them is group-specific. `SecurityHubClient` binds one `securityhub` client and one `events` client; both groups' operations go through the former. `SecurityHubCheck` is one base, one `NAMESPACE`, one table, and `vars(SecurityHubCheck)` is what the accessor adapter table enumerates, so adding accessors to it is one table edit. The layering question the task raised — whether a second package could import the first's client — has an answer (the layering suite permits it; the IAM generator needs the importing module to bind its own `self.client`), but under (b) it does not arise.

## Architecture

### Package layout after the change

```
services/securityhub/
├── __init__.py                    unchanged
├── base.py                        + CSPM_FINDINGS_DETAIL_TYPE, SELF_MANAGED_POLICY_ID
│                                  + get_finding_aggregator(region, arn)
│                                  + get_configuration_policy_associations(region)
│                                  + cspm_unlinked_regions(), association_of(), matches_cspm_findings()
│                                  (+ up to two probe-gated NOT_CONFIGURED_ERRORS entries)
├── client.py                      + get_finding_aggregator(arn)
│                                  + list_configuration_policy_associations()
└── checks/
    ├── sra_securityhub_01..13.py  meta.service = "Security Hub CSPM"   (one line each)
    ├── sra_securityhub_14..20.py  meta.service = "Security Hub"        (one line each)
    ├── sra_securityhub_21.py      NEW  CSPM aggregator links every scanned Region
    ├── sra_securityhub_22.py      NEW  every active account centrally managed
    ├── sra_securityhub_23.py      NEW  FSBP standard enabled and READY
    ├── sra_securityhub_24.py      NEW  CIS standard enabled and READY
    └── sra_securityhub_25.py      NEW  EventBridge rule routes CSPM findings
```

Registration is automatic: the five files' presence under `checks/` with stems `sra_securityhub_21` – `_25`, class names `SRA_SECURITYHUB_21` – `_25` and matching `check_id` values is the whole of it. `import sraverify.services` registers 187 checks.

### Who calls what

```
SRA-SECURITYHUB-21  get_finding_aggregators(regions[0]) ─┐
SRA-SECURITYHUB-22  get_finding_aggregators(regions[0]) ─┼─ ListFindingAggregators (existing, cached once)
SRA-SECURITYHUB-25  get_finding_aggregators(regions[0]) ─┘
SRA-SECURITYHUB-21  get_finding_aggregator(home, arn)    ── GetFindingAggregator            NEW
SRA-SECURITYHUB-22  get_configuration_policy_associations(home) ── ListConfigurationPolicyAssociations  NEW
SRA-SECURITYHUB-22  self.organization.accounts()         ── ListAccounts (provider, cached once per scan)
SRA-SECURITYHUB-23  get_enabled_standards(region)        ─┐
SRA-SECURITYHUB-24  get_enabled_standards(region)        ─┴─ GetEnabledStandards (existing; -01 and -12 share the cache slot)
SRA-SECURITYHUB-25  get_event_rules(region), get_rule_targets(region, name) ── events:ListRules, ListTargetsByRule (existing; -20 shares)
```

Three of the five checks issue no new operation at all. The two new operations need two new IAM actions, `securityhub:GetFindingAggregator` and `securityhub:ListConfigurationPolicyAssociations`, which the generator derives from the two `self.client.<method>` call sites and which `simulate-principal-policy` confirms in the live phase (action names are not always operation names — `GetFindingsV2` is authorized by `securityhub:GetFindings` — so the simulation is the proof, not the generator).

## Components and interfaces

### `services/securityhub/client.py` — two methods

Both acquire nothing: `self.client` is bound in `__init__` already.

```python
def get_finding_aggregator(self, aggregator_arn: str) -> Mapping[str, Any]:
    """
    Get one Security Hub CSPM finding aggregator.

    Args:
        aggregator_arn: The ``FindingAggregatorArn`` from ``ListFindingAggregators``.

    Returns:
        The ``GetFindingAggregator`` response -- ``FindingAggregationRegion``,
        ``FindingAggregatorArn``, ``RegionLinkingMode`` and ``Regions`` -- or the
        error result. Called from the home Region, which the ARN names: the
        user guide requires creating and updating the aggregator there, the
        reference does not say whether a read from elsewhere answers, and the
        live probe records what it does. Reading from the home Region is
        correct either way.
        https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingAggregator.html
    """
    try:
        return self.client.get_finding_aggregator(FindingAggregatorArn=aggregator_arn)
    except AWS_EXCEPTIONS as e:
        return self.aws_error(e)

def list_configuration_policy_associations(self) -> Mapping[str, Any]:
    """
    List every configuration policy association in the organization.

    Returns:
        ``{"ConfigurationPolicyAssociationSummaries": [...]}`` with every page
        merged, or the error result. Each summary carries ``TargetId``,
        ``TargetType`` (ACCOUNT | ORGANIZATIONAL_UNIT | ROOT),
        ``ConfigurationPolicyId`` (a UUID, or ``SELF_MANAGED_SECURITY_HUB``),
        ``AssociationType`` (APPLIED | INHERITED), ``AssociationStatus``
        (PENDING | SUCCESS | FAILED) and ``AssociationStatusMessage``. Only the
        delegated administrator may call this, and only from the home Region.
        https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListConfigurationPolicyAssociations.html
        https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ConfigurationPolicyAssociationSummary.html
    """
    try:
        summaries = []
        for page in self.client.get_paginator(
            'list_configuration_policy_associations'
        ).paginate():
            summaries.extend(page.get('ConfigurationPolicyAssociationSummaries', []))
        return {"ConfigurationPolicyAssociationSummaries": summaries}
    except AWS_EXCEPTIONS as e:
        return self.aws_error(e)
```

The paginator loop is wholly inside the `try`, so a failure on page two arrives as an error result rather than a short list. `MaxResults` is left at the service default; the API caps it at 100 and the paginator walks `NextToken`.

Documented error codes, from the API reference and confirmed against the botocore service model: `GetFindingAggregator` — `AccessDeniedException`, `InternalException`, `InvalidAccessException`, `InvalidInputException`, `LimitExceededException`, `ResourceNotFoundException`; `ListConfigurationPolicyAssociations` — the same set without `ResourceNotFoundException`. Which of them is semantic is decided in the base's table, not here.

### `services/securityhub/base.py` — constant, two accessors, three helpers

```python
#: The EventBridge ``detail-type`` of a Security Hub CSPM finding event.
#: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-integration-types.html
CSPM_FINDINGS_DETAIL_TYPE = "Security Hub Findings - Imported"

#: The ``ConfigurationPolicyId`` of a self-managed association.
#: https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_StartConfigurationPolicyAssociation.html
SELF_MANAGED_POLICY_ID = "SELF_MANAGED_SECURITY_HUB"
```

Accessors, through the existing `_cached_call`:

```python
def get_finding_aggregator(self, region: str, aggregator_arn: str) -> Mapping[str, Any]:
    return self._cached_call(
        region, f"finding_aggregator:{region}:{aggregator_arn}",
        "get_finding_aggregator", aggregator_arn,
    )

def get_configuration_policy_associations(self, region: str) -> Mapping[str, Any]:
    return self._cached_call(
        region, f"configuration_policy_associations:{region}",
        "list_configuration_policy_associations",
    )
```

`_cached_call` already gives both the contract: cache hit → cached value; no client → `no_client_result(service="SecurityHub", region=region)`; error result → returned unchanged, not cached; success → cached under the key.

Helpers, all `@staticmethod`, all pure:

```python
@staticmethod
def cspm_unlinked_regions(aggregator: Mapping[str, Any], regions: list[str]) -> list[str]:
    """
    Return the Regions a CSPM finding aggregator does not link to its home Region.

    ``RegionLinkingMode``: ALL_REGIONS links everything; ALL_REGIONS_EXCEPT_SPECIFIED
    links everything but ``Regions``; SPECIFIED_REGIONS links only ``Regions``;
    NO_REGIONS links nothing. The home Region (``FindingAggregationRegion``) is
    always covered. An unrecognized mode links nothing, so it reads as a gap.
    https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_CreateFindingAggregator.html
    """
    home = aggregator.get("FindingAggregationRegion")
    mode = aggregator.get("RegionLinkingMode")
    listed = set(aggregator.get("Regions") or [])
    uncovered = []
    for region in regions:
        if region == home or mode == "ALL_REGIONS":
            continue
        if mode == "ALL_REGIONS_EXCEPT_SPECIFIED" and region not in listed:
            continue
        if mode == "SPECIFIED_REGIONS" and region in listed:
            continue
        uncovered.append(region)
    return sorted(uncovered)
```

This is a sibling of `unlinked_regions`, not a generalization of it: the V2 response spells the fields `AggregationRegion` / `LinkedRegions` and has no `NO_REGIONS`, and folding both into one function would mean a parameterized field map that reads worse than two twelve-line functions.

```python
@staticmethod
def association_of(
    summaries: list[Mapping[str, Any]], account_id: str
) -> Optional[Mapping[str, Any]]:
    """
    Return the association summary whose target is ``account_id``, or None.

    Matches ``TargetType == "ACCOUNT"`` and ``TargetId == account_id``. OU and
    root associations are not an account's association: an account governed
    through inheritance is listed with its own ACCOUNT entry and
    ``AssociationType`` INHERITED. The reference supports that reading --
    ``ListConfigurationPolicyAssociations`` takes an ``AssociationType`` filter
    (INHERITED | APPLIED), which only makes sense on a list that contains
    inherited targets, and each summary documents ``AssociationType`` as
    "directly applied ... or inherited from a parent" -- and the read-only
    probe confirms it before this helper is written (ACCOUNT summaries ==
    active accounts, or each gap explained). If two entries name one account
    (not observed; the API lists each target once), the first in list order
    wins, which keeps the result deterministic.
    https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_AssociationFilters.html
    https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ConfigurationPolicyAssociationSummary.html
    """
    for summary in summaries:
        if summary.get("TargetType") == "ACCOUNT" and summary.get("TargetId") == account_id:
            return summary
    return None

@staticmethod
def matches_cspm_findings(rule: Mapping[str, Any]) -> bool:
    """
    Return whether an EventBridge rule's pattern matches CSPM finding events.

    The pattern must be valid JSON naming ``aws.securityhub`` in ``source``, and
    either name ``Security Hub Findings - Imported`` in ``detail-type`` or omit
    ``detail-type``. A pattern that omits ``detail-type`` but filters on
    ``detail`` counts here and not in :meth:`matches_v2_findings`: the only
    ``detail.findings`` schema Security Hub emits is the CSPM ASFF schema, so a
    ``detail``-filtered rule was written against CSPM events. A rule that names
    only ``Findings Imported V2`` is a V2 rule and does not count; a rule that
    names only ``Security Hub Findings - Custom Action`` needs a person to
    trigger it and does not count as automated response.
    https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-all-findings.html
    """
    try:
        pattern = json.loads(rule.get("EventPattern") or "")
    except ValueError:
        return False
    if not isinstance(pattern, dict):
        return False
    sources = pattern.get("source")
    if not isinstance(sources, list) or "aws.securityhub" not in sources:
        return False
    detail_types = pattern.get("detail-type")
    if detail_types is None:
        return True
    return isinstance(detail_types, list) and CSPM_FINDINGS_DETAIL_TYPE in detail_types
```

Consequence worth stating: a bare `{"source":["aws.securityhub"]}` rule matches both `matches_v2_findings` and `matches_cspm_findings`, and that is correct — such a rule receives every Security Hub event.

### `NOT_CONFIGURED_ERRORS` — nothing on inference, two probe-gated entries

The existing table declares ten pairs: six `InvalidAccessException` entries with the needle `not subscribed to aws security hub` (one each on `GetEnabledStandards`, `ListEnabledProductsForImport`, `GetAdministratorAccount`, `DescribeOrganizationConfiguration`, `ListMembers`, `ListOrganizationAdminAccounts`), `ListMembers` / `BadRequestException`, the two V2 entries (`DescribeSecurityHubV2` / `ResourceNotFoundException`, `ListAggregatorsV2` / `ConflictException`), and `ListConfigurationPolicies` / `AccessDeniedException` with the needle `with central configuration enabled`. It is not edited by this feature except as follows, and the decision is taken in the base-class task from the read-only probe that precedes all code (`testing_checks.md` step 1), not after the suite has run.

**Not declared, with reasons.**

- `GetFindingAggregator` / `ResourceNotFoundException`. The reference documents it as "we can't find the specified resource". The check only calls `GetFindingAggregator` with an ARN that `ListFindingAggregators` just returned, so this code would mean the aggregator was deleted between the two calls, or the call went to the wrong Region. Neither is "the control is absent". Stays ERROR.
- `GetFindingAggregator` / `InvalidAccessException`. Not observed. Stays ERROR.
- `ListConfigurationPolicyAssociations` / `AccessDeniedException` with the wrong-Region message `can only be called from the aggregation region`. A fact about where we asked; the not-scanned guard in `-22` means it is reached only if the aggregator ARN and the scanned Regions disagree. Stays ERROR, as it does for `ListConfigurationPolicies`.

**Probe-gated entry A** — declared only if the live probe observes it (Requirement 9.2):

```python
"ListFindingAggregators": {
    "InvalidAccessException": NotConfigured(
        evidence=(
            "Observed <date> from <role> account in <region>, where Security Hub "
            "CSPM is not subscribed: 'aws_call_failed operation=ListFindingAggregators "
            "code=InvalidAccessException message=\"... not subscribed to AWS Security "
            "Hub ...\"'. Same overloaded code as the six sibling operations; the "
            "needle separates it from a permission denial. "
            "https://docs.aws.amazon.com/securityhub/1.0/APIReference/CommonErrors.html"
        ),
        message="not subscribed to aws security hub",
    ),
},
```

Golden row: `('SecurityHubCheck', 'ListFindingAggregators', 'InvalidAccessException', 'not subscribed to aws security hub', '<sha256 of the evidence string>')`, with `# pragma: allowlist secret` as the existing rows carry, inserted **in sorted `(base, operation, code, needle)` position** — between the `SecurityHubCheck` rows for `ListEnabledProductsForImport` and `ListMembers`, because `_live_non_owned_entries()` sorts by that tuple and the test compares the two sequences element-wise — and `assert len(_NON_OWNED_NOT_CONFIGURED_ENTRIES) == 46` (`test_discriminator_property.py:671`) bumped by one per entry added.

Observation route: `aws securityhub list-finding-aggregators --profile <application> --region <unsubscribed Region>`, in the probe.

Effect if added: `-13`, `-21`, `-22` and `-25` reach their existing `is_not_configured` FAIL arm on `get_finding_aggregators` when the audit account is not subscribed in `regions[0]`; today that arm is unreachable and the row is an ERROR. `-13`'s row would move from ERROR to FAIL in that one situation — the test organization's audit account is subscribed, so the live gate is expected to show no such row, and the report must say so.

**Probe-gated entry B** — declared only if observed (Requirement 9.3):

```python
"ListConfigurationPolicyAssociations": {
    "AccessDeniedException": NotConfigured(
        evidence=(
            "Observed <date> from a non-delegated-administrator account: "
            "'AccessDeniedException: Must be a Security Hub delegated administrator "
            "with Central Configuration enabled' -- states central configuration is "
            "not in use. The same code arrives from the delegated administrator in a "
            "non-home Region as 'Central Configuration APIs can only be called from "
            "the aggregation region' and from a plain IAM denial; both stay ERROR. "
            "https://docs.aws.amazon.com/securityhub/1.0/APIReference/"
            "API_ListConfigurationPolicyAssociations.html"
        ),
        message="with central configuration enabled",
    ),
},
```

Golden row: `('SecurityHubCheck', 'ListConfigurationPolicyAssociations', 'AccessDeniedException', 'with central configuration enabled', '<sha256>')`, same pragma, same length bump, inserted in sorted position between the `ListConfigurationPolicies` and `ListEnabledProductsForImport` rows.

Observation route: the **raw CLI**, `aws securityhub list-configuration-policy-associations --profile <management> --region <home>`, in the probe. Not the check: `-22` calls `ListFindingAggregators` first, and from an account that owns no finding aggregator that call succeeds with an empty list, so the check resolves at the no-aggregator FAIL and never issues `ListConfigurationPolicyAssociations`. The raw call is the one place the message can be seen without the check's guard in front of it.

Effect if added: `-22`'s per-account loop is preceded by one FAIL row with `region=home_region` saying central configuration is not enabled, mirroring `-13`.

Both entries are written out here so the implementer types nothing new after the probe; the probe decides only whether they go in. If the probe does not reach the condition (the test organization's audit account is subscribed everywhere scanned; a non-DA account's call may be blocked earlier by IAM), the entry stays out and the report records that it was not observable.

## Per-check specifications

Conventions shared by all five: `from collections.abc import Iterable`; imports of `AccountType`, `Severity`, `Finding`, `CheckMeta`, `Remediation` and `SecurityHubCheck` exactly as `sra_securityhub_13.py` has them (`-22` additionally imports `is_active_account` from `sraverify.core.accounts`, `is_error` from `sraverify.core.aws_errors`, and `SELF_MANAGED_POLICY_ID` from the base module); `sra_sections=("Security Tooling account", "AWS Security Hub CSPM")`; no `__init__`; one `execute()` generator; `checked_value` passed on every helper call (so the `CheckedValue` cell does not depend on the display name); parenthesized implicit concatenation for every multi-line string. Every ERROR row is `actual_value=f"{error['Operation']} failed: {error['Code']}: {error['Message']}"` with `remediation=self._remediation_for(error)`. Every classification is `self.is_not_configured(error)`.

### SRA-SECURITYHUB-21 — CSPM cross-Region aggregation links every scanned Region

| Field                 | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Module / class        | `checks/sra_securityhub_21.py` / `SRA_SECURITYHUB_21`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `title`               | `Security Hub CSPM cross-Region aggregation links all Regions to a home Region`                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `description`         | This check verifies that the Security Hub CSPM delegated administrator has created a finding aggregator that links every Region to a single home Region, so findings, control statuses and security scores from all Regions and member accounts are replicated to one place. This is the CSPM finding aggregator and is a separate resource from the unified Security Hub AggregatorV2 (SRA-SECURITYHUB-18). An aggregator in NO_REGIONS mode exists but replicates nothing. Member accounts inherit the administrator's aggregation settings. |
| `check_logic`         | From the audit account call securityhub:ListFindingAggregators; the aggregator ARN names the home Region. Call GetFindingAggregator there. Passes if RegionLinkingMode and Regions cover every scanned Region. Fails if no aggregator exists or a scanned Region is not linked, naming it. One row, labelled with the home Region.                                                                                                                                                                                                             |
| `severity`            | `Severity.MEDIUM` (mirrors `-18`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `account_type`        | `AccountType.AUDIT`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `service`             | `Security Hub CSPM`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `resource_type`       | `AWS::SecurityHub::FindingAggregator`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `remediation.text`    | In the delegated administrator account, create or update the Security Hub CSPM finding aggregator in the home Region so that it links all Regions.                                                                                                                                                                                                                                                                                                                                                                                             |
| `remediation.cli`     | `aws securityhub update-finding-aggregator --finding-aggregator-arn <arn> --region-linking-mode ALL_REGIONS --region <home-region>`                                                                                                                                                                                                                                                                                                                                                                                                            |
| `remediation.console` | Security Hub CSPM console in the delegated administrator account and home Region, Settings, Regions, Cross-Region aggregation, Edit, link all Regions.                                                                                                                                                                                                                                                                                                                                                                                         |
| `additional_urls`     | `https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html`, `https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingAggregator.html`                                                                                                                                                                                                                                                                                                                                                                  |

Operations and fields: `ListFindingAggregators` → `FindingAggregators[].FindingAggregatorArn` (ARN `arn:aws:securityhub:<home>:<account>:finding-aggregator/<uuid>`; `home_region_of` reads segment 3). `GetFindingAggregator(FindingAggregatorArn)` → `FindingAggregationRegion`, `RegionLinkingMode`, `Regions`. References: `https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListFindingAggregators.html`, `…/API_GetFindingAggregator.html`, `…/API_CreateFindingAggregator.html` (the `RegionLinkingMode` semantics).

Flow (mirrors `-18`, with CSPM names):

```python
checked_value = "A Security Hub CSPM finding aggregator links every scanned Region"
resource_id = f"securityhub:finding-aggregator/{self.account_id}"
probe_region = self.regions[0]
listed = self.get_finding_aggregators(probe_region)
if "Error" in listed:
    error = listed["Error"]
    if self.is_not_configured(error):            # reachable only if entry A is declared
        yield self.failed(region="global", resource_id=resource_id, checked_value=checked_value,
                          actual_value=f"Security Hub CSPM is not enabled in {probe_region}, so {probe_region} cannot be linked to a finding aggregator",
                          remediation=f"Enable Security Hub CSPM in the delegated administrator account in {probe_region}, then link it to the finding aggregator")
    else:
        yield self.error(region="global", resource_id=resource_id, checked_value=checked_value,
                         actual_value=f"{error['Operation']} failed: {error['Code']}: {error['Message']}",
                         remediation=self._remediation_for(error))
    return
home_region = self.home_region_of(listed)
if not home_region:
    yield self.failed(region="global", resource_id=resource_id, checked_value=checked_value,
                      actual_value="No Security Hub CSPM finding aggregator exists, so findings are not aggregated to a home Region")
    return
aggregator_arn = next(a["FindingAggregatorArn"] for a in listed["FindingAggregators"] if a.get("FindingAggregatorArn"))
if home_region not in self.regions:
    yield self.error(region="global", resource_id=aggregator_arn, checked_value=checked_value,
                     actual_value=f"The finding aggregator lives in home Region {home_region}, which is not among the scanned Regions ({', '.join(self.regions)})",
                     remediation=f"Re-run the check with {home_region} included in --regions so the aggregator can be read from its home Region")
    return
aggregator = self.get_finding_aggregator(home_region, aggregator_arn)
if "Error" in aggregator:
    error = aggregator["Error"]
    yield self.error(region=home_region, resource_id=aggregator_arn, checked_value=checked_value,
                     actual_value=f"{error['Operation']} failed: {error['Code']}: {error['Message']}",
                     remediation=self._remediation_for(error))
    return
mode = aggregator.get("RegionLinkingMode", "unknown")
listed_regions = sorted(aggregator.get("Regions") or [])
unlinked = self.cspm_unlinked_regions(aggregator, list(self.regions))
if unlinked:
    yield self.failed(region=home_region, resource_id=aggregator_arn, checked_value=checked_value,
                      actual_value=f"Finding aggregator in {home_region} ({mode}, Regions: {', '.join(listed_regions) or 'none'}) does not aggregate {', '.join(unlinked)}",
                      remediation=f"Link {', '.join(unlinked)}: aws securityhub update-finding-aggregator --finding-aggregator-arn {aggregator_arn} --region-linking-mode ALL_REGIONS --region {home_region}")
else:
    yield self.passed(region=home_region, resource_id=aggregator_arn, checked_value=checked_value,
                      actual_value=f"Finding aggregator in {home_region} ({mode}) aggregates all {len(self.regions)} scanned Regions")
```

The entry-A FAIL wording claims only what an `InvalidAccessException` from `regions[0]` establishes: that the audit account is unsubscribed *there*, so that Region cannot be linked. It does not say "no finding aggregator exists" — an aggregator may exist in another Region. `-22` and `-25` use the same sentence with their own consequence clause ("so central configuration cannot reach it from {probe_region}" / "so no CSPM finding event can be routed from {probe_region}"). `-13`'s existing wording overreaches in the same way and is out of scope.

`GetFindingAggregator`'s `ResourceNotFoundException` and `InvalidAccessException` are undeclared, so the `"Error" in aggregator` branch has one arm. The remediation recommends `ALL_REGIONS` rather than the V2 check's `SPECIFIED_REGIONS` because `UpdateFindingAggregator` accepts every mode (`https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_UpdateFindingAggregator.html`); the live phase runs the recommended CLI during Phase 4, as `testing_checks.md` requires.

Region labelling: one row, `region=home_region` for the real verdict, `global` for the no-aggregator FAIL and the pre-call ERRORs. Missing-input guard: none (no flag is read).

### SRA-SECURITYHUB-22 — every active account is centrally managed

| Field                 | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Module / class        | `checks/sra_securityhub_22.py` / `SRA_SECURITYHUB_22`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `title`               | `Security Hub CSPM central configuration associates every active account with a configuration policy`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `description`         | This check verifies that every active account in the organization is centrally managed by the Security Hub CSPM delegated administrator: its configuration policy association names a configuration policy rather than SELF_MANAGED_SECURITY_HUB, and the association status is SUCCESS. A self-managed account configures its own standards and controls, so a policy that passes SRA-SECURITYHUB-13 does not reach it; a PENDING or FAILED association means the policy's settings are not yet, or not fully, applied. Associations exist only in the home Region, which is resolved from the finding aggregator. One row per active account. |
| `check_logic`         | Resolve the home Region from securityhub:ListFindingAggregators, call securityhub:ListConfigurationPolicyAssociations there, and list the active organization accounts. Per account, passes if an ACCOUNT association names a policy other than SELF_MANAGED_SECURITY_HUB with AssociationStatus SUCCESS. Fails otherwise: no association, self-managed, or PENDING/FAILED.                                                                                                                                                                                                                                                                     |
| `severity`            | `Severity.HIGH` (mirrors `-04`: central configuration is the organization-wide enablement control)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `account_type`        | `AccountType.AUDIT`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `service`             | `Security Hub CSPM`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `resource_type`       | `AWS::SecurityHub::PolicyAssociation`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `remediation.text`    | In the delegated administrator account and home Region, associate the configuration policy with the organization root (or with each OU and account), and resolve any FAILED association from its status message.                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `remediation.cli`     | `aws securityhub start-configuration-policy-association --configuration-policy-identifier <policy-arn> --target RootId=<root-id> --region <home-region>`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `remediation.console` | Security Hub CSPM console in the delegated administrator account and home Region, Settings, Configuration, Policies, select the policy, Edit targets, add the root or the account.                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `additional_urls`     | `https://docs.aws.amazon.com/securityhub/latest/userguide/central-configuration-intro.html`, `https://docs.aws.amazon.com/securityhub/latest/userguide/view-policy.html`, `https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListConfigurationPolicyAssociations.html`                                                                                                                                                                                                                                                                                                                                                               |

Operations and fields: `ListFindingAggregators` as above. `ListConfigurationPolicyAssociations` → `ConfigurationPolicyAssociationSummaries[]{TargetId, TargetType, ConfigurationPolicyId, AssociationType, AssociationStatus, AssociationStatusMessage}` (`…/API_ListConfigurationPolicyAssociations.html`, `…/API_ConfigurationPolicyAssociationSummary.html`; the `AssociationType` filter that grounds the inherited-targets reading is `…/API_AssociationFilters.html`; `SELF_MANAGED_SECURITY_HUB` from `…/API_StartConfigurationPolicyAssociation.html`; "the delegated administrator can also apply a self-managed configuration to specific accounts, OUs, or the root" and "a self-managed account" wording from `central-configuration-intro.html`). `organizations:ListAccounts` through `self.organization.accounts()`, filtered with `is_active_account`.

**Load-bearing assumption and its fallback.** The per-account verdict rests on inherited accounts appearing as their own `TargetType=ACCOUNT` summaries. If they did not, nearly every account in a centrally-managed organization would FAIL "no configuration policy association". The reference grounds the assumption (above) but does not state it in one sentence, so the probe asserts it directly: from the delegated administrator in the home Region, the count of `ACCOUNT` summaries equals the count of active organization accounts, or every gap is explained (an account that is not a Security Hub member, for instance). If the probe contradicts it, `-22` changes shape before it is written: `association_of` is replaced by a resolver that walks `ROOT` and `ORGANIZATIONAL_UNIT` summaries against the organization tree (`self.organization.roots()`, `ous_for_parent(parent_id)`, `accounts_for_parent(parent_id)` — all existing provider accessors, all already granted in the member role), attributing to each account the nearest ancestor's association as `INHERITED`, and the `-22` section of this document is rewritten to that design first. The probe is cheap and read-only; writing the check twice is not.

Flow:

```python
checked_value = "Every active account has a SUCCESS association with a configuration policy"
scope_id = f"securityhub:configuration-policy-association/{self.account_id}"

# 1. Home Region, from the aggregator -- first, so a failure here resolves the
#    check before ListAccounts is reached (see the classification-harness note).
listed = self.get_finding_aggregators(self.regions[0])
# ... identical error / no-aggregator / not-scanned handling to -21, with
#     wording "No Security Hub CSPM finding aggregator exists, so central
#     configuration is not in use" on the no-aggregator FAIL and "so central
#     configuration cannot reach it from {probe_region}" on the entry-A FAIL,
#     all with region="global" and resource_id=scope_id ...
#     NOTE: from an account that owns no aggregator (e.g. the management
#     account), the check resolves HERE and never issues
#     ListConfigurationPolicyAssociations. See the live-validation plan.

# 2. Associations, from the home Region.
associations = self.get_configuration_policy_associations(home_region)
if "Error" in associations:
    error = associations["Error"]
    if self.is_not_configured(error):          # reachable only if entry B is declared
        yield self.failed(region=home_region, resource_id=scope_id, checked_value=checked_value,
                          actual_value="Security Hub CSPM central configuration is not enabled for this account, so no account is centrally managed",
                          remediation="Enable central configuration from the delegated administrator account, then associate a configuration policy with the root")
    else:
        yield self.error(region=home_region, resource_id=scope_id, ...)
    return
summaries = associations.get("ConfigurationPolicyAssociationSummaries", [])

# 3. The organization's active accounts.
accounts = self.organization.accounts()
if "Error" in accounts:
    error = accounts["Error"]
    if self.is_not_configured(error):          # ListAccounts / AWSOrganizationsNotInUseException, provider table
        yield self.failed(region=home_region, resource_id=scope_id, checked_value=checked_value,
                          actual_value="No organization exists, so no account can be centrally managed")
    else:
        yield self.error(region=home_region, resource_id=scope_id, ...)
    return
active = sorted(a["Id"] for a in accounts.get("Accounts", []) if is_active_account(a) and a.get("Id"))

# The management account cannot be associated until it has Security Hub CSPM
# enabled itself (view-policy.html, "Troubleshooting association failure"), so
# its no-association and FAILED remediations name that prerequisite. The
# provider accessor derives this from the DescribeOrganization result it has
# already cached for the scan; an error result means "unknown", and the suffix
# is simply omitted — the verdict does not depend on it.
mgmt = self.organization.management_account_id()   # str | ErrorResult
mgmt_id = None if is_error(mgmt) else mgmt           # is_error from core/aws_errors.py, as sra_securityincidentresponse_05 does
MGMT_HINT = (" This is the organization management account: enable Security Hub CSPM "
             "in it first so it becomes a member, or the association fails")

def _hint(account_id):
    return MGMT_HINT if account_id == mgmt_id else ""

# 4. One row per active account, in ascending account-ID order.
for account_id in active:
    summary = self.association_of(summaries, account_id)
    if summary is None:
        yield self.failed(region=home_region, resource_id=account_id, checked_value=checked_value,
                          actual_value=f"Account {account_id} has no configuration policy association",
                          remediation=f"Associate a configuration policy with account {account_id} or with its OU or the root in {home_region}.{_hint(account_id)}")
        continue
    policy_id = summary.get("ConfigurationPolicyId") or "unknown"
    status = summary.get("AssociationStatus") or "UNKNOWN"
    kind = summary.get("AssociationType") or "UNKNOWN"
    if policy_id == SELF_MANAGED_POLICY_ID:
        yield self.failed(..., actual_value=f"Account {account_id} is self-managed ({kind}, {status})", remediation=f"Associate a configuration policy with account {account_id}: aws securityhub start-configuration-policy-association --configuration-policy-identifier <policy-arn> --target AccountId={account_id} --region {home_region}")
    elif status != "SUCCESS":
        message = summary.get("AssociationStatusMessage")
        detail = f": {message}" if message else ""
        yield self.failed(..., actual_value=f"Account {account_id} is associated with configuration policy {policy_id} ({kind}) but the association is {status}{detail}",
                          remediation=(f"The association for {account_id} is still propagating; re-run the check later" if status == "PENDING"
                                       else f"Resolve the FAILED association for {account_id} in {home_region} using its status message, then re-associate the policy.{_hint(account_id)}"))
    else:
        yield self.passed(..., actual_value=f"Account {account_id} is centrally managed by configuration policy {policy_id} ({kind}, SUCCESS)")
```

Region labelling: `region=home_region` on every per-account row, since the association is a home-Region fact; `global` only for the pre-home-Region rows. The delegated administrator and the management account are included (the reference says the DA can itself be self-managed). The management account's no-association and FAILED rows carry the extra sentence from `_hint`, because `view-policy.html` ("Troubleshooting association failure", in `additional_urls`) states that an association with the Organizations management account fails unless that account already has Security Hub CSPM enabled; without the sentence the recommended `start-configuration-policy-association` would itself fail or land as `FAILED`. `management_account_id()` is an existing provider accessor over the cached `DescribeOrganization` result, so the hint adds no AWS call and no IAM action, and an error result from it only drops the sentence. `PENDING` is a FAIL with its own wording, as `-12` treats a `PENDING` standard: the control is not in effect yet, and the row says so rather than claiming it is.

Classification-harness note: `test_check_classification_property` drives every accessor with the same error result and skips a declared pair unless the *first* accessor the check calls issues that operation. `-22` calls `get_finding_aggregators` first, so the provider's `ListAccounts` / `AWSOrganizationsNotInUseException` pair is skipped for it (as for every check whose first call is a service accessor), and `_PROVIDER_PAIRS_WITHOUT_FAIL_ARM` needs no edit. Calling `accounts()` first would instead require either a FAIL arm the harness can see (which the check has) or a frozenset edit; the order above is chosen so the harness's behaviour needs no explanation beyond this paragraph.

### SRA-SECURITYHUB-23 — the FSBP standard is enabled and READY

| Field                 | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Module / class        | `checks/sra_securityhub_23.py` / `SRA_SECURITYHUB_23`                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `title`               | `Security Hub CSPM AWS Foundational Security Best Practices standard is enabled`                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `description`         | This check verifies that the AWS Foundational Security Best Practices standard (aws-foundational-security-best-practices/v/1.0.0) is among the enabled Security Hub CSPM standards in each Region and that its subscription is READY. SRA-SECURITYHUB-01 passes on any standard, so an account subscribed only to a vendor or industry standard passes it while the AWS baseline is unevaluated. A FAILED or INCOMPLETE subscription carries the standard's ARN while evaluating nothing, or only part of the standard. |
| `check_logic`         | Call securityhub:GetEnabledStandards in each Region and read StandardsSubscriptions[]. Passes if a subscription's StandardsArn ends with standards/aws-foundational-security-best-practices/v/1.0.0 and its StandardsStatus is READY. Fails if that subscription is absent, if its status is anything else, or if Security Hub CSPM is not enabled in the Region.                                                                                                                                                       |
| `severity`            | `Severity.HIGH` (mirrors `-12`; FSBP is the AWS baseline)                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `account_type`        | `AccountType.APPLICATION`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `service`             | `Security Hub CSPM`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `resource_type`       | `AWS::SecurityHub::Standard`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `remediation.text`    | Enable the AWS Foundational Security Best Practices standard in every Region where Security Hub CSPM is enabled, or add it to the central configuration policy so members inherit it.                                                                                                                                                                                                                                                                                                                                   |
| `remediation.cli`     | `aws securityhub batch-enable-standards --standards-subscription-requests 'StandardsArn=arn:aws:securityhub:<region>::standards/aws-foundational-security-best-practices/v/1.0.0' --region <region>`                                                                                                                                                                                                                                                                                                                    |
| `remediation.console` | Security Hub CSPM console, Security standards, AWS Foundational Security Best Practices, Enable. Repeat per Region, or edit the configuration policy in the delegated administrator's home Region.                                                                                                                                                                                                                                                                                                                      |
| `additional_urls`     | `https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html`, `https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetEnabledStandards.html`                                                                                                                                                                                                                                                                                                                                                  |

Operations and fields: `GetEnabledStandards` → `StandardsSubscriptions[]{StandardsArn, StandardsStatus, StandardsStatusReason.StatusReasonCode}` (`…/API_GetEnabledStandards.html`, `…/API_StandardsSubscription.html`: `StandardsStatus` is `PENDING | READY | FAILED | DELETING | INCOMPLETE`). The FSBP ARN shape `arn:aws:securityhub:<region>::standards/aws-foundational-security-best-practices/v/1.0.0` is confirmed by the CLI reference's `describe-standards` example (`https://docs.aws.amazon.com/cli/latest/reference/securityhub/describe-standards.html`).

Module constant: `FSBP_STANDARD_SUFFIX = "standards/aws-foundational-security-best-practices/v/1.0.0"`. Flow: a copy of `sra_securityhub_12.execute` with `AI_STANDARD_SUFFIX` replaced by `FSBP_STANDARD_SUFFIX`, the `checked_value` `"AWS Foundational Security Best Practices standard is enabled and READY"`, the same `if not self._clients` global FAIL guard, the same two-arm error branch (declared `GetEnabledStandards` / `InvalidAccessException` needle → FAIL "not enabled in region"; else ERROR), the same `READY` / transient / settled branches, and `standard_name_of` for the sorted standards list in `ActualValue`. `-12` is the reference implementation; `-23` adds no logic to it.

Region labelling: one row per scanned Region. No missing-input guard.

### SRA-SECURITYHUB-24 — a CIS AWS Foundations Benchmark version is enabled and READY

| Field                 | Value                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Module / class        | `checks/sra_securityhub_24.py` / `SRA_SECURITYHUB_24`                                                                                                                                                                                                                                                                                                                                                                           |
| `title`               | `Security Hub CSPM CIS AWS Foundations Benchmark standard is enabled`                                                                                                                                                                                                                                                                                                                                                           |
| `description`         | This check verifies that a version of the CIS AWS Foundations Benchmark is among the enabled Security Hub CSPM standards in each Region and that at least one such subscription is READY. Any supported version counts: v5.0.0, v3.0.0 and v1.4.0 use standards ARNs, and the legacy v1.2.0 uses a ruleset ARN. A subscription in FAILED or INCOMPLETE carries the ARN while evaluating nothing, or only part of the benchmark. |
| `check_logic`         | Call securityhub:GetEnabledStandards in each Region and read StandardsSubscriptions[]. Passes if a subscription's StandardsArn contains cis-aws-foundations-benchmark/v/ and its StandardsStatus is READY. Fails if no such subscription exists, if none is READY, or if Security Hub CSPM is not enabled in the Region, naming every CIS version found and its status.                                                         |
| `severity`            | `Severity.MEDIUM` (a second baseline alongside FSBP; organizations that must run CIS treat it as HIGH, but the SRA lists it after FSBP)                                                                                                                                                                                                                                                                                         |
| `account_type`        | `AccountType.APPLICATION`                                                                                                                                                                                                                                                                                                                                                                                                       |
| `service`             | `Security Hub CSPM`                                                                                                                                                                                                                                                                                                                                                                                                             |
| `resource_type`       | `AWS::SecurityHub::Standard`                                                                                                                                                                                                                                                                                                                                                                                                    |
| `remediation.text`    | Enable a CIS AWS Foundations Benchmark version in every Region where Security Hub CSPM is enabled, or add it to the central configuration policy so members inherit it.                                                                                                                                                                                                                                                         |
| `remediation.cli`     | `aws securityhub batch-enable-standards --standards-subscription-requests 'StandardsArn=arn:aws:securityhub:<region>::standards/cis-aws-foundations-benchmark/v/5.0.0' --region <region>`                                                                                                                                                                                                                                       |
| `remediation.console` | Security Hub CSPM console, Security standards, CIS AWS Foundations Benchmark v5.0.0, Enable. Repeat per Region, or edit the configuration policy in the delegated administrator's home Region.                                                                                                                                                                                                                                  |
| `additional_urls`     | `https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html`, `https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetEnabledStandards.html`                                                                                                                                                                                                                                          |

ARNs (from `cis-aws-foundations-benchmark.html`, "ARNs for CIS AWS Foundations Benchmarks"): `arn:aws:securityhub:<region>::standards/cis-aws-foundations-benchmark/v/5.0.0`, `…/v/3.0.0`, `…/v/1.4.0`, and `arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0`. Module constant: `CIS_STANDARD_MARKER = "cis-aws-foundations-benchmark/v/"`, matched with `in` rather than `endswith` because the version suffix varies and the v1.2.0 ARN uses `ruleset/`. `standard_name_of` partitions on `"standards/"` and returns the whole ARN for the `ruleset/` form; the `ActualValue` therefore lists `cis-aws-foundations-benchmark/v/3.0.0` for the new ARNs and the full `arn:aws:securityhub:::ruleset/…` for v1.2.0, which is accurate and diffable.

Flow: as `-23`, with two differences. The subscriptions are filtered to `[s for s in subs if CIS_STANDARD_MARKER in s.get("StandardsArn", "")]`; if the list is empty → FAIL "no CIS AWS Foundations Benchmark version is enabled"; if any has `StandardsStatus == "READY"` → PASS; otherwise → FAIL, with the transient wording if every CIS subscription is `PENDING` or `DELETING` and the settled wording (with `StatusReasonCode` of the first non-READY) otherwise.

`ActualValue` shape (Requirement 6.4 inherits 5.5, so the cell is fixed here rather than left to the implementer): the sorted full standards list exactly as `-23` renders it through `standard_name_of`, followed by `"; CIS: "` and the CIS subscriptions sorted by `StandardsArn`, each as `<standard_name_of(arn)> <StandardsStatus>` joined with `", "`. Example: `Enabled standards: aws-foundational-security-best-practices/v/1.0.0, cis-aws-foundations-benchmark/v/3.0.0, arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0; CIS: cis-aws-foundations-benchmark/v/3.0.0 READY, arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0 INCOMPLETE`. When the filtered list is empty the `"; CIS: "` segment reads `; CIS: none`. Both halves are sorted lists, never sets, so the cell is diffable.

### SRA-SECURITYHUB-25 — an EventBridge rule routes CSPM findings to a response target

| Field                 | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Module / class        | `checks/sra_securityhub_25.py` / `SRA_SECURITYHUB_25`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `title`               | `EventBridge rule routes Security Hub CSPM findings to a response target`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `description`         | This check verifies that an ENABLED Amazon EventBridge rule on the default event bus matches Security Hub CSPM finding events (detail-type Security Hub Findings - Imported) and has at least one target, so findings drive automated response and remediation. With cross-Region aggregation, aggregated findings raise their events in the home Region, so that is where the rule is evaluated; without an aggregator, every scanned Region is evaluated. Rules filtered only on the unified Security Hub Findings Imported V2 event, or only on Custom Action events, do not count; SRA-SECURITYHUB-20 covers the V2 event. |
| `check_logic`         | Resolve the home Region from securityhub:ListFindingAggregators. Call events:ListRules there (every scanned Region if no aggregator) and events:ListTargetsByRule for each ENABLED rule naming source aws.securityhub and detail-type Security Hub Findings - Imported, or no detail-type. Passes on the first such rule with a target. Fails: no match, DISABLED, or no target.                                                                                                                                                                                                                                               |
| `severity`            | `Severity.MEDIUM` (mirrors `-20`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `account_type`        | `AccountType.AUDIT`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `service`             | `Security Hub CSPM`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `resource_type`       | `AWS::Events::Rule`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `remediation.text`    | In the delegated administrator account's home Region, create an EventBridge rule for source aws.securityhub and detail-type Security Hub Findings - Imported, and give it a response target such as a Lambda function, Step Functions state machine or SNS topic.                                                                                                                                                                                                                                                                                                                                                              |
| `remediation.cli`     | `aws events put-rule --name securityhub-cspm-findings --event-pattern '{"source":["aws.securityhub"],"detail-type":["Security Hub Findings - Imported"]}' --state ENABLED --region <home-region>` then `aws events put-targets --rule securityhub-cspm-findings --targets Id=1,Arn=<target-arn> --region <home-region>`                                                                                                                                                                                                                                                                                                        |
| `remediation.console` | EventBridge console in the delegated administrator account and home Region, Rules, Create rule, Event pattern: AWS services, Security Hub, Security Hub Findings - Imported; add a target.                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `additional_urls`     | `https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-all-findings.html`, `https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-integration-types.html`, `https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_ListRules.html`                                                                                                                                                                                                                                                                                                                                              |

Operations and fields: `ListFindingAggregators` as above. `events:ListRules` → `Rules[]{Name, Arn, State, EventPattern}` (`https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_ListRules.html`); `events:ListTargetsByRule(Rule)` → `Targets[]` (`…/API_ListTargetsByRule.html`). The detail-type string is confirmed by `securityhub-cwe-event-formats.html` (`"detail-type":"Security Hub Findings - Imported"`).

Flow: `sra_securityhub_20.execute` and `_evaluate_region` with `get_aggregators_v2` / `aggregation_region_of` replaced by `get_finding_aggregators` / `home_region_of`, `matches_v2_findings` replaced by `matches_cspm_findings`, `V2_FINDINGS_DETAIL_TYPE` by `CSPM_FINDINGS_DETAIL_TYPE`, the `checked_value` `"An ENABLED EventBridge rule with a target matches Security Hub Findings - Imported events"`, and `resource_id = f"events:rule/{self.account_id}"` for rows that name no rule. The `_evaluate_region` structure — one PASS and `return` on the first ENABLED matching rule with a target; an ERROR if at least one ENABLED candidate's `ListTargetsByRule` returned an error result and no candidate passed (`undetermined = undetermined or targets["Error"]`, so the first error result is the one reported, and it is reported even when the other ENABLED candidates were merely targetless); otherwise one FAIL whose detail distinguishes targetless, DISABLED and no-match — is kept exactly. Requirement 7.5 states the same ERROR condition, so the two documents and the `-20` code agree. The `get_finding_aggregators` error branch has the two arms; the `is_not_configured` arm is reachable only if entry A is declared.

Region labelling: one row for the home Region when an aggregator exists; one per scanned Region otherwise; `global` for the pre-home-Region rows.

### Gaps deliberately not added

| Checklist item                                                      | Why not                                                                                                                                                                                                                                                    |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 4 GuardDuty and Detective share the CSPM delegated administrator    | Detective has no package; the GuardDuty half is already the pair `SRA-GUARDDUTY-14` / `SRA-SECURITYHUB-07`, both compared to `--audit-account`. A Detective package is its own spec.                                                                       |
| 10 Findings from all member accounts aggregated in Security Tooling | A restatement of facts `-07` (DA is the audit account), `-08` (all active accounts are members) and `-09` (all members Enabled) already hold; there is no further API fact to read.                                                                        |
| 13 Other standards enabled as applicable                            | "As applicable" has no objective criterion; `-12`, `-23` and `-24` cover the three the SRA names.                                                                                                                                                          |
| 14 CSPM findings consumed by Security Hub for exposure correlation  | A V2 fact: `SRA-SECURITYHUB-19`'s coverage findings assess CSPM as a building-block capability per account and Region. Nothing on the CSPM API answers it.                                                                                                 |
| 15 Automation rule enriches findings with resource context          | `ListAutomationRules` / `BatchGetAutomationRules` are read-only, but whether a rule's `FindingFieldsUpdate` "enriches with resource context" is a judgement about customer-authored content; an existence check would PASS a suppression rule. Non-Goal 5. |
| 17 CloudWatch telemetry enablement rule for the organization        | The `observabilityadmin` service (`ListTelemetryRulesForOrganization` and siblings, present in botocore 1.43.105), not Security Hub; needs its own package and IAM actions.                                                                                |

## Data models

### The two new success shapes

```python
# SecurityHubClient.get_finding_aggregator
{"FindingAggregationRegion": "us-east-1",
 "FindingAggregatorArn": "arn:aws:securityhub:us-east-1:111122223333:finding-aggregator/<uuid>",
 "RegionLinkingMode": "ALL_REGIONS" | "ALL_REGIONS_EXCEPT_SPECIFIED" | "SPECIFIED_REGIONS" | "NO_REGIONS",
 "Regions": ["us-west-2", ...]}            # excluded or included, by mode; may be absent

# SecurityHubClient.list_configuration_policy_associations
{"ConfigurationPolicyAssociationSummaries": [
    {"TargetId": "111122223333", "TargetType": "ACCOUNT",
     "ConfigurationPolicyId": "<uuid>" | "SELF_MANAGED_SECURITY_HUB",
     "AssociationType": "APPLIED" | "INHERITED",
     "AssociationStatus": "PENDING" | "SUCCESS" | "FAILED",
     "AssociationStatusMessage": "...",     # present on FAILED
     "UpdatedAt": datetime}, ...]}
```

Every field is optional in the API reference; the helpers use `.get` throughout and treat an absent `RegionLinkingMode` as linking nothing and an absent `AssociationStatus` as `UNKNOWN` (a FAIL).

### Cache slots

Two new keys under `NAMESPACE = "securityhub"`: `finding_aggregator:{region}:{arn}` and `configuration_policy_associations:{region}`. Both hold the client's success dict. Neither holds an error result (`_cached_call` returns those uncached; `_set` refuses them as a backstop).

### The error result

Unchanged: `{"Error": {"Code", "Message", "Operation"}}`. `GetFindingAggregator` and `ListConfigurationPolicyAssociations` arrive with their own operation names from `ClientError.operation_name`; a `BotoCoreError` arrives as `UNKNOWN_OPERATION`.

### Rows

Row shapes per check, for the comparison dashboard's key (`CheckId`, `AccountId`, `Region`, `ResourceId`):

| Check | Rows                                    | `Region`                                                                                   | `ResourceId`                                                                      |
| ----- | --------------------------------------- | ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| -21   | 1                                       | home Region (verdict); `global` (no aggregator, not-scanned, ListFindingAggregators error) | aggregator ARN; `securityhub:finding-aggregator/<audit>` before the ARN is known  |
| -22   | 1 per active account                    | home Region; `global` before the home Region is known                                      | account ID; `securityhub:configuration-policy-association/<audit>` for scope rows |
| -23   | 1 per scanned Region                    | the Region; `global` only for the no-clients guard                                         | `securityhub:standards/<account>`                                                 |
| -24   | 1 per scanned Region                    | same                                                                                       | `securityhub:standards/<account>`                                                 |
| -25   | 1 (home Region) or 1 per scanned Region | the evaluated Region; `global` before the home Region is known                             | rule ARN on PASS; `events:rule/<audit>` otherwise                                 |

## Error handling

Each operation's failure conditions, who sees them, and what they become.

| Operation (caller)                          | Condition                                                                                                                 | Classification                                                      | Row                                                    |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------ |
| `ListFindingAggregators` (-21, -22, -25)    | `InvalidAccessException` "not subscribed"                                                                                 | FAIL only if entry A is declared after observation; otherwise ERROR | one `global` row, then `return`                        |
| `ListFindingAggregators`                    | `AccessDeniedException`, transport, `NoClient`                                                                            | ERROR                                                               | one `global` row, `return`                             |
| home Region ∉ `--regions` (-21, -22, -25)   | not an AWS error; decided before the next call                                                                            | ERROR naming `--regions`                                            | one `global` row, `return`                             |
| `GetFindingAggregator` (-21)                | any error result                                                                                                          | ERROR (nothing declared)                                            | one home-Region row, `return`                          |
| `ListConfigurationPolicyAssociations` (-22) | `AccessDeniedException` "with central configuration enabled"                                                              | FAIL only if entry B is declared; otherwise ERROR                   | one home-Region row, `return`                          |
| `ListConfigurationPolicyAssociations`       | wrong-Region `AccessDeniedException`, IAM denial, transport                                                               | ERROR                                                               | one home-Region row, `return`                          |
| `ListAccounts` via provider (-22)           | `AWSOrganizationsNotInUseException`                                                                                       | FAIL (provider table)                                               | one home-Region row, `return`                          |
| `ListAccounts` via provider                 | anything else                                                                                                             | ERROR                                                               | one home-Region row, `return`                          |
| `DescribeOrganization` via `management_account_id()` (-22) | any error result | no classification: the management-account hint is omitted; the verdict is unchanged | — (no row; the failure is already one `aws_call_failed` record) |
| `GetEnabledStandards` (-23, -24)            | `InvalidAccessException` "not subscribed"                                                                                 | FAIL (declared)                                                     | per-Region row, `continue`                             |
| `GetEnabledStandards`                       | anything else                                                                                                             | ERROR                                                               | per-Region row, `continue`                             |
| `ListRules` (-25)                           | any                                                                                                                       | ERROR                                                               | per evaluated Region, `return` from `_evaluate_region` |
| `ListTargetsByRule` (-25)                   | error result for one or more ENABLED candidates, and no candidate passed (other candidates may be targetless or DISABLED) | ERROR (first error result kept)                                     | one row for the Region                                 |
| `ListTargetsByRule`                         | error result for one or more candidates, but another candidate passed                                                     | swallowed by the PASS; the passing rule is the verdict              | —                                                      |
| Account identity / Region list              | `ScanPreconditionError`                                                                                                   | orchestrator's precondition row                                     | — (never caught in `execute`)                          |

The two `return`-versus-`continue` choices follow `creating_checks_best_practices.md`'s fan-out rule: an enumeration failure (`ListFindingAggregators`, `ListConfigurationPolicyAssociations`, `ListAccounts`, `ListRules`) ends the check with one row because nothing downstream can be evaluated; a per-item failure (`GetEnabledStandards` per Region, `ListTargetsByRule` per rule) costs one item. `-22` has no per-account AWS call, so its per-account loop cannot error.

Logging: nothing new. Each failed call is one `aws_call_failed` record at `debug` from `AWSClient.aws_error`; the accessors log `SecurityHub: Fetching …` / `Using cached …` at `debug` and `No client available` at `warning` as the existing ones do. No `logger.error` anywhere in the new code, because no new code produces an ERROR row that the orchestrator does not already see.

### Validation of inputs

The checks read no CLI flag (`--audit-account` is not needed: the audit account scans itself). The only external inputs are AWS responses, validated by shape: every field read with `.get`, every list defaulted to `[]`, `EventPattern` parsed with `json.loads` inside `try/except ValueError` and rejected when not a dict. `self.regions` is the scan's list and is non-empty by the time `execute` runs (`regions[0]` is safe; `-13`, `-18`, `-20` already rely on it).

## Correctness properties

Each is held by an existing property module once the adapter rows are added; none needs a new test module.

1. **Both new client methods honour the client contract.** `test_client_contract_property.py` drives `get_finding_aggregator` and `list_configuration_policy_associations` through `ClientError`, `EndpointConnectionError`, `NoCredentialsError` and `RuntimeError` and asserts the return shape, the propagated operation name, and that `RuntimeError` escapes. Held by the two new `ClientAdapter` rows; the module's AST rules (handler shape, constructor-only acquisition, no `-> bool`) run over the edited `client.py` unchanged.
2. **Both new accessors never cache a failure, re-issue on retry, and return `no_client_result` without a client.** `test_accessor_cache_property.py`, from the two new `accessor` rows with their `cache_key`.
3. **Every public method on `SecurityHubCheck` is classified.** `test_every_public_base_method_is_classified` — the three helpers need `helper` rows or it fails.
4. **Every new check reaches `error()` and never `failed()` when every accessor fails, and every ERROR row names operation and code.** `test_check_classification_property.py`, catalog-wide, picks the five up through the registry.
5. **A declared semantic pair reaches `failed()`.** For `-23` and `-24`, `GetEnabledStandards` / `InvalidAccessException` is their first accessor's operation, so the harness observes the FAIL. For `-21`, `-22`, `-25` the first operation is `ListFindingAggregators`, undeclared today, so every pair is skipped for them until entry A is added — at which point the harness observes their FAIL arm.
6. **No check reaches the cache or the provider's client; the sixteen consumers read `accounts()` once.** `test_layering_property.py`, with the `_CONSUMERS` edit.
7. **The catalog has 187 checks, bijective with the module stems.** `test_catalog_identity_property.py`, `test_registry_bijection_property.py`.
8. **Nothing writes to stdout.** `test_stdout_contract_property.py`, unchanged.
9. **Every `NOT_CONFIGURED_ERRORS` entry has evidence and matches the golden.** `test_discriminator_property.py`; the golden changes only if an entry is added.
10. **Metadata validates at import.** `--list-checks` with no credentials.

## Testing strategy

**Unit, offline (the whole of the automated obligation).** The adapter rows above; the two `EXPECTED_CHECK_COUNT` edits; the `_CONSUMERS` edit. Representative `args` for the helpers: `cspm_unlinked_regions({"FindingAggregationRegion": "us-west-2", "RegionLinkingMode": "SPECIFIED_REGIONS", "Regions": ["us-east-1"]}, ["us-east-1", "us-west-2", "eu-west-1"])` → `["eu-west-1"]`; `association_of([{"TargetType": "ACCOUNT", "TargetId": "111122223333", "ConfigurationPolicyId": "abc", "AssociationStatus": "SUCCESS"}], "111122223333")`; `matches_cspm_findings({"EventPattern": '{"source":["aws.securityhub"],"detail-type":["Security Hub Findings - Imported"]}'})` → `True`. The implementer adds a small table-driven unit test for the three helpers' edge cases (`NO_REGIONS`, absent `Regions`, the v1.2.0 `ruleset/` ARN through `standard_name_of`, a `detail`-only pattern, a V2-only pattern) under `tests/unit/services/`, beside `test_inspector_batching.py`.

**Verification run.** `sraverify --check SRA-SECURITYHUB-2N --debug` for each of the five against the audit profile, stderr kept.

**Live, per `testing_checks.md`.** Below.

## Live validation plan

Accounts and profiles are in `sratester/accounts.md`; nothing below names them. Scratch output goes to `.tmp/sratester/securityhub-cspm-split/`; the report to `sratester/securityhub-cspm-split-test-report.md`.

**Step 1 — probe, read-only, and it runs first.** This step is task 1.5 in `tasks.md`: it precedes every code change, because four facts the design depends on are settled here and each would otherwise re-open the base, the checks, the suite and the security scan. It is re-run at the start of the live phase only to confirm nothing moved. From the audit, management and one application profile, in the home Region and in one non-home scanned Region: `aws securityhub list-finding-aggregators`, `get-finding-aggregator --finding-aggregator-arn <arn>` where `<arn>` is the delegated administrator's aggregator ARN taken from the audit profile's `list-finding-aggregators` (also from the non-home Region, to learn whether it answers or refuses; from the application and management profiles, which own no aggregator, the expected answer is an error, and its code and message are what is recorded), `list-configuration-policy-associations`, `get-enabled-standards`. Also from an application profile in a Region where CSPM is not subscribed: `list-finding-aggregators`. Record every response and every error code and message to `probe.txt`. The probe answers, explicitly, in its output:

1. Does `get-finding-aggregator` answer from a non-home Region? (Shapes the client docstring; the check reads from the home Region either way.)
2. From the delegated administrator in the home Region, does the number of `TargetType=ACCOUNT` summaries equal the number of active organization accounts (`aws organizations list-accounts`, `Status=ACTIVE`)? List every gap and its explanation. A mismatch that is not explained triggers the `-22` fallback design (§ SRA-SECURITYHUB-22) before task 5.2.
3. Entry A: did `list-finding-aggregators` from the unsubscribed Region return `InvalidAccessException` with the "not subscribed" message?
4. Entry B: did `list-configuration-policy-associations` with the management profile in the home Region return `AccessDeniedException` with the "with central configuration enabled" message? This is the raw-CLI observation; the check cannot provide it (next step).
5. What does `list-finding-aggregators` return from the management profile — an empty list, or the delegated administrator's aggregator? This decides the expected `-22` row in step 2.

**Step 2 — read-only negatives.** `--regions` without the home Region → `-21`, `-22`, `-25` ERROR rows naming it. `--check SRA-SECURITYHUB-23` / `-24` against a Region where CSPM is not subscribed → FAIL "not enabled". `--account-type audit --check SRA-SECURITYHUB-22` with the management profile is run and recorded, but its row depends on probe answer 5: `-22` calls `ListFindingAggregators` first, and if the management account lists no aggregator the check yields the no-aggregator FAIL (`global`, "so central configuration is not in use") and returns without issuing `ListConfigurationPolicyAssociations`; only if the management account does list the DA's aggregator does the run reach the `ListConfigurationPolicyAssociations` error branch (ERROR, or FAIL if entry B landed). The `ListConfigurationPolicyAssociations` ERROR arm is otherwise reachable only from an account that owns a finding aggregator and is not the delegated administrator, or by a wrong-Region call the not-scanned guard forbids. No such account exists in the test organization without a mutation, so the status table pre-marks that arm 🔄 ATTEMPTED with this reason unless answer 5 opens the route; it is held offline by `test_check_classification_property.py`.

**Step 3 — snapshot.** For `-22`: the chosen application account's summary from `list-configuration-policy-associations`, keeping `ConfigurationPolicyId`, `TargetId`, `TargetType`, `AssociationType`, `AssociationStatus` (and `UpdatedAt` for the record, excluded from the comparison). `AssociationType` is what decides the restoration. For `-25`: the matching rule's `describe-rule` and `list-targets-by-rule`. For `-21`, if mutated: `get-finding-aggregator` output.

**Step 4 — the five phases, sequential per check.**

| Check | Baseline (expected)                                                            | Mutation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Detect                                                                                       | Fix                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Validate                                                | Status if blocked                                                                                                                                     |
| ----- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| -21   | PASS if the aggregator is `ALL_REGIONS`                                        | Preferred read-only: add to `--regions` an enabled Region the aggregator does not link, if one exists. Otherwise `update-finding-aggregator --region-linking-mode SPECIFIED_REGIONS --regions <linked minus one scanned Region>`                                                                                                                                                                                                                                                                  | FAIL naming the Region                                                                       | Restore the snapshotted mode and Regions (or run the recommended `ALL_REGIONS` CLI, then restore)                                                                                                                                                                                                                                                                                                                                                                                                            | PASS                                                    | 🔄 if the owner declines the mutation: unlinking a Region also removes it from central configuration's scope while unlinked                            |
| -22   | PASS per account                                                               | `start-configuration-policy-association --configuration-policy-identifier SELF_MANAGED_SECURITY_HUB --target AccountId=<one application account> --region <home>`; wait for the association to leave PENDING (poll `get-configuration-policy-association`; docs allow up to 24 h, observed minutes)                                                                                                                                                                                               | exactly that account's row FAIL "self-managed (APPLIED, SUCCESS)"; every other row unchanged | **By snapshotted `AssociationType`.** INHERITED (the normal case, policy on root/OU): `start-configuration-policy-disassociation --configuration-policy-identifier SELF_MANAGED_SECURITY_HUB --target AccountId=<id> --region <home>`; the account resumes inheriting from its closest parent. APPLIED: `start-configuration-policy-association` back to the snapshotted policy ARN. Poll `get-configuration-policy-association` until `AssociationStatus=SUCCESS` and `AssociationType` equals the snapshot | PASS, with `ActualValue` showing the snapshotted `kind` | —                                                                                                                                                     |
| -23   | PASS where the policy enables FSBP; FAIL "not enabled" in unsubscribed Regions | None available in a centrally-managed account (`BatchDisableStandards` is refused there); an org-wide policy edit is out of scope                                                                                                                                                                                                                                                                                                                                                                 | —                                                                                            | —                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | —                                                       | 🔄 for the standard-absent arm; the not-subscribed FAIL and the PASS are both observed, so both verdicts are seen                                      |
| -24   | as -23                                                                         | as -23                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | —                                                                                            | —                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | —                                                       | as -23                                                                                                                                                |
| -25   | PASS if a CSPM rule exists; otherwise FAIL                                     | If PASS: `events disable-rule --name <rule>` in the home Region, where `<rule>` is a matching rule that is **not** named `aws-controltower-*` and **not** stack-owned (`describe-rule` reports no `ManagedBy`; `list-tags-for-resource` shows no `aws:cloudformation:stack-name`). If every matching rule is managed, or if the baseline is FAIL: `put-rule` + `put-targets` with a temporary rule (`sraverify-test-cspm`, target an existing SNS topic or a temporary log group), then delete it | FAIL "DISABLED" / PASS naming the rule                                                       | `enable-rule` / `remove-targets` + `delete-rule`                                                                                                                                                                                                                                                                                                                                                                                                                                                             | baseline verdict                                        | — (a managed rule is never disabled: `testing_checks.md` forbids changing Control Tower resources, and disabling a stack-owned rule drifts its stack) |

**Why the `-22` restore is a disassociation, not a re-association.** Re-associating the parent's policy *to the account* creates a direct association: `AssociationType` comes back `APPLIED`, not `INHERITED`. The row's `ActualValue` embeds `kind`, so the Requirement 2 diff would show the cell changed, the restoration comparison would fail on `AssociationType`, and — worse — the test organization would be left with an account-level association that no longer follows future root or OU policy changes. `StartConfigurationPolicyDisassociation` is the operation for this case: "when you disassociate a configuration from its target, the target inherits the configuration of the closest parent … A target can be disassociated from a configuration policy or self-managed behavior" (`https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_StartConfigurationPolicyDisassociation.html`); the user guide confirms the identifier for a self-managed target: "Provide SELF_MANAGED_SECURITY_HUB for this field to disassociate self-managed behavior" (`https://docs.aws.amazon.com/securityhub/latest/userguide/disassociate-policy.html`). Note the guide's constraint, which is exactly why the order matters: "You can disassociate only a directly applied configuration, not an inherited configuration" — the mutation *made* the association direct, so the disassociation is legal; it would not have been before the mutation. The probe (step 1) reads the disassociation reference and the account's current `AssociationType` before anything is changed.

**Step 5 — restoration proof.** A script re-reads each snapshotted resource and compares it field by field against `snapshot.json`: for the `-22` account, `ConfigurationPolicyId`, `TargetId`, `TargetType`, `AssociationType` and `AssociationStatus` must be identical and `UpdatedAt` is excluded (a correct restore necessarily changes it); for the `-25` rule, `State`, `EventPattern` and the target list must be identical; for `-21`, if mutated, `RegionLinkingMode` and `Regions`. The script's output goes in the report verbatim. A byte-for-byte `cmp` of the raw JSON is not the right tool for the association summary, because `UpdatedAt` would make it fail on every correct restore.

**Step 6 — IAM.** `simulate-principal-policy` for `securityhub:GetFindingAggregator` and `securityhub:ListConfigurationPolicyAssociations` against the deployed member role; `simulate-custom-policy` against the edited template. Deploy the StackSet and the management-account stack before step 7.

**Step 7 — CodeBuild.** One build with a `buildspecOverride` that replaces the `git clone` line with a tarball copy (`sraverify/` and `sra-verify-dashboard.html`, excluding `.venv`, `build`, `dist`, `*.egg-info`, `__pycache__`, `.hypothesis`). Judge from the consolidated CSV: `-21`, `-22`, `-25` one row each per audit account (`-22` one per active account); `-23`, `-24` one row per account per Region; zero ERROR rows from the five; total ERROR delta explainable by the new rows; and the Requirement 2 diff — Security Hub rows' `Service` normalized, every other cell identical.

**What is never touched.** The CSPM and V2 delegated administrators, Security Hub enablement in any Region, Control Tower resources, any configuration policy's content. The `-22` mutation changes one account's association, not the policy.

## Documentation changes

- `product.md`: 187 checks; `securityhub 25`; a paragraph stating the soft split and the two display names; the five new checks listed beside the AI-coverage and V2 descriptions.
- `structure.md` and `tech.md`: 187 checks, 98 client methods, the new pytest totals (passed and skipped), and `--service "Security Hub CSPM"` as a filter example.
- `creating_checks_best_practices.md`: the two `182` mentions.
- `docs/check-report.md`: items 6, 9, 11, 12, 16 → Covered with the new IDs; items 4, 10, 13, 14, 15, 17 keep their status with a note pointing at this spec; the CSPM summary row goes from 17 / 6 / 5 / 6 to **17 / 11 / 3 / 3** (Partial {4, 10, 13}, Missing {14, 15, 17}); the total row is recomputed from the per-service rows (224 / 124 / 13 / 87 if nothing else moves); the header count.
- `README.md`: the service list at line 5 names "Security Hub CSPM" and "Security Hub" and its stale "158" becomes 187. The `--service CloudTrail` example at line 231 is unaffected and stays.
- `sraverify/README.md`: one paragraph on two display names in one package.
- `docs/checks.txt`: regenerated.
- `1-sraverify-member-roles.yaml`: the two actions.

## Responses to the design review (revision 2)

The first review (`review.md`, verdict CHANGES_REQUESTED: 1 HIGH, 4 MEDIUM, 8 LOW) was applied in full. Each finding and what changed:

| ID  | Disposition | Change                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| --- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| H1  | Fixed       | The `-22` restoration is chosen by the snapshotted `AssociationType`: `StartConfigurationPolicyDisassociation` with `SELF_MANAGED_SECURITY_HUB` for an INHERITED baseline, re-association only for an APPLIED one. The snapshot records `AssociationType`; the restoration comparison is field-by-field and excludes `UpdatedAt`. Cited `API_StartConfigurationPolicyDisassociation.html` and `disassociate-policy.html`, both fetched (200) and confirmed against the botocore 1.43.105 model, which carries the operation and its `ConfigurationPolicyIdentifier` doc ("or a value of SELF_MANAGED_SECURITY_HUB"). Requirement 12.3, 12.10 and tasks 12.3–12.5 rewritten to match. |
| M1  | Fixed       | The read-only probe is task 1.5, before any code; entries A and B are decided in task 3.5 from its output; task 12.1 is a re-confirmation. The probe's five explicit questions are listed in § Live validation Step 1.                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| M2  | Fixed       | CSPM summary row is 17 / 11 / 3 / 3 (Partial {4, 10, 13}, Missing {14, 15, 17}); the total row is recomputed from the per-service rows. Requirement 11.3, § Documentation changes and task 9.2 agree.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| M3  | Fixed       | `association_of`'s docstring and Requirement 4.4 cite `API_AssociationFilters.html` and `ConfigurationPolicyAssociationSummary.AssociationType`; probe question 2 asserts `ACCOUNT` summaries == active accounts with every gap explained; the fallback (walk ROOT/OU summaries against the provider's `roots()` / `ous_for_parent()` / `accounts_for_parent()`) is stated in § SRA-SECURITYHUB-22 and Requirement 4.5a, to be designed before task 5.2 if the probe contradicts the assumption.                                                                                                                                                                                     |
| M4  | Fixed       | Step 2 and Requirement 12.2 state the real expected row: from an account owning no aggregator, `-22` resolves at the no-aggregator FAIL and never issues `ListConfigurationPolicyAssociations`. Probe question 5 (what the management profile's `list-finding-aggregators` returns) decides whether the ERROR arm is reachable; entry B's observation moved to the raw CLI in the probe; the arm is pre-marked 🔄 ATTEMPTED unless the probe opens the route.                                                                                                                                                                                                                         |
| L1  | Fixed       | Requirement 2.2 reads "in no row's `Service` cell" and lists where the token legitimately remains.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| L2  | Fixed       | Ten pairs, six `InvalidAccessException`; 16 cached accessors, 6 derived delegators, 8 helpers. Both passages corrected; neither changes the argument.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| L3  | Fixed       | The `assert len(_NON_OWNED_NOT_CONFIGURED_ENTRIES) == 46` bump is named beside each golden row, in Requirement 9.4 and in task 3.5.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| L4  | Fixed       | Requirement 8.4 lists both constants.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| L5  | Fixed       | Requirement 1.4 and 11.4 target the README service list (line 5) and leave the `--service CloudTrail` example alone; the stale "158" is corrected in the same edit.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| L6  | Fixed       | Entry-A FAIL wording is "Security Hub CSPM is not enabled in {probe_region}, so {probe_region} cannot be linked to a finding aggregator", with per-check consequence clauses for `-22` and `-25`. `-13`'s wording is out of scope, as the review noted.                                                                                                                                                                                                                                                                                                                                                                                                                              |
| L7  | Fixed       | Task 1.1 admits the untracked `.worktrees/` entry.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| L8  | Fixed       | Introduction contrasts exit 2 with the header-only report, and notes `--service SecurityHub` matches twenty checks today.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |

Nothing was backlogged or declined. The review's "unverified" list was re-checked where possible without web access from the reviewer's side: the three newly cited URLs answered 200 on 2026-10-05; `StartConfigurationPolicyDisassociation` exists in botocore 1.43.105 with the documented `Target` / `ConfigurationPolicyIdentifier` members; `AssociationFilters.AssociationType` is documented as "directly applied … or inherited from a parent". The remaining items the reviewer could not verify (a non-home-Region `GetFindingAggregator` answer; the exact `central-configuration-intro.html` sentence about the delegated administrator being self-managed; `NO_REGIONS` for CSPM) are probe questions or rest on the cited `CreateFindingAggregator` reference, as before.
## Responses to the design review (revision 3)

The second review (`review.md`, verdict CHANGES_REQUESTED: 0 HIGH, 1 MEDIUM, 3 LOW plus 5 nits) was applied in full. Each finding and what changed:

| ID  | Disposition | Change                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| --- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| M1  | Fixed       | Requirement 7.5's ERROR clause now reads "at least one ENABLED candidate rule's `ListTargetsByRule` returned an error result and no candidate PASSed (the first error result is the one reported, even if other ENABLED candidates were merely targetless), mirroring `SRA-SECURITYHUB-20._evaluate_region`". § SRA-SECURITYHUB-25 Flow spells out the `undetermined = undetermined or targets["Error"]` behaviour, and the two `ListTargetsByRule` rows in § Error handling now partition the cases. The `-20` code is unchanged; the requirement was the one that diverged. |
| L1  | Fixed       | Requirement 12.4, § Live validation Step 4 (`-25` row) and task 12.4 give the selection rule: not `aws-controltower-*`, no `ManagedBy` from `describe-rule`, no `aws:cloudformation:stack-name` tag; if every matching rule is managed, the `sraverify-test-cspm` create-then-delete route is used and no existing rule is disabled.                                                                                                                                                                                                                                          |
| L2  | Fixed       | § SRA-SECURITYHUB-22 Flow computes `mgmt_id` once from `self.organization.management_account_id()` (an existing provider accessor over the cached `DescribeOrganization`; `is_error` → no hint) and appends the enable-CSPM-first sentence to the management account's no-association and FAILED remediations, citing `view-policy.html` "Troubleshooting association failure". New Requirement 4.8 states it; the verdict does not depend on the lookup, and no call or IAM action is added.                                                                                 |
| L3  | Fixed       | § SRA-SECURITYHUB-24 now fixes the `ActualValue` shape: the sorted full standards list as `-23` renders it, then `; CIS: ` and the CIS subscriptions sorted by ARN as `<name> <status>` (or `; CIS: none`), with an example cell. Requirement 6.4's inheritance of 5.5 stands.                                                                                                                                                                                                                                                                                                |
| L4  | Fixed       | Task 1.3 says "the local `generated_*` files" and what to do if they are absent; task 13.1 says "the test modules edited or added in tasks 3.5 and 6" and enumerates them; task 3.5 and both golden-row paragraphs say "in sorted `(base, operation, code, needle)` position" with the two insertion points; the Architecture tree lists `SELF_MANAGED_POLICY_ID`; task 1.5 and § Live validation Step 1 say the DA's aggregator ARN is passed to `get-finding-aggregator` and that an error code is the expected answer from the application and management profiles.        |

Nothing was backlogged or declined. The review's remaining "unverified" items are test-organization facts (inherited `ACCOUNT` summaries, non-home-Region `GetFindingAggregator`, the management profile's `list-finding-aggregators`, observability of entries A and B, audit-account subscription in every scanned Region) and are still settled by probe questions 1–5 in task 1.5, with the consequences the design already states. The Introduction's "2026-09-16 probe" sentence is historical and load-bearing for no requirement, as the review noted.
