# Design Document — Phase 2

**Feature:** Organizations provider, Phase 2 — the rest of the Organizations surface

**Requirements:** `requirements.md` (this directory), Requirement 13 (criteria 1–7 as approved; 8–12 appended by this design, 9 and 10 reworded in revision 2 and 10's evidence parenthetical narrowed in revision 3, all before any approval; no criterion renumbered) and the Phase 1 requirements it builds on.

**Extends:** `design.md` revision 5, the approved Phase 1 design. Phase 2's reference tree is the merged Phase 1, merge commit `f517024` on `main` (tasks.md task 21).

**Revision:** 6 (2026-10-03). Revision 5 was reviewed (`design-review.md`: CHANGES_REQUESTED, 0 HIGH, 1 MEDIUM, 3 NIT; the revision 4 finding list is kept in `design-review.rev4.json` and `review4/design-review.rev4.md`). Revision 6 addresses every finding without changing a decision. It fixes one acquisition point the design had left open: `get_enabled_regions` now acquires its EC2 client **before** its `try`, as `get_account_info` does for STS and Account, so all three context lookups follow one rule. It also corrects the claim that a construction-time `PartialCredentialsError` moves nothing. For the identity lookup the claim holds text for text. For the Regions lookup the synthetic row keeps its row, `Status` and every cell but `ActualValue`, which loses the merged tree's `Failed to get enabled regions:` wrapper. That is now scope item 2's third case, with a unit test and a read-only negative run 2d. Three NITs are also fixed: "a profile with no credentials" replaces "a missing profile", the Account client's construction claim is cited, and the stale task 25.1 note is marked superseded. Revision 5 (2026-10-03) followed the revision 4 review. Revision 4 was reviewed (`design-review.md`: CHANGES_REQUESTED, 0 HIGH, 1 MEDIUM, 4 NIT; the revision 3 finding list is kept in `design-review.rev3.json` and `review3/design-review.rev3.md`). Revision 5 addresses every finding without changing a decision or the set of rows the design moves: the credential set behind the precondition remediation now includes the client-side botocore credential failures (`NoCredentialsError` and five siblings), derived from their classes the way `TRANSPORT_ERROR_CODES` is, so a `regions` precondition row in a scan with no usable credentials gets the credentials wording rather than the `ec2:DescribeRegions` grant; and four wording and precision fixes (the golden constant's name, the Account API handler, the Config delegator's argument path, the SIR accessor-table rows). Revision 4 (2026-10-03) followed the revision 3 review. Revision 3 was reviewed (`design-review.md`: CHANGES_REQUESTED, 1 HIGH, 1 MEDIUM, 5 NIT; the revision 2 finding list is kept in `design-review.rev2.json`). Revision 4 addresses every finding. It corrects one drafting error that would have moved verdicts: `IAMCheck` loses only its `ListDelegatedAdministrators` entry, not its whole table, and Property 43 now holds every non-owned service-table entry to the merged tree with a golden comparison. It also changes one decision: the precondition remediation is chosen by credential code before lookup, so an `AuthFailure` from `DescribeRegions` no longer sends the operator to an IAM grant. Revision 1 was reviewed (CHANGES_REQUESTED, 1 HIGH, 6 MEDIUM, 7 NIT; finding list kept in `.tmp/sratester/organizations-provider-phase2/design-review.rev1.json`). Revision 2 addressed every finding; its two changed decisions were the identity and Region reporting (lazy and per check, so the row set is exactly the merged tree's) and Open Question 5 (reversed: the remediation keeps naming the check's own service, on live evidence). Revision 2 was reviewed (`design-review.md`: CHANGES_REQUESTED, 0 HIGH, 2 MEDIUM, 7 NIT). Revision 3 addresses every finding without changing a decision: the precondition row gets the same secondary-failure guard as the synthetic row and an explicit `scan_region` parameter, and the identity remediation stops pointing at a permission that cannot be denied. Dispositions for all three reviews are in "Responses to the design review" at the end.

**Why a separate file.** This is a new document beside `design.md`, not a revision 6 of it. `design.md` is the approved, merged Phase 1 record: `tasks.md` tasks 1–20 and the Phase 1 test report cite its sections, property numbers and line references, and rewriting it in place would make those citations point at text the Phase 1 code was not built against. Phase 2 also needs its own review loop (task 22.1), and one self-contained file is what a reviewer can read against the merged tree without diffing a 1,084-line document. `design.md` keeps every Phase 1 decision; this file states only what Phase 2 changes, and where it is silent the Phase 1 design governs. Property numbers continue from `design.md` (Phase 1 ends at Property 36), so "Property N" is unambiguous across the two files.

**Evidence.** Under `.tmp/sratester/organizations-provider-phase2/`: `survey-org.txt` (every `organizations` binding), `org-client-methods.txt` (the fifteen `org_client` methods, verbatim), `org-base-accessors.txt` (the base accessors that wrap them), `fail-arms.txt` (every consumer's `is_not_configured` arm), `tables.txt` (every Organizations entry in every `NOT_CONFIGURED_ERRORS`), `ledger-sim.txt` (an offline drive of the catalog through each candidate provider entry), `op-collisions.txt` (operation names shared across services), `botocore-org-errors.txt` (botocore 1.43.105's Organizations error model and paginators), `apiref-evidence.txt` (the three `AWSOrganizationsNotInUseException` pages, fetched 2026-10-02), `method-count.txt` (client methods per module). Added for revision 2: `caller-apiref.txt` and `caller-apiref2.txt` (the caller restriction sentence of all nine owned operations' API reference pages, fetched 2026-10-02), `caller-probe.txt` (a read-only live probe of who may call them in the test organization), `lda-counts.txt` (delegated administrators per service principal the package queries), `lda-maxresults.txt` (botocore's `MaxResults` bound for `ListDelegatedAdministrators`), and `caller-evidence.md` (the summary). Revision 3 adds `review2/gci.txt` (the STS `GetCallerIdentity` API reference's permissions sentence, fetched 2026-10-03 by the reviewer) and regenerates `lda-counts.txt` as one clean sequential run (2026-10-03T15:52:41Z, one `DONE` line; the revision-2 file held two interleaved runs of the same script, whose values agreed with each other and with this run). Revision 4 adds `review3/ec2-sts-invalid-creds.txt` (the reviewer's read-only probe with deliberately invalid static credentials and no profile, 2026-10-03T16:06:45Z: EC2 `DescribeRegions` returns `AuthFailure`, STS `GetCallerIdentity` returns `InvalidClientTokenId`). Revision 5 adds `review4/nocreds-probe.txt` (the reviewer's offline probe with no credential source at all, 2026-10-03T16:48:59Z, botocore 1.43.105: both `DescribeRegions` and `GetCallerIdentity` return `Code` `NoCredentialsError`, `Operation` `Request` through the real `AWSClient.aws_error`, and all six botocore credential-provider exception classes are `BotoCoreError` subclasses), `cred-raise-sites.txt` (where botocore 1.43.105 raises each of the six, all in credential or token loading: `auth.py`, `credentials.py`, `tokens.py`, `utils.py`) `cred-subclasses.txt` (none of the six has a subclass, so matching by exact class name misses nothing), and `cred-surface-probe.txt` (offline, 2026-10-03: with no credential source `session.client("sts")` succeeds and the call raises `NoCredentialsError`; with an access key and no secret, `session.client()` itself raises `PartialCredentialsError`). Revision 6 adds three of the reviewer's offline probes from `review5/`, none of which sends an AWS request. `partial_regions_probe.txt` was run on `f517024` with an access key and no secret: the merged `get_enabled_regions` raises `Exception: Failed to get enabled regions: Partial credentials found in env, missing: AWS_SECRET_ACCESS_KEY`, and `get_account_info` raises `PartialCredentialsError` unwrapped. `account_ctor_probe.txt` (botocore 1.43.105) shows that `account`, `sts`, `ec2` and `organizations` clients all construct in seven partitions' Regions. `cred_probe.txt` shows that `boto3.Session(profile_name=<nonexistent>)` raises `ProfileNotFound` at session construction. The denied fan-out figures are from the Phase 1 live validation, `.tmp/sratester/organizations-provider/lv2/fanout/summary.txt`.

## Overview

Phase 1 put organization data on the `ScanContext` behind one accessor, `self.organization.accounts()`, and left everything else where it was. After Phase 1 the package still reaches AWS Organizations from seventeen places outside the provider: fifteen `org_client` methods across eight service clients, `SecurityHubCheck.get_organization()`'s raw boto3 call, and `ScanContext.get_management_account_id`'s own `get_client("organizations")`. Each is its own cache slot in its own namespace, keyed by Region where the answer is organization-wide, and each is classified by whichever service table its caller's base happens to carry. That is why `AWSOrganizationsNotInUseException` from `ListDelegatedAdministrators` is a FAIL through `SRA-IAM-04` and an ERROR through twelve other checks that ask the identical question.

Phase 2 finishes the move. The provider grows ten accessors (`describe`, `management_account_id`, `delegated_administrators`, `roots`, `ous_for_parent`, `policies`, `policies_for_target`, `describe_policy`, `effective_policy`, `accounts_for_parent`), the relocated `OrganizationsClient` grows three methods (`list_delegated_administrators`, `list_policies_for_target`, `describe_policy`), every `org_client` binding is deleted, and every base accessor that wrapped one becomes a one-line delegator to the provider, so **no check module's call sites change, except `sra_securityincidentresponse_05`**, which consumes the management-account lookup's new error result. `ScanContext`'s three raising accessors move to the error-result model, and a failed `sts:GetCallerIdentity` or `ec2:DescribeRegions` is reported lazily, per check, by the orchestrator's existing per-check guard, exactly where and as often as the merged tree reports it today. The provider's `NOT_CONFIGURED_ERRORS` table takes over every Organizations classification whose operation name no other service issues, which unifies `ListDelegatedAdministrators` and declares `ListAccounts`, each with API-reference evidence.

What this design moves, and nothing else:

1. **Task 26's table entries**: the FAIL rows they produce. In the test organization they number **zero**, because every account is a member and `AWSOrganizationsNotInUseException` cannot be returned. They are held offline by a per-row ledger test, under Requirement 13.12.
2. **Two text cells on rows that are synthetic today**, required by Requirement 13.3: when STS, EC2 `DescribeRegions` or the management-account lookup fails, the `ActualValue` and `Remediation` of the row the merged tree already emits become `<Operation> failed: <Code>: <Message>` and a scan-environment remediation. Row count, `Status`, `Region`, `ResourceId` and the account cells are unchanged. There is one more case of the same class, which follows from acquiring the EC2 client before its `try` (below). Suppose constructing that client raises, as `PartialCredentialsError` does for an access key with no secret. The row stays synthetic, and its `Remediation` stays the control's text. Only its `ActualValue` loses the merged tree's wrapper: `Error running SRA-X: Exception: Failed to get enabled regions: <msg>` becomes `Error running SRA-X: PartialCredentialsError: <msg>` (`review5/partial_regions_probe.txt`). The identity lookup's construction failure already propagates unwrapped and is unchanged. These rows occur only in a scan whose identity, Region or management-account lookup fails, so a successful A/B shows none.
3. **Conditionally, rows that a first-page `ListDelegatedAdministrators` read truncated**, in an organization with more than one page (more than 20 delegated administrators) for one queried principal; the new client method paginates, as task 23.1 mandates. There are none in the test organization (`lda-counts.txt`, `lda-maxresults.txt`); see "Pagination of `ListDelegatedAdministrators`" below.

Every `NOT_CONFIGURED_ERRORS` entry for an operation the provider does not own stays byte-identical, so no other verdict moves (Property 43). Open Question 5 moves nothing: the decision is to keep `_remediation_for` byte-identical (below).

## Architecture

The layering Phase 1 established is unchanged. What changes is that every Organizations operation now travels the path `ListAccounts` already does:

```
<Service>Check base accessor  ──►  self.organization.<accessor>()   (core/organization.py)
   (one-line delegator,               │  cache: ("organizations", <key>)
    classified `derived`)             ▼
                                   OrganizationsClient(ctx).<method>()   (core/organizations_client.py)
                                      │  Region: scan_region(ctx)
                                      ▼
                                   ctx.get_client("organizations", region=<scan Region>)
```

After Phase 2, `core/organizations_client.py` is the only module that binds an `organizations` boto3 client, `core/organization.py` is the only module other than the client's own that names `OrganizationsClient`, and no `services/*/base.py` reads the `organizations` namespace by key. Property 41 and Property 42 hold those statements by AST.

`ScanContext` gains no new member. `ScanContext.get_management_account_id` becomes a delegator to `self.organization.management_account_id()`, so the context's own `get_client("organizations")` goes, and the `_management_account_id` field goes with it. The orchestrator gains one `except` clause in its existing per-check guard, ahead of `except Exception`, which is where a failed identity or Region lookup is reported.

## Components and Interfaces

The technology stack is unchanged from `design.md` and is locked: Python ≥ 3.11, boto3/botocore ≥ 1.43.96 as pinned (every paginator this design uses exists in the bundled 1.43.105 model, `botocore-org-errors.txt`), the existing `ScanContext` primitives, `pytest` + `hypothesis`, and `ast` + `pyyaml` for the generator. No new dependency, no lock change, no new module under `core/` or `services/`.

### `core/organizations_client.py` — three new methods

Added in the canonical shape: paginator where botocore publishes one, the whole loop inside the `try`, the byte-identical handler, no new boto3 acquisition (the constructor already binds `self.client`).

```python
def list_delegated_administrators(self, service_principal: str) -> Mapping[str, Any]:
    """The delegated administrators registered for one service principal.

    Returns:
        ``{"DelegatedAdministrators": [...]}`` with every page merged, or the
        error result.
    """
    try:
        admins = []
        paginator = self.client.get_paginator('list_delegated_administrators')
        for page in paginator.paginate(ServicePrincipal=service_principal):
            admins.extend(page.get('DelegatedAdministrators', []))
        return {"DelegatedAdministrators": admins}
    except AWS_EXCEPTIONS as e:
        return self.aws_error(e)

def list_policies_for_target(self, target_id: str, policy_type: str) -> Mapping[str, Any]:
    """The policies of one type attached directly to a root, OU or account.

    Returns:
        ``{"Policies": [...]}`` with every page merged, or the error result.
        Summaries only; the content needs ``describe_policy``.
    """
    try:
        policies = []
        paginator = self.client.get_paginator('list_policies_for_target')
        for page in paginator.paginate(TargetId=target_id, Filter=policy_type):
            policies.extend(page.get('Policies', []))
        return {"Policies": policies}
    except AWS_EXCEPTIONS as e:
        return self.aws_error(e)

def describe_policy(self, policy_id: str) -> Mapping[str, Any]:
    """One policy with its stored content.

    Returns:
        The ``DescribePolicy`` response, or the error result.
    """
    try:
        return self.client.describe_policy(PolicyId=policy_id)
    except AWS_EXCEPTIONS as e:
        return self.aws_error(e)
```

`list_policies_for_target` and `describe_policy` are `SecurityHubClient`'s two methods of the same names moved verbatim apart from the receiver. `list_delegated_administrators` takes the principal as a **required** positional argument: every service client defaulted it to its own principal, and a default on a shared client would name one service's principal for all of them.

**Client-method count.** Task 23.1 takes the count from 108 to **111** (the relocated client from 7 to 10). Task 24.1 then deletes the fifteen `org_client` methods (`method-count.txt`): `accessanalyzer` 1, `cloudtrail` 1, `config` 2, `iam` 2, `macie` 1, `securityhub` 5, `securityincidentresponse` 1, `securitylake` 2. Today there are 101 service-client methods (108 − 7); 101 − 15 = **86**, plus the relocated client's 10, gives **96** at the end of Phase 2, the figure task 29.1 records. 111 exists only between tasks 23 and 24. No service client becomes empty: of the eight clients that lose methods, the smallest survivors are `accessanalyzer` (2), then `cloudtrail`, `iam` and `securityincidentresponse` (4 each).

Two of the fifteen are dead today and are deleted rather than redirected: `ConfigClient.get_management_account_id` and `SecurityLakeClient.get_delegated_admin` have no base-class caller.

**Pagination of `ListDelegatedAdministrators`.** Six of the eight retired copies read the first page only; `IAM_Client` used the paginator and `SecurityHubClient` looped on `NextToken`. The new method paginates, because the client contract requires the paginator where botocore has one, and one method cannot be both. This is not the deferred Shield pagination: that defers paginating a *surviving* first-page method, and here the first-page methods are deleted, not changed. It cannot move a row in the test organization: botocore bounds a page at `MaxResults` 20 (`lda-maxresults.txt`), and every service principal the package queries has zero or one delegated administrator there (`lda-counts.txt`, 2026-10-03T15:52:41Z), so every answer is one page. Outside the test organization the claim is conditional, and this design does not source per-service delegated-administrator caps to make it general: in any organization where each queried principal has at most 20 delegated administrators, which is the one-page case, no row moves; an organization with more than 20 for one principal would now see the rest, which makes a truncated answer complete rather than changing a correct one, and the A/B would list any such row. The A/B confirms zero row-count changes on the twelve delegated-administrator checks in the test organization.

### `core/organization.py` — the ten new accessors

The public surface after Phase 2 is exactly these eleven methods. Every one takes only organization-scoped arguments and **no Region**, returns the client's success dict by identity or the error result unchanged, caches only a success, and has no no-client path (the Phase 1 reasoning in `design.md` applies unchanged to each).

| Accessor                                                | Returns on success                   | Client method                                       | Operation                          | Cache key (namespace `organizations`)           |
| ------------------------------------------------------- | ------------------------------------ | --------------------------------------------------- | ---------------------------------- | ----------------------------------------------- |
| `accounts()`                                            | `{"Accounts": [...]}`                | `list_accounts()`                                   | `ListAccounts`                     | `all_accounts` (Phase 1, unchanged)             |
| `describe()`                                            | `{"Organization": {...}}`            | `describe_organization()`                           | `DescribeOrganization`             | `organization`                                  |
| `management_account_id()`                               | `str` (derived from `describe()`)    | — (reads `describe()`)                              | `DescribeOrganization`             | none of its own; reads `organization`           |
| `delegated_administrators(service_principal: str)`      | `{"DelegatedAdministrators": [...]}` | `list_delegated_administrators(service_principal)`  | `ListDelegatedAdministrators`      | `delegated_admins:<service_principal>`          |
| `roots()`                                               | `{"Roots": [...]}`                   | `list_roots()`                                      | `ListRoots`                        | `roots`                                         |
| `ous_for_parent(parent_id: str)`                        | `{"OrganizationalUnits": [...]}`     | `list_organizational_units_for_parent(parent_id)`   | `ListOrganizationalUnitsForParent` | `ous:<parent_id>`                               |
| `policies(policy_type: str)`                            | `{"Policies": [...]}`                | `list_policies(policy_type)`                        | `ListPolicies`                     | `policies:<policy_type>`                        |
| `policies_for_target(target_id: str, policy_type: str)` | `{"Policies": [...]}`                | `list_policies_for_target(target_id, policy_type)`  | `ListPoliciesForTarget`            | `policies_for_target:<target_id>:<policy_type>` |
| `describe_policy(policy_id: str)`                       | `{"Policy": {...}}`                  | `describe_policy(policy_id)`                        | `DescribePolicy`                   | `policy:<policy_id>`                            |
| `effective_policy(policy_type: str, target_id: str)`    | `{"EffectivePolicy": {...}}`         | `describe_effective_policy(policy_type, target_id)` | `DescribeEffectivePolicy`          | `effective_policy:<policy_type>:<target_id>`    |
| `accounts_for_parent(parent_id: str)`                   | `{"Accounts": [...]}`                | `list_accounts_for_parent(parent_id)`               | `ListAccountsForParent`            | `accounts:<parent_id>`                          |

The names are the ones Requirement 13.1 lists, with one deliberate spelling: `effective_policy(policy_type, target_id)`, not `account_id`, because it is the client method's parameter name and `DescribeEffectivePolicy`'s own (`TargetId`), and the API answers `InvalidInputException` for a root or OU target, so the docstring says "an account ID" without the parameter pretending only accounts exist. Argument order follows the client method in every case, so a delegator passes its arguments through unchanged.

**Cache keys.** The six keys `OrganizationsCheck` writes today (`organization`, `roots`, `ous:<parent>`, `policies:<type>`, `accounts:<parent>`, `effective_policy:<type>:<target>`) are kept byte for byte. The **log text** for them does change: `OrganizationsCheck` writes its own phrases today (`organizations/base.py:127,156,188,220,252,287`), and `_cached` writes `Organizations: Fetching <key>`. So the task 28 gate counts `Fetching` records **per key**, translating the merged tree's six phrases through this fixed map:

| Merged Phase 1 record (`services/organizations/base.py`) | Key                                |
| -------------------------------------------------------- | ---------------------------------- |
| `Organizations: Fetching organization details`           | `organization`                     |
| `Organizations: Fetching organization roots`             | `roots`                            |
| `Organizations: Fetching OUs for parent <id>`            | `ous:<id>`                         |
| `Organizations: Fetching policies of type <type>`        | `policies:<type>`                  |
| `Organizations: Fetching accounts for parent <id>`       | `accounts:<id>`                    |
| `Organizations: Fetching effective <type> for <target>`  | `effective_policy:<type>:<target>` |

`accounts()` keeps its Phase 1 phrase on both trees, so it needs no entry. `organization` is also the key `SecurityHubCheck.get_organization()` used through its own constants, so Security Hub and Organizations shared that answer already and still do. The three new keys follow the same `<thing>:<discriminator>` form. No key carries an account ID or a Region: the provider is per scan and the answers are organization-wide. The keys are distinct by prefix (`accounts:` versus `all_accounts`, `policies:` versus `policies_for_target:` versus `policy:`): the ten caching accessors, called once each with one argument set, write ten distinct keys, and `management_account_id()` writes none of its own and reads `organization` through `describe()` (Properties 39 and 40).

Retired keys, all in service namespaces and all Region- or account-keyed: `accessanalyzer:delegated_admin:<account>`, `cloudtrail:delegated_admins:<account>`, `config:delegated_admin:<account>:<principal>`, `iam:delegated_admins:<account>`, `iam:organization:<account>`, `macie:delegated_admin:<region>`, `securityhub:delegated_admin:<region>`, `securityhub:roots`, `securityhub:policies_for_target:<target>:<type>`, `securityhub:policy:<id>`, `securityhub:effective_policy:<type>:<target>`, `securitylake:delegated_administrators:<region>`. Where the old key was per Region, the per-scan call count falls; that is an `aws_call_failed` and `Fetching` count change, not a row change, and the A/B explains it.

**One shared miss path.** The ten new accessors go through one private helper, so the hit / fetch / guard / store sequence has one correct form instead of ten:

```python
def _cached(
    self, key: str, fetch: Callable[[OrganizationsClient], Mapping[str, Any]]
) -> Mapping[str, Any]:
    ctx = self._ctx
    if ctx._has(NAMESPACE, key):
        logger.debug(f"Organizations: Using cached {key}")
        return ctx._get(NAMESPACE, key)
    logger.debug(f"Organizations: Fetching {key}")
    response = fetch(OrganizationsClient(ctx))   # a wrapper per miss, never memoised
    if is_error(response):
        return response                           # never cached; the next caller re-issues
    ctx._set(NAMESPACE, key, response)
    logger.debug(f"Organizations: Cached {key}")
    return response

def delegated_administrators(self, service_principal: str) -> Mapping[str, Any]:
    return self._cached(
        f"delegated_admins:{service_principal}",
        lambda client: client.list_delegated_administrators(service_principal),
    )
```

The other eight data accessors are the same two lines with their own key and method. `accounts()` is **left byte-identical** to Phase 1 rather than rewritten over the helper, because its three log lines (`Fetching organization accounts`, `Cached <N> organization accounts`, `Using cached organization accounts`) are asserted by Property 29 and counted by the Phase 1 gate scripts the Phase 2 A/B reuses.

`management_account_id()` is derived and issues nothing of its own:

```python
def management_account_id(self) -> str | ErrorResult:
    """The management account's ID, read from ``describe()``.

    Returns:
        The account ID string, or ``describe()``'s error result unchanged.
    """
    response = self.describe()
    if is_error(response):
        return response
    return response["Organization"]["MasterAccountId"]
```

It returns a `str` on success rather than a dict, because its one consumer (`SecurityCheck.get_management_accountId`) has always returned a string and the derived value has no other key. `MasterAccountId` is always present in a successful `DescribeOrganization` response; a `KeyError` would be a botocore contract violation and propagates as a programming defect, which is the existing rule for an unexpected response shape.

The provider gains one class attribute, not callable, so Property 4's public-callable set is the eleven methods above and its module-level-names set is unchanged (`OrganizationsProvider`, `NAMESPACE`, `ACCOUNTS_KEY`):

```python
#: Operations this provider issues whose names no other service's client issues.
#: ``ListPolicies`` is excluded because ``fms:ListPolicies`` shares the name.
#: The provider table may declare only these (Property 43), and the AST guard's
#: boto3-spelling set is these in snake_case (Property 41).
OWNED_OPERATIONS: ClassVar[frozenset[str]] = frozenset({
    "ListAccounts", "DescribeOrganization", "ListDelegatedAdministrators",
    "ListRoots", "ListOrganizationalUnitsForParent", "ListPoliciesForTarget",
    "DescribePolicy", "DescribeEffectivePolicy", "ListAccountsForParent",
})
```

Revision 1 also added `SERVICE = "Organizations"` for the remediation change; with Open Question 5 reversed it has no reader and is not added.

The module docstring's four decisions stay, and its "one sweep per scan" paragraph becomes "one fetch per accessor per key per scan, for sequential execution" (Concurrency, below).

### Which call site becomes which accessor

Every base accessor named here keeps its **name and signature**, becomes a one-line delegator, and is reclassified from `accessor` to `derived` in `test_accessor_cache_property.py`. A Region parameter it carried is accepted and ignored, with a docstring line saying so, because removing it would edit every check that passes one, and Requirement 13.6 holds the call sites where they are.

| Service client method (deleted)                                                                     | Base accessor (kept, now a delegator)                                      | Becomes                                                                                                                                                                                                               | Consuming checks               |
| --------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| `AccessAnalyzerClient.get_delegated_admin`                                                          | `AccessAnalyzerCheck.get_delegated_admin()`                                | `self.organization.delegated_administrators("access-analyzer.amazonaws.com")`                                                                                                                                         | `accessanalyzer_02`, `_03`     |
| `CloudTrailClient.list_delegated_administrators`                                                    | `CloudTrailCheck.get_delegated_administrators()`                           | `self.organization.delegated_administrators("cloudtrail.amazonaws.com")`                                                                                                                                              | `cloudtrail_12`, `_13`         |
| `ConfigClient.list_delegated_administrators`                                                        | `ConfigCheck.get_delegated_administrators(service_principal=None)`         | `principals = [service_principal] if service_principal else list(self.CONFIG_SERVICE_PRINCIPALS)`; for each `p`, `self.organization.delegated_administrators(p)`; first failure wins (returned unchanged), merge kept | `config_07`, `_08`             |
| `ConfigClient.get_management_account_id` (dead)                                                     | —                                                                          | deleted                                                                                                                                                                                                               | —                              |
| `IAM_Client.list_delegated_administrators`                                                          | `IAMCheck.get_iam_delegated_administrators()`                              | `self.organization.delegated_administrators(IAM_SERVICE_PRINCIPAL)`                                                                                                                                                   | `iam_04`                       |
| `IAM_Client.describe_organization`                                                                  | `IAMCheck.get_organization()`                                              | `self.organization.describe()`                                                                                                                                                                                        | `iam_05`                       |
| `MacieClient.list_delegated_administrators`                                                         | `MacieCheck.get_macie_delegated_admin(region)`                             | `self.organization.delegated_administrators("macie.amazonaws.com")`                                                                                                                                                   | none today                     |
| `SecurityHubClient.list_delegated_administrators` (both `org_client` calls in its `NextToken` loop) | `SecurityHubCheck.get_delegated_administrators(region)`                    | `self.organization.delegated_administrators("securityhub.amazonaws.com")`                                                                                                                                             | `securityhub_03`, `_06`, `_07` |
| `SecurityHubClient.list_roots`                                                                      | `SecurityHubCheck.get_roots(region)`                                       | `self.organization.roots()`                                                                                                                                                                                           | `securityhub_16`               |
| `SecurityHubClient.list_policies_for_target`                                                        | `SecurityHubCheck.get_policies_for_target(region, target_id, policy_type)` | `self.organization.policies_for_target(target_id, policy_type)`                                                                                                                                                       | `securityhub_16`               |
| `SecurityHubClient.describe_policy`                                                                 | `SecurityHubCheck.get_policy(region, policy_id)`                           | `self.organization.describe_policy(policy_id)`                                                                                                                                                                        | `securityhub_16`               |
| `SecurityHubClient.describe_effective_policy`                                                       | `SecurityHubCheck.get_effective_policy(region, policy_type, target_id)`    | `self.organization.effective_policy(policy_type, target_id)`                                                                                                                                                          | `securityhub_17`               |
| `SecurityIncidentResponseClient.list_delegated_administrators`                                      | `SecurityIncidentResponseCheck.get_delegated_administrators()`             | `self.organization.delegated_administrators("security-ir.amazonaws.com")`                                                                                                                                             | `securityincidentresponse_01`  |
| `SecurityLakeClient.get_delegated_admin` (dead)                                                     | —                                                                          | deleted                                                                                                                                                                                                               | —                              |
| `SecurityLakeClient.list_delegated_administrators`                                                  | `SecurityLakeCheck.get_delegated_administrators(region)`                   | `self.organization.delegated_administrators("securitylake.amazonaws.com")`                                                                                                                                            | `securitylake_14`, `_15`       |

The two "two call sites" the task names are the two `org_client.list_delegated_administrators` calls inside `SecurityHubClient`'s `NextToken` loop (one method), and `SecurityLakeClient`'s two methods (one live, one dead). Each service principal literal moves from the deleted client method's default into the delegator, so the principal is visible where the service is. `SecurityIncidentResponseCheck.get_delegated_administrators()` no longer touches `self.regions[0]`; `get_role()` and `SRA-SECURITYINCIDENTRESPONSE-01`'s row label still do, so no `Region` cell moves (task 29.1 amends the `structure.md` oddity sentence to match).

The three paths that are not `org_client` bindings:

- **`SecurityHubCheck.get_organization()`** becomes `return self.organization.describe()`. The raw boto3 call, the inline `error_result` construction and its hand-rolled `aws_call_failed` record, and the `_ORGANIZATIONS_NAMESPACE` / `_ORGANIZATION_CACHE_KEY` constants are deleted, as are the `scan_region`, `AWS_EXCEPTIONS` and `error_result` imports if nothing else uses them. It has no production caller (Phase 1 task 20.7) and is kept as a delegator rather than deleted because task 24.2 names it and deleting it removes public surface from a base class; `tests/unit/services/test_securityhub_organization.py` is rewritten to assert the delegation by identity.
- **`OrganizationsCheck`'s six accessors** — `get_organization`, `get_roots`, `get_ous_for_parent`, `list_policies(policy_type="SERVICE_CONTROL_POLICY")`, `get_accounts_for_parent`, `get_effective_policy` — become delegators to `describe`, `roots`, `ous_for_parent`, `policies`, `accounts_for_parent`, `effective_policy`, keeping the `list_policies` default. `_setup_clients` becomes `self._clients.clear()` only; `self._org_client`, `get_org_client` and the `OrganizationsClient` import go. `guardrail_identifiers_of` is untouched. The six `self._org_client is None` no-client branches go with the client: they were dead (Phase 1 Requirement 1.5).
- **`ScanContext.get_management_account_id()`** becomes `return self.organization.management_account_id()` (next section).

`IAM_Client` loses `self.org_client` and its `scan_region` import. `IAMCheck._cached_call` serves five calls today (`iam/base.py:191,200,209` and the two Organizations ones); after Phase 2 it keeps serving the three IAM calls, `organizations_features`, `account_summary` and `password_policy`. `IAM_SERVICE_PRINCIPAL` is defined in `services/iam/client.py:24` today and its only reader is the deleted `IAM_Client.list_delegated_administrators` (`:112`); it **moves to `services/iam/base.py`**, beside its one remaining reader, the delegator, and `client.py` no longer defines it (nothing in `tests/` or `sra-verify-mcp` imports it). Task 24.2 also rewrites `IAMCheck.get_organization()`'s docstring (`iam/base.py:224`), whose "Used instead of `get_management_accountId()`, which raises on failure" goes stale with task 25.1; the new docstring says it delegates to `self.organization.describe()`. Every other client loses its `self.org_client = ctx.get_client('organizations', region=region)` line and the `organizations` mention in its `_setup_clients` docstring.

The base delegators drop their own no-client branches (`AccessAnalyzerCheck`'s `if not self._clients`, `CloudTrailCheck`'s and `ConfigCheck`'s `if not self.regions`). Those branches are unreachable in a scan: every regional base builds one client per scanned Region in `_setup_clients`, `self.regions` is never empty once a scan has started (Phase 1 fail-fast), and the provider has no no-client path to report.

### `core/scan_context.py` — the three accessors on the error-result model

The three accessors stop raising and stop logging at `error`. A failure is returned as an error result, logged once as `aws_call_failed` at `debug`, and never cached. To keep "exactly one record per failed call, emitted by `AWSClient.aws_error` and nowhere else", the context does not format the record itself:

```python
def _call_failed(self, e: Exception) -> ErrorResult:
    """The error result for a failed lookup, through the one shared formatter."""
    return AWSClient(self._scan_region, self).aws_error(e)
```

`scan_context.py` gains a direct `from sraverify.core.aws_client import AWSClient`. That adds no import cycle and no new module load: `aws_client.py` imports `scan_context` only under `TYPE_CHECKING`, and the module is already loaded at run time through `organization → organizations_client → aws_client`. `AWSClient.__init__` stores two attributes and has no side effect; the throwaway instance holds `self` only for the duration of the call.

- **`get_account_info() -> dict[str, str] | ErrorResult`.** `sts:GetCallerIdentity` inside `try: ... except AWS_EXCEPTIONS as e: return self._call_failed(e)`; nothing is cached on failure. On success, `account:GetAccountInformation` stays best-effort for an **AWS** outcome: its handler is `except AWS_EXCEPTIONS as e: self._call_failed(e)` (one debug record, result discarded, name `""`), a response without `AccountName` reads as `""` (`response.get("AccountName", "")`, which replaces today's reliance on `except Exception` around the subscript), and the identity is cached. A non-AWS exception from the Account call **propagates**, like one from the STS call: it is a programming defect, and passing it to `_call_failed` would make `aws_error` raise `TypeError` inside the handler (`core/aws_client.py:160–165`). Both boto3 clients are acquired with `self.get_client(...)` **before** their `try`, as the STS one is today, so an acquisition failure is a defect rather than an error result describing a call never made (the constructor-only acquisition rule's reasoning). The `logger.error`, the `raise Exception(...)` and the account-name `logger.warning` go. Today's `except Exception` around the Account call also swallows non-AWS exceptions; after Phase 2 the only non-AWS sources left are a defect in this method or a failing client construction (the subscript is gone; botocore resolves the endpoint per request, so constructing an `account` client with a Region set issues nothing. It does not raise: `review5/account_ctor_probe.txt`, botocore 1.43.105, offline, constructs `account`, `sts`, `ec2` and `organizations` clients in `us-east-1`, `eu-west-1`, `us-gov-west-1`, `cn-north-1`, `us-iso-east-1`, `us-isob-east-1` and `eu-isoe-west-1`. Once STS has succeeded, the session's credentials are already resolved, so a credential failure cannot first appear at the Account client's construction. The narrowing is therefore not expected to move a row; if it ever did, the row would be the pre-loop `logger.error` with `exc_info` and a synthetic row naming the exception, read as a defect, which is the honest report.
- **`get_management_account_id() -> str | ErrorResult`.** Delegates to `self.organization.management_account_id()`. The context's own lock-and-field cache goes, because the provider's `organization` slot is the cache.
- **`get_enabled_regions() -> list[str] | ErrorResult`.** Explicit Regions return immediately as today. Otherwise the method calls `ec2:DescribeRegions` (bound to the scan Region since !55) under the same handler. A success is cached in `_resolved_regions`, and a failure is returned and not cached. The EC2 client is acquired **before** the `try`, which moves it out of the merged tree's `try` (`scan_context.py:552–561`). That way all three lookups follow one acquisition rule:

  ```python
  logger.debug("Getting enabled AWS regions")
  ec2_client = self.get_client("ec2", region=self._scan_region)   # outside the try
  try:
      response = ec2_client.describe_regions(AllRegions=False)
      regions = [r["RegionName"] for r in response["Regions"]]
  except AWS_EXCEPTIONS as e:
      return self._call_failed(e)
  ```

  An exception raised constructing the client therefore propagates unchanged: it is neither wrapped nor turned into an error result. A `PartialCredentialsError` (raised by `session.client()`, `cred-surface-probe.txt`) consequently reaches the per-check guard's `except Exception` raw, as the identity lookup's already does. It does not reach a precondition row. Its one visible effect is the `ActualValue` change in scope item 2. The alternative of acquiring inside `try / except AWS_EXCEPTIONS` was rejected. It would send a construction failure into an error result describing a `DescribeRegions` call that was never made, which is what the constructor-only acquisition rule forbids. It would also give the Region lookup a different construction-failure path from the identity lookup.

`except Exception` becomes `except AWS_EXCEPTIONS` around the STS and EC2 calls, so a programming defect (a `KeyError` on `Account`, which botocore never omits) propagates instead of being re-labelled as an AWS failure. Where it propagates to is fixed below.

### How a failed `sts:GetCallerIdentity` is reported: lazily, per check, by the orchestrator

`SecurityCheck._finding` reads `ctx.get_account_info()` for every row, and `self.account_id`, `self.account_name` and `self.regions` are read throughout `execute()` bodies, many of them in comparisons (`self.account_id == management_id`). Handing those properties an empty string on failure would make every such comparison silently false and could fabricate a FAIL from an unreachable STS endpoint, which is the one outcome the FAIL-versus-ERROR contract forbids. A `try` in `execute()` is ruled out by the steering and by `test_no_confessing_fail_property.py`.

**What the merged tree does today**, which is the row set this design must reproduce. A check that reads identity (through `_finding`, `account_info`, `account_id` or `account_name`) or, with no explicit Regions, the Region list (through `self.regions`, including from `_setup_clients` during `initialize`) gets `Exception` raised into it; the per-check guard in `run_checks` discards whatever the check had yielded and emits one synthetic ERROR row (`global`, `ResourceId` empty, the fallback account). A check that reads neither is unaffected: none of the 18 IAM and Organizations checks reads `self.regions`, so a denied `DescribeRegions` leaves their genuine verdicts in place, and a check that returns before its first `_finding` call still yields zero rows. Only identity is read up front, in `run_checks`, for the fallback account; the Region list is not.

**Decision: keep exactly that shape, and change only the text of the row.** The failure is raised into the check as a typed exception at the point the check reads the fact, and the orchestrator's existing per-check guard turns it into one honest ERROR row instead of one synthetic row.

```python
# core/errors.py
class ScanPreconditionError(SRAVerifyError):
    """A check read the account identity or Region list, and the lookup failed.

    Raised by SecurityCheck's context properties; caught by run_checks' per-check
    guard, never by a check. Not a usage error: the CLI never sees it.
    """
    def __init__(self, *, check_id: str, lookup: str, error: Mapping[str, str]) -> None:
        self.check_id = check_id
        self.lookup = lookup          # "identity" or "regions"
        self.error = error            # the error result's "Error" sub-dict
        super().__init__(
            f"{check_id}: {lookup} lookup failed: "
            f"{error['Operation']} failed: {error['Code']}: {error['Message']}"
        )
```

```python
# core/check.py
def _identity(self, accessor: str) -> dict[str, str]:
    info = self._require_ctx(accessor).get_account_info()
    if is_error(info):
        raise ScanPreconditionError(check_id=self.check_id, lookup="identity", error=info["Error"])
    return info
```

`account_info`, `account_id`, `account_name` and `_finding` read identity through `_identity`; `regions` raises the same error with `lookup="regions"` when `ctx.get_enabled_regions()` returns an error result. `hasattr(self, 'regions')` in the service `_setup_clients` methods does not swallow it, since `hasattr` catches only `AttributeError`, so a regional base fails in `initialize`, inside the guard, exactly where it fails today.

```python
# scanner.py, run_checks: the pre-loop block keeps its guard (review F2);
# its logger.error gains exc_info=True (today's scanner.py:404 has none)
try:
    info = ctx.get_account_info()
    if is_error(info):
        logger.debug(f"Account identity unavailable: {info['Error'].get('Code')}")
        fallback_account = ("", "")
    else:
        fallback_account = (info["account_id"], info["account_name"])
except Exception as exc:              # a programming defect, as today
    logger.error(f"Could not resolve account identity: {exc}", exc_info=True)
    fallback_account = ("", "")

# inside the per-check guard, AHEAD of the existing `except Exception`
except ScanPreconditionError as exc:
    logger.error(f"{selected_id} could not run: {exc}")
    try:
        all_findings.append(
            _precondition_error(check_class, exc, fallback_account, ctx.scan_region)
        )
    except Exception:
        # Same secondary-failure rule as the synthetic row (scanner.py:487,
        # Requirement 10.12): an exception raised inside an `except` handler is
        # not caught by a sibling clause of the same `try`, so without this
        # nesting a defect in building the row would escape the per-check guard
        # and end the scan. A failure here costs this check its row, never the scan.
        logger.error(
            f"Could not build precondition ERROR row for {selected_id}",
            exc_info=True,
        )
```

```python
# scanner.py, beside _synthetic_error
def _precondition_error(
    check_class: type[SecurityCheck],
    exc: ScanPreconditionError,
    fallback_account: tuple[str, str],
    scan_region: str,
) -> Finding: ...
```

`_precondition_error` is a module function beside `_synthetic_error`. Its fourth parameter is the scan Region, which the caller passes as `ctx.scan_region` (read-only, computed at context construction, so reading it cannot fail), and which is interpolated into the two transport remediations. The row is built from `check_class.meta` the same way as the synthetic row: `status=ERROR`, `region=GLOBAL_REGION`, `resource_id=None`, the check's real severity, `account_id`/`account_name` from `fallback_account`, `checked_value=f"{meta.service} Configuration"`, `actual_value=f"{Operation} failed: {Code}: {Message}"` from `exc.error`, and a scan-environment remediation chosen by the code class and then `exc.lookup`.

The remediation is selected by the **code first**, then by lookup, in this order (first match wins):

| Order | Code class                                      | `exc.lookup` | Remediation                                                                                                                                                                                             |
| ----- | ----------------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | in `TRANSPORT_ERROR_CODES`                      | `identity`   | `Confirm the STS endpoint for <scan Region> is reachable from the scanner's network, then re-run the scan`                                                                                              |
| 1     | in `TRANSPORT_ERROR_CODES`                      | `regions`    | `Confirm the EC2 endpoint for <scan Region> is reachable from the scanner's network, or pass --regions`                                                                                                 |
| 2     | in `_CREDENTIAL_ERROR_CODES`                    | either       | `Confirm the scan has valid, unexpired credentials (no credentials found, an expired session token or SSO login, a wrong --profile, or an invalid access key is the usual cause), then re-run the scan` |
| 3     | any other code                                  | `identity`   | the same credentials wording as order 2 (no permission can deny `GetCallerIdentity`, below)                                                                                                             |
| 3     | any other code                                  | `regions`    | `Pass --regions explicitly, or grant the scanning role ec2:DescribeRegions (1-sraverify-member-roles.yaml), then re-run the scan`                                                                       |
| —     | unknown `exc.lookup` (defensive, not reachable) | —            | the credentials wording, as order 3 `identity`                                                                                                                                                          |

```python
# scanner.py, beside _precondition_error
from botocore.exceptions import (
    CredentialRetrievalError, NoCredentialsError, PartialCredentialsError,
    SSOTokenLoadError, TokenRetrievalError, UnauthorizedSSOTokenError,
)

#: botocore raises these before any request is sent when no usable credential
#: can be loaded: no credential source, partial static keys, a failed
#: credential_process or container/IMDS fetch, or a missing or expired SSO
#: token. All six are BotoCoreError subclasses with no subclasses of their own,
#: and AWSClient.aws_error uses a BotoCoreError's class name as its Code
#: (core/aws_client.py), so the codes are derived from the classes rather than
#: written out, the way TRANSPORT_ERROR_CODES is. NoCredentialsError observed
#: for DescribeRegions and GetCallerIdentity 2026-10-03
#: (.tmp/sratester/organizations-provider-phase2/review4/nocreds-probe.txt);
#: raise sites in botocore 1.43.105: cred-raise-sites.txt.
_LOCAL_CREDENTIAL_EXCEPTIONS: Final = (
    NoCredentialsError, PartialCredentialsError, CredentialRetrievalError,
    UnauthorizedSSOTokenError, TokenRetrievalError, SSOTokenLoadError,
)

#: Codes AWS returns when it rejects the credentials themselves, whichever
#: service is asked. Observed 2026-10-03 with deliberately invalid static
#: credentials (.tmp/sratester/organizations-provider-phase2/review3/
#: ec2-sts-invalid-creds.txt): EC2 DescribeRegions -> AuthFailure, STS
#: GetCallerIdentity -> InvalidClientTokenId. Add a server code only with an
#: observed aws_call_failed line or an API reference page, never by inference.
_REJECTED_CREDENTIAL_CODES: Final = frozenset({"AuthFailure", "InvalidClientTokenId"})

_CREDENTIAL_ERROR_CODES: Final[frozenset[str]] = _REJECTED_CREDENTIAL_CODES | frozenset(
    exc.__name__ for exc in _LOCAL_CREDENTIAL_EXCEPTIONS
)
```

The credential check comes before the lookup because a rejected or missing credential is not a property of the lookup that happened to issue the first call. In a scan with unusable credentials and no `--regions`, which is the ordinary local-CLI path when the profile sets a Region, every regional check reads `self.regions` in `initialize` before it reads identity, so its precondition row has `lookup="regions"`. Its code is `AuthFailure` when AWS rejects a static key, and a botocore class name (`NoCredentialsError`, `UnauthorizedSSOTokenError`, `TokenRetrievalError`, …) when no usable credential could be loaded at all, which is at least as common locally. The causes are a profile with no credentials, no credential source at all, or an expired SSO session. A profile that does not exist is a different case: `boto3.Session` raises `ProfileNotFound` before any `ScanContext` exists (`review5/cred_probe.txt`), so it never reaches a lookup. Under revision 3's per-lookup table either row told the operator to grant `ec2:DescribeRegions` or pass `--regions`, and neither fixes it: with `--regions` the next run fails on identity instead. Revision 4's set held only the two server codes, so the client-side half still fell to order 3 (review rev 4, M1); revision 5 derives that half from botocore's classes.

The two halves have different evidence and say so. The server half is a closed list of observed codes, because what AWS returns is not knowable from the package. The client half is not inferred: `aws_error` maps a `BotoCoreError` to its class name by construction, the classes and their raise sites are in the pinned botocore (`cred-raise-sites.txt`), and none has a subclass that would produce a different name (`cred-subclasses.txt`); one of the six, `NoCredentialsError`, is also observed end to end through both lookups. A future botocore that adds a credential class, or renames one, leaves the set as it is: the new name falls to order 3 and the row still names `--regions` and the grant, which is the stated residual; an import of a removed name fails at import time, a loud failure rather than a silent drift.

Not every one of the six reaches a precondition row, and the design does not claim it. A failure botocore raises while **constructing** a client never reaches a lookup's handler: `PartialCredentialsError` is raised by `session.client()` itself (observed offline, `cred-surface-probe.txt`, 2026-10-03, botocore 1.43.105, an access key with no secret), whereas `NoCredentialsError` is raised by the call (same file). After Phase 2, construction sits outside every lookup's `try` by the constructor-only acquisition rule: STS and Account in `get_account_info`, EC2 in `get_enabled_regions`. A construction-time credential failure therefore never becomes an error result. Up front, the identity lookup's failure reaches the pre-loop block's `except Exception` (`logger.error` with `exc_info`, fallback `("", "")`). Inside the scan, every check whose `_setup_clients` or lookup constructs the client produces one synthetic row, through the per-check guard's `except Exception`. The two lookups compare differently with the merged tree (`review5/partial_regions_probe.txt`, `f517024`):

- **Identity: unchanged, row for row and text for text.** The merged tree already acquires STS outside its `try` (`scan_context.py:448`), so `PartialCredentialsError` propagates unwrapped on both trees. The synthetic row reads `Error running SRA-X: PartialCredentialsError: <msg>` on both.
- **Regions: same rows, one cell changes.** The merged tree acquires EC2 inside `try / except Exception` and re-raises `Exception("Failed to get enabled regions: <msg>")`. The candidate does not wrap. The synthetic row's `ActualValue` therefore goes from `Error running SRA-X: Exception: Failed to get enabled regions: <msg>` to `Error running SRA-X: PartialCredentialsError: <msg>`. Row count, `Status`, `Region`, `ResourceId`, the account cells and `Remediation` (the control's text, from `_synthetic_error`) are unchanged. This is scope item 2's third case, the same class of change: the text of a row on a failed lookup.

Routing construction failures into the error-result model would contradict the acquisition rule and is out of scope. The class stays in the set because the set is derived from the family, not from where each member happens to surface, and a membership that is wrong only in the harmless direction (a name that may never reach `_precondition_error`) costs nothing.

Order 3's `regions` wording is kept for the case it is right for, a denied action (EC2 documents `UnauthorizedOperation` for that), and it remains the residual for any **server-side** credential code EC2 might return that has not been observed (an expired STS session token's code from EC2 is the one known unobserved case); such a code is added to `_REJECTED_CREDENTIAL_CODES` only with evidence, and until then the row still names `--regions` and the grant rather than nothing. The sets are module-private and no check reads them: they select text for a row the orchestrator builds, never a `Status`, so they are not a `NOT_CONFIGURED_ERRORS` table and their evidence rule is the comments, held by Property 45's pinned cases.

The key is `exc.lookup`, not the error's `Operation`, because a `BotoCoreError` carries `Operation` `Request` and would otherwise lose which lookup failed. The literals name `sts:GetCallerIdentity` and `ec2:DescribeRegions` directly: the orchestrator knows exactly which action failed, so Requirement 4.8's ban on *composing* an action string from a display name does not apply. `<scan Region>` is the `scan_region` parameter.

**Why the identity row names no permission.** The STS API reference for `GetCallerIdentity` says: "No permissions are required to perform this operation. If an administrator attaches a policy to your identity that explicitly denies access to the sts:GetCallerIdentity action, you can still perform this operation." (fetched 2026-10-03, `review2/gci.txt`). No IAM policy or SCP can therefore be the cause of a non-transport failure, and a remediation that suggested a grant would send the operator to the wrong place, the same reasoning that keeps `_remediation_for` unchanged under Open Question 5. What can fail it is the credential itself: an expired session token (`ExpiredToken`), an unknown access key (`InvalidClientTokenId`, observed in `review3/ec2-sts-invalid-creds.txt` and the code task 28's negative run 2 is expected to produce), no usable credential at all (`NoCredentialsError` or an SSO token error, raised by botocore before any request; `review4/nocreds-probe.txt`), or a wrong `--profile`. The `regions` row does name a grant, because `ec2:DescribeRegions` is an ordinary grantable action and `SRAVerifyLeastPrivilege` grants it.

Why this is the right owner and the right shape:

- **The row set is the merged tree's, row for row.** Same checks, same count (one per check that reads the failed fact), same `Status`, `Region`, `ResourceId` and account cells; a check that never reads the fact yields its genuine rows; a zero-row check stays zero-row. Only `ActualValue` changes, from `Error running SRA-X: Exception: Failed to get account ID: …` to `GetCallerIdentity failed: <Code>: <Message>` (or `Request failed: <Code>: …` for a `BotoCoreError`), and `Remediation`, from the control's text to the scan-environment text above. That is what Requirement 13.3 asks for, and Requirement 13.9 is reworded to say exactly this.
- **No new AWS call.** Identity is still read once up front, as today; the Region list is still read only by the checks that need it. A check that reads a failed fact re-issues the lookup, because failures are never cached, which is also today's behaviour, so call counts do not change.
- **No `try` in any `execute()`.** The catch is in the orchestrator. A check never names `ScanPreconditionError`; Property 45 asserts that by AST over the 182 check modules.
- **`logger.error` still means an ERROR row.** One record per precondition row. The one exception is the one the synthetic path already has: if building the row itself fails, which is a programming defect, a second `error` record with `exc_info` is written and the check contributes no row, and the loop continues with the next check. The pre-loop identity failure, which produces no row of its own, drops from `error` to `debug`; that is a stderr change only. A programming defect in the pre-loop block keeps its `logger.error`, which **gains** `exc_info=True` (`scanner.py:404` logs without it today; a stderr-only change, made so the defect's traceback is visible as it is for every other defect the orchestrator catches), and keeps its `("", "")` fallback, so a defect there still yields one synthetic row per check that then fails, read as a defect.

Outside `run_checks` — a library caller or test that builds a context and calls a check directly — the same `ScanPreconditionError` reaches the caller, naming the check, the lookup and the failed call. It never escapes `run_checks`, so `SRAVerify`'s and the CLI's exit-code handling are unchanged.

**`SecurityCheck.get_management_accountId()`** returns `str | ErrorResult`, and its one caller, `sra_securityincidentresponse_05`, consumes it:

```python
management_account_id = self.get_management_accountId()
if is_error(management_account_id):
    error = management_account_id["Error"]
    yield self.error(
        region=region,                 # "global", as the check already sets
        resource_id=None,              # as today's synthetic row
        actual_value=f"{error['Operation']} failed: {error['Code']}: {error['Message']}",
        remediation=self._remediation_for(error),
    )
    return
is_management_account = self.account_id == management_account_id
```

Any error is ERROR, including `AWSOrganizationsNotInUseException`, deliberately: the management-account fact only selects remediation wording on a FAIL, and the check has no FAIL arm that a missing organization should reach (adding one is out of scope). `resource_id=None` keeps the row identical to today's synthetic row in every cell but the two text cells. `DescribeOrganization` is callable from any member account (`caller-apiref.txt`), so the test organization cannot produce this row and the A/B shows none. The `session` argument stays accepted and ignored; the call drops the `self.session` it passed.

### `core/check.py` — `_remediation_for` is unchanged (Open Question 5)

**Decision: no.** `_remediation_for` keeps naming the check's own service for every operation, byte-identical to the merged Phase 1.

Revision 1 proposed naming Organizations for the operations the provider owns, on the premise that they "are answered for the management account or the Organizations delegated administrator". The review showed the premise is wrong for two of them, and the evidence gathered for this revision shows it is wrong for the rest:

- **`DescribeOrganization` and `DescribeEffectivePolicy`**: "You can call this operation from any account in a organization" (API reference, `caller-apiref.txt`). A denial cannot be about delegated administration at all.
- **The other seven** (`ListAccounts`, `ListDelegatedAdministrators`, `ListRoots`, `ListOrganizationalUnitsForParent`, `ListPoliciesForTarget`, `DescribePolicy`, `ListAccountsForParent`): "You can only call this operation from the management account or a member account that is **a delegated administrator**" (`caller-apiref.txt`, `caller-apiref2.txt`). The live probe (`caller-probe.txt`, 2026-10-02) tells which delegated administrator suffices, for three of the seven: the log-archive account is a delegated administrator only for `observabilityadmin.amazonaws.com` and is not a principal in the organization's resource policy, and the admin-only `ListAccounts`, `ListRoots` and `ListDelegatedAdministrators` all succeed from it (as does `DescribeOrganization`, which is any-member and so proves nothing here); an application account that is no delegated administrator is denied `ListAccounts` (Phase 1 `lv2/fanout`). So being a delegated administrator **for any service** is sufficient for those three. The other four (`ListOrganizationalUnitsForParent`, `ListPoliciesForTarget`, `DescribePolicy`, `ListAccountsForParent`) were not exercised from that account; they rest on the API reference sentence, which is word for word the one the three observed operations carry. That is adequate for a decision that changes nothing: if one of the four were stricter, the cost would be that remediation text which is already in the tree stays imprecise for it, not a new defect.

Under that evidence the current wording is right. A Security Hub check whose `ListDelegatedAdministrators` is refused without a reason is told to check the IAM grant and "whether the scanned account is the Security Hub delegated administrator"; becoming it does grant the call. Naming "the Organizations delegated administrator" instead would send the operator to the organization's resource-based delegation policy, which is not required. The operation's name is already in every access-denied remediation, so nothing is lost. Organizations' own denial text ("You don't have permissions to access this resource.") matches none of `_NOT_THE_ADMINISTRATOR_NEEDLES`, so these rows land in the cause-not-stated bucket that names both causes, which is the honest answer for `DescribeOrganization` and `DescribeEffectivePolicy` too.

Consequences: no `ADMIN_ONLY_OPERATIONS` set and no `SERVICE` attribute are added; Requirement 13.10 is reworded to require byte-identical output; Property 47 pins it; the A/B expects zero `Remediation` changes on rows that are not precondition rows.

### Concurrency and the denied fan-out

**Concurrency stays deferred.** `run_checks` is sequential, and the provider adds no lock. The guarantee Phase 1 stated as "one sweep per scan holds under sequential execution" extends to "one fetch per accessor per key per scan, under sequential execution" (Property 38). Per-key in-flight coordination (a future or event per cache key, in the provider) remains the follow-up Requirement 13.7 names, to land before or with concurrent scanning. Task 23.3's concurrency clause stays **open and unticked**, with a note that its measurement clause is already satisfied.

**Never cache a failure stays.** The measured worst case (Phase 1 live validation, `lv2/fanout/summary.txt`): **207** denied `ListAccounts` calls over **17** Regions when an application account that is neither management nor a delegated administrator runs every check of the seven consuming services (twelve regional consumers × 17 + three global), each producing exactly one ERROR row; and **0** under a real `--account-type application` scan, the CodeBuild member-account shape, because none of the consumers is an application-type check. Phase 2 adds the same shape for `ListDelegatedAdministrators` and the other owned operations at lower breadth: a delegated-administrator key is per principal, not per Region, so the retired per-Region keys (`macie`, `securityhub`, `securitylake`) issue fewer calls on success, and on failure each caller re-issues as before. The A/B records the `aws_call_failed` count per operation so a later decision has the Phase 2 figures too.

**Proposal only, not designed for implementation:** a constrained non-retryable marker. If a future measurement justifies it, the provider could record, per cache key, the error result of a failure whose code is in a closed allowlist that is deterministic for one principal within one scan — `AWSOrganizationsNotInUseException`, and `AccessDeniedException` from an owned operation whose message names neither an IAM action nor a principal — and replay that **identical** error result to later callers, so every row's `Status`, `ActualValue` and `Remediation` would be unchanged and only the `aws_call_failed` count would fall (207 → 1 in the worst case). Throttling, transport, 5xx and any unlisted code would never be recorded. It would live in the provider, not in `_set`, so the `_set` backstop and the never-cache rule for every service base stay as they are. It needs a steering amendment and the owner's sign-off, and today's figures do not justify it: the fan-out exists only in a scan shape the buildspec never runs, and costs seconds. Recorded for the owner; nothing in Phase 2 implements it.

### Tests that change

- **`tests/property/test_client_contract_property.py`** — three `ClientAdapter` rows added to `_ORGANIZATIONS` (23.1); the fifteen retired rows removed from their eight services' tables (24.1). `test_the_adapter_table_is_complete_and_exact` holds at 111 and then at 96.
- **`tests/property/test_organization_provider_property.py`** — `PROVIDER_ADAPTERS` grows to eleven rows, each with representative `args` (`("securityhub.amazonaws.com",)`, `("r-root",)`, `("SERVICE_CONTROL_POLICY",)`, `("r-root", "SECURITYHUB_POLICY")`, `("p-abc123",)`, `("BEDROCK_POLICY", "111122223333")`, `("ou-abc",)`) and an `operation`. The cache contract (Properties 37–40) is parametrized over the table, so an accessor added later is covered by adding its row, and `test_the_provider_adapter_table_is_complete_and_exact` fails until it is. `stub_organization` needs no change: it already iterates the table. Property 4's public-callable set becomes the eleven names.
- **`tests/property/test_accessor_cache_property.py`** — the base accessors in the call-site table move from `accessor` to `derived` with the default `error_bearing` (the `config` and `securityincidentresponse` `get_delegated_administrators` rows drop their explicit `error_bearing=True`; see the classification bullet below for why); the `organizations` entries for `get_org_client` (`client_lookup`) and the six accessors are reclassified; `_global_client_attributes` stops finding `_org_client`. No provider accessor is added to a base table (Requirement 10.6).
- **`tests/property/test_check_classification_property.py`** — `_semantic_targets` also enumerates `OrganizationsProvider.NOT_CONFIGURED_ERRORS`, so every provider pair is driven through every check; `_PROVIDER_OPERATIONS` already resolves from `PROVIDER_ADAPTERS`. **The delegators are left unpatched** (option (a) of review N2): each is classified `derived` with the default `error_bearing`, so `bears_error()` is `False`, `_prepare` does not patch it, and it runs for real against the context's `stub_organization`, which records `organization.<method>` and which `_PROVIDER_OPERATIONS` already resolves to the provider operation. No new mapping is added, and `_OPERATION_OF_ACCESSOR` is not changed: it is a join derived from the two adapter tables, and a delegator row declares no `client_method` that the client table still lists, so it contributes no entry. This is the better-covering choice: the delegator's own code, including `ConfigCheck`'s first-failure-wins loop over `CONFIG_SERVICE_PRINCIPALS`, is exercised by every catalog-wide harness instead of being replaced by a stub. It requires removing the explicit `error_bearing=True` from the two rows that carry it today, `config`'s and `securityincidentresponse`'s `get_delegated_administrators` (`test_accessor_cache_property.py:281, :843`); the other five SIR rows keep their explicit `error_bearing` (four `True`, at `:849`, `:856`, `:862`, `:868`, and one `False`, `discover_sir_region` at `:875`). Task 24.1 rewrites the SIR table's comment, "All six of these hand a check the client's dict directly, so they are error-bearing", to say that of the five remaining rows, four hand a check the client's dict directly and are error-bearing, `discover_sir_region` returns a Region name and is not, and that `get_delegated_administrators` now delegates to the provider and runs unpatched. Property 14a gains one asserted exemption set, because two checks reach a provider-declared pair first and deliberately have no FAIL arm for it:

  ```python
  #: Provider pairs a check reaches first but routes to ERROR by design
  #: (design-phase2.md, moved-verdict ledger: the "stays ERROR" rows reached
  #: first by the classification harness). For these the
  #: property asserts error() and never failed(), instead of skipping.
  _PROVIDER_PAIRS_WITHOUT_FAIL_ARM = frozenset({
      ("SRA-SECURITYHUB-17", "ListAccounts"),
      ("SRA-IAM-05", "DescribeOrganization"),
  })
  ```

  A companion test asserts the set equals the ledger's "stays ERROR" rows **reached first by the classification harness** (`test_provider_classification.py` exports the ledger), the qualifier Property 44 uses. The ledger has three "stays ERROR" rows; the qualifier is what excludes the third, `SRA-SECURITYINCIDENTRESPONSE-05` / `DescribeOrganization`, which the harness never reaches because `_prepare` stubs `ctx.get_management_account_id` with a success. Adding a FAIL arm to either check is out of scope: it would move a verdict this design does not list.
- **New `tests/unit/core/test_provider_classification.py`** — the per-check ledger of task 26 (below), driven offline (Property 44).
- **`tests/property/test_discriminator_property.py`** — Property 43, including its golden clause: a module constant `_NON_OWNED_NOT_CONFIGURED_ENTRIES` (named for what it holds, not for the commit it was taken from, because it outlives Phase 2 as a change-detector), with the comment `# Captured at f517024. A deliberate change to a non-owned NOT_CONFIGURED_ERRORS entry updates this tuple in the same commit.`, a sorted tuple of `(base class name, operation, code, message needle or None, sha256 hex digest of evidence)` for every entry in every service base's `NOT_CONFIGURED_ERRORS` whose operation is not in `OWNED_OPERATIONS`, captured once from the merged tree at `f517024` and committed literally. On that tree the service bases declare 51 `(operation, code)` entries, five of them for owned operations (the five task 26 relocates), so the constant has **46** rows (`nonowned-entries.txt`, counted from the live classes on this branch, which carries no code change from `f517024`). The test rebuilds the same tuple from the live classes and asserts equality, so any removal, addition or evidence edit to a non-owned entry fails offline. The digest keeps the constant short while still making "byte-identical" the assertion; a future, deliberate change to a non-owned entry updates the constant in the same commit, which is what makes it reviewable.
- **`tests/property/test_layering_property.py`** — Properties 41 and 42, replacing Phase 1's `list_accounts`-only Property 8 tests with the widened rule (the Phase 1 `.list_accounts(` count in `core/organization.py` stays as one case of it).
- **`tests/unit/core/test_scan_context.py`** — the three accessors (Property 46). It includes one case for the revision 5 review's M1: the session's `client("ec2")` raises `PartialCredentialsError`, and with no explicit Regions `get_enabled_regions()` raises that same exception object. The case asserts that the exception is not wrapped in another exception and is not returned as an error result, that no `aws_call_failed` record is emitted, and that `_resolved_regions` is left unset. A twin case does the same for `client("sts")` and `get_account_info()`. **New `tests/unit/core/test_scan_preconditions.py`** — Property 45, with the remediation pinned per order-table row: at least `identity`/`EndpointConnectionError`, `regions`/`EndpointConnectionError`, `identity`/`InvalidClientTokenId`, **`regions`/`AuthFailure`** (the review M1 case: credentials wording, and the string `ec2:DescribeRegions` absent), `identity`/an unlisted code, `regions`/`UnauthorizedOperation` (grant wording), **`regions`/`NoCredentialsError`** with `Operation` `Request` (the rev-4 review M1 case: credentials wording, and the string `ec2:DescribeRegions` absent), and an unknown `lookup` value; plus a test that `_CREDENTIAL_ERROR_CODES` equals `{"AuthFailure", "InvalidClientTokenId"}` united with the class names of `_LOCAL_CREDENTIAL_EXCEPTIONS`, and that every class in `_LOCAL_CREDENTIAL_EXCEPTIONS` is a `BotoCoreError` subclass, so a code is added only by a reviewed edit; and one end-to-end case that raises a real `NoCredentialsError` through `AWSClient.aws_error` into `get_enabled_regions` and asserts the resulting precondition row's remediation, so the class-name-to-code mapping the derivation rests on is held by a test rather than by the comment. **`tests/unit/core/test_remediation_for.py`** — Property 47.
- **`tests/unit/services/test_securityhub_organization.py`** — rewritten to assert `get_organization()` returns `self.organization.describe()` by identity.
- **`tests/property/test_check_classification_property.py`'s `_prepare`** already sets `ctx.get_account_info.return_value` and `ctx.get_management_account_id.return_value` to successes, so the catalog-wide harnesses never reach a precondition error; no change.

## Data Models

### The `organizations` namespace after Phase 2

| Key                                             | Value                                  | Written and read by          |
| ----------------------------------------------- | -------------------------------------- | ---------------------------- |
| `all_accounts`                                  | `{"Accounts": [...]}`                  | `accounts()`                 |
| `organization`                                  | the `DescribeOrganization` response    | `describe()`                 |
| `delegated_admins:<service_principal>`          | `{"DelegatedAdministrators": [...]}`   | `delegated_administrators()` |
| `roots`                                         | `{"Roots": [...]}`                     | `roots()`                    |
| `ous:<parent_id>`                               | `{"OrganizationalUnits": [...]}`       | `ous_for_parent()`           |
| `policies:<policy_type>`                        | `{"Policies": [...]}`                  | `policies()`                 |
| `policies_for_target:<target_id>:<policy_type>` | `{"Policies": [...]}`                  | `policies_for_target()`      |
| `policy:<policy_id>`                            | the `DescribePolicy` response          | `describe_policy()`          |
| `effective_policy:<policy_type>:<target_id>`    | the `DescribeEffectivePolicy` response | `effective_policy()`         |
| `accounts:<parent_id>`                          | `{"Accounts": [...]}`                  | `accounts_for_parent()`      |

Ten keys, each written by exactly one caching accessor and read by that accessor only; `management_account_id()` reads `organization` through `describe()`. The steering sentence Phase 1 scoped to the slot (`design.md` Open Question 4) widens to the namespace: *the `organizations` namespace is written and read only by the Organizations provider; no service base reads it by key.* `OrganizationsCheck.NAMESPACE = "organizations"` stays, because every base declares its namespace and Property 1's test compares against it, but `OrganizationsCheck` no longer calls `_has`, `_get` or `_set`.

### The provider table after Phase 2

```python
NOT_CONFIGURED_ERRORS: ClassVar[NotConfiguredTable] = {
    "ListDelegatedAdministrators": {
        "AWSOrganizationsNotInUseException": NotConfigured(evidence=(
            "https://docs.aws.amazon.com/organizations/latest/APIReference/"
            "API_ListDelegatedAdministrators.html -- 'Your account isn't a member of "
            "an organization.' (page fetched 2026-10-02). No organization means no "
            "delegated administrator can be registered for any principal."
        )),
    },
    "ListAccounts": {
        "AWSOrganizationsNotInUseException": NotConfigured(evidence=(
            "https://docs.aws.amazon.com/organizations/latest/APIReference/"
            "API_ListAccounts.html -- 'Your account isn't a member of an "
            "organization.' (page fetched 2026-10-02). No organization means no "
            "accounts to enrol."
        )),
    },
    "DescribeOrganization": {
        "AWSOrganizationsNotInUseException": NotConfigured(evidence=(
            "https://docs.aws.amazon.com/organizations/latest/APIReference/"
            "API_DescribeOrganization.html -- 'Your account isn't a member of an "
            "organization.' (page fetched 2026-10-02). Moved from ConfigCheck and "
            "OrganizationsCheck, which declared the identical pair."
        )),
    },
    "DescribeEffectivePolicy": {
        "EffectivePolicyNotFoundException": NotConfigured(evidence=(
            "https://docs.aws.amazon.com/organizations/latest/APIReference/"
            "API_DescribeEffectivePolicy.html -- no policy of the type is in effect "
            "for the target. Observed 2026-09-16 for every active account (the "
            "aws_call_failed record quoted in OrganizationsCheck's former entry). "
            "Moved from OrganizationsCheck and SecurityHubCheck."
        )),
    },
}
```

Each entry cites the API reference page for **that operation**; the three `AWSOrganizationsNotInUseException` pages were fetched and their text recorded (`apiref-evidence.txt`), and the code also appears in botocore's error model for each (`botocore-org-errors.txt`). The `DescribeEffectivePolicy` entry keeps its observed `aws_call_failed` evidence verbatim from the service tables. Nothing is inferred. No message needle: the code is not overloaded.

Removed from service tables in the same change, because the provider now declares the identical pair: `IAMCheck`'s `ListDelegatedAdministrators` entry, `ConfigCheck`'s and `OrganizationsCheck`'s `DescribeOrganization` entries, `OrganizationsCheck`'s and `SecurityHubCheck`'s `DescribeEffectivePolicy` entries. Every other entry in those tables stays **byte-identical**:

- `IAMCheck.NOT_CONFIGURED_ERRORS` (`services/iam/base.py:56–93`) loses **only** its `ListDelegatedAdministrators` entry. Its `ListOrganizationsFeatures` / `ServiceAccessNotEnabledException` entry (`SRA-IAM-02`, `-03`; observed 2026-09-29 in the test-org management account) and its `GetAccountPasswordPolicy` / `NoSuchEntity` entry (`SRA-IAM-06`; observed 2026-09-29 in three test-org accounts) stay exactly as they are; neither is an Organizations operation, and removing either would move FAIL rows to ERROR in the test organization. The class comment's `DescribeOrganization` paragraph ("`DescribeOrganization` is absent too: SRA-IAM-05 only uses it to recognise the management account, and a standalone account is not a member account the control can be judged for") is rewritten to say: the Organizations operations `IAMCheck`'s accessors reach (`ListDelegatedAdministrators`, `DescribeOrganization`) are classified by `OrganizationsProvider.NOT_CONFIGURED_ERRORS`; after task 26 the provider declares `DescribeOrganization` / `AWSOrganizationsNotInUseException`, so `is_not_configured` answers `True` for it, and `SRA-IAM-05` still yields ERROR because it has no FAIL arm on that branch (ledger row "stays ERROR"). The paragraphs on `ListUsers`, `GetAccountSummary` and `ListOrganizationsFeatures` are unchanged.
- `ConfigCheck.NOT_CONFIGURED_ERRORS` keeps `GetBucketPolicy` / `NoSuchBucketPolicy` byte-identical. Its class comment ("Both entries are about a resource whose *absence is the finding*: no organization, or a bucket with no policy") is rewritten for the one remaining entry, and says that `DescribeOrganization` is now classified by the provider's table.
- `OrganizationsCheck` keeps `ListPolicies` / `PolicyTypeNotEnabledException` (next paragraph). `SecurityHubCheck` keeps every entry other than `DescribeEffectivePolicy`.

Property 43 holds this offline: every service-table entry whose operation is outside `OWNED_OPERATIONS` is compared against a golden snapshot of the merged Phase 1 (`f517024`), so a removal like the one revision 3 drafted fails a named test before any scan. **Kept on `OrganizationsCheck`:** `ListPolicies` / `PolicyTypeNotEnabledException`, because the provider table is keyed by operation name and `fms:ListPolicies` shares it — declared in the provider, it would be consulted for every Firewall Manager check too (`ledger-sim.txt` shows the harness driving six Firewall Manager checks to FAIL through it). That is why the provider table is restricted to `OWNED_OPERATIONS` (Property 43, Requirement 13.11).

**Deliberately not declared:** `AWSOrganizationsNotInUseException` for `ListRoots`, `ListOrganizationalUnitsForParent`, `ListAccountsForParent`, `ListPoliciesForTarget` and `DescribePolicy`. The consuming checks (`organizations_02`–`_04`, `_08`–`_10`, `securityhub_16`) have no FAIL arm written for "no organization" on those branches, so a declaration would route the answer to wording that was never reviewed for it. They stay ERROR; any later entry follows the same evidence and ledger rule.

### The moved-verdict ledger (task 26, held offline)

Every check whose verdict an entry above can move, by branch, from `fail-arms.txt` and `ledger-sim.txt`. Today each "moves" branch yields ERROR for the declared pair; after task 26 it yields FAIL with the wording already written in the check.

| Entry                         | Check and branch                                                                                                                                   | Region cell                                  | Outcome after task 26                                                                           |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `ListDelegatedAdministrators` | `SRA-ACCESSANALYZER-02`, `-03`: delegated-admin branch                                                                                             | `global`                                     | moves: `No AWS Organization exists, so IAM Access Analyzer can have no delegated administrator` |
|                               | `SRA-CLOUDTRAIL-12`, `-13`: delegated-admin branch                                                                                                 | `global`                                     | moves: `No AWS Organization exists, so CloudTrail can have no delegated administrator`          |
|                               | `SRA-CONFIG-07`, `-08`: delegated-admin branch                                                                                                     | `global`                                     | moves: `No AWS Organization exists, so AWS Config can have no delegated administrator`          |
|                               | `SRA-SECURITYHUB-03`: delegated-admin branch                                                                                                       | `global`                                     | moves: `No AWS Organization exists, so Security Hub can have no delegated administrator`        |
|                               | `SRA-SECURITYHUB-06`: delegated-admin branch (after the admin-account branch)                                                                      | scanned Region                               | moves: same text                                                                                |
|                               | `SRA-SECURITYHUB-07`: delegated-admin branch, per Region                                                                                           | scanned Region                               | moves: same text                                                                                |
|                               | `SRA-SECURITYINCIDENTRESPONSE-01`: delegated-admin branch                                                                                          | `regions[0]` (deferred labelling, unchanged) | moves: `No delegated administrator is configured for Security Incident Response`                |
|                               | `SRA-SECURITYLAKE-14`, `-15`: delegated-admin branch                                                                                               | `global`                                     | moves: `No AWS Organization exists, so Security Lake can have no delegated administrator`       |
|                               | `SRA-IAM-04`: already FAIL through `IAMCheck`'s entry                                                                                              | `global`                                     | does not move                                                                                   |
| `ListAccounts`                | `SRA-INSPECTOR-07`, `SRA-MACIE-07`, `SRA-SECURITYHUB-08`, `SRA-SECURITYLAKE-01`, `SRA-SECURITYLAKE-06`…`-13`: accounts branch, per Region          | scanned Region                               | moves: each check's existing `No AWS Organization exists, …` text                               |
|                               | `SRA-ORGANIZATIONS-12`, `SRA-SECURITYINCIDENTRESPONSE-04`: accounts branch                                                                         | `global` / SIR Region                        | moves: existing text                                                                            |
|                               | `SRA-SECURITYHUB-17`: accounts branch has no FAIL arm                                                                                              | `global`                                     | stays ERROR (in `_PROVIDER_PAIRS_WITHOUT_FAIL_ARM`)                                             |
| `DescribeOrganization`        | `SRA-ORGANIZATIONS-01`, `-05`, `-06`, `-07`, `-11`: already FAIL through `OrganizationsCheck`'s table (`ConfigCheck`'s entry has no live consumer) | as today                                     | does not move (relocation of an identical pair)                                                 |
|                               | `SRA-IAM-05`: no FAIL arm                                                                                                                          | `global`                                     | stays ERROR (in `_PROVIDER_PAIRS_WITHOUT_FAIL_ARM`)                                             |
|                               | `SRA-SECURITYINCIDENTRESPONSE-05`: does not consult `is_not_configured`                                                                            | `global`                                     | stays ERROR                                                                                     |
| `DescribeEffectivePolicy`     | every consumer: already declared by its service table                                                                                              | as today                                     | does not move (relocation)                                                                      |

Twelve checks move through the `ListDelegatedAdministrators` entry and fourteen through `ListAccounts`, all only in an account that is not a member of any organization. `SRA-IAM-05` is the one check whose table classification changes without a verdict change: `IAMCheck` never declared `DescribeOrganization`, so after task 26 `is_not_configured` answers `True` for it, but the check has no FAIL arm on that branch and yields ERROR either way.

**Evidence, under Requirement 13.12.** In the test organization every account is a member, so `AWSOrganizationsNotInUseException` cannot be returned and the live A/B is expected to show **zero rows moved by task 26**; any row it does move is a rejection. Creating a standalone account to observe the code is a write outside this feature's scope. Both new entries (`ListDelegatedAdministrators` and `ListAccounts`) are therefore held by the same three things: the API reference citation in the entry; the zero-moved live A/B; and `tests/unit/core/test_provider_classification.py`, which has one parametrized case per ledger row, driving the check with the row's accessor returning `error_result(code="AWSOrganizationsNotInUseException", operation=<op>, message="Your account isn't a member of an organization.")` and every accessor the check consults first returning a minimal success named in the case (for `SRA-SECURITYHUB-06`, its admin-account accessor; for `SRA-CONFIG-07`/`-08`, a non-empty Region list; for `SRA-SECURITYINCIDENTRESPONSE-01`, an `--audit-account` on the stub context). Each "moves" case asserts at least one FAIL, no PASS, the existing `ActualValue` text, and that the same drive with the provider table patched empty yields ERROR and no FAIL on that branch, so the case proves the entry is what moves it. Each "does not move" and "stays ERROR" case asserts the same status under both tables. The Phase 2 test report flags this reading of Requirement 13.4 for the owner's review at hand-off (Requirement 13.12).

## Error Handling

The three tiers are unchanged. Per operation this design touches:

| Operation                                                                                    | Failure                                                                                                                                                                         | Who sees it                                                                                                                                        | Recoverable                                                                                     | Logged                                                                                                             |
| -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Any of the ten new provider accessors                                                        | `ClientError` / `BotoCoreError` on any page                                                                                                                                     | the calling check, as an error result                                                                                                              | yes; never cached, the next caller re-issues                                                    | one `aws_call_failed` at `debug`, from the client                                                                  |
| `management_account_id()`                                                                    | `describe()` failed                                                                                                                                                             | caller, `describe()`'s error result unchanged                                                                                                      | yes                                                                                             | nothing beyond the client's record                                                                                 |
| `management_account_id()`                                                                    | success without `MasterAccountId`                                                                                                                                               | `KeyError` → per-check guard → synthetic row                                                                                                       | no: botocore contract violation                                                                 | `logger.error` with `exc_info` by the orchestrator                                                                 |
| `get_account_info()` STS call, read up front by `run_checks`                                 | any AWS exception                                                                                                                                                               | nobody directly; `fallback_account` is `("", "")`                                                                                                  | yes, next scan                                                                                  | one `aws_call_failed` (`debug`) + one `debug` line                                                                 |
| `get_account_info()` STS call, read by a check                                               | any AWS exception                                                                                                                                                               | `ScanPreconditionError` → one precondition ERROR row for that check; its other rows discarded, as today                                            | yes, next scan; re-issued by the next check                                                     | one `aws_call_failed` (`debug`) + one `logger.error` naming the check                                              |
| `get_account_info()` STS or Account API call, or constructing either client                  | non-AWS exception (`KeyError` on `Account`, a defect in the method), or a client-construction failure such as `PartialCredentialsError` (`cred-surface-probe.txt`)              | up front: `logger.error` + `("", "")`; in a check: synthetic row (today's rows, text for text)                                                     | a defect: no; a construction-time credential failure: next scan, once the credentials are fixed | `logger.error` with `exc_info`                                                                                     |
| `get_account_info()` Account API call                                                        | any AWS exception (`except AWS_EXCEPTIONS as e: self._call_failed(e)`), or no `AccountName` in the response                                                                     | nobody; name `""`, identity cached                                                                                                                 | best-effort, as today                                                                           | one `aws_call_failed` at `debug` for an AWS exception; nothing for a missing key                                   |
| `get_enabled_regions()` (no explicit Regions), read by a check                               | any AWS exception                                                                                                                                                               | `ScanPreconditionError` → one precondition ERROR row for that check; checks that never read it are unaffected                                      | yes; never cached                                                                               | one `aws_call_failed` (`debug`) + one `logger.error` naming the check                                              |
| `get_enabled_regions()` EC2 call, or constructing the EC2 client (acquired before the `try`) | non-AWS exception (a `KeyError` on `Regions`, a defect in the method), or a client-construction failure such as `PartialCredentialsError` (`review5/partial_regions_probe.txt`) | propagates unchanged; in a check: synthetic row (today's rows; the `ActualValue` loses its `Failed to get enabled regions:` wrapper, scope item 2) | a defect: no; a construction-time credential failure: next scan, once the credentials are fixed | `logger.error` with `exc_info` by the orchestrator                                                                 |
| `get_management_account_id()`                                                                | `DescribeOrganization` failed                                                                                                                                                   | `sra_securityincidentresponse_05`: one ERROR row, `global`, `ResourceId` empty                                                                     | yes                                                                                             | client's record only, plus nothing: the row is a normal `error()` row                                              |
| A check property read outside `run_checks` on a failed lookup                                | —                                                                                                                                                                               | `ScanPreconditionError` to the library caller                                                                                                      | caller's choice                                                                                 | by the caller                                                                                                      |
| `_precondition_error` building the row                                                       | any exception (a defect in the row builder)                                                                                                                                     | nobody; that check contributes no row, the loop continues                                                                                          | no: defect                                                                                      | the precondition `logger.error` + one `logger.error` with `exc_info` (secondary failure, as for the synthetic row) |

**Classification.** `SecurityCheck.is_not_configured` is unchanged: service table, then provider table, first to declare decides. After task 26 no service table declares an owned operation, so for those operations the provider table alone decides, and two checks reading the same answer can no longer classify it differently.

**Input validation.** The provider's inputs are literals or values read from earlier successful responses: service principals are string constants in the delegators; `parent_id`, `target_id` and `policy_id` come from `ListRoots`, `ListAccounts` or `ListPoliciesForTarget` responses; policy types are module constants. The provider does not validate them: an empty or malformed ID reaches AWS and returns `InvalidInputException` as an error result, which is ERROR, the honest outcome. No external user input reaches it. `ScanPreconditionError`'s `lookup` is one of two literals set by `SecurityCheck`; `_precondition_error` falls back to the "any other code" wording of the `identity` row for an unknown value rather than raising, because it runs inside error handling.

## Correctness Properties

Each statement below is held offline with no credentials. Statements that range over accessors are parametrized over `PROVIDER_ADAPTERS`, which a companion test proves equal to the provider's public callables, so an accessor added later is covered by adding one row. Statements that range over modules are AST rules over package `.py` files located from `sraverify.__file__`, so they run from an installed wheel (Property 36). Live behaviour — the zero-moved ledger, the `aws_call_failed` Region change, the `Fetching` counts — is held by the task 28 gate.

### Property 37: Every provider accessor caches a success and never a failure

*For any* row of `PROVIDER_ADAPTERS` and any outcome of its client method (a success dict, a `ClientError` on any page, a `BotoCoreError`), the accessor returns the success dict by identity and stores it under its documented key in the `organizations` namespace, or returns the error result unchanged with `Operation` equal to the row's operation (`Request` for a `BotoCoreError`) and leaves the key unwritten; a later call after a failure re-issues, and a later call after a success issues nothing.

**Validates: Requirements 13.1, 1.4, 10.6**

### Property 38: One fetch per accessor per key under sequential execution

*For any* sequential sequence of calls to provider accessors with any multiset of argument tuples, made through checks on any service base, the client method behind each accessor is invoked exactly once per distinct argument tuple that succeeded, and each of the ten new caching accessors emits one `Organizations: Fetching <key>` record per such tuple and one `Organizations: Using cached <key>` record per later read, while `accounts()` keeps its Phase 1 wording (`Fetching organization accounts`, `Using cached organization accounts`) under Property 29; concurrent first callers are out of scope until Requirement 13.7's coordination lands.

**Validates: Requirements 13.1, 13.7**

### Property 39: Distinct arguments are distinct slots

*For any* two argument tuples to the same accessor, or any two caching accessors, the cache keys differ unless the accessor and arguments are equal; the ten caching accessors, called once each with one argument set, write ten distinct keys, and `management_account_id()` writes no key of its own.

**Validates: Requirements 13.1**

### Property 40: The management account ID is derived from `describe()`

*For any* `DescribeOrganization` outcome, `management_account_id()` returns `Organization.MasterAccountId` on success or `describe()`'s error result by identity on failure, reads the `organization` slot through `describe()` and issues no client call when it is cached, and `ScanContext.get_management_account_id()` and `SecurityCheck.get_management_accountId()` return the same value.

**Validates: Requirements 13.1, 13.3**

### Property 41: Only the provider's client issues an Organizations operation

*For any* module under `core/` or `services/` other than `core/organizations_client.py`, no call `get_paginator('<op>')` names an operation in `OWNED_OPERATIONS` converted to snake_case, and no call `<receiver>.<op>(` with `<op>` in that set has a receiver other than an attribute named `organization` (the provider, as in `self.organization.describe_policy(...)`), except in `core/organization.py`, where any receiver is permitted (the `_cached` lambda's parameter cannot be typed by AST, and that module is otherwise held to calling the wrapper by containing no `get_paginator(` and no `.client.` receiver, the Phase 1 two-set shape); no module other than `core/organizations_client.py` binds `get_client('organizations', ...)`, which is what covers `ListPolicies` (excluded from the set because `services/firewallmanager/client.py:61` legitimately calls `get_paginator('list_policies')` on an `fms` client); and no module other than `core/organizations_client.py` and `core/organization.py` names `OrganizationsClient`.

**Validates: Requirements 13.2, 5.2**

### Property 42: No service base reads the `organizations` namespace by key

*For any* `services/*/base.py`, no `_has`, `_get` or `_set` call takes as its namespace argument the string `"organizations"`, a name bound to that string, or `self.NAMESPACE` in a class whose `NAMESPACE` is `"organizations"`, and `OrganizationsCheck` contains no `_has`, `_get` or `_set` call at all.

**Validates: Requirements 13.8, 5.2, 11.1**

### Property 43: The provider table declares only operations it owns

*For any* operation declared in `OrganizationsProvider.NOT_CONFIGURED_ERRORS`, the operation is in `OWNED_OPERATIONS`; `OWNED_OPERATIONS` is a subset of the operations named by `PROVIDER_ADAPTERS` and is disjoint from every operation named by a `ClientAdapter` outside `organizations`; no service table declares an operation in `OWNED_OPERATIONS`; and every service-table entry for an operation outside `OWNED_OPERATIONS` is unchanged from the merged Phase 1 (same base, operation, code, message needle and evidence text), held by a golden comparison against `f517024`.

**Validates: Requirements 13.11, 13.4, 3.1**

### Property 44: Each ledger row reaches the verdict the table assigns

*For any* row of the moved-verdict ledger, driving the check with the row's accessor returning `AWSOrganizationsNotInUseException` for the row's operation yields, for a "moves" row, at least one FAIL with the check's existing `ActualValue` and no PASS under the committed provider table and ERROR with no FAIL on that branch under an empty one, and for a "does not move" or "stays ERROR" row the same status under both; and `_PROVIDER_PAIRS_WITHOUT_FAIL_ARM` equals the set of "stays ERROR" rows reached first by the classification harness.

**Validates: Requirements 13.4, 13.12**

### Property 45: A failed identity or Region lookup costs exactly the rows it costs today

*For any* selection of checks and any failure of `sts:GetCallerIdentity` (or, with no explicit Regions, of `ec2:DescribeRegions`), `run_checks` yields, for each check that reads the failed fact, exactly one ERROR row with `Region` `global`, `ResourceId` empty, the check's own severity, the scan's fallback account, `ActualValue` matching `^\S+ failed: \S+: ` and the precondition-table remediation for its code class and lookup, in which a code in `_CREDENTIAL_ERROR_CODES`, including the class name of a `BotoCoreError` that is a botocore credential-provider failure, carries the credentials remediation for either lookup (so a `regions` row with `AuthFailure` or `NoCredentialsError` never names `ec2:DescribeRegions`), and for each check that does not read it exactly the rows it yields when the lookup succeeds; issues no `DescribeRegions` call that the merged tree does not issue; emits one `logger.error` record per precondition row; when building a precondition row itself raises, logs that failure at `error` with `exc_info`, contributes no row for that check, and continues with the next check rather than ending the scan; releases the context; and no check module names `ScanPreconditionError` or catches an exception in `execute()`.

**Validates: Requirements 13.3, 13.9**

### Property 46: The context's lookups never raise for an AWS outcome and never cache a failure

*For any* `ClientError` or `BotoCoreError` raised by the STS, EC2 or Organizations call behind `get_account_info`, `get_enabled_regions` or `get_management_account_id`, the accessor returns an error result naming the operation and code, emits exactly one `aws_call_failed` record and no `error`-level record, and leaves its cache unwritten so the next call re-issues; a failure of the Account API call, or a response without `AccountName`, yields `account_name` `""` with the identity cached; and a non-AWS exception from the STS, Account or EC2 call, or any exception raised while constructing the STS, Account or EC2 client (each acquired before its `try`), propagates unchanged, with no wrapping, no error result and no `aws_call_failed` record.

**Validates: Requirements 13.3**

### Property 47: An Organizations-operation error keeps the Phase 1 remediation

*For any* error result whose operation is in `OWNED_OPERATIONS` or is `ListPolicies`, any code and any message, and any check, `_remediation_for` returns exactly the string the merged Phase 1 returns for the same check and error, held by a golden table of the six bucket templates with the check's own `service` interpolated.

**Validates: Requirements 13.10**

## Testing Strategy

**Unit and property (offline).** Properties 37–47 above, in the modules named under "Tests that change". The ledger cases (Property 44) hold task 26's entries, since the live A/B cannot reach `AWSOrganizationsNotInUseException`. The suite stays green with no `xfail`; the Python 3.11 frozen-plus-slots dataclass failures that predate Phase 2 are out of scope and are neither fixed nor masked. Counts are measured at the end and recorded by task 29.1.

**Live (task 28), per `testing_checks.md`.** Two trees, the merged Phase 1 (`phase1-wt` at `f517024`) and the Phase 2 candidate, scanned in one window with identical arguments from the management and audit profiles, over the ten services that touched Organizations (Inspector, Macie, Organizations, Security Hub, Security Incident Response, Security Lake, IAM, Access Analyzer, CloudTrail, Config). Expected, joined on (account, account type, Region, check ID, ResourceId): zero `Status` changes, zero `ActualValue` changes, zero `Remediation` changes, zero row-count changes. Per-scan gates as Phase 1, with `Fetching` records once per accessor per key; `aws_call_failed region=` on retired paths moving from the scanned Region to the scan Region with no `Region` cell moving (Requirement 13.5); per-operation `aws_call_failed` counts tabulated against Phase 1 and every drop explained by a retired per-Region key.

Three read-only negative runs:

1. The Phase 1 denied-`ListAccounts` run (application profile, every check of the consuming services) repeated on both trees: same rows, same `Status`, call counts tabulated.
2. **Identity failure**: deliberately invalid static credentials in the environment (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` set to non-existent values, `--regions` given) on both trees, over the same services. Expected: the same row count per check on both trees; the merged tree's rows are synthetic (`Error running …: Exception: Failed to get account ID: …`) and the candidate's read `GetCallerIdentity failed: InvalidClientTokenId: …` with the identity remediation; every other cell equal. This is the only run expected to show text changes, and they are listed per check.
   **2b. Identity failure with no `--regions`** (added for review M1): the same invalid static credentials, `AWS_DEFAULT_REGION=us-east-1` in the environment and **no** `--regions`, so the scan Region resolves without an AWS call and the first lookup a regional check makes is `ec2:DescribeRegions`. Read-only and touches no test-organization resource, since the credentials belong to no principal. Expected on both trees: the same row count per check. On the merged tree, regional checks' rows are synthetic (`… Exception: Failed to get enabled regions: …`) and the IAM and Organizations checks' rows are synthetic (`… Failed to get account ID: …`). On the candidate, regional checks read `DescribeRegions failed: AuthFailure: …` and the IAM and Organizations checks read `GetCallerIdentity failed: InvalidClientTokenId: …`, **both** with the credentials remediation, and no row names `ec2:DescribeRegions`. Every other cell is equal.
   **2c. No credential source, no `--regions`** (added for the rev-4 review M1): `env -i` with `PATH`, `HOME` pointing at an empty directory, `AWS_CONFIG_FILE=/dev/null`, `AWS_SHARED_CREDENTIALS_FILE=/dev/null`, `AWS_EC2_METADATA_DISABLED=true`, `AWS_DEFAULT_REGION=us-east-1`, no `--profile` and no `--regions`, on both trees over the same services. botocore raises `NoCredentialsError` before sending any request, so the run is read-only and reaches no AWS endpoint (`review4/nocreds-probe.txt`). Expected: the same row count per check on both trees. On the merged tree the rows are synthetic (`… Exception: Failed to get enabled regions: …` for regional checks, `… Failed to get account ID: …` for the IAM and Organizations checks). On the candidate, regional checks read `Request failed: NoCredentialsError: Unable to locate credentials` and the IAM and Organizations checks read the same text from the identity lookup, **all** with the credentials remediation, and no row names `ec2:DescribeRegions`. Every other cell is equal. The unit case `regions`/`NoCredentialsError` holds the same arm offline; the live run confirms the CLI reaches it with no earlier failure (the banner's STS call is already wrapped).
   **2d. Partial credentials, no `--regions`** (added for the rev-5 review's M1): the same `env -i` environment as 2c, plus `AWS_ACCESS_KEY_ID` set to a non-existent value and no secret, run on both trees over the same services. botocore raises `PartialCredentialsError` while constructing a client, before any request is sent, so the run is read-only and reaches no AWS endpoint (`review5/partial_regions_probe.txt`). Expected: the same row count per check, and every row synthetic, on both trees. The regional checks' `ActualValue` goes from `Error running …: Exception: Failed to get enabled regions: Partial credentials found in env, missing: AWS_SECRET_ACCESS_KEY` on the merged tree to `Error running …: PartialCredentialsError: Partial credentials found in env, missing: AWS_SECRET_ACCESS_KEY` on the candidate. The IAM and Organizations checks' rows read `Error running …: PartialCredentialsError: …` on both trees, identical text. `Remediation` and every other cell are equal on both trees. This run is the live form of scope item 2's third case.
3. **No explicit Regions, Region list denied by a policy**: not reachable in the test organization without a template change (every principal holds `ec2:DescribeRegions` after the Phase 1 deploy), so the grant-wording arm of Property 45 (order 3, `regions`) is unit-tested only and reported 🔄 with that reason. The credential arm of the Region lookup is reached by runs 2b (server-side rejection) and 2c (no usable credential).

**What is integration-only.** Partition behaviour (unchanged from Phase 1, offline-derived); the `aws_call_failed` Region change; the real pagination of `ListDelegatedAdministrators` (no principal in the test organization has more than one delegated administrator, `lda-counts.txt`).

## Migration and Rollout

Ordered so each step leaves the suite green.

1. **Client (23.1).** Three methods and three `ClientAdapter` rows. Count 111.
2. **Provider (23.2).** `_cached`, the ten accessors, `OWNED_OPERATIONS`, eleven `PROVIDER_ADAPTERS` rows, Properties 37–40. Nothing calls the new accessors yet; no row can move.
3. **Delegators and retirement (24.1, 24.2).** Every base accessor in the call-site table delegates; the fifteen client methods, every `org_client` binding, `SecurityHubCheck`'s raw call and constants, `OrganizationsCheck._org_client` and `get_org_client` go. Accessor tables reclassified; fifteen `ClientAdapter` rows removed. Count 96. The service tables still carry their Organizations entries here, so no verdict moves in this step and an A/B of this intermediate state, if run, shows only `Fetching`/`aws_call_failed` count changes.
4. **Guards (24.3).** Properties 41 and 42.
5. **ScanContext and the per-check precondition (25.1).** The three accessors, `_call_failed`, `ScanPreconditionError`, `SecurityCheck._identity` and the `regions` raise, `_precondition_error(check_class, exc, fallback_account, scan_region)` with `_CREDENTIAL_ERROR_CODES` (the two observed server codes united with the six derived botocore class names) and the code-first remediation order, the Account API handler narrowed to `AWS_EXCEPTIONS`, the EC2 client in `get_enabled_regions` acquired before its `try` like STS and Account, and the one new `except` clause in `run_checks` with its nested secondary-failure guard, the pre-loop block's `is_error` branch, `sra_securityincidentresponse_05`. Properties 45 and 46.
6. **Classification (26.1).** The provider table, the five owned-operation service-table removals (and nothing else from any service table), the rewritten `IAMCheck` and `ConfigCheck` class comments, Property 43 with its 46-row golden, the ledger module and the `_PROVIDER_PAIRS_WITHOUT_FAIL_ARM` exemption (Property 44). The only step that changes a verdict, and only outside an organization.
7. **Remediation pin (Open Question 5).** No code change; Property 47's golden test lands with step 6 so the A/B measures the zero-`Remediation`-change expectation in the same run.
8. **IAM artefacts (27.1).** Regenerate and diff: expected **no** new action (`ListDelegatedAdministrators`, `ListPoliciesForTarget`, `DescribePolicy` and the rest are already granted, `1-sraverify-member-roles.yaml:212–221`) and no removal; attribution moves to `core/organizations_client.py`. Template expected unchanged.
9. **Live A/B, report (28), steering and close (29).** The report carries the ledger, the zero-moved result and the Requirement 13.12 flag for the owner. Steering records the eleven accessors, the client-method count **96**, `org_client` in a service client as a named anti-pattern, the widened namespace sentence, the error-result model and the per-check precondition, the amended `structure.md` SIR oddity sentence (`get_delegated_administrators()` no longer pins `self.regions[0]`; `get_role()` and SIR-01's row label still do), the corrected empty-table sentence in `creating_checks_best_practices.md` (review N4), and the measured test counts; every deferral not closed here is carried forward.

   The empty-table sentence today reads "`auditmanager`, `config`, `cloudtrail`, `ec2` and `iam` all declare `{}`", followed by "`auditmanager`'s is the instructive one: the 'Please complete AWS Audit Manager setup' condition … was **omitted** rather than declared on inference". It is stale for four of the five, one more than the review counted: `auditmanager` declares `GetOrganizationAdminAccount` / `AccessDeniedException` with the message needle `Please complete AWS Audit Manager setup` (`services/auditmanager/base.py:40–43`), so the "omitted" sentence is stale too; `config` declares `DescribeOrganization` and `GetBucketPolicy`; `cloudtrail` declares `GetEventSelectors` and `GetTrailStatus`; `iam` declares three entries. After Phase 2 only `ec2` declares `{}`; `auditmanager` and `cloudtrail` are unchanged, `config` keeps `GetBucketPolicy`, and `iam` keeps `ListOrganizationsFeatures` and `GetAccountPasswordPolicy`. Task 29.1 rewrites both sentences to say that, and to name the 46-row golden (Property 43) as what holds the non-owned entries. A documentation correction; it moves no row.

   Task 29.1 also adds one line to `structure.md`'s "Adding a new check" step 4a and to `creating_checks_best_practices.md`'s "Declaring a `NOT_CONFIGURED_ERRORS` entry": adding, removing or editing any service-table entry for an operation the provider does not own fails `test_discriminator_property.py`'s golden until `_NON_OWNED_NOT_CONFIGURED_ENTRIES` is updated in the same commit, and that is deliberate, because the edit can move a verdict and the golden is what makes it visible in review.

**Version.** `SRAVerify` and `run_checks` keep their signatures. Four public return types widen to `… | ErrorResult` (`ScanContext.get_account_info`, `get_management_account_id`, `get_enabled_regions`, and `SecurityCheck.get_management_accountId`), and `SecurityCheck`'s identity and `regions` properties can raise `ScanPreconditionError` outside `run_checks`; `sra-verify-mcp` calls none of them. A version bump is the owner's choice; if made, run `uv sync --reinstall-package sraverify`.

## Non-Goals carried forward

Nothing here relabels a `Region` cell (`securityincidentresponse`'s `regions[0]`, `sra_firewallmanager_01`), fixes set ordering (`sra_inspector_07`, `sra_securityhub_08`, `sra_macie_07`), paginates `ShieldClient.list_protections`, hoists a per-scan call above a Region loop (every delegator keeps its caller's loop position, and `securityhub_16`'s `regions[0]` client pick simply stops mattering), changes the same-partition STS rule (the first `--regions` value stays the STS and AssumeRole endpoint, a documented accepted limitation), adds a FAIL arm to any check (`SRA-SECURITYHUB-17`, `SRA-IAM-05`, `SRA-SECURITYINCIDENTRESPONSE-05`), addresses the pre-existing Python 3.11 frozen-plus-slots dataclass test failures, or edits `sra-verify-mcp`.

## Open Questions

**Resolved by this design.**

- **Open Question 4 (`design.md`) — the namespace sentence.** Resolved: after task 24.2 the `organizations` namespace is written and read only by the provider; the steering sentence widens from the `all_accounts` slot to the whole namespace (tasks 24.3, 29.1), and Property 42 enforces it. Appended as Requirement 13.8.
- **Open Question 5 (`design.md`) — whose service `_remediation_for` names.** Resolved: **the check's own, unchanged.** Any member may call `DescribeOrganization` and `DescribeEffectivePolicy` (API reference); for the seven admin-only reads, a live probe observed a delegated administrator for an unrelated service calling three of them (`ListAccounts`, `ListRoots`, `ListDelegatedAdministrators`), and the other four rest on the identical API reference sentence. So the existing wording is correct and naming Organizations would be wrong advice. Moves no row. Requirement 13.10 (appended in revision 1) is reworded to require byte-identical output; Property 47 pins it.
- **Open Question 12 (`design.md`) — Requirement 5.2's by-key clause versus `SecurityHubCheck.get_organization()`.** Resolved: `get_organization()` becomes `self.organization.describe()` and its `_ORGANIZATIONS_NAMESPACE` / `_ORGANIZATION_CACHE_KEY` constants are deleted, so the tension disappears and the prohibition widens to the whole namespace with no exemption (Property 42, Requirement 13.8).
- **Open Questions 13 and 14 (`design.md`).** Kept open as stated in "Concurrency and the denied fan-out": coordination deferred while scans are sequential, never-cache-a-failure unchanged, the non-retryable marker a recorded proposal only. Task 23.3 stays unticked.

**Open, for the owner at hand-off (none blocks implementation).**

1. **The reading of Requirement 13.4's "A/B evidence"** for codes the test organization cannot return (Requirement 13.12). The design proceeds under it; if the owner rejects it, task 26 drops the `ListDelegatedAdministrators` and `ListAccounts` entries, their ledger rows become "does not move" assertions, and nothing else changes.
2. **`SecurityHubCheck.get_organization()` could be deleted rather than delegated.** It has no production caller; this design keeps it because task 24.2 names it.

## Responses to the design review

### Revision 5 review (addressed in revision 6)

The revision 5 review (`design-review.md`, `design-review.json`) raised 4 findings: 0 HIGH, 1 MEDIUM, 3 NIT. All four are addressed, and none is backlogged or ignored. No decision changed. The precondition remediation order, the credential set, the ledger, and the Open Question 4, 5 and 12 resolutions are as in revision 5. One previously unspecified detail is now fixed: where the EC2 client is acquired. Fixing it adds one text change to scope item 2. No `Status`, `Region` or row count moves.

- **M1 (MEDIUM): the `PartialCredentialsError` claim was wrong for the Regions lookup, and the EC2 acquisition point was unspecified.** Addressed with the review's recommended option. The `get_enabled_regions()` bullet now acquires the EC2 client before the `try`, as STS and Account are acquired, and shows the code. It also records why acquisition inside a `try / except AWS_EXCEPTIONS` was rejected. The paragraph is rewritten as two cases, both cited to `review5/partial_regions_probe.txt`. Identity is unchanged, text for text. Regions keeps its row, `Status` and every other cell, but its synthetic `ActualValue` goes from `Exception: Failed to get enabled regions: <msg>` to `PartialCredentialsError: <msg>`. That is now scope item 2's third case. The Error Handling identity row reads "today's rows, text for text", and a new row covers the EC2 call and its construction. Property 46 adds construction failures of the STS, Account and EC2 clients to its propagate-unchanged clause. `test_scan_context.py` gains the case the review asked for: EC2 construction raising `PartialCredentialsError` propagates unwrapped, with no error result and no `aws_call_failed` record. It also gains an STS twin. Migration step 5 names the acquisition move. One addition goes beyond the review: task 28 gains read-only negative run 2d (an access key with no secret, no `--regions`, which sends no request). The review noted that runs 2, 2b and 2c could not reach this path, so the text change would otherwise go unobserved live.
- **N1: "a missing profile".** Replaced with "a profile with no credentials". The text now also says that a nonexistent profile raises `ProfileNotFound` at `boto3.Session` construction, before any `ScanContext` exists (`review5/cred_probe.txt`). The remediation's "a wrong --profile" stays.
- **N2: the stale revision 4 note on task 25.1.** The revision 5 note in `tasks.md` now ends with "supersedes rev 4's two-code set; the set-equality test is the derived form". A revision 6 note on 25.1 records the EC2 acquisition move and the new unit cases, and a revision 6 note on 28.1 records run 2d.
- **N3: the Account client construction claim was unsourced.** It now cites `review5/account_ctor_probe.txt`: botocore 1.43.105, offline, all four clients constructed in seven partitions' Regions. The text adds that once STS has succeeded, credentials are already resolved on the session.

### Revision 4 review (addressed in revision 5)

The revision 4 review (`design-review.md`, `design-review.json`) raised 5 findings: 0 HIGH, 1 MEDIUM, 4 NIT. All five are addressed; none is backlogged or ignored. No decision changed: the precondition remediation is still chosen code first, and the rows this design moves are still exactly the three scope items. Open Questions 4, 5 and 12 keep their resolutions.

- **M1 (MEDIUM): `_CREDENTIAL_ERROR_CODES` missed the client-side credential failures.** Addressed with the review's full form rather than the minimal one. `_CREDENTIAL_ERROR_CODES` is now `_REJECTED_CREDENTIAL_CODES` (`AuthFailure`, `InvalidClientTokenId`, observed) united with the class names of `_LOCAL_CREDENTIAL_EXCEPTIONS` (`NoCredentialsError`, `PartialCredentialsError`, `CredentialRetrievalError`, `UnauthorizedSSOTokenError`, `TokenRetrievalError`, `SSOTokenLoadError`), derived the way `TRANSPORT_ERROR_CODES` is. The evidence for the derived half is the deterministic `aws_error` mapping, the classes' raise sites in the pinned botocore (`cred-raise-sites.txt`), the absence of subclasses (`cred-subclasses.txt`), and the observed `NoCredentialsError` for both lookups (`review4/nocreds-probe.txt`); nothing is inferred. Two things found while checking it are recorded rather than glossed: `PartialCredentialsError` surfaces at client construction, not at the call (`cred-surface-probe.txt`), so it reaches today's synthetic path rather than a precondition row (revision 6 corrects "which moves nothing": that holds for identity, but the Regions synthetic row's `ActualValue` loses its wrapper; see the revision 5 review's M1 above); and the order-2 wording gains "no credentials found" and "or SSO login", because "valid and unexpired" alone reads oddly when there is no credential (`Confirm the scan has valid, unexpired credentials (no credentials found, an expired session token or SSO login, a wrong --profile, or an invalid access key is the usual cause), then re-run the scan`; it supersedes the revision 3 wording, and it appears only on precondition rows). `test_scan_preconditions.py` gains the `regions`/`NoCredentialsError` case asserting no `ec2:DescribeRegions`, the set-equality test is now "two server codes plus the derived class names" with a `BotoCoreError`-subclass check, and an end-to-end case drives a real `NoCredentialsError` through `aws_error`. Property 45 gains the `BotoCoreError` clause. Task 28 gains negative run 2c (no credential source, `AWS_DEFAULT_REGION` set, no `--regions`; read-only, sends no request).
- **N1: the golden constant's name.** Renamed `_NON_OWNED_NOT_CONFIGURED_ENTRIES`, with the comment "Captured at f517024. A deliberate change to a non-owned NOT_CONFIGURED_ERRORS entry updates this tuple in the same commit." Migration step 9 and the task 29.1 note add one line to `structure.md` step 4a and to the "Declaring a `NOT_CONFIGURED_ERRORS` entry" section.
- **N2: the Account API handler.** Now `except AWS_EXCEPTIONS as e: self._call_failed(e)`, with both client acquisitions before their `try`; a non-AWS exception propagates. Property 46's last clause covers "the STS, Account or EC2 call", and the Error Handling table's non-AWS row names the Account call and construction failures.
- **N3: the Config delegator's argument path.** The call-site cell is now `principals = [service_principal] if service_principal else list(self.CONFIG_SERVICE_PRINCIPALS)`, each through `self.organization.delegated_administrators(p)`, first failure returned unchanged, merge kept, matching `config/base.py:237–295`.
- **N4: the SIR rows.** "The other five SIR rows keep their explicit `error_bearing` (four `True`, one `False`)", with line numbers; task 24.1 rewrites the table comment (note added).

### Revision 3 review (addressed in revision 4)

The revision 3 review (`design-review.md`, `design-review.json`) raised 7 findings: 1 HIGH, 1 MEDIUM, 5 NIT. All seven are addressed; none is backlogged or ignored. One decision changed (M1, the precondition remediation order). The H1 correction removes an unintended verdict move, so the set of rows this design moves is now exactly the one the scope list states.

- **H1 (HIGH): "`IAMCheck`'s table becomes `{}`" would have deleted two non-Organizations entries.** Addressed as proposed. "The provider table after Phase 2" now says that `IAMCheck` loses **only** `ListDelegatedAdministrators`, and that `ListOrganizationsFeatures` / `ServiceAccessNotEnabledException` and `GetAccountPasswordPolicy` / `NoSuchEntity` stay byte-identical. The `IAMCheck` class comment's `DescribeOrganization` paragraph and the `ConfigCheck` class comment are rewritten as specified. Property 43 gains the clause "every service-table entry for an operation outside `OWNED_OPERATIONS` is unchanged from the merged Phase 1". It is held by a 46-row golden of `(base, operation, code, message, evidence digest)` captured from `f517024` (`nonowned-entries.txt`: 51 service-table entries, 5 owned). So a removal like this one now fails offline, before any scan. Migration step 6 says "the five owned-operation service-table removals (and nothing else)".
- **M1 (MEDIUM): an `AuthFailure` from `DescribeRegions` was sent to an IAM grant.** Addressed as proposed, and the decision changed. The remediation is chosen by code first:
  - transport codes get the endpoint wording, per lookup;
  - `_CREDENTIAL_ERROR_CODES` = {`AuthFailure`, `InvalidClientTokenId`} gets the credentials wording for either lookup;
  - only then does `regions` fall to the grant wording.

  The set is closed, its evidence is the observed `review3/ec2-sts-invalid-creds.txt`, and the comment on it states the add-only-on-evidence rule. Property 45 gains the credential clause. `test_scan_preconditions.py` pins an `AuthFailure`/`regions` case, which asserts that `ec2:DescribeRegions` is absent, and also pins the set's exact contents. Task 28 gains negative run 2b (invalid credentials, `AWS_DEFAULT_REGION` set, no `--regions`). The run is read-only and reaches the Region lookup's credential arm live. Only the policy-denial arm stays 🔄. The residual is stated: an unobserved EC2 credential code would still get the grant wording until it is added with evidence.
- **N1: the scope list left out the conditional pagination effect.** Added as item 3. It is mandated by task 23.1, and there are none in the test organization (`lda-counts.txt`, `lda-maxresults.txt`).
- **N2: the `_OPERATION_OF_ACCESSOR` mapping was dead.** Chose option (a). The delegators are `derived` with the default `error_bearing`, so they are unpatched and run for real against `stub_organization`, which `_PROVIDER_OPERATIONS` already resolves. The mapping is dropped, and `_OPERATION_OF_ACCESSOR` stays the derived join it is today. The `config` and `securityincidentresponse` `get_delegated_administrators` rows drop their explicit `error_bearing=True` (`test_accessor_cache_property.py:281, :843`). This covers more, because `ConfigCheck`'s first-failure-wins loop is exercised.
- **N3: stale date.** The pagination paragraph now cites `lda-counts.txt` as 2026-10-03T15:52:41Z.
- **N4: the stale steering sentence.** Added to Migration step 9, with a matching note on task 29.1. The check found it stale for **four** of the five services, not three. `auditmanager` also declares an entry (`GetOrganizationAdminAccount` / `AccessDeniedException`, with a message needle, `auditmanager/base.py:40–43`), so the follow-on "omitted rather than declared" sentence is corrected too. This is a doc correction and moves no row.
- **N5: `exc_info` on the pre-loop block.** The snippet comment and the `logger.error` bullet now say the block **gains** `exc_info=True`, because `scanner.py:404` has none today. It is a stderr-only change. Revision 1's F2 response below, which said "keeps … `exc_info=True`", is superseded by this wording.

### Revision 2 review (addressed in revision 3)

The revision 2 review (`design-review.md`, `design-review.json`) raised 9 findings: 0 HIGH, 2 MEDIUM, 7 NIT. Eight are addressed. N7 is addressed as far as the evidence in hand allows and its general form is backlogged; the reason is given below. No decision changed, and nothing new moves a row.

- **M1 (MEDIUM): the precondition branch had no secondary-failure guard, and `_precondition_error`'s signature had no Region.** Addressed as proposed. `_precondition_error(check_class, exc, fallback_account, scan_region)` now takes the scan Region as a fourth parameter, and the caller passes `ctx.scan_region`. The `append` is wrapped in its own `try / except Exception` with `logger.error(..., exc_info=True)`, the same shape `scanner.py:487` uses for the synthetic row. Property 45 gains the clause "a failure while building a precondition row is logged at `error` with `exc_info`, costs that check its row, and the loop continues". The Error Handling table gains the row, and the `logger.error` bullet records the one exception, which the synthetic path already has.
- **M2 (MEDIUM): the identity remediation pointed at a permission that cannot be denied.** Addressed with the review's wording: `Confirm the scan's credentials are valid and unexpired (an expired session token, a wrong --profile, or an invalid access key is the usual cause), then re-run the scan`. The STS API reference sentence is quoted beside the table, with `review2/gci.txt` as its source. Property 45 pins "the precondition-table remediation", so it pins the corrected text.
- **N1: the "debug log reads the same" claim.** Corrected. The keys are kept byte for byte and the log text changes to `Organizations: Fetching <key>`. The task 28 gate counts `Fetching` per key, and translates the six merged-tree phrases through a fixed map that this document now contains.
- **N2: Property 41's receiver could not be decided by AST.** Changed to "any receiver in `core/organization.py`", held by that module's no-`get_paginator(`, no-`.client.` rule, the Phase 1 two-set shape.
- **N3: the companion test wording.** "Tests that change" and the exemption-set comment now use Property 44's qualifier, "reached first by the classification harness", and name SIR-05 as the row that qualifier excludes.
- **N4: the IAM details.**
  - `_cached_call` serves five calls today and three after Phase 2.
  - `IAM_SERVICE_PRINCIPAL` moves from `iam/client.py:24` to `iam/base.py`.
  - Task 24.2 rewrites the stale `iam/base.py:224` docstring. A note on task 24.2 records it.
- **N5: the OQ5 generalisation was wider than the probe.** The OQ5 section, the Open Questions bullet and Requirement 13.10 now say the probe observed three of the seven admin-only reads, and that the other four rest on the identical API reference sentence. `lda-counts.txt` was regenerated as one sequential run (2026-10-03T15:52:41Z), with the same values as before.
- **N6: "adds no import edge".** Changed to "adds no import cycle and no new module load", naming the new direct import.
- **N7: pagination evidence covered the test organization only.** Partly addressed. The claim is now stated conditionally: no row moves wherever each queried principal has at most 20 delegated administrators, and beyond 20 the change completes a truncated answer, which the A/B would list. The per-service caps the review suggested citing were not fetched for this revision. Sourcing them is **backlogged** to the task 28 report, where the pagination behaviour is integration-only anyway. The design does not depend on the caps, because the conditional statement is true either way.

### Revision 1 review (addressed in revision 2)

Revision 1's review (finding list in `design-review.rev1.json`; its markdown was replaced by the revision 2 review, whose closing table records each finding's status) raised 14 findings. All are addressed; none is backlogged or ignored.

- **F1 (HIGH) — the up-front Regions precondition moved genuine verdicts.** Addressed as the review proposed. The precondition is lazy and per check: `SecurityCheck`'s identity properties, `_finding` and `regions` raise `ScanPreconditionError`, and one new `except` ahead of `except Exception` in the existing per-check guard emits one `_precondition_error` row. No `get_enabled_regions()` up front, so the 18 IAM and Organizations checks keep their verdicts and no scan gains a `DescribeRegions` call; zero-row checks stay zero-row. Requirement 13.9 reworded ("per selected check that reads the failed fact", plus "a check that never reads it yields exactly its rows" and "no up-front lookup the merged tree does not issue"); Property 45 rewritten.
- **F2 (MEDIUM) — unguarded pre-loop identity read.** Addressed: the pre-loop block keeps `except Exception` with `logger.error(..., exc_info=True)` and `("", "")`, gains an `is_error` branch at `debug`, and the Account API stays best-effort for both an AWS failure and a missing `AccountName` (`.get("AccountName", "")`). Both outcomes are in the Error Handling table.
- **F3 (MEDIUM) — Property 41 flagged `fms`'s `get_paginator('list_policies')`.** Addressed: the spelling set is `OWNED_OPERATIONS` in snake_case; `ListPolicies` is covered by "no module outside the client binds `get_client('organizations', ...)`"; the property names `services/firewallmanager/client.py:61` as the excluded case. The receiver rule also exempts `self.organization.<accessor>(`, since `describe_policy` is both a provider accessor and an owned operation's snake_case name.
- **F4 (MEDIUM) — the Open Question 5 rationale was wrong for two operations.** Addressed more strongly than proposed. Fetching all nine caller-restriction sentences and probing the test organization showed the premise is wrong for all nine: the admin-only seven accept any service's delegated administrator. The decision is reversed: `_remediation_for` is unchanged and Property 47 pins it byte-identical. `ADMIN_ONLY_OPERATIONS` is therefore not needed and not added; `SERVICE` is dropped.
- **F5 (MEDIUM) — eleven keys versus ten.** Addressed in the Cache keys paragraph, the Data Models table note and Property 39: ten caching accessors write ten distinct keys, and `management_account_id()` writes none of its own.
- **F6 (MEDIUM) — Requirements 3.3 and 13.4 ask for A/B evidence the test org cannot produce.** Addressed by appending Requirement 13.12 (at the end of Requirement 13, so no criterion is renumbered) rather than editing approved 3.3 and 13.4 mid-text: offline ledger plus API-reference citation plus a zero-moved live A/B, applied to both entries, and flagged in the test report for the owner. Settled in the design, so it does not block task 26.
- **F7 (MEDIUM) — Property 14a would fail for `SRA-SECURITYHUB-17` and `SRA-IAM-05`.** Addressed: `_PROVIDER_PAIRS_WITHOUT_FAIL_ARM`, asserting `error()` and never `failed()`, with a companion test tying it to the ledger (Property 44). Adding a FAIL arm is listed as a non-goal.
- **N1** — "93" corrected to 86 (101 − 15), total 96.
- **N2** — qualified as "of the eight clients that lose methods".
- **N3** — `_precondition_rows` no longer exists; `_precondition_error(check_class, exc, fallback_account)` is given its full signature (revision 3 adds a fourth parameter, `scan_region`, under M1).
- **N4** — task 29.1 amends the `structure.md` SIR oddity sentence (Migration step 9, and a note on task 29.1). No Region cell changes.
- **N5** — sourced: botocore's `MaxResults` max is 20 (`lda-maxresults.txt`), and every principal the package queries has zero or one delegated administrator in the test organization (`lda-counts.txt`).
- **N6** — the Overview now says "except `sra_securityincidentresponse_05`".
- **N7** — Property 38 states that `accounts()` keeps its Phase 1 log wording under Property 29.

One further correction found while revising revision 1: its SIR-05 error row set `ResourceId` to the role ARN, which would have added a new join key. Revision 2 uses `resource_id=None`, so the row matches today's synthetic row in every cell but the two text cells.
