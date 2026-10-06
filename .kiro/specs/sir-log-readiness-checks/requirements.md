# Requirements Document

## Introduction

The AWS Security Incident Response (SIR) user guide publishes a configuration-validation procedure (<https://docs.aws.amazon.com/security-ir/latest/userguide/config-validation.md>) that a customer walks through after onboarding: confirm the membership and its incident response team, confirm the service linked roles, confirm the proactive-response EventBridge rules and GuardDuty suppression filters that triage creates, and confirm that the log sources responders will need during an investigation — CloudTrail management events, VPC Flow Logs and Route 53 Resolver DNS query logs — are actually being collected. SRA Verify today has five SIR checks (`SRA-SECURITYINCIDENTRESPONSE-01` to `-05`) covering the delegated administrator, the membership state, organization coverage, per-account association and the triage service linked role. Nothing in the catalog checks the rest of the procedure, and nothing checks the log sources at all.

This feature adds five checks that turn the remaining automatable steps of that procedure into SRA Verify controls. The test-domain and test-case steps of the procedure (Steps 3 and 4) are excluded at the user's direction: they create an alert or a case, and SRA Verify is read-only.

Every candidate was first probed against the test organization, read-only, per `.kiro/steering/testing_checks.md`. The probe findings (`.agents/tasks/sir-log-readiness-checks/probe-findings.md`, raw responses in `probes/` beside it) are authoritative for this document. Of eight candidates, five are kept, two are dropped because the probe showed their FAIL arm is unreachable or not a configuration fact, and one is out of scope because its discriminator could not be proven without a mutation. See Out of Scope.

The five kept checks, with their final IDs (the SIR checks are numbered contiguously after the existing `-05` because the dropped candidates would otherwise leave gaps):

| Check ID                          | Control                                                        | Account type | Row grain                            |
| --------------------------------- | -------------------------------------------------------------- | ------------ | ------------------------------------ |
| `SRA-SECURITYINCIDENTRESPONSE-06` | `AWSServiceRoleForSecurityIncidentResponse` exists             | audit        | one, `global`                        |
| `SRA-SECURITYINCIDENTRESPONSE-07` | SIR proactive-response EventBridge rules present and `ENABLED` | application  | one per Region                       |
| `SRA-CLOUDTRAIL-15`               | Organization trail logs all management events                  | management   | one per organization trail, `global` |
| `SRA-EC2-02`                      | VPC Flow Logs enabled for every VPC                            | application  | one per owned VPC per Region         |
| `SRA-ROUTE53RESOLVER-01`          | Resolver query logging associated with every VPC               | application  | one per owned VPC per Region         |

`SRA-ROUTE53RESOLVER-01` introduces a nineteenth service package, `route53resolver`. The catalog grows from 182 checks across 18 services to 187 across 19.

Baseline observed in the test organization (13 ACTIVE accounts, 17 enabled Regions, SIR membership `Active` in home Region `us-west-2`, `coverEntireOrganization: true`): the SIR service linked role is present in the audit (delegated administrator) account; the two SIR-managed EventBridge rules are present and `ENABLED` in every Region of every covered account except the management account, which has none; the Control Tower organization trail logs all management events; and no VPC in any probed account has a flow log or a Resolver query logging association. So the expected baselines are PASS, PASS-except-management, PASS, FAIL and FAIL respectively, and each check must also be seen producing the opposite verdict during live validation.

Assumptions made where the probe left a decision open, each stated as a criterion below so the design review can overturn it:

- `SRA-SECURITYINCIDENTRESPONSE-07` does not gate on whether the account is SIR-covered, because the member role in an application account cannot answer `BatchGetMemberAccountDetails` and the SRA expectation is whole-organization coverage.
- `SRA-CLOUDTRAIL-15` judges each organization trail separately, one row per trail, matching `SRA-CLOUDTRAIL-14`; a non-empty `ExcludeManagementEventSources` is a FAIL; no organization trail at all is one FAIL row.
- `SRA-EC2-02` and `SRA-ROUTE53RESOLVER-01` include default VPCs, evaluate only VPCs the scanned account owns, and emit one PASS row for a Region with no owned VPC so that every scanned Region has a row.
- `SRA-EC2-02` accepts any `ACTIVE` VPC-level flow log regardless of `TrafficType`, and reports the type; subnet- and ENI-level flow logs do not count.

## Glossary

- **SRA Verify**: The read-only security assessment tool in this repository.
- **SIR**: AWS Security Incident Response.
- **Config_Validation_Doc**: The SIR user guide page <https://docs.aws.amazon.com/security-ir/latest/userguide/config-validation.md>.
- **Probe_Findings**: `.agents/tasks/sir-log-readiness-checks/probe-findings.md` and its `probes/` directory, the read-only Phase 1 probe of every candidate against the test organization.
- **Delegated_Administrator**: The account returned by Organizations `ListDelegatedAdministrators` for service principal `security-ir.amazonaws.com`. In the SRA layout this is the audit account.
- **SIR_SLR**: The IAM service linked role `AWSServiceRoleForSecurityIncidentResponse`, path `/aws-service-role/security-ir.amazonaws.com/`.
- **SIR_Managed_Rule**: An EventBridge rule returned by `events:ListRules` on the default event bus whose `ManagedBy` field equals `triage.security-ir.amazonaws.com`. Observed names are `SIRGuardDutyRule` and `SIRSecurityHubRule`.
- **GuardDuty_Rule**: A SIR_Managed_Rule whose `EventPattern`, parsed as JSON, has a `source` that includes `aws.guardduty`.
- **SecurityHub_Rule**: A SIR_Managed_Rule whose `EventPattern`, parsed as JSON, has a `source` that includes `aws.securityhub`.
- **Organization_Trail**: A trail returned by `cloudtrail:DescribeTrails` with `IsOrganizationTrail: true`, as filtered today by `CloudTrailCheck.get_organization_trails`.
- **Management_Event_Coverage**: The condition that a trail's `GetEventSelectors` response records every management event, read and write, from every event source. Defined precisely in Requirement 3.
- **Owned_VPC**: A VPC returned by `ec2:DescribeVpcs` in a Region whose `OwnerId` equals the scanned account ID. VPCs shared into the account through AWS RAM are not Owned_VPCs.
- **Active_Flow_Log**: A flow log returned by `ec2:DescribeFlowLogs` whose `ResourceId` equals a VPC ID and whose `FlowLogStatus` is `ACTIVE`.
- **Active_Query_Log_Association**: An entry returned by `route53resolver:ListResolverQueryLogConfigAssociations` whose `ResourceId` equals a VPC ID and whose `Status` is `ACTIVE`.
- **Error_Result**: The `{"Error": {"Code", "Message", "Operation"}}` value defined in `core/aws_errors.py`, returned by every client method on failure.
- **Not_Configured_Table**: A service base class's `NOT_CONFIGURED_ERRORS`, read through `self.is_not_configured(error)`; a declared `(Operation, Code)` pair is a FAIL and every undeclared pair is an ERROR.
- **Error_Row**: An ERROR finding whose `ActualValue` is `f"{Operation} failed: {Code}: {Message}"` and whose remediation is `self._remediation_for(error)`.
- **Availability_Lookup**: `core/availability.py::service_available_in_region`, the offline, cached regional-availability test.
- **Live_Validation**: The procedure in `.kiro/steering/testing_checks.md`: probe, read-only negative runs, snapshot, the five phases per check, restoration verification, IAM simulation and a CodeBuild run.

## Out of Scope

1. **Incident response team has at least two members (proposed `SIR-06`). Dropped.** The FAIL arm is unreachable. The `IncidentResponseTeam` shape is `min: 2, max: 10` in the botocore model and the API reference, and the probe sent `UpdateMembership` with one member (client-side validation disabled) and with two members sharing one email: AWS rejected both with `ValidationException` and the team read back unchanged. A check that can only PASS is noise, and a non-`Active` membership is already `SRA-SECURITYINCIDENTRESPONSE-02`.
2. **Responders' communication preferences enabled (proposed `SIR-07`). Out of scope until a mutation probe resolves it.** A per-member field exists (`IncidentResponder.communicationPreferences`, 16 `CommunicationType` values, `Required: No`), but on the raw wire body neither responder in the test membership carries it at all. The Config_Validation_Doc says every option is enabled by default and asks the reader to verify they "haven't been cleared", but no API page says what a cleared responder looks like, so an absent field cannot be told apart from a cleared one. A check built on that reading would either FAIL every default membership or never fire. It can be reconsidered as a separate change once a mutation probe (set one responder to an explicit subset, then `[]`, read back each, restore) shows how a cleared list round-trips.
3. **`SIRTriage-*` GuardDuty suppression filters present (proposed `SIR-10`). Dropped.** A detector exists in all 68 probed account-Region pairs and `ListFilters` returns `[]` in all 68, including the Delegated_Administrator, in a healthy, fully covered, triage-enabled membership. The Config_Validation_Doc describes these filters as created over time for finding types confirmed as expected activity, so their absence reflects finding history rather than configuration, and a FAIL would be a false finding in exactly the healthy case observed. `guardduty:ListFilters` is therefore not added to the member role.
4. **Creating a test domain, a test alert or a test case** (Config_Validation_Doc Steps 3 and 4). Excluded by the user, and a mutation in any case.
5. **The management-account Triage SLR gap.** The probe found the management account `Associated` in the membership but holding no `AWSServiceRoleForSecurityIncidentResponse_Triage`, which `SRA-SECURITYINCIDENTRESPONSE-05` should already report. Whether it does is not investigated here; no existing check is changed by this feature.
6. **Gating `SRA-SECURITYINCIDENTRESPONSE-07` on SIR coverage of the scanned account.** It would need a cross-account `BatchGetMemberAccountDetails` the application-account member role cannot answer. Accepted cost: an account deliberately excluded from SIR coverage reports a FAIL; under the SRA expectation of whole-organization coverage that is the correct finding.
7. **VPCs shared into the account through AWS RAM.** They are evaluated in the owning account, which is where their flow logs and query log associations live. Accepted cost: a VPC owned by an account outside the scan is never evaluated.
8. **Subnet- and ENI-level flow logs, flow log destinations, log format and retention.** `SRA-EC2-02` asks only whether every VPC has an `ACTIVE` VPC-level flow log. Whether the destination is the Log Archive account is a separate control.
9. **Query logging configuration destination and ownership.** `SRA-ROUTE53RESOLVER-01` requires an `ACTIVE` association on each Owned_VPC and does not require the query logging configuration to be owned by the scanned account, because a configuration shared through RAM is a legitimate SRA pattern (centralized logging). Not observed live: no shared configuration exists in the test organization.
10. **Changing pagination, Region labelling or any verdict of an existing check**, including the known deferrals listed in `structure.md`. No existing check's rows may move.
11. **Mutating the Control Tower organization trail** `aws-controltower-BaselineCloudTrail` during Live_Validation. Its selectors are a Control Tower baseline resource. The live FAIL arm of `SRA-CLOUDTRAIL-15` can be reached only with a separate, temporary organization trail, which is created only after explicit user sign-off (Requirement 8 criterion 2); without it that arm is 🔄 and is covered by unit tests.

## Requirements

### Requirement 1: SIR service linked role exists in the audit account

**User Story:** As a security administrator, I want SRA Verify to confirm that the SIR service linked role exists in the delegated administrator account, so that I know the service can act on the organization's behalf before an incident rather than discovering a missing role during one.

**Check Title:** Security Incident Response service linked role exists (SRA-SECURITYINCIDENTRESPONSE-06)

#### Acceptance Criteria

1. THE SRA Verify package SHALL register a check with ID `SRA-SECURITYINCIDENTRESPONSE-06` in `services/securityincidentresponse/checks/sra_securityincidentresponse_06.py`, with account type `audit`, severity `MEDIUM`, service `SecurityIncidentResponse` (the display name the existing five SIR checks use), and resource type `AWS::IAM::Role`.
2. WHEN `SRA-SECURITYINCIDENTRESPONSE-06` executes, THE check SHALL call `iam:GetRole` for role name `AWSServiceRoleForSecurityIncidentResponse` through the existing `SecurityIncidentResponseCheck.get_role` accessor, and SHALL add no new client method and no new IAM action.
3. THE check SHALL produce exactly one finding per execution, with `Region` equal to `global`, because IAM is a global service and the role is an account-wide fact.
4. WHEN `GetRole` succeeds, THE check SHALL produce a PASS finding whose `ResourceId` is the role ARN returned in `Role.Arn` and whose `ActualValue` states that the role exists.
5. IF `GetRole` returns an Error_Result with Operation `GetRole` and Code `NoSuchEntity`, THEN THE check SHALL produce a FAIL finding whose `ResourceId` is `arn:aws:iam::<account_id>:role/aws-service-role/security-ir.amazonaws.com/AWSServiceRoleForSecurityIncidentResponse` and whose `ActualValue` states that the role does not exist. This classification SHALL come from the existing `NoSuchEntity` entry in `SecurityIncidentResponseCheck.NOT_CONFIGURED_ERRORS`, whose evidence SHALL be extended to cite the Probe_Findings observation (`NoSuchEntity`: `The role with name AWSServiceRoleForSecurityIncidentResponse cannot be found.` in three non-delegated-administrator accounts).
6. IF `GetRole` returns any other Error_Result, including `AccessDenied` and a transport failure, THEN THE check SHALL produce one Error_Row and no PASS or FAIL finding.
7. WHEN the check produces a FAIL finding, THE remediation SHALL name the concrete action to create the role, `aws iam create-service-linked-role --aws-service-name security-ir.amazonaws.com`, and that command SHALL be run during Live_Validation Phase 4 to prove it is accepted.
8. THE check SHALL NOT require `--audit-account`, because it evaluates the account it is run in; the comparison of the Delegated_Administrator against the audit account remains `SRA-SECURITYINCIDENTRESPONSE-01`'s.

### Requirement 2: SIR proactive-response EventBridge rules are present and enabled

**User Story:** As a security administrator, I want SRA Verify to confirm that the EventBridge rules SIR triage uses to receive GuardDuty and Security Hub findings exist and are enabled in every Region of every account, so that proactive response is not silently blind in an account or Region.

**Check Title:** Security Incident Response proactive response EventBridge rules are enabled (SRA-SECURITYINCIDENTRESPONSE-07)

#### Acceptance Criteria

1. THE SRA Verify package SHALL register a check with ID `SRA-SECURITYINCIDENTRESPONSE-07` in `services/securityincidentresponse/checks/sra_securityincidentresponse_07.py`, with account type `application`, severity `MEDIUM`, service `SecurityIncidentResponse`, and resource type `AWS::Events::Rule`.
2. WHEN the check executes, THE check SHALL, for each scanned Region, list every rule on the default event bus with `events:ListRules`, reading every page, through a cached accessor on `SecurityIncidentResponseCheck` that follows the never-cache-a-failure rule.
3. THE check SHALL identify SIR_Managed_Rules by `ManagedBy == "triage.security-ir.amazonaws.com"`, and SHALL NOT identify them by rule name, because a customer rule named `SIR…` would otherwise match and a renamed managed rule would otherwise be missed (Probe_Findings §4).
4. THE check SHALL classify a SIR_Managed_Rule as a GuardDuty_Rule or a SecurityHub_Rule by parsing its `EventPattern` as JSON and reading `source`; a SIR_Managed_Rule whose `EventPattern` is absent or is not valid JSON SHALL count as neither, and the check SHALL NOT raise on it.
5. WHEN, in a Region, at least one GuardDuty_Rule and at least one SecurityHub_Rule exist and every such rule has `State` equal to `ENABLED`, THE check SHALL produce one PASS finding for that Region whose `ActualValue` names the matched rules.
6. IF, in a Region, no GuardDuty_Rule exists, or no SecurityHub_Rule exists, THEN THE check SHALL produce one FAIL finding for that Region whose `ActualValue` names which of the two is missing. This is the observed baseline of the management account in all 17 Regions.
7. IF, in a Region, a GuardDuty_Rule or SecurityHub_Rule exists with a `State` other than `ENABLED`, THEN THE check SHALL produce one FAIL finding for that Region whose `ActualValue` names each such rule and its state.
8. IF `ListRules` returns an Error_Result in a Region, THEN THE check SHALL produce one Error_Row for that Region and SHALL continue to the next Region. The `events` Not_Configured_Table entries SHALL be empty for `ListRules`: the only non-permission code observed, `ResourceNotFoundException` for a nonexistent event bus, cannot arise on the default bus and SHALL NOT be declared.
9. THE check SHALL NOT call the Availability_Lookup: `events` has an endpoint in every Region of every partition botocore knows (34/34 `aws`, 2/2 `aws-us-gov`, 2/2 `aws-cn`, botocore 1.43.105), so the lookup could never answer False, and `test_availability_property.py` rejects full-coverage services from its candidate set (`_REJECTED_SERVICE_IDS`).
10. THE `ResourceId` of every row SHALL identify the account and Region, not a rule, so that a Region's row keeps the same `(Region, ResourceId)` key when its status changes between PASS, FAIL and ERROR.
11. WHEN the check produces a FAIL finding, THE remediation SHALL direct the operator to confirm the account is covered by the SIR membership with proactive response (triage) enabled, and, for the management account, to create the triage service linked role manually, as the Config_Validation_Doc's troubleshooting guidance describes.

### Requirement 3: Organization trail logs all management events

**User Story:** As an incident responder, I want SRA Verify to confirm that the organization trail records every management event, read and write, from every source, so that the control-plane history I need during an investigation exists in every account.

**Check Title:** Organization trail logs all management events (SRA-CLOUDTRAIL-15)

#### Acceptance Criteria

1. THE SRA Verify package SHALL register a check with ID `SRA-CLOUDTRAIL-15` in `services/cloudtrail/checks/sra_cloudtrail_15.py`, with account type `management`, severity `HIGH`, service `CloudTrail`, and resource type `AWS::CloudTrail::Trail`.
2. WHEN the check executes, THE check SHALL obtain Organization_Trails through the existing `CloudTrailCheck.get_organization_trails` accessor and each trail's selectors through the existing `get_event_selectors(region, trail_arn)` accessor, called with the trail's `HomeRegion` and its full `TrailARN`, and SHALL add no new client method and no new IAM action.
3. THE check SHALL produce one finding per Organization_Trail with `Region` equal to `global` and `ResourceId` equal to the trail ARN, matching `SRA-CLOUDTRAIL-14`.
4. WHEN a trail's `GetEventSelectors` response carries basic `EventSelectors`, THE check SHALL treat the trail as having Management_Event_Coverage only if at least one selector has `IncludeManagementEvents` equal to `true`, `ReadWriteType` equal to `All`, and an absent or empty `ExcludeManagementEventSources`.
5. WHEN a trail's `GetEventSelectors` response carries `AdvancedEventSelectors`, THE check SHALL treat the trail as having Management_Event_Coverage only if at least one advanced selector has a field selector `eventCategory` with `Equals` containing `Management`, has no `readOnly` field selector, and has no `eventSource` field selector that excludes or restricts event sources.
6. WHEN a trail has Management_Event_Coverage, THE check SHALL produce a PASS finding for that trail. This is the observed baseline: `aws-controltower-BaselineCloudTrail` with `ReadWriteType: All`, `IncludeManagementEvents: true` and an empty `ExcludeManagementEventSources`.
7. IF a trail does not have Management_Event_Coverage, THEN THE check SHALL produce a FAIL finding for that trail whose `ActualValue` states the specific reason: management events not included, only read or only write events recorded, or the event sources excluded, naming each excluded source in a deterministic order.
8. IF `get_organization_trails` succeeds with no Organization_Trail, THEN THE check SHALL produce exactly one FAIL finding with `Region` `global` and `ResourceId` `organization/<account_id>`, stating that no organization trail exists.
9. IF `get_organization_trails` returns an Error_Result, THEN THE check SHALL classify it through the CloudTrail Not_Configured_Table, producing one FAIL finding (with `ResourceId` `organization/<account_id>`) when declared and one Error_Row otherwise, and SHALL produce no other row.
10. IF `GetEventSelectors` returns an Error_Result for a trail, THEN THE check SHALL produce one finding for that trail and SHALL continue to the next trail: a FAIL stating the trail does not exist for the already-declared `GetEventSelectors`/`TrailNotFoundException` pair (observed: `Unknown trail: … for the user: …`), and an Error_Row for every other code.
11. WHEN the check produces a FAIL finding, THE remediation SHALL name the `aws cloudtrail put-event-selectors` (or `--advanced-event-selectors`) command that restores full management-event logging and SHALL warn that the call replaces the trail's existing selectors, so data-event selectors must be included in the same call.

### Requirement 4: VPC Flow Logs are enabled for every VPC

**User Story:** As an incident responder, I want SRA Verify to confirm that every VPC in every account and Region has an active flow log, so that network evidence exists for any workload I may need to investigate.

**Check Title:** VPC Flow Logs are enabled for every VPC (SRA-EC2-02)

#### Acceptance Criteria

1. THE SRA Verify package SHALL register a check with ID `SRA-EC2-02` in `services/ec2/checks/sra_ec2_02.py`, with account type `application`, severity `MEDIUM`, service `EC2`, and resource type `AWS::EC2::VPC`.
2. THE `EC2Client` SHALL gain a method for `ec2:DescribeVpcs` and a method for `ec2:DescribeFlowLogs`, each reading every page through its botocore paginator with the whole loop inside the `try`, returning `{"Vpcs": [...]}` and `{"FlowLogs": [...]}` respectively on success and the Error_Result on failure; and `EC2Check` SHALL gain one cached accessor per method, keyed by Region, that never caches a failure and returns `no_client_result` when no client exists for the Region.
3. THE check SHALL list all flow logs in a Region in one call sequence and match them to VPCs by `ResourceId`, and SHALL NOT filter `DescribeFlowLogs` by VPC ID, because a filter on a nonexistent resource ID returns an empty list rather than an error (Probe_Findings §7).
4. THE check SHALL evaluate every Owned_VPC in the Region, including the default VPC, and SHALL skip any VPC whose `OwnerId` differs from the scanned account ID.
5. WHEN an Owned_VPC has at least one Active_Flow_Log, THE check SHALL produce a PASS finding for that VPC whose `ActualValue` names the flow log ID and its `TrafficType`.
6. IF an Owned_VPC has no Active_Flow_Log, THEN THE check SHALL produce a FAIL finding for that VPC whose `ActualValue` states that no active VPC-level flow log exists and notes when the VPC is the default VPC. A flow log on a subnet or network interface of the VPC SHALL NOT satisfy the control. This is the observed baseline in every probed Region that has a VPC.
7. WHEN `DescribeVpcs` succeeds with no Owned_VPC in a Region, THE check SHALL produce exactly one PASS finding for that Region stating that the Region has no VPC, and SHALL NOT call `DescribeFlowLogs` there.
8. IF `DescribeVpcs` returns an Error_Result in a Region, THEN THE check SHALL produce one Error_Row for that Region and continue to the next Region.
9. IF `DescribeFlowLogs` returns an Error_Result in a Region after `DescribeVpcs` succeeded, THEN THE check SHALL produce one Error_Row per Owned_VPC in that Region, not one for the Region, so that a failed listing does not drop VPCs from the report.
10. THE `EC2Check.NOT_CONFIGURED_ERRORS` table SHALL remain empty: no error code was observed for either operation, so every Error_Result from them is an ERROR.
11. THE `ResourceId` of a per-VPC row SHALL be the VPC ID, and the `ResourceId` of a Region's no-VPC or Region-level error row SHALL identify the account and Region; neither SHALL change when the row's status changes.
12. WHEN the check produces a FAIL finding, THE remediation SHALL name `aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL` with a log destination, and that command SHALL be run during Live_Validation Phase 4 to prove it is accepted.

### Requirement 5: Route 53 Resolver query logging is enabled for every VPC

**User Story:** As an incident responder, I want SRA Verify to confirm that every VPC in every account and Region has Route 53 Resolver query logging associated, so that DNS evidence exists when I trace an incident.

**Check Title:** Route 53 Resolver query logging is enabled for every VPC (SRA-ROUTE53RESOLVER-01)

#### Acceptance Criteria

1. THE SRA Verify package SHALL contain a new service package `services/route53resolver/` with `__init__.py` (the three-line discovery call), `base.py` (`Route53ResolverCheck`, `NAMESPACE = "route53resolver"`, an explicitly empty `NOT_CONFIGURED_ERRORS`), `client.py` (`Route53ResolverClient(AWSClient)`), and `checks/__init__.py`, following the layout in `structure.md`.
2. THE SRA Verify package SHALL register a check with ID `SRA-ROUTE53RESOLVER-01` in `services/route53resolver/checks/sra_route53resolver_01.py`, with account type `application`, severity `MEDIUM`, service `Route 53 Resolver`, and resource type `AWS::EC2::VPC`.
3. THE `Route53ResolverClient` SHALL gain a method for `route53resolver:ListResolverQueryLogConfigAssociations` that reads every page through its botocore paginator inside the `try`, returning `{"ResolverQueryLogConfigAssociations": [...]}` on success and the Error_Result on failure, and `Route53ResolverCheck` SHALL gain a cached accessor for it, keyed by Region, that never caches a failure.
4. THE check SHALL obtain the Region's VPCs through an `ec2:DescribeVpcs` call issued from within the `route53resolver` package, without importing another service's base class, and SHALL apply the same Owned_VPC rule as Requirement 4 criterion 4.
5. WHEN an Owned_VPC has at least one Active_Query_Log_Association, THE check SHALL produce a PASS finding for that VPC whose `ActualValue` names the associated query logging configuration ID. Ownership of the configuration SHALL NOT be required.
6. IF an Owned_VPC has no Active_Query_Log_Association, THEN THE check SHALL produce a FAIL finding for that VPC whose `ActualValue` states that no active query logging association exists and notes when the VPC is the default VPC. This is the observed baseline in every probed Region that has a VPC.
7. WHEN `DescribeVpcs` succeeds with no Owned_VPC in a Region, THE check SHALL produce exactly one PASS finding for that Region stating that the Region has no VPC, and SHALL NOT call `ListResolverQueryLogConfigAssociations` there.
8. IF `DescribeVpcs` returns an Error_Result in a Region, THEN THE check SHALL produce one Error_Row for that Region and continue to the next Region.
9. IF `ListResolverQueryLogConfigAssociations` returns an Error_Result in a Region after `DescribeVpcs` succeeded, THEN THE check SHALL produce one Error_Row per Owned_VPC in that Region and continue to the next Region.
10. THE `Route53ResolverCheck.NOT_CONFIGURED_ERRORS` table SHALL be empty. In particular `UnrecognizedClientException`, observed only in a Region not enabled for the account, SHALL NOT be declared, because a scan covers only enabled Regions and the code otherwise means a credential problem.
11. THE check SHALL NOT call the Availability_Lookup: `route53resolver` has an endpoint in every Region of every partition botocore knows (34/34 `aws`, 2/2 `aws-us-gov`, 2/2 `aws-cn`, botocore 1.43.105, the same coverage as `ec2`), so the lookup could never answer False, and `test_availability_property.py` rejects full-coverage services from its candidate set (`_REJECTED_SERVICE_IDS`).
12. THE `ResourceId` rules of Requirement 4 criterion 11 SHALL apply.
13. WHEN the check produces a FAIL finding, THE remediation SHALL name `aws route53resolver create-resolver-query-log-config` and `aws route53resolver associate-resolver-query-log-config --resolver-query-log-config-id <id> --resource-id <vpc-id>`, and the association command SHALL be run during Live_Validation Phase 4 to prove it is accepted.

### Requirement 6: Contract conformance of the new code

**User Story:** As a maintainer, I want the five new checks and their clients held by the same contract tests as the rest of the catalog, so that a defect in them fails the suite rather than a scan.

#### Acceptance Criteria

1. THE five checks SHALL each declare `meta = CheckMeta(...)` in their own class body, define no `__init__`, yield findings only through `passed()`, `failed()` and `error()`, contain no `except` inside `execute()`, and reach AWS only through their base-class accessors.
2. THE new client methods SHALL each acquire their boto3 client in `__init__`, catch exactly `AWS_EXCEPTIONS`, and return `self.aws_error(e)`, and SHALL each be added as a `ClientAdapter` row in `tests/property/test_client_contract_property.py`.
3. THE new base accessors SHALL each be added as an `AccessorAdapter` row in `tests/property/test_accessor_cache_property.py` so that `test_every_public_base_method_is_classified` passes.
4. THE catalog-wide property suites SHALL pass over all 187 registered checks, including the assertion that every Error_Result reaches `error()` with an `ActualValue` naming the operation and code.
5. THE unit test suite SHALL include, for each of the five checks, tests driving stubbed accessors through every PASS, FAIL and ERROR arm named in Requirements 1 to 5, issuing no AWS call.
6. WHEN `uv run pytest -q` runs, THE suite SHALL report zero failures, and the pass count SHALL exceed the branch baseline of 10080 passed.

### Requirement 7: Permissions, catalog artifacts and documentation

**User Story:** As an operator deploying SRA Verify, I want the member role, the published check inventory and the steering documents updated with the new checks, so that a deployed scan can run them without ERROR rows and the documentation describes the code.

#### Acceptance Criteria

1. THE `1-sraverify-member-roles.yaml` template SHALL grant `ec2:DescribeVpcs`, `ec2:DescribeFlowLogs` and `route53resolver:ListResolverQueryLogConfigAssociations`, the three actions the Probe_Findings found missing, and SHALL grant no other new action.
2. WHEN `util/generate_iam_policy.py` is run against the package, THE generated action set SHALL include those three actions, and the run SHALL write nothing to stderr.
3. THE edited template SHALL pass `aws cloudformation validate-template`, and each new action SHALL be shown `allowed` by `aws iam simulate-custom-policy` against the edited policy and, after deployment, by `aws iam simulate-principal-policy` against the deployed `SRAMemberRole`.
4. THE `docs/checks.txt` file SHALL be regenerated with the installed `sraverify --list-checks` console script and SHALL be byte-identical (`cmp`) to a fresh regeneration.
5. THE steering documents (`product.md`, `structure.md`, `tech.md`, `creating_checks_best_practices.md`) SHALL be updated wherever they state the check count, the service count, the per-service counts, the client-method count or the test counts, and `product.md` SHALL describe the five new checks.

### Requirement 8: Live validation and delivery

**User Story:** As the maintainer, I want every new check proven against the test organization and the branch scanned and submitted for review, so that a green unit suite is not mistaken for evidence about AWS.

#### Acceptance Criteria

1. THE Live_Validation SHALL take each of the five checks through the five phases, and each check SHALL be observed producing both a PASS and a FAIL verdict, with the mutation for each phase scoped to one account or Region where possible and run strictly sequentially per check.
2. THE Live_Validation SHALL NOT mutate the SIR delegated administrator registration, Control Tower baseline resources (including `aws-controltower-BaselineCloudTrail`), or any service-managed SIR rule without explicit sign-off, and SHALL NOT create an organization trail without explicit sign-off from the user requested at the time (an organization trail is billable organization-wide: it delivers a second copy of management events for every account); WHERE an arm can be reached only that way and sign-off is not given, THE report SHALL mark it 🔄 with the reason.
3. THE Live_Validation SHALL accept a scan only when it meets the gates in `testing_checks.md`: zero synthetic rows, zero `- ERROR -` log records, every ERROR row explained, and a plausible `aws_call_failed` count.
4. THE Live_Validation SHALL snapshot every resource it changes to `.tmp/sratester/snapshot.json` and SHALL include in the report the output of a script that re-reads and compares each snapshotted resource after restoration.
5. WHEN `1-sraverify-member-roles.yaml` has been deployed, THE Live_Validation SHALL make one CodeBuild run with a `buildspecOverride` that installs the working tree, and its consolidated CSV SHALL show zero ERROR rows from the five new checks.
6. THE report SHALL be written to `sratester/sir-log-readiness-checks-test-report.md`, with raw output under `.tmp/sratester/`.
7. WHEN a commit message is about to be proposed, THE ASH scan in `security_scanning.md` SHALL be clean.
8. THE change SHALL be committed on branch `feature/sir-log-readiness-checks` in the existing worktree `.worktrees/sir-log-readiness-checks`, pushed, and submitted as a GitLab merge request with `glab mr create`, whose description summarizes the changes, the testing, and any arm left 🔄.
