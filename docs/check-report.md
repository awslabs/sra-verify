# AWS SRA best practices checklist → SRA Verify coverage

Maps every item in the [AWS SRA best practices checklist](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/checklist.html)
to the SRA Verify checks that assess it, so gaps are visible.

- **Checklist source:** AWS SRA best practices checklist, retrieved 2026-09-16. 224 items across 24 service sections.
- **Check source:** the live registry (`sraverify --list-checks`), **159 checks across 18 services**.
- Content from the AWS documentation was rephrased for compliance with licensing restrictions.

## How to read the Status column

| Status  | Meaning                                                                                                                                                                |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Covered | One or more checks assess the item directly.                                                                                                                           |
| Partial | A check touches the item but does not fully establish it — narrower scope, adjacent signal, or only one arm of a two-part recommendation. The note says what is short. |
| Missing | No check assesses the item.                                                                                                                                            |

`docs/checks.txt` is **stale** at the time of writing — it lists 158 checks and omits
`SRA-ORGANIZATIONS-10`. This report is built from the live registry, not from that file.

## Summary

| Checklist section                 |   Items | Covered | Partial | Missing |
| --------------------------------- | ------: | ------: | ------: | ------: |
| AWS Organizations                 |      11 |       7 |       1 |       3 |
| AWS CloudTrail                    |      14 |       8 |       0 |       6 |
| AWS Security Hub CSPM             |      17 |       6 |       5 |       6 |
| AWS Config                        |       7 |       5 |       0 |       2 |
| Amazon GuardDuty                  |      17 |      11 |       1 |       5 |
| IAM                               |       8 |       1 |       0 |       7 |
| IAM Access Analyzer               |       8 |       4 |       0 |       4 |
| Amazon Detective                  |       9 |       0 |       0 |       9 |
| AWS Firewall Manager              |      10 |       8 |       0 |       2 |
| Amazon Inspector                  |       8 |       6 |       1 |       1 |
| Amazon Macie                      |       6 |       6 |       0 |       0 |
| Amazon Security Lake              |      17 |      15 |       0 |       2 |
| AWS WAF                           |      10 |       9 |       0 |       1 |
| AWS Shield Advanced               |      14 |      11 |       2 |       1 |
| AWS Security Incident Response    |       4 |       3 |       0 |       1 |
| AWS Audit Manager                 |       6 |       3 |       0 |       3 |
| AWS Security Hub (unified)        |       8 |       0 |       1 |       7 |
| AWS Network Firewall              |       8 |       0 |       1 |       7 |
| Route 53 Resolver DNS Firewall    |       4 |       0 |       1 |       3 |
| AWS Key Management Service        |       8 |       0 |       0 |       8 |
| AWS Private Certificate Authority |       6 |       0 |       0 |       6 |
| AWS IAM Identity Center           |       8 |       0 |       1 |       7 |
| AWS Systems Manager               |       8 |       0 |       0 |       8 |
| AWS Secrets Manager               |       8 |       0 |       0 |       8 |
| **Total**                         | **224** | **103** |  **14** | **107** |

Coverage is concentrated in the security services SRA Verify has packages for. Six
checklist sections — Detective, KMS, Private CA, IAM Identity Center, Systems Manager,
Secrets Manager — have **no** corresponding service package, which accounts for 46 of
the 107 missing items.

---

## AWS Organizations

|    # | Checklist item                                                | SRA Verify check(s)                        | Status  | Note                                                                                                                                         |
| ---: | ------------------------------------------------------------- | ------------------------------------------ | ------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
|    1 | Organizations enabled with all features                       | SRA-ORGANIZATIONS-01, SRA-ORGANIZATIONS-05 | Covered | -01 enablement, -05 `FeatureSet=ALL`                                                                                                         |
|    2 | SCPs used for IAM principal access control                    | SRA-ORGANIZATIONS-06                       | Covered |                                                                                                                                              |
|    3 | RCPs used for resource access control                         | SRA-ORGANIZATIONS-07                       | Covered |                                                                                                                                              |
|    4 | Declarative policies used to enforce service configuration    | SRA-ORGANIZATIONS-10                       | Partial | Only the `BEDROCK_POLICY` declarative type is checked, and only that it is enabled on the root — not that any declarative policy is attached |
|    5 | Three foundational OUs (Security, Infrastructure, Workloads)  | SRA-ORGANIZATIONS-02, SRA-ORGANIZATIONS-03, SRA-ORGANIZATIONS-04             | Covered | One check per OU                                                                                                                             |
|    6 | Security Tooling account created under the Security OU        | SRA-ORGANIZATIONS-08                       | Covered | Needs `--audit-account`                                                                                                                      |
|    7 | Log Archive account created under the Security OU             | SRA-ORGANIZATIONS-09                       | Covered | Needs `--log-archive-account`                                                                                                                |
|    8 | Network account created under the Infrastructure OU           | —                                          | Missing | No account-to-OU check beyond audit and log-archive                                                                                          |
|    9 | Shared Services account created under the Infrastructure OU   | —                                          | Missing |                                                                                                                                              |
|   10 | Application account created under the Workloads OU            | —                                          | Missing |                                                                                                                                              |
|   11 | Alternate contacts (billing, operations, security) configured | SRA-ACCOUNT-01, SRA-ACCOUNT-02, SRA-ACCOUNT-03                   | Covered | Security, billing, operations respectively                                                                                                   |

## AWS CloudTrail

|    # | Checklist item                                                          | SRA Verify check(s)                  | Status  | Note                                                                              |
| ---: | ----------------------------------------------------------------------- | ------------------------------------ | ------- | --------------------------------------------------------------------------------- |
|    1 | Organization trail configured for management and all member accounts    | SRA-CLOUDTRAIL-01                    | Covered |                                                                                   |
|    2 | Organization trail is multi-Region                                      | SRA-CLOUDTRAIL-04                    | Covered |                                                                                   |
|    3 | Organization trail captures global service events                       | SRA-CLOUDTRAIL-06                    | Covered |                                                                                   |
|    4 | Additional trails for specific data events                              | —                                    | Missing | Only the organization management-event trail is assessed                          |
|    5 | Security Tooling account is delegated administrator of the trail        | SRA-CLOUDTRAIL-12, SRA-CLOUDTRAIL-13 | Covered | -12 a delegated admin exists, -13 it is the audit account                         |
|    6 | Trail automatically enabled for new member accounts                     | —                                    | Missing |                                                                                   |
|    7 | Trail publishes to a centralized S3 bucket in the Log Archive account   | SRA-CLOUDTRAIL-08, SRA-CLOUDTRAIL-11 | Covered | -08 delivery working, -11 bucket is in the Log Archive account                    |
|    8 | Log file validation enabled                                             | SRA-CLOUDTRAIL-03, SRA-CLOUDTRAIL-10 | Covered | -10 also confirms digest files are delivered                                      |
|    9 | Integrated with CloudWatch Logs for retention                           | SRA-CLOUDTRAIL-05, SRA-CLOUDTRAIL-09 | Covered | -05 configuration present, -09 delivery working                                   |
|   10 | Trail encrypted with a customer managed key                             | SRA-CLOUDTRAIL-02                    | Covered | Verifies a KMS key is set; does not distinguish customer managed from AWS managed |
|   11 | Central log bucket in Log Archive encrypted with a customer managed key | —                                    | Missing | No S3 encryption check on the log bucket                                          |
|   12 | Central log bucket configured with S3 Object Lock                       | —                                    | Missing |                                                                                   |
|   13 | Versioning enabled on the central log bucket                            | —                                    | Missing |                                                                                   |
|   14 | Central log bucket resource policy restricts uploads to the trail ARN   | —                                    | Missing |                                                                                   |

## AWS Security Hub CSPM

|    # | Checklist item                                                   | SRA Verify check(s)                                        | Status  | Note                                                                                                            |
| ---: | ---------------------------------------------------------------- | ---------------------------------------------------------- | ------- | --------------------------------------------------------------------------------------------------------------- |
|    1 | CSPM enabled for all member accounts and the management account  | SRA-SECURITYHUB-08, SRA-SECURITYHUB-09                     | Covered | -08 all active accounts are members, -09 all members are Enabled                                                |
|    2 | AWS Config enabled as a prerequisite                             | SRA-CONFIG-01, SRA-CONFIG-02                               | Covered | Recorder configured and running per Region                                                                      |
|    3 | Security Tooling account is delegated administrator              | SRA-SECURITYHUB-06, SRA-SECURITYHUB-07, SRA-SECURITYHUB-03 | Covered | -06 exists, -07 is the audit account, -03 account-level agreement                                               |
|    4 | GuardDuty and Detective share the CSPM delegated administrator   | SRA-GUARDDUTY-14, SRA-SECURITYHUB-07                       | Partial | Both are compared to the audit account independently, which implies agreement; Detective is not assessed at all |
|    5 | Central configuration used                                       | SRA-SECURITYHUB-04                                         | Covered |                                                                                                                 |
|    6 | All OUs and member accounts designated centrally managed         | —                                                          | Missing | Central configuration is checked, per-target association is not                                                 |
|    7 | Automatically enabled for new member accounts                    | SRA-SECURITYHUB-10                                         | Covered |                                                                                                                 |
|    8 | Automatically enabled for new standards                          | SRA-SECURITYHUB-02                                         | Covered |                                                                                                                 |
|    9 | Findings from all Regions aggregated to a single home Region     | —                                                          | Missing | No finding-aggregator check                                                                                     |
|   10 | Findings from all member accounts aggregated in Security Tooling | SRA-SECURITYHUB-08, SRA-SECURITYHUB-09                     | Partial | Membership implies finding flow but is not the aggregation configuration itself                                 |
|   11 | FSBP standard enabled for all member accounts                    | SRA-SECURITYHUB-01                                         | Partial | Passes if *any* standard is enabled; does not identify FSBP                                                     |
|   12 | CIS AWS Foundations Benchmark enabled for all member accounts    | SRA-SECURITYHUB-01                                         | Partial | Same — no per-standard identification                                                                           |
|   13 | Other standards enabled as applicable                            | SRA-SECURITYHUB-01                                         | Partial | Same                                                                                                            |
|   14 | CSPM findings consumed by Security Hub for exposure correlation  | —                                                          | Missing |                                                                                                                 |
|   15 | Automation rule enriches findings with resource context          | —                                                          | Missing |                                                                                                                 |
|   16 | Custom EventBridge rules for automated response and remediation  | —                                                          | Missing |                                                                                                                 |
|   17 | CloudWatch telemetry enablement rule for the organization        | —                                                          | Missing |                                                                                                                 |

## AWS Config

|    # | Checklist item                                                        | SRA Verify check(s)          | Status  | Note                                                 |
| ---: | --------------------------------------------------------------------- | ---------------------------- | ------- | ---------------------------------------------------- |
|    1 | Recorder enabled for all member accounts and the management account   | SRA-CONFIG-01, SRA-CONFIG-02, SRA-CONFIG-03      | Covered | -03 also confirms the last recording event succeeded |
|    2 | Recorder enabled for all Regions                                      | SRA-CONFIG-01                | Covered | Emits one row per Region in `--regions`              |
|    3 | Delivery channel S3 bucket centralized in the Log Archive account     | SRA-CONFIG-06                | Covered | Needs `--log-archive-account`                        |
|    4 | Delegated administrator set to the Security Tooling account           | SRA-CONFIG-07, SRA-CONFIG-08 | Covered | -07 exists, -08 is the audit account                 |
|    5 | Organization aggregator set up, covering all Regions                  | SRA-CONFIG-04, SRA-CONFIG-05, SRA-CONFIG-09      | Covered | -04 exists, -05 all Regions, -09 valid status        |
|    6 | Conformance packs deployed uniformly from the delegated administrator | —                            | Missing |                                                      |
|    7 | Config rule findings sent to Security Hub CSPM                        | —                            | Missing |                                                      |

## Amazon GuardDuty

|    # | Checklist item                                                      | SRA Verify check(s)                  | Status  | Note                                                                                                                                                     |
| ---: | ------------------------------------------------------------------- | ------------------------------------ | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
|    1 | Detector enabled for all member accounts and the management account | SRA-GUARDDUTY-01, SRA-GUARDDUTY-03   | Covered | -01 detector exists, -03 it is enabled                                                                                                                   |
|    2 | Detector enabled for all Regions                                    | SRA-GUARDDUTY-01                     | Covered | One row per Region                                                                                                                                       |
|    3 | Automatically enabled for new member accounts                       | SRA-GUARDDUTY-15, SRA-GUARDDUTY-20, SRA-GUARDDUTY-21, SRA-GUARDDUTY-22, SRA-GUARDDUTY-23, SRA-GUARDDUTY-24, SRA-GUARDDUTY-25     | Covered | -15 detector auto-enable; -20 S3 data events, -21 EBS malware, -22 EKS audit logs, -23 runtime monitoring, -24 Lambda network logs, -25 RDS login events |
|    4 | Delegated administration set to the Security Tooling account        | SRA-GUARDDUTY-13, SRA-GUARDDUTY-14   | Covered |                                                                                                                                                          |
|    5 | Foundational data sources (CloudTrail, VPC flow logs, Route 53 DNS) | SRA-GUARDDUTY-08, SRA-GUARDDUTY-05, SRA-GUARDDUTY-04           | Covered | CloudTrail, VPC flow logs, DNS logs respectively                                                                                                         |
|    6 | S3 Protection enabled                                               | SRA-GUARDDUTY-06                     | Covered |                                                                                                                                                          |
|    7 | Malware Protection for EBS volumes enabled                          | SRA-GUARDDUTY-09                     | Covered |                                                                                                                                                          |
|    8 | Malware Protection for S3 enabled                                   | —                                    | Missing | -06 is S3 data-event protection, a different feature                                                                                                     |
|    9 | RDS Protection enabled                                              | SRA-GUARDDUTY-10                     | Covered |                                                                                                                                                          |
|   10 | Lambda Protection enabled                                           | SRA-GUARDDUTY-12                     | Covered |                                                                                                                                                          |
|   11 | EKS Protection enabled                                              | SRA-GUARDDUTY-07                     | Covered |                                                                                                                                                          |
|   12 | EKS Runtime Monitoring enabled                                      | SRA-GUARDDUTY-11, SRA-GUARDDUTY-17, SRA-GUARDDUTY-18, SRA-GUARDDUTY-19 | Covered | -17 EKS addon, -18 ECS Fargate agent, -19 EC2 agent management                                                                                           |
|   13 | Findings flow to Security Hub CSPM and Security Hub                 | SRA-SECURITYHUB-05                   | Partial | -05 passes if any product is ingesting; it does not confirm GuardDuty specifically                                                                       |
|   14 | Integrated with Amazon Detective                                    | —                                    | Missing |                                                                                                                                                          |
|   15 | Findings exported to S3 encrypted with a customer managed KMS key   | —                                    | Missing |                                                                                                                                                          |
|   16 | Extended Threat Detection enabled                                   | —                                    | Missing |                                                                                                                                                          |
|   17 | Findings exported to a central bucket in Log Archive, CMK-encrypted | —                                    | Missing |                                                                                                                                                          |

## IAM

|    # | Checklist item                                                     | SRA Verify check(s) | Status  | Note                             |
| ---: | ------------------------------------------------------------------ | ------------------- | ------- | -------------------------------- |
|    1 | IAM users are not used                                             | SRA-IAM-01          | Covered |                                  |
|    2 | Centralized management of root access for member accounts enforced | —                   | Missing |                                  |
|    3 | Centralized privileged root user task for the management account   | —                   | Missing |                                  |
|    4 | Centralized root access management delegated to Security Tooling   | —                   | Missing |                                  |
|    5 | All member account root credentials removed                        | —                   | Missing |                                  |
|    6 | Account password policies set to the organization standard         | —                   | Missing |                                  |
|    7 | IAM access advisor used to review last-used information            | —                   | Missing | Not machine-assessable as stated |
|    8 | Permission boundaries restrict maximum permissions for roles       | —                   | Missing |                                  |

## IAM Access Analyzer

|    # | Checklist item                                                     | SRA Verify check(s)                          | Status  | Note                                   |
| ---: | ------------------------------------------------------------------ | -------------------------------------------- | ------- | -------------------------------------- |
|    1 | Enabled for all member accounts and the management account         | SRA-ACCESSANALYZER-01                        | Covered | Account zone-of-trust analyzer present |
|    2 | Delegated administrator set to the Security Tooling account        | SRA-ACCESSANALYZER-02, SRA-ACCESSANALYZER-03 | Covered |                                        |
|    3 | External access analyzer, organization zone of trust, every Region | SRA-ACCESSANALYZER-04                        | Covered |                                        |
|    4 | External access analyzer, account zone of trust, every Region      | SRA-ACCESSANALYZER-01                        | Covered |                                        |
|    5 | Internal access analyzer, organization zone of trust, every Region | —                                            | Missing |                                        |
|    6 | Internal access analyzer, account zone of trust, every Region      | —                                            | Missing |                                        |
|    7 | Unused access analyzer for the current account                     | —                                            | Missing |                                        |
|    8 | Unused access analyzer for the current organization                | —                                            | Missing |                                        |

## Amazon Detective

No `detective` service package exists. All 9 items are Missing.

|    # | Checklist item                                                  | Status  |
| ---: | --------------------------------------------------------------- | ------- |
|    1 | Detective enabled for all member accounts                       | Missing |
|    2 | Automatically enabled for new member accounts                   | Missing |
|    3 | Enabled for all Regions                                         | Missing |
|    4 | Delegated administrator set to the Security Tooling account     | Missing |
|    5 | Detective, GuardDuty and CSPM share one delegated administrator | Missing |
|    6 | Integrated with Security Lake for raw log storage and analysis  | Missing |
|    7 | Integrated with GuardDuty for finding ingestion                 | Missing |
|    8 | Ingesting Amazon EKS audit logs                                 | Missing |
|    9 | Ingesting Security Hub CSPM logs                                | Missing |

## AWS Firewall Manager

|    # | Checklist item                                                        | SRA Verify check(s)              | Status  | Note                                                              |
| ---: | --------------------------------------------------------------------- | -------------------------------- | ------- | ----------------------------------------------------------------- |
|    1 | Security policies are set                                             | SRA-FIREWALLMANAGER-09, SRA-FIREWALLMANAGER-08, SRA-FIREWALLMANAGER-10 | Covered | -09 policies active, -08 remediation enabled, -10 cleanup enabled |
|    2 | Delegated administrator set to the Security Tooling account           | SRA-FIREWALLMANAGER-01           | Covered | Pinned to us-east-1; `--regions` does not affect the row          |
|    3 | AWS Config enabled as a prerequisite                                  | SRA-CONFIG-01, SRA-CONFIG-02     | Covered |                                                                   |
|    4 | Multiple administrators with scope restricted per OU, account, Region | —                                | Missing |                                                                   |
|    5 | AWS WAF security policy defined                                       | SRA-FIREWALLMANAGER-03           | Covered |                                                                   |
|    6 | AWS WAF centralized logging policy defined                            | —                                | Missing |                                                                   |
|    7 | Shield Advanced security policy defined                               | SRA-FIREWALLMANAGER-04           | Covered |                                                                   |
|    8 | Security group security policy defined                                | SRA-FIREWALLMANAGER-02           | Covered |                                                                   |
|    9 | AWS Network Firewall policy defined                                   | SRA-FIREWALLMANAGER-06           | Covered |                                                                   |
|   10 | Route 53 DNS Firewall policy defined                                  | SRA-FIREWALLMANAGER-07           | Covered |                                                                   |

## Amazon Inspector

|    # | Checklist item                                              | SRA Verify check(s)                | Status  | Note                                                                                    |
| ---: | ----------------------------------------------------------- | ---------------------------------- | ------- | --------------------------------------------------------------------------------------- |
|    1 | Enabled for all member accounts                             | SRA-INSPECTOR-01, SRA-INSPECTOR-07 | Covered | -01 per account, -07 org-wide from the delegated admin                                  |
|    2 | Automatically enabled for any new member account            | SRA-INSPECTOR-08, SRA-INSPECTOR-09, SRA-INSPECTOR-10, SRA-INSPECTOR-11    | Covered | EC2, ECR, Lambda, Lambda code                                                           |
|    3 | Delegated administrator set to the Security Tooling account | SRA-INSPECTOR-05, SRA-INSPECTOR-06 | Covered |                                                                                         |
|    4 | EC2 vulnerability scanning enabled                          | SRA-INSPECTOR-02                   | Covered |                                                                                         |
|    5 | ECR image vulnerability scanning enabled                    | SRA-INSPECTOR-03                   | Covered |                                                                                         |
|    6 | Lambda function and layer vulnerability scanning enabled    | SRA-INSPECTOR-04                   | Covered |                                                                                         |
|    7 | Lambda code scanning enabled                                | SRA-INSPECTOR-11                   | Partial | Only the org auto-enable flag; no per-account "is it on now" check as -02 … -04 provide |
|    8 | Code security scanning enabled                              | —                                  | Missing |                                                                                         |

## Amazon Macie

Fully covered.

|    # | Checklist item                                                       | SRA Verify check(s)        | Status  | Note                                         |
| ---: | -------------------------------------------------------------------- | -------------------------- | ------- | -------------------------------------------- |
|    1 | Enabled for applicable member accounts                               | SRA-MACIE-09, SRA-MACIE-07 | Covered | -09 enabled, -07 member relationship enabled |
|    2 | Automatically enabled for applicable new member accounts             | SRA-MACIE-08               | Covered |                                              |
|    3 | Delegated administrator set to the Security Tooling account          | SRA-MACIE-05, SRA-MACIE-06 | Covered |                                              |
|    4 | Findings exported to a central bucket in the Log Archive account     | SRA-MACIE-03               | Covered |                                              |
|    5 | Buckets storing Macie findings encrypted with a customer managed key | SRA-MACIE-04               | Covered |                                              |
|    6 | Policy and classification findings published to Security Hub CSPM    | SRA-MACIE-01, SRA-MACIE-02 | Covered |                                              |

## Amazon Security Lake

|    # | Checklist item                                                 | SRA Verify check(s)                      | Status  | Note                                      |
| ---: | -------------------------------------------------------------- | ---------------------------------------- | ------- | ----------------------------------------- |
|    1 | Organization configuration enabled                             | SRA-SECURITYLAKE-04, SRA-SECURITYLAKE-01 | Covered | -01 enabled for all organization accounts |
|    2 | Delegated administrator set to the Log Archive account         | SRA-SECURITYLAKE-14, SRA-SECURITYLAKE-15 | Covered |                                           |
|    3 | Organization configuration enabled for new member accounts     | SRA-SECURITYLAKE-05                      | Covered |                                           |
|    4 | Security Tooling set up as a data access subscriber            | SRA-SECURITYLAKE-17                      | Covered |                                           |
|    5 | Security Tooling set up as a data query subscriber             | SRA-SECURITYLAKE-16                      | Covered |                                           |
|    6 | CloudTrail management log source enabled                       | SRA-SECURITYLAKE-11                      | Covered |                                           |
|    7 | VPC flow log source enabled                                    | SRA-SECURITYLAKE-13                      | Covered |                                           |
|    8 | Route 53 log source enabled                                    | SRA-SECURITYLAKE-06                      | Covered |                                           |
|    9 | CloudTrail S3 data event source enabled                        | SRA-SECURITYLAKE-07                      | Covered |                                           |
|   10 | Lambda execution log source enabled                            | SRA-SECURITYLAKE-10                      | Covered |                                           |
|   11 | Amazon EKS audit log source enabled                            | SRA-SECURITYLAKE-09                      | Covered |                                           |
|   12 | Security Hub findings log source enabled                       | SRA-SECURITYLAKE-08                      | Covered |                                           |
|   13 | AWS WAF log source enabled                                     | SRA-SECURITYLAKE-12                      | Covered |                                           |
|   14 | SQS queues in the delegated admin account encrypted with a CMK | SRA-SECURITYLAKE-02                      | Covered |                                           |
|   15 | Dead-letter queue encrypted with a CMK                         | SRA-SECURITYLAKE-03                      | Covered |                                           |
|   16 | Security Lake S3 bucket encrypted with a CMK                   | —                                        | Missing |                                           |
|   17 | S3 bucket resource policy restricts access to Security Lake    | —                                        | Missing |                                           |

## AWS WAF

|    # | Checklist item                                                  | SRA Verify check(s) | Status  | Note                                           |
| ---: | --------------------------------------------------------------- | ------------------- | ------- | ---------------------------------------------- |
|    1 | All CloudFront distributions associated with AWS WAF            | SRA-WAF-01          | Covered |                                                |
|    2 | All API Gateway REST APIs associated with AWS WAF               | SRA-WAF-03          | Covered |                                                |
|    3 | All Application Load Balancers associated with AWS WAF          | SRA-WAF-02          | Covered |                                                |
|    4 | All AppSync GraphQL APIs associated with AWS WAF                | SRA-WAF-04          | Covered |                                                |
|    5 | All Cognito user pools associated with AWS WAF                  | SRA-WAF-05          | Covered |                                                |
|    6 | All App Runner services associated with AWS WAF                 | SRA-WAF-06          | Covered |                                                |
|    7 | All Verified Access instances associated with AWS WAF           | SRA-WAF-07          | Covered |                                                |
|    8 | All Amplify applications associated with AWS WAF                | SRA-WAF-08          | Covered |                                                |
|    9 | AWS WAF logging enabled                                         | SRA-WAF-09          | Covered |                                                |
|   10 | WAF logs centralized in an S3 bucket in the Log Archive account | —                   | Missing | -09 confirms logging is on, not where it lands |

## AWS Shield Advanced

|    # | Checklist item                                                    | SRA Verify check(s)          | Status  | Note                                                                         |
| ---: | ----------------------------------------------------------------- | ---------------------------- | ------- | ---------------------------------------------------------------------------- |
|    1 | Subscription enabled and set to auto-renew                        | SRA-SHIELD-01, SRA-SHIELD-02 | Covered |                                                                              |
|    2 | Configured for all CloudFront distributions                       | SRA-SHIELD-03                | Covered |                                                                              |
|    3 | Configured for all Application Load Balancers                     | SRA-SHIELD-04                | Covered |                                                                              |
|    4 | Configured for Elastic IPs associated with Network Load Balancers | SRA-SHIELD-05                | Partial | -05 covers Elastic IPs generically; it does not separate the NLB association |
|    5 | Configured for Elastic IPs associated with EC2 instances          | SRA-SHIELD-05                | Partial | Same                                                                         |
|    6 | Configured for all Route 53 hosted zones                          | SRA-SHIELD-06                | Covered |                                                                              |
|    7 | Configured for all Elastic IP addresses                           | SRA-SHIELD-05                | Covered |                                                                              |
|    8 | Configured for all Global Accelerators                            | SRA-SHIELD-07                | Covered |                                                                              |
|    9 | CloudWatch alarms for protected CloudFront and Route 53 resources | SRA-SHIELD-13                | Covered |                                                                              |
|   10 | Shield Response Team access configured                            | SRA-SHIELD-08                | Covered |                                                                              |
|   11 | Proactive engagement enabled                                      | SRA-SHIELD-09                | Covered | Reads `ProactiveEngagementStatus`                                            |
|   12 | Proactive engagement contacts configured                          | —                            | Missing | -09 reads only the status; emergency contact settings are not checked        |
|   13 | Protected resources have a custom AWS WAF rule configured         | SRA-SHIELD-12                | Covered | Verifies a web ACL association                                               |
|   14 | Automatic application-layer DDoS mitigation enabled               | SRA-SHIELD-14                | Covered |                                                                              |

Note: `ShieldClient.list_protections` reads the first page only, so the per-resource
fan-out in items 2 – 9 can under-report on organizations with many protections.

## AWS Security Incident Response

|    # | Checklist item                                              | SRA Verify check(s)                  | Status  | Note                                                        |
| ---: | ----------------------------------------------------------- | ------------------------------------ | ------- | ----------------------------------------------------------- |
|    1 | Enabled for the whole AWS organization                      | SRA-SECURITYINCIDENTRESPONSE-02, SRA-SECURITYINCIDENTRESPONSE-04 | Covered | -02 membership active, -04 one row per organization account |
|    2 | Delegated administrator set to the Security Tooling account | SRA-SECURITYINCIDENTRESPONSE-01      | Covered | Region cell is labelled from `regions[0]` — a known defect  |
|    3 | Proactive response and alert triaging workflow enabled      | SRA-SECURITYINCIDENTRESPONSE-03, SRA-SECURITYINCIDENTRESPONSE-05 | Covered | -03 Triage opt-in, -05 triage service-linked role           |
|    4 | AWS CIRT containment actions authorized                     | —                                    | Missing |                                                             |

## AWS Audit Manager

|    # | Checklist item                                              | SRA Verify check(s)          | Status  | Note                                                         |
| ---: | ----------------------------------------------------------- | ---------------------------- | ------- | ------------------------------------------------------------ |
|    1 | Enabled for all member accounts                             | SRA-AUDITMANAGER-01          | Covered |                                                              |
|    2 | Automatically enabled for new member accounts               | —                            | Missing |                                                              |
|    3 | Delegated administrator set to the Security Tooling account | SRA-AUDITMANAGER-02          | Covered | Needs `--audit-account`; absent flag is an ERROR, not a FAIL |
|    4 | AWS Config enabled as a prerequisite                        | SRA-CONFIG-01, SRA-CONFIG-02 | Covered |                                                              |
|    5 | Customer managed key used for data stored in Audit Manager  | —                            | Missing |                                                              |
|    6 | Default assessment report destination configured            | —                            | Missing |                                                              |

## AWS Security Hub (unified, exposure correlation)

The `securityhub` package targets **Security Hub CSPM**, not the newer unified
Security Hub. Nothing here reads the V2 API surface.

|    # | Checklist item                                                             | SRA Verify check(s) | Status  | Note                                                                       |
| ---: | -------------------------------------------------------------------------- | ------------------- | ------- | -------------------------------------------------------------------------- |
|    1 | Security Hub enabled for all member accounts and the management account    | —                   | Missing | Existing checks read the CSPM API                                          |
|    2 | Security Tooling set as delegated administrator for Security Hub           | —                   | Missing |                                                                            |
|    3 | All Regions, OUs and accounts enabled automatically, including future ones | —                   | Missing |                                                                            |
|    4 | Cross-Region aggregation into a single home Region                         | —                   | Missing |                                                                            |
|    5 | CSPM, GuardDuty, Inspector and Macie enabled as building-block services    | SRA-SECURITYHUB-05  | Partial | -05 passes if any product ingests findings; it does not require these four |
|    6 | Coverage findings used to validate uniform service enablement              | —                   | Missing |                                                                            |
|    7 | Findings formatted in OCSF                                                 | —                   | Missing |                                                                            |
|    8 | EventBridge integration for automated response and remediation             | —                   | Missing |                                                                            |

## AWS Network Firewall

|    # | Checklist item                                                | SRA Verify check(s)    | Status  | Note                                                                   |
| ---: | ------------------------------------------------------------- | ---------------------- | ------- | ---------------------------------------------------------------------- |
|    1 | Deployed in the inspection VPC within the Network account     | —                      | Missing | No `networkfirewall` package                                           |
|    2 | All inter-VPC traffic passes through the inspection VPC       | —                      | Missing |                                                                        |
|    3 | Firewall subnet dedicated exclusively to firewall endpoints   | —                      | Missing |                                                                        |
|    4 | Stateful inspection, IPS and web filtering rules configured   | —                      | Missing |                                                                        |
|    5 | Activity visible in real time through CloudWatch metrics      | —                      | Missing |                                                                        |
|    6 | Logs sent to S3, CloudWatch or Data Firehose                  | —                      | Missing |                                                                        |
|    7 | Firewall Manager used to centrally configure and deploy rules | SRA-FIREWALLMANAGER-06 | Partial | Confirms a Network Firewall policy exists, not the deployment topology |
|    8 | Firewall endpoints in every AZ containing protected subnets   | —                      | Missing |                                                                        |

## Amazon Route 53 Resolver DNS Firewall

|    # | Checklist item                                                             | SRA Verify check(s)    | Status  | Note                                                           |
| ---: | -------------------------------------------------------------------------- | ---------------------- | ------- | -------------------------------------------------------------- |
|    1 | Used to prevent DNS exfiltration from VPCs needing DNS protection          | —                      | Missing | No `route53resolver` package                                   |
|    2 | Rule groups configured to block or allow specific domains                  | —                      | Missing |                                                                |
|    3 | Blocks resolution of unauthorized private zones, endpoints, instance names | —                      | Missing |                                                                |
|    4 | Rule groups managed centrally via Firewall Manager or AWS RAM              | SRA-FIREWALLMANAGER-07 | Partial | Confirms a DNS Firewall policy exists in Firewall Manager only |

## AWS Key Management Service

No `kms` service package. All 8 items are Missing. Several service-specific checks do
verify CMK usage for a particular resource (SRA-CLOUDTRAIL-02, SRA-MACIE-04,
SRA-SECURITYLAKE-02, SRA-SECURITYLAKE-03), but none assesses key configuration itself.

|    # | Checklist item                                                           | Status  |
| ---: | ------------------------------------------------------------------------ | ------- |
|    1 | Customer managed keys used for all sensitive data at rest                | Missing |
|    2 | Separate keys per service and per account where appropriate              | Missing |
|    3 | Key policies restrict usage to intended services and principals          | Missing |
|    4 | Automatic annual rotation enabled for customer managed symmetric keys    | Missing |
|    5 | Key administration separated from key usage via distinct IAM permissions | Missing |
|    6 | Key policies use condition keys such as `kms:ViaService`                 | Missing |
|    7 | Key usage audited through CloudTrail                                     | Missing |
|    8 | AWS managed keys used only for non-sensitive or public data              | Missing |

## AWS Private Certificate Authority

No `acmpca` service package. All 6 items are Missing.

|    # | Checklist item                                                         | Status  |
| ---: | ---------------------------------------------------------------------- | ------- |
|    1 | Private CA hierarchy created in the Security Tooling account           | Missing |
|    2 | Root CA protected with stringent controls in Security Tooling          | Missing |
|    3 | Subordinate CAs shared with Application accounts through AWS RAM       | Missing |
|    4 | Private certificates used for internal application communication       | Missing |
|    5 | Certificate lifecycle automated through ACM integration                | Missing |
|    6 | Hierarchy follows limited revocable trust with separate CAs per domain | Missing |

## AWS IAM Identity Center

No `identitystore` / `sso-admin` service package. 7 Missing, 1 Partial.

|    # | Checklist item                                                       | SRA Verify check(s) | Status  | Note                                                                                   |
| ---: | -------------------------------------------------------------------- | ------------------- | ------- | -------------------------------------------------------------------------------------- |
|    1 | Enabled in the organization management account                       | —                   | Missing |                                                                                        |
|    2 | Delegated administration configured to the Shared Services account   | —                   | Missing |                                                                                        |
|    3 | Integrated with a corporate IdP via SAML 2.0 or SCIM                 | —                   | Missing |                                                                                        |
|    4 | Permission sets centrally managed and provisioned to member accounts | —                   | Missing |                                                                                        |
|    5 | MFA enforced for all Identity Center users                           | —                   | Missing |                                                                                        |
|    6 | Access to the delegated administrator account tightly controlled     | —                   | Missing |                                                                                        |
|    7 | Identity Center used instead of IAM users for all human access       | SRA-IAM-01          | Partial | Confirms the absence of IAM users; does not confirm Identity Center is the replacement |
|    8 | Multi-Region replication enabled for workforce identity              | —                   | Missing |                                                                                        |

## AWS Systems Manager

No `ssm` service package. All 8 items are Missing.

|    # | Checklist item                                                     | Status  |
| ---: | ------------------------------------------------------------------ | ------- |
|    1 | Deployed across all member accounts using delegated administration | Missing |
|    2 | All EC2 instances registered as managed instances via SSM Agent    | Missing |
|    3 | Session Manager used instead of SSH or RDP                         | Missing |
|    4 | Patch Manager automates OS and application patching                | Missing |
|    5 | Automation runbooks used for standardized remediation              | Missing |
|    6 | Explorer configured with cross-account sync through Organizations  | Missing |
|    7 | VPC endpoints provisioned for private Systems Manager connectivity | Missing |
|    8 | Compliance data integrated with AWS Config and Security Hub CSPM   | Missing |

## AWS Secrets Manager

No `secretsmanager` service package. All 8 items are Missing.

|    # | Checklist item                                                             | Status  |
| ---: | -------------------------------------------------------------------------- | ------- |
|    1 | All credentials, database passwords and API keys stored in Secrets Manager | Missing |
|    2 | Automatic rotation configured for all secrets that support it              | Missing |
|    3 | Fine-grained IAM and resource policies control access to each secret       | Missing |
|    4 | Secrets encrypted with customer managed keys for sensitive workloads       | Missing |
|    5 | Secret access monitored through CloudTrail                                 | Missing |
|    6 | Config rules configured to detect changes to secrets                       | Missing |
|    7 | Integrated with Amazon RDS for automatic credential management             | Missing |
|    8 | Secrets managed locally in the account closest to their use                | Missing |

---

## SRA Verify checks with no checklist counterpart

These 13 checks assess something the checklist does not state as an item. They are
additional coverage, not gaps.

| Check                  | Title                                                                |
| ---------------------- | -------------------------------------------------------------------- |
| SRA-CLOUDTRAIL-07      | Organization trail is actively publishing events                     |
| SRA-EC2-01             | AWS account level EBS encryption by default is enabled               |
| SRA-S3-01              | S3 restrict public bucket is enabled                                 |
| SRA-S3-02              | S3 block public ACLs is set                                          |
| SRA-S3-03              | S3 ignore public ACL is enabled                                      |
| SRA-S3-04              | S3 block public policy is enabled                                    |
| SRA-FIREWALLMANAGER-05 | Firewall Manager manages Network ACL policies                        |
| SRA-GUARDDUTY-02       | GuardDuty finding frequency is set                                   |
| SRA-GUARDDUTY-16       | GuardDuty member account limit not reached                           |
| SRA-MACIE-10           | Macie member account limit not reached                               |
| SRA-SECURITYHUB-11     | Security Hub member account limit not reached                        |
| SRA-SHIELD-10          | Health checks are configured for Shield Advanced protected resources |
| SRA-SHIELD-11          | Shield engagement Lambda function is configured                      |

## Largest coverage gaps, by size

1. **Six service sections with no package at all** — Detective (9), KMS (8), Systems Manager (8), Secrets Manager (8), IAM Identity Center (7 of 8), Private CA (6). 46 missing items.
2. **Unified Security Hub** (8 items) — the `securityhub` package reads the CSPM API surface only.
3. **Network Firewall and DNS Firewall** (12 items) — visible only through the Firewall Manager policy checks.
4. **Log-repository bucket hardening** (6 items) — CloudTrail items 11 – 14, Security Lake items 16 – 17. No check inspects encryption, Object Lock, versioning, or resource policy on a destination bucket. The `s3` package covers public-access block only.
5. **IAM root access management** (IAM items 2 – 5) — centralized root access is entirely unassessed.
6. **Finding routing and automation** — CSPM items 9, 14 – 17; Config item 7; GuardDuty items 13 – 17; WAF item 10. Enablement is checked thoroughly; where findings and logs *go* is largely not.
