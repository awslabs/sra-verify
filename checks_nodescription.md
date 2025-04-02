
## accessanalyzer
* **Title:** SRA-IAA-1 IAM Access Analyzer external access analyzer is configured with account zone of trust for this region.
* **Title:** SRA-IAA-2 IAM Access Analyzer administration for the AWS Organization has a delegated administrator
* **Title:** SRA-IAA-3 IAM Access Analyzer delegated admin account is the Security Tooling (Audit) account.
* **Title:** SRA-IAA-4 IAM Access Analyzer external access analyzer is configured with Organization zone of trust for this region.
## cloudtrail
* **Title:** SRA-CT-1 An Organization trail is configured for the AWS Organization.
* **Title:** SRA-CT-2 Organization trail is encrypted with KMS.
* **Title:** SRA-CT-3 Organization trail has Log File validation enabled.
* **Title:** SRA-CT-4 Organization Trail is a multi-region trail.
* **Title:** SRA-CT-5 Organization trail is delivering logs to CloudWatch logs
* **Title:** SRA-CT-6 Organization trail is configured to publish events from global services
* **Title:** SRA-CT-7 Organization trail is actively publishing events
* **Title:** SRA-CT-8 Organization trail is publishing logs to destination S3 bucket
* **Title:** SRA-CT-9 Organization trail is publishing logs to CloudWatch Logs
* **Title:** SRA-CT-10 Organization trail is configured to deliver Log file validation digest files to destination bucket
* **Title:** SRA-CT-11 Organization trail Logs are delivered to a centralized S3 bucket in the Log Archive Account
* **Title:** SRA-CT-12 Delegated Administrator set for CloudTrail
* **Title:** SRA-CT-13 The Security Tooling Account is the Delegated Administrator set for Cloudtrail
## config
* **Title:** SRA-CONFIG-1 AWS Config recorder is configured in this region
* **Title:** SRA-CONFIG-2 AWS Config recorder is recording for resource configuration
* **Title:** SRA-CONFIG-3 AWS Config latest recording event is processed successfully
* **Title:** SRA-CONFIG-4 AWS Config has organization aggregator
* **Title:** SRA-CONFIG-5 AWS Config organization aggregator includes all regions
* **Title:** SRA-CONFIG-6 AWS Config delivery channel S3 bucket is centralized in Security Tooling account
* **Title:** SRA-CONFIG-7 AWS Config last config history delivery is successful 
* **Title:** SRA-CONFIG-8 AWS Config rule exists in all member accounts
* **Title:** SRA-CONFIG-9 Config administration for the AWS Organization has a delegated administrator
* **Title:** SRA-CONFIG-10 Config delegated admin account is the Security Tooling (Audit) account
* **Title:** SRA-CONFIG-11 Config Organization aggregator is in a valid status
## ec2
* **Title:** SRA-EC2-1 AWS account level EBS encryption by default is enabled
## guardduty
* **Title:** SRA-GD-1 Guard Duty detector exists
* **Title:** SRA-GD-2 GuardDuty finding frequency is set
* **Title:** SRA-GD-3 GuardDuty detector is enabled
* **Title:** SRA-GD-4 GuardDuty has DNS logs as a log source enabled.
* **Title:** SRA-GD-5 GuardDuty has VPC flow logs as a log source enabled.
* **Title:** SRA-GD-6 GuardDuty has S3 protection enabled.
* **Title:** SRA-GD-7 GuardDuty has EKS protection enabled.
* **Title:** SRA-GD-8 GuardDuty has malware protection for S3 enabled.
* **Title:** SRA-GD-9 GuardDuty has CloudTrail logs as feature enabled.
* **Title:** SRA-GD-10 Checks detector feature DNS Logs status
* **Title:** SRA-GD-11 GuardDuty has VPC flow logs feature enabled.
* **Title:** SRA-GD-12 GuardDuty has S3 protection feature enabled.
* **Title:** SRA-GD-13 GuardDuty has EKS protection feature enabled.
* **Title:** SRA-GD-14 GuardDuty has malware protection for EBS enabled.
* **Title:** SRA-GD-15 GuardDuty has RDS protection enabled.
* **Title:** SRA-GD-16 GuardDuty has EKS runtime monitoring enabled.
* **Title:** SRA-GD-17 GuardDuty has Lambda protection enabled.
* **Title:** SRA-GD-18 GuardDuty has runtime monitoring enabled.
* **Title:** SRA-GD-19 GuardDuty administration for the AWS Organization has a delegated administrator
* **Title:** SRA-GD-20 GuardDuty delegated admin account is the Security Tooling (Audit) account
* **Title:** SRA-GD-21 GuardDuty AutoEnable configuration is enabled for member accounts
* **Title:** SRA-GD-22 GuardDuty member account limit not reached
* **Title:** SRA-GD-23 All active member accounts have GuardDuty protection enabled
* **Title:** SRA-GD-24 GuardDuty member account status is enabled
* **Title:** SRA-GD-25 Checks the presence of a single administrator account
* **Title:** SRA-GD-26 Checks the administrator account status is enabled
## inspector
* **Title:** SRA-inspector-1 Inspector service status is enabled
* **Title:** SRA-inspector-2 Inspector has EC2 instance scanning enabled
* **Title:** SRA-inspector-3 Inspector has ECR scanning enabled
* **Title:** SRA-inspector-4 Inspector has Lambda scanning enabled
* **Title:** SRA-inspector-5 Inspector administration for the AWS Organization has a delegated administrator
* **Title:** SRA-inspector-6 Inspector delegated admin account is the Security Tooling (Audit) account
* **Title:** SRA-inspector-7 All active member accounts have Inspector enabled
* **Title:** SRA-inspector-8 Inspector has EC2 instance scanning auto-enabled for member accounts
* **Title:** SRA-inspector-9 Inspector has ECR image scanning auto-enabled for member accounts
* **Title:** SRA-inspector-10 Inspector has Lambda functions and layers scanning auto-enabled for member accounts
* **Title:** SRA-inspector-11 Inspector member account limit not reached
## macie
* **Title:** SRA-macie-1 Macie publish policy findings to Security Hub is enabled
* **Title:** SRA-macie-2 Macie publish classification findings to Security Hub is enabled
* **Title:** SRA-macie-3 Macie findings exported to a S3 bucket in Log Archive account are encrypted at rest
* **Title:** SRA-macie-4 Checks that findings are being exported to S3 in the log archive account are encrypted at rest
* **Title:** SRA-macie-5 Macie administration for the AWS Organization has a delegated administrator
* **Title:** SRA-macie-6 Macie delegated admin account is the Security Tooling (Audit) account
* **Title:** SRA-macie-7 All active member accounts have relationship with delegated admin account enabled.
* **Title:** SRA-macie-8 Macie AutoEnable configuration is enabled for new member accounts
* **Title:** SRA-macie-9 All active member accounts have Macie enabled
* **Title:** SRA-macie-10 Macie member account limit not reached
## s3control
* **Title:** SRA-S3-2 S3 block public ACLs is set
* **Title:** SRA-S3-3 S3 ignore public ACL is enabled. 
* **Title:** SRA-S3-4 S3 block public policy is enabled
* **Title:** SRA-S3-5 S3 restrict public bucket is enabled
## securityhub
* **Title:** SRA-SH-1 Security Hub enabled account level standards  matches the delegated admin configuration
* **Title:** SRA-SH-2 Security Hub auto-enable new controls is enabled
* **Title:** SRA-SH-3 Security Hub administration for the account matches delegated administrator
* **Title:** SRA-SH-4 Security Hub administrator account is enabled.
* **Title:** SRA-SH-5 Security Hub integration with findings generating products
* **Title:** SRA-SH-6 Security Hub administration for the AWS Organization has a delegated administrator
* **Title:** SRA-SH-7 Security Hub delegated admin account is the Security Tooling (Audit) account
* **Title:** SRA-SH-8 All active member accounts are Security Hub members
* **Title:** SRA-SH-9 Security Hub member accounts has enabled status
* **Title:** SRA-SH-10 Security Hub auto-enable is configured
* **Title:** SRA-SH-11 Security Hub member account limit not reached
## securitylake
* **Title:** SRA-ASL-1 Amazon Security Lake is Enabled for this region
* **Title:** SRA-ASL-2 Amazon Security Lake SQS Queues within delegated admin account  is encrypted with customer managed key (from KMS key) in this region
* **Title:** SRA-ASL-3 Amazon Security Lake SQS Dlq within delegated admin account is encrypted with customer managed key (from KMS key) in this region
* **Title:** SRA-ASL-4 Amazon Security Lake organization configuration is enabled
* **Title:** SRA-ASL-5 Amazon Security Lake organization configuration matches expected configuration
* **Title:** SRA-ASL-6 Route 53 log source is enabled for Amazon Security Lake  in all or specified active member accounts,
* **Title:** SRA-ASL-7 CloudTrail data event for S3 log source is enabled for Amazon Security Lake in all or specified active member accounts
* **Title:** SRA-ASL-8 Security Hub findings log source is enabled for Amazon Security Lake in all or specified active member accounts
* **Title:** SRA-ASL-9 EKS Audit log source is enabled for Amazon Security Lake in all or specified active member accounts
* **Title:** SRA-ASL-10 Lambda execution log source is enabled for Amazon Security Lake in all or specified active member accounts
* **Title:**  SRA-ASL-11 CloudTrail management log source is enabled for Amazon Security Lake in all or specified active member accounts
* **Title:** SRA-ASL-12 AWS WAF log source is enabled for Amazon Security Lake in all or specified active member accounts
* **Title:** SRA-ASL-13 VPC Flow log source is enabled for Amazon Security Lake in all or specified active member accounts
* **Title:** SRA-ASL-14 Amazon Security Lake administration for the AWS Organization has a delegated administrator
* **Title:** SRA-ASL-15 Amazon Security Lake delegated admin account is the Log Archive account
* **Title:** SRA-ASL-16 Security tooling (Audit) account is set up as query access subscriber
* **Title:** SRA-ASL-17 Security tooling (Audit) account is set up as data access subscriber
* **Title:** SRA-ASL-18 Amazon Security Lake is successfully collecting data from its source