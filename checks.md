
## accessanalyzer
* **Title:** SRA-IAA-1 IAM Access Analyzer external access analyzer is configured with account zone of trust for this region.
    * **Description:** SRA-IAA-1 This check verifies whether IAA external access analyzer is configured with a zone of trust of AWS account. IAM Access Analyzer generates a finding for each instance of a resource-based policy that grants access to a resource within your zone of trust to a principal that is not within your zone of trust. When you configure an AWS account as the zone of trust for an analyzer- IAA generates findings or each instance of a resource-based policy that grants access to a resource within your AWS account whether the analyzer exists to a principal that is not within your AWS account.
    * **Check Type:** Account
    * **Multi-Region:** Yes
* **Title:** SRA-IAA-2 IAM Access Analyzer administration for the AWS Organization has a delegated administrator
    * **Description:** SRA-IAA-2 This check verifies whether IAA service administration for your AWS Organization is delegated out of your AWS Organization management account. The delegated administrator has permissions to create and manage analyzers with the AWS organization as the zone of trust.
    * **Check Type:** Organization
* **Title:** SRA-IAA-3 IAM Access Analyzer delegated admin account is the Security Tooling (Audit) account.
    * **Description:** SRA-IAA-3 This check verifies whether IAA delegated admin account is the security tooling account of your AWS organization. Security Tooling account is dedicated to operating security services, monitoring AWS accounts, and automating security alerting and response. IAA helps monitor resources shared outside zone of trust.
    * **Check Type:** Organization
* **Title:** SRA-IAA-4 IAM Access Analyzer external access analyzer is configured with Organization zone of trust for this region.
    * **Description:** SRA-IAA-4 This check verifies whether IAA external access analyzer is configured with a zone of trust of your AWS organization. IAM Access Analyzer generates a finding for each instance of a resource-based policy that grants access to a resource within your zone of trust to a principal that is not within your zone of trust. When you configure an organization as the zone of trust for an analyzer- IAA generates findings or each instance of a resource-based policy that grants access to a resource within your AWS organization to a principal that is not within your AWS organization.
    * **Check Type:** Organization

## cloudtrail
* **Title:** SRA-CT-1 An Organization trail is configured for the AWS Organization.
    * **Description:** SRA-CT-1 This check verifies that an organization trail is configured for your AWS Organization. It is important to have uniform logging strategy for your AWS environment. Organization trail logs all events for all AWS accounts in that organization and delivers logs to a single S3 bucket, CloudWatch Logs and Event Bridge. Organization trails are automatically applied to all member accounts in the organization. Member accounts can see the organization trail, but can't modify or delete it. Organization trail should be configured for all AWS regions even if you are not operating out of any region.
    * **Check Type:** Organization
* **Title:** SRA-CT-2 Organization trail is encrypted with KMS.
    * **Description:** SRA-CT-2 This check verifies that your organization trail is encrypted with a KMS key. Log files delivered by CloudTrail to your bucket should be encrypted by using SSE-KMS. This is selected by default in the console but can be altered by users. With SSE-KMS you create and manage the KMS key yourself with the ability to manage permissions on who can use the key. For a user to read log files they must have read permissions to the bucket and have permissions that allows decrypt permission on the key applied by the KMS key policy.
    * **Check Type:** Organization
* **Title:** SRA-CT-3 Organization trail has Log File validation enabled.
    * **Description:** SRA-CT-3 This check verifies that your organization trail has log file validation enabled. Validated log files are especially valuable in security and forensic investigations. CloudTrail log file integrity validation uses industry standard algorithms: SHA-256 for hashing and SHA-256 with RSA for digital signing. This makes it computationally unfeasible to modify, delete or forge CloudTrail log files without detection.
    * **Check Type:** Organization
* **Title:** SRA-CT-4 Organization Trail is a multi-region trail.
    * **Description:** SRA-CT-4 This check verifies whether the Organization trail is configured as a multi-region trail. This helps with visibility across your entire AWS environment, even for AWS Regions where you are not operating to ensure you detect any malicious and/or unauthorized activities. 
    * **Check Type:** Organization
* **Title:** SRA-CT-5 Orgzanization trail is delivering logs to CloudWatch logs
    * **Description:** SRA-CT-5 This check verifies that last delivery of cloudtrail logs to CloudWatch Logs was successful. CloudWatch Logs enables you to centralize the cloudtrail logs from all your AWS accounts and regions in the AWS Organization, to a single, highly scalable service. You can then easily view them, search them for specific error codes or patterns, filter them based on specific fields, or archive them securely for future analysis.
    * **Check Type:** Organization
* **Title:** SRA-CT-6 Organization trail is configured to publish events from global services
    * **Description:** SRA-CT-6 This check verifies that your organization trail is configured to publish event from AWS global services. The organization trail should capture events from global services such as AWS IAM, AWS STS and Amazon CloudFront. Trails created using CloudTrail console by default have global service event configured but if you are creating trail with AWS CLI, AWS SDKs, or CloudTrail API you have to specify to included global services events.
    * **Check Type:** Organization
* **Title:** SRA-CT-7 Organization trail is actively publishing events
    * **Description:** SRA-CT-7 This check verifies that your organization trail is running and actively logging events. If a trail is modified to stop logging, accidently or by malicious user, you will not have visibility into any API activity across your AWS environment. 
    * **Check Type:** Account
    * **Multi-Region:** Yes
* **Title:** SRA-CT-8 Organization trail is publishing logs to destination S3 bucket
    * **Description:** SRA-CT-8 This check verifies that last attempt to send CloudTrail logs to S3 bucket was successful. CloudTrail log files are an audit log of actions taken by an IAM identity or an AWS service. The integrity, completeness and availability of these logs is crucial for forensic and auditing purposes. By logging to a dedicated and centralized Amazon S3 bucket, you can enforce strict security controls, access, and segregation of duties. 
    * **Check Type:** Organization
* **Title:** SRA-CT-9 Organization trail is publishing logs to CloudWatch Logs
    * **Description:** SRA-CT-9 This check verifies that last attempt to send CloudTrail logs to CloudWatch Logs was successful. Successful delivery of CloudTrails logs to CloudWatch ensures later availability for monitoring. CloudTrail requires right permission to send log events to CloudWatch Logs.
    * **Check Type:** Organization
* **Title:** SRA-CT-10 Organization trail is configured to deliver Log file validation digest files to destination bucket
    * **Description:** SRA-CT-10 This check verifies that log file validation digest files are being successfully delivered to a S3 bucket.
    * **Check Type:** Organization
* **Title:** SRA-CT-11 Organization trail Logs are delivered to a centralized S3 bucket in the Log Archive Account
    * **Description:** SRA-CT-11 This check verifies whether the corresponding S3 buckets that stores organization trail logs in created in Log Archive account. This separates the management and usage of CloudTrail log privileges. The Log Archive account is dedicated to ingesting and archiving all security-related logs and backups.
    * **Check Type:** Organization
* **Title:** SRA-CT-12 Delegated Administrator set for CloudTrail
    * **Description:** SRA-CT-12 This check verifies whether CloudTrail service administration for the AWS Organization is delegated out to AWS Organization management account. The delegated administrator has permissions to create and manage analyzers with the AWS organization as the zone of trust.
    * **Check Type:** Organization
* **Title:** SRA-CT-13 The Security Tooling Account is the Delegated Administrator set for Cloudtrail
    * **Description:** SRA-CT-13 This check verifies whether CloudTrail delegated admin account is the security tooling account of your AWS organization. Security Tooling account is dedicated to operating security services, monitoring AWS accounts, and automating security alerting and response. CloudTrail helps monitor API activities across all your AWS accounts and regions.
    * **Check Type:** Organization
## config
* **Title:** SRA-CONFIG-1 AWS Config recorder is configured in this region
    * **Description:** SRA-CONFIG-1 This check verifies that a configuration recorders exists in the AWS Region. AWS Config uses the configuration recorder to detect changes in your resource configurations and capture these changes as configuration items. You must create a configuration recorder in every AWS Region for AWS Config can track your resource configurations in the region.
    * **Check Type:** Account
    * **Multi-Region:** Yes
* **Title:** SRA-CONFIG-2 AWS Config recorder is recording for resource configuration
    * **Description:** SRA-CONFIG-2 This check verifies that configuration recorder is running. AWS Config configuration recorder must be started and running to record resource configurations. If you set up AWS Config by using the console or the AWS CLI, AWS Config automatically creates and then starts the configuration recorder for you. Users with right permission have the ability to stop configuration recorder.
* **Title:** SRA-CONFIG-3 AWS Config lastest recording event is processed succesfully
    * **Description:** SRA-CONFIG-3 This check verifies whether the last delivery attempt to the delivery channel was successful to ensure you receive configuration change notifications. As AWS Config continually records the changes that occur to your AWS resources, it sends notifications and updated configuration states through the delivery channel.
* **Title:** SRA-CONFIG-4 AWS Config has organization aggregator
    * **Description:** SRA-CONFIG-4 This check verifies that a AWS Config aggregator exists in the AWS Region that collects configuration and compliance data from all member accounts of the AWS Organization. It periodically retrieves configuration snapshots from the source accounts and stores them in the designated S3 bucket.
* **Title:** SRA-CONFIG-5 AWS Config organization aggregator includes all regions
    * **Description:** SRA-CONFIG-5 This check verifies that the AWS Config organization aggregator is configured to aggregate config data from all existing and future AWS Regions. This provides you visibility into activities across all regions even if your business do not operate in the region. 
* **Title:** SRA-CONFIG-6 AWS Config delivery channel S3 bucket is centralized in Security Tooling account
    * **Description:** SRA-CONFIG-6 This check verifies that the AWS Config delivery channel S3 bucket is centralized in Security Tooling (Audit) account. Security Tooling provides central visibility and monitoring of AWS Organization wide resource configuration.
* **Title:** SRA-CONFIG-7 AWS Config last config history delivery is successful 
    * **Description:** SRA-CONFIG-7 This check verifies that the last delivery of resource config history by AWS config into the delivery channel was successful 
* **Title:** SRA-CONFIG-8 AWS Config rule exisists in all member accounts
    * **Description:** SRA-CONFIG-8 This check verifies the presence of specific AWS Config rule/s across all member accounts in the AWS Organization. To specify the list of config rules to check, update the utils.py file. 
* **Title:** SRA-CONFIG-9 Config administration for the AWS Organization has a delegated administrator
    * **Description:** SRA-CONFIG-9 This check verifies whether Config service administration for your AWS Organization is delegated out of the AWS Organization management account. 
* **Title:** SRA-CONFIG-10 Config delegated admin account is the Security Tooling (Audit) account
    * **Description:** SRA-CONFIG-10 This check verifies whether Config delegated admin account is the security tooling account of your AWS organization. Security Tooling account is dedicated to operating security services, monitoring AWS accounts, and automating security alerting and response.
* **Title:** SRA-CONFIG-11 Config Organization aggregator is in a valid status
    * **Description:** SRA-CONFIG-11 This check verifies whether Config Organization aggregator has a valid status. A value of FAILED indicates errors while moving data and value OUTDATED indicates the data is not the most recent.
## ec2
* **Title:** SRA-EC2-1 AWS account level EBS encryption by default is enabled
    * **Description:** SRA-EC2-1 This check verifies that the AWS account level configuration to encrypt EBS volumes by default is enabled in the AWS Region. This enforces, at AWS account level, the encryption of the new EBS volumes and snapshot copies that you create. You can use AWS managed keys or a customer managed KMS key.
## guardduty
* **Title:** SRA-GD-1 GuardDuty detector exists
    * **Description:** SRA-GD-1 This check verifies that an GuardDuty detector exists in the AWS Region. A detector is a resource that represents the GuardDuty service and should be present in all AWS member account and AWS Region so that GuardDuty can generate findings about unauthorized or unusual activity even in those Regions that you may not be using actively.
* **Title:** SRA-GD-2 GuardDuty finding frequency is set
    * **Description:** SRA-GD-2 This check verifies that the GuardDuty finding frequency is set as per your organization requirement. This determines how often updates to active findings are exported to EventBridge, S3 (optional) and Detective (optional). By default, updated findings are exported every 6 hours but you can set to every 15 minutes or 1 hour.
* **Title:** SRA-GD-3 GuardDuty detector is enabled
    * **Description:** SRA-GD-3 This check verifies that the GuardDuty detector in the AWS account and AWS region is enabled. Detector represents GuardDuty service in the AWS account and specific region, if disabled will not provided threat intelligence service.
* **Title:** SRA-GD-4 GuardDuty has DNS logs as a log source enabled.
    * **Description:** SRA-GD-4 This check verifies that GuardDuty has DNS logs as one of the log sources, enabled. If you use AWS DNS resolvers for your Amazon EC2 instances (the default setting), then GuardDuty can access and process your request and response DNS logs through the internal AWS DNS resolvers.
* **Title:** SRA-GD-5 GuardDuty has VPC flow logs as a log source enabled.
    * **Description:** SRA-GD-5 This check verifies that GuardDuty has VPC flow logs as one of the log sources, enabled.GuardDuty analyzes your VPC flow logs from Amazon EC2 instances within your account. It consumes VPC flow log events directly from the VPC Flow Logs feature through an independent and duplicative stream of flow logs.
* **Title:** SRA-GD-6 GuardDuty has S3 protection enabled.
    * **Description:** SRA-GD-6 This check verifies that GuardDuty has S3 protection enabled. GuardDuty provides enhanced visibility through S3 protection. GuardDuty monitors both AWS CloudTrail management events and AWS CloudTrail S3 data events to identify potential threats in your Amazon S3 resources.
* **Title:** SRA-GD-7 GuardDuty has EKS protection enabled.
    * **Description:** SRA-GD-7 This check verifies that GuardDuty has EKS protection enabled. EKS Audit Log Monitoring helps you detect potentially suspicious activities in your EKS clusters within Amazon Elastic Kubernetes Service. It consumes Kubernetes audit log events directly from the Amazon EKS control plane logging feature through an independent and duplicative stream of audit logs.
* **Title:** SRA-GD-8 GuardDuty has malware protection for S3 enabled.
    * **Description:** SRA-GD-8 This check verifies that GuardDuty malware protection for S3 is enabled. Malware Protection for S3 helps  detect potential presence of malware by scanning newly uploaded objects to your selected Amazon S3 bucket.
* **Title:** SRA-GD-9 GuardDuty has CloudTrail logs as feature enabled.
    * **Description:** SRA-GD-9 This check verifies that GuardDuty has CloudTrail event and management logs as one of the feature, enabled. GuardDuty consumes CloudTrail management events directly from CloudTrail through an independent and duplicated stream of events and analyzes the CloudTrail event logs.
* **Title:** SRA-GD-10 Checks detector feature DNS Logs status
    * **Description:** SRA-GD-10 This check verifies that GuardDuty detector has DNS logs as one of the features. If you use AWS DNS resolvers for your Amazon EC2 instances (the default setting), then GuardDuty can access and process your request and response DNS logs through the internal AWS DNS resolvers.
* **Title:** SRA-GD-11 GuardDuty has VPC flow logs feature enabled.
    * **Description:** SRA-GD-11 This check verifies that GuardDuty detector has VPC flow logs as one of the features, enabled.GuardDuty analyzes your VPC flow logs from Amazon EC2 instances within your account. It consumes VPC flow log events directly from the VPC Flow Logs feature through an independent and duplicative stream of flow logs.
* **Title:** SRA-GD-12 GuardDuty has S3 protection feature enabled.
    * **Description:** SRA-GD-12 This check verifies that GuardDuty detector has S3 protection feature enabled. GuardDuty provides enhanced visibility through S3 protection. GuardDuty monitors both AWS CloudTrail management events and AWS CloudTrail S3 data events to identify potential threats in your Amazon S3 resources.
* **Title:** SRA-GD-13 GuardDuty has EKS protection feature enabled.
    * **Description:** SRA-GD-13 This check verifies that GuardDuty detector has EKS protection feature enabled. EKS Audit Log Monitoring helps you detect potentially suspicious activities in your EKS clusters within Amazon Elastic Kubernetes Service. It consumes Kubernetes audit log events directly from the Amazon EKS control plane logging feature through an independent and duplicative stream of audit logs.
* **Title:** SRA-GD-14 GuardDuty has malware protection for EBS enabled.
    * **Description:** SRA-GD-14 This check verifies that GuardDuty malware protection for EBS is enabled. Malware Protection for EC2 helps you detect the potential presence of malware by scanning the Amazon EBS volumes that are attached to the Amazon EC2 instances and container workloads.
* **Title:** SRA-GD-15 GuardDuty has RDS protection enabled.
    * **Description:** SRA-GD-15 This check verifies that GuardDuty RDS protection is enabled. RDS Protection in Amazon GuardDuty analyzes and profiles RDS login activity for potential access threats to Amazon Aurora databases and Amazon RDS for PostgreSQL.
* **Title:** SRA-GD-16 GuardDuty has EKS runtime monitoring enabled.
    * **Description:** SRA-GD-16 This check verifies that GuardDuty EKS runtime protection is enabled. Runtime Monitoring observes and analyzes operating system-level, networking, and file events to help you detect potential threats in specific AWS workloads (EKS).
* **Title:** SRA-GD-17 GuardDuty has Lambda protection enabled.
    * **Description:** SRA-GD-17 This check verifies that GuardDuty Lambda protection is enabled. Lambda Protection helps identify potential security threats when an AWS Lambda function gets invoked in the AWS environment.
* **Title:** SRA-GD-18 GuardDuty has runtime monitoring enabled.
    * **Description:** SRA-GD-18 This check verifies that GuardDuty runtime protection is enabled. Runtime Monitoring observes and analyzes operating system-level, networking, and file events to help you detect potential threats in specific AWS workloads (ECS Fargate, EC2).
* **Title:** SRA-GD-19 GuardDuty administration for the AWS Organization has a delegated administrator
    * **Description:** SRA-GD-19 This check verifies whether GuardDuty service administration for the AWS Organization is delegated out to AWS Organization management account. 
* **Title:** SRA-GD-20 GuardDuty delegated admin account is the Security Tooling (Audit) account
    * **Description:** SRA-GD-20 This check verifies whether GuardDuty delegated admin account is the security tooling account of your AWS organization. Security Tooling account is dedicated to operating security services, monitoring AWS accounts, and automating security alerting and response. IGuardDuty helps monitor resources for unusual and suspicious activities.
* **Title:** SRA-GD-21 GuardDuty AutoEnable configuration is enabled for member accounts
    * **Description:** SRA-GD-21 This check verifies whether auto-enablement configuration for GuardDuty and its corresponding protection plan is enabled for member accounts of the AWS Organization. This ensures that all existing and new member accounts will have GuardDuty monitoring.
* **Title:** SRA-GD-22 GuardDuty member account limit not reached
    * **Description:** SRA-GD-22 This check verifies whether the maximum number of allowed member accounts are already associated with the delegated administrator account for the AWS Organization.
* **Title:** SRA-GD-23 All active member accounts have GuardDuty protection enabled
    * **Description:** SRA-GD-23 This check verifies whether all active members accounts of the AWS Organization have GuardDuty enabled. GuardDuty provides threat intelligence service and service coverage should include all AWS accounts.
* **Title:** SRA-GD-24 GuardDuty member account status is enabled
    * **Description:** SRA-GD-24 This check verifies whether the relationship status between GuardDuty administrator and members is enabled.
* **Title:** SRA-GD-25 Checks the presence of a single administrator account
    * **Description:** SRA-GD-25 DESC: Checks the presence of a single administrator account
* **Title:** SRA-GD-26 Checks the administrator account status is enabled
    * **Description:** SRA-GD-26 DESC: Checks the administrator account status is enabled
## inspector
* **Title:** SRA-inspector-1 Inspector service status is enabled
    * **Description:** SRA-inspector-1 This check verifies whether Inspector service status for the account is enabled. Amazon Inspector is a vulnerability management service that continuously scans your AWS workloads for software vulnerabilities and unintended network exposure.
* **Title:** SRA-inspector-2 Inspector has EC2 instance scanning enabled
    * **Description:** SRA-inspector-2 This check verifies whether Inspector EC2 vulnerability scanning feature is enabled. Inspector automatically discovers EC2 instances and scans for software vulnerability. 
* **Title:** SRA-inspector-3 Inspector has ECR scanning enabled
    * **Description:** SRA-inspector-3 This check verifies whether Inspector ECR image vulnerability scanning feature is enabled. Amazon Inspector scans container images stored in Amazon ECR for software vulnerabilities to generate findings.
* **Title:** SRA-inspector-4 Inspector has Lambda scanning enabled
    * **Description:** SRA-inspector-4 This check verifies whether Inspector Lambda function and layers for package and code vulnerability. Amazon Inspector monitors each Lambda function throughout its lifetime until it's either deleted or excluded from scanning.
* **Title:** SRA-inspector-5 Inspector administration for the AWS Organization has a delegated administrator
    * **Description:** SRA-inspector-5 This check verifies whether Inspector service administration for the AWS Organization is delegated out of AWS Organization management account to a member account.
* **Title:** SRA-inspector-6 Inspector delegated admin account is the Security Tooling (Audit) account
    * **Description:** SRA-inspector-6 This check verifies whether Inspector delegated admin account is the security tooling account of your AWS organization. Security Tooling account is dedicated to operating security services, monitoring AWS accounts, and automating security alerting and response. Inspector provides vulnerability management service.
* **Title:** SRA-inspector-7 All active member accounts have Inspector enabled
    * **Description:** SRA-inspector-7 This check verifies whether all active members accounts of the AWS Organization have Inspector enabled. Inspector is an automated vulnerability management service that continually scans Amazon Elastic Compute Cloud (EC2), AWS Lambda functions, and container images in Amazon ECR.
* **Title:** SRA-inspector-8 Inspector has EC2 instance scanning auto-enabled for member accounts
    * **Description:** SRA-inspector-8 This check verifies whether auto-enablement configuration for Inspector EC2 instance scanning is enabled for member accounts of the AWS Organization. This ensures that all existing and new member accounts will have EC2 vulnerability scanning.
* **Title:** SRA-inspector-9 Inspector has ECR image scanning auto-enabled for member accounts
    * **Description:** SRA-inspector-9 This check verifies whether auto-enablement configuration for Inspector ECR image scanning is enabled for member accounts of the AWS Organization. This ensures that all existing and new member accounts will have ECR image vulnerability scanning.
* **Title:** SRA-inspector-10 Inspector has Lambda functions and layers scanning auto-enabled for member accounts
    * **Description:** SRA-inspector-10 This check verifies whether auto-enablement configuration for Inspector Lambda functions and layers scanning is enabled for member accounts of the AWS Organization. This ensures that all existing and new member accounts will have Lambda functions and layers vulnerability scanning.
* **Title:** SRA-inspector-11 Inspector member account limit not reached
    * **Description:** SRA-inspector-11 This check verifies whether the maximum number of allowed member accounts are already associated with the delegated administrator account for the AWS Organization.
## macie
* **Title:** SRA-macie-1 Macie publish policy findings to Security Hub is enabled
    * **Description:** SRA-macie-1 This check verifies whether Macie is configured to publish new and updated policy findings to AWS Security Hub. Policy findings denotes potential security or privacy issue with a S3 bucket.
* **Title:** SRA-macie-2 Macie publish classification findings to Security Hub is enabled
    * **Description:** SRA-macie-2 This check verifies whether Macie is configured to publish sensitive data findings to AWS Security Hub. Sensitive data findings denotes potential sensitive data in as S3 object. Macie continually evaluates your S3 bucket inventory and uses sampling techniques to identify and select representative S3 objects from your buckets. Macie then retrieves and analyzes the selected objects, inspecting them for sensitive data.
* **Title:** SRA-macie-3 Macie findings exported to a S3 bucket in Log Archive account are encrypted at rest
    * **Description:** SRA-macie-3 This check verifies whether all Macie findings are being exported to a S3 bucket within the Log Archive account. Log Archive account is the central repository of all AWS Organization logs.
* **Title:** SRA-macie-4 Checks that findings are being exported to S3 in the log archive account are encrypted at rest
    * **Description:** SRA-macie-4 This check verifies whether all Macie findings that are being exported to a S3 bucket within the Log Archive account are encrypted using KMS key. Macie findings are sensitive in natures and should be encrypted to prevent from unauthorized disclosure.
* **Title:** SRA-macie-5 Macie administration for the AWS Organization has a delegated administrator
    * **Description:** SRA-macie-5 This check verifies whether Macie service administration for the  AWS Organization is delegated out to AWS Organization management account.
* **Title:** SRA-macie-6 Macie delegated admin account is the Security Tooling (Audit) account
    * **Description:** SRA-macie-6 This check verifies whether Macie delegated admin account is the security tooling account of your AWS organization. Security Tooling account is dedicated to operating security services, monitoring AWS accounts, and automating security alerting and response. Macie provides sensitive data discovery service.
* **Title:** SRA-macie-7 All active member accounts have relationship with delegated admin account enabled.
    * **Description:** SRA-macie-7 This check verifies whether all active members accounts of the AWS Organization have Macie member relationship enabled with Macie delgated admin account. Amazon Macie is a data security service that discovers sensitive data by using machine learning and pattern matching, provides visibility into data security risks, and enables automated protection against those risks.
* **Title:** SRA-macie-8 Macie AutoEnable configuration is enabled for new member accounts
    * **Description:** SRA-macie-8 This check verifies whether auto-enablement configuration for Macie is enabled for member accounts of the AWS Organization. This ensures that all existing and new member accounts will have Macie monitoring.
* **Title:** SRA-macie-9 All active member accounts have Macie enabled
    * **Description:** SRA-macie-9 This check verifies whether all active members accounts of the AWS Organization have Macie enabled. Amazon Macie is a data security service that discovers sensitive data by using machine learning and pattern matching, provides visibility into data security risks, and enables automated protection against those risks.
* **Title:** SRA-macie-10 Macie member account limit not reached
    * **Description:** SRA-macie-10 This check verifies whether the maximum number of allowed member accounts are already associated with the delegated administrator account for the AWS Organization.
## s3control
* **Title:** SRA-S3-2 S3 block public ACLs is set
    * **Description:** SRA-S3-2 This check verifies whether S3 public block access control lists (ACLs) for buckets and object is enabled. Setting this fails prevents from setting a public ACL on S3 buckets and Objects. It also prevent creating a bucket with public ACL and uploading a object with public ACL.
* **Title:** SRA-S3-3 S3 ignore public ACL is enabled. 
    * **Description:** SRA-S3-3 This check verifies whether the IgnorePublicACLs is set to True. Setting this causes Amazon S3 to ignore all public ACLs on buckets and objects in the bucket.
* **Title:** SRA-S3-4 S3 block public policy is enabled
    * **Description:** SRA-S3-4 This check verifies whether S3 should block public bucket policies for buckets. Setting this causes Amazon S3 to reject calls that attaches a public access bucket policy to a S3 bucket.
* **Title:** SRA-S3-5 S3 restrict public bucket is enabled
    * **Description:** SRA-S3-5 This check verifies whether S3 should restrict public policies for S3 buckets. Setting this restricts access to this bucket to only AWS service principals and authorized users within this account if the bucket has a public policy.
## securityhub
* **Title:** SRA-SH-1 Security Hub enabled account level standards  matches the delegated admin configuration
    * **Description:** SRA-SH-1 This check verifies whether the list of enabled Security Hub standards for the current AWS account matches with the list if standards enabled though Security Hub delegated admin (Security Tooling) account. Security Hub delegated admin account should be used to enforce standard configuration across the AWS Organization.
* **Title:** SRA-SH-2 Security Hub auto-enable new controls is enabled
    * **Description:** SRA-SH-2 This check verifies whether Security Hub is configured to auto-enable new security controls as they are added to existing standards. This will ensure that as existing standard are updated new controls the AWS account gets evaluated on those new controls.
* **Title:** SRA-SH-3 Security Hub administration for the account matches delegated administrator
    * **Description:** SRA-SH-3 This check verifies whether Security Hub service administration for the AWS account is set to AWS Organization delegated admin account for Security Hub. This check is only applicable if Security Hub member account has been setup through invitation method only and not through integration with AWS Organization.
* **Title:** SRA-SH-4 Security Hub administrator account is enabled.
    * **Description:** SRA-SH-4 This check verifies whether Security Hub administrator account is enabled. Administrator account has access to view findings for associated member accounts.
* **Title:** SRA-SH-5 Security Hub integration with findings generating products
    * **Description:** SRA-SH-5 This check verifies whether Security Hub has expected integration with AWS services and third party products to ingest security findings.
* **Title:** SRA-SH-6 Security Hub administration for the AWS Organization has a delegated administrator
    * **Description:** SRA-SH-6 This check verifies whether Security Hub service administration for the AWS Organization  is set to AWS Organization delegated admin account for Security Hub.
* **Title:** SRA-SH-7 Security Hub delegated admin account is the Security Tooling (Audit) account
    * **Description:** SRA-SH-7 This check verifies whether GuardDuty delegated admin account is the security tooling account of your AWS organization. Security Tooling account is dedicated to operating security services, monitoring AWS accounts, and automating security alerting and response. AWS Security Hub provides a comprehensive view of the security state in AWS and helps assess AWS environment against security industry standards and best practices.
* **Title:** SRA-SH-8 All active member accounts are Security Hub members
    * **Description:** SRA-SH-8 This check verifies whether all active members accounts of the AWS Organization are Security Hub members Security Hub provides comprehensive security state and should include all AWS accounts.
* **Title:** SRA-SH-9 Security Hub member accounts has enabled status
    * **Description:** SRA-SH-9 This check verifies whether each Security Hub member account member status enabled. Indicates that the member account is currently active. For manually invited member accounts, indicates that the member account accepted the invitation.
* **Title:** SRA-SH-10 Security Hub auto-enable is configured
    * **Description:** SRA-SH-10 This check verifies whether Security Hub is configured to be automatically enabled for new member accounts when they join the organization.
* **Title:** SRA-SH-11 Security Hub member account limit not reached
    * **Description:** SRA-SH-11 This check verifies whether the maximum number of allowed member accounts are already associated with the delegated administrator account for the AWS Organization.
## securitylake
* **Title:** SRA-ASL-1 Amazon Security Lake is Enabled for this region
    * **Description:** This check verifies whether Amazon Security Lake is enabled in this region. Amazon Security Lake is a fully managed security data lake service that you can use to automatically centralize security data from AWS environments, SaaS providers, on premises, cloud sources, and third-party sources into a purpose-built data lake that's stored in your AWS account. The data lake is backed by Amazon S3 buckets, and you retain ownership over your data. You must enable security lake in every AWS account and AWS region to collect security logs and event from your entire AWS environment.
* **Title:** SRA-ASL-2 Amazon Security Lake SQS Queues within delegated admin account  is encrypted with customer managed key (from KMS key) in this region
    * **Description:** This check verifies whether Security Lake manager SQS Queues within delegated admin account is encrypted with a customer managed key from AWS KMS. These SQS queues are used by AWS Lambda function for ETL job and also by subscribers looking for new logs deposited into the data lake. You must use a customer managed KMS key for the encryption as you have greater control on the key usage and permission.
* **Title:** SRA-ASL-3 Amazon Security Lake SQS Dlq within delegated admin account is encrypted with customer managed key (from KMS key) in this region
    * **Description:** This check verifies whether Security Lake SQS Dlq is encrypted in this region with a customer managed key from AWS KMS. You must use a customer managed KMS key for the encryption as you have greater control on the key usage and permission.
* **Title:** SRA-ASL-4 Amazon Security Lake organization configuration is enabled
    * **Description:** This check verifies whether Amazon Security Lake has configuration that will be automatically enable new organization accounts as member accounts from an Amazon Security Lake administrator account.
* **Title:** SRA-ASL-5 Amazon Security Lake organization configuration matches expected configuration
    * **Description:** This check verifies whetherAmazon Security Lake organization configuration matches expected value for log sources (ROUTE53,VPC_FLOW,SH_FINDINGS,CLOUD_TRAIL_MGMT,LAMBDA_EXECUTION,S3_DATA,EKS_AUDIT,WAF).
* **Title:** SRA-ASL-6 Route 53 log source is enabled for Amazon Security Lake  in all or specified active member accounts,
    * **Description:** This check verifies whether Amazon Security Lake is configured with Rote 53 log and event source. Route 53 resolver query logs track DNS queries made by resources within Amazon VPC.Security Lake collects resolver query logs directly from Route 53 through an independent and duplicated stream of events.
* **Title:** SRA-ASL-7 CloudTrail data event for S3 log source is enabled for Amazon Security Lake in all or specified active member accounts
    * **Description:** This check verifies whether Amazon Security Lake is configured with CloudTrail data event for S3 log and event source configurations. CloudTrail data events, also known as data plane operations, show the resource operations performed on or within resources in your AWS account. These operations are often high-volume activities and should be enabled as per your requirement. Security Lake pulls data directly from S3 through an independent and duplicated stream of events.
* **Title:** SRA-ASL-8 Security Hub findings log source is enabled for Amazon Security Lake in all or specified active member accounts
    * **Description:** This check verifies whether Amazon Security Lake is configured with SecurityHub findings  log and event source. Security Hub findings help you understand your security posture in AWS and let you check your environment against security industry standards and best practices. Security Lake collects findings directly from Security Hub through an independent and duplicated stream of events.
* **(Optional)Title:** SRA-ASL-9 EKS Audit log source is enabled for Amazon Security Lake in all or specified active member accounts
    * **Description:**  This check verifies whether Amazon Security Lake is configured with  EKS Audit log and event source. EKS Audit Logs help you detect potentially suspicious activities in your EKS clusters within the Amazon Elastic Kubernetes Service. Security Lake consumes EKS Audit Log events directly from the Amazon EKS control plane logging feature through an independent and duplicative stream of audit logs.
* **Title:** SRA-ASL-10 Lambda execution log source is enabled for Amazon Security Lake in all or specified active member accounts
    * **Description:** This check verifies whether Amazon Security Lake is configured with Lambda execution log and event source. These operations are often high-volume activities and should be enabled as per your requirement. Security Lake pulls data directly from Lambda through an independent and duplicated stream of events.
* **Title:**  SRA-ASL-11 CloudTrail management log source is enabled for Amazon Security Lake in all or specified active member accounts
    * **Description:** This check verifies whether Amazon Security Lake is configured with CloudTrail management log and event source. CloudTrail management events, also known as control plane events, provide insight into management operations that are performed on CloudTrail in your AWS account. To collect CloudTrail management events in Security Lake, there must be at least one CloudTrail multi-Region organization trail that collects read and write CloudTrail management events. Logging must be enabled for the trail.
* **(Optional)Title:** SRA-ASL-12 AWS WAF log source is enabled for Amazon Security Lake in all or specified active member accounts
    * **Description:** This check verifies whether Amazon Security Lake is configured with AWS WAF log and event source. Logged information includes the time that AWS WAF received a web request from your AWS resource, detailed information about the request, and details about the rules that the request matched. Security Lake consumes AWS WAF logs directly from AWS WAF through an independent and duplicate stream of logs.
* **Title:** SRA-ASL-13 VPC Flow log source is enabled for Amazon Security Lake in all or specified active member accounts
    * **Description:** This check verifies whether Amazon Security Lake is configured with VPC Flow log and event source. The VPC Flow Logs feature of Amazon VPC captures information about the IP traffic going to and from network interfaces within your environment. Security Lake consumes VPC Flow Logs directly from Amazon VPC through an independent and duplicate stream of Flow Logs.
* **Title:** SRA-ASL-14 Amazon Security Lake administration for the AWS Organization has a delegated administrator
    * **Description:** This check verifies whether Security Lake service administration for the AWS Organization is delegated out from AWS Organization management account to a member account.
* **Title:** SRA-ASL-15 Amazon Security Lake delegated admin account is the Log Archive account
    * **Description:** This check verifies whether Security Lake delegated admin account is the Log Archive account of your AWS organization. The Log Archive account is dedicated to ingesting and archiving all security-related logs and backups.
* **Title:** SRA-ASL-16 Security tooling (Audit) account is set up as query access subscriber
    * **Description:** This check verifies whether the AWS Organization Security tooling(Audit) account is set up as query access subscriber. These subscribers directly query AWS Lake Formation tables in your S3 bucket with services like Amazon Athena. Separation of log storage (Log Archive account) and log access (Security Tooling account) helps is separation of duties and helps in least privilege access.
* **Title:** SRA-ASL-17 Security tooling (Audit) account is set up as data access subscriber
    * **Description:**  This check verifies whether the AWS Organization Security tooling(Audit) account is set up as data access subscriber. These subscribers can directly access the S3 objects and receive notifications of new objects through a subscription endpoint or by polling an Amazon SQS queue.
* **Title:** SRA-ASL-18 Amazon Security Lake is successfully collecting data from its source
    * **Description:** This check verifies whether Security Lake is  being able to successfully collect log and events from all its sources. Misconfiguration or other issues may prevent security lake from getting appropriate logs which may results unavailability of critical logs.

