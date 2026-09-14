# SRA Verify: AWS Security Reference Architecture Verification Tool

SRA Verify is a security assessment tool that automates the verification of [AWS Security Reference Architecture (SRA)](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html) implementations across multiple AWS accounts and regions. It provides detailed findings and actionable remediation steps to ensure your AWS environment follows security best practices.

The tool performs **158 automated security checks across 18 AWS services**: Account, Audit Manager, CloudTrail, Config, EC2, Firewall Manager, GuardDuty, IAM, IAM Access Analyzer, Inspector, Macie, Organizations, S3, Security Hub, Security Incident Response, Security Lake, Shield, and WAF. It supports multi-account environments and can run checks specific to management, audit, and log archive accounts while providing detailed findings with remediation guidance.

For the full check inventory, see [docs/checks.txt](./docs/checks.txt) or run `sraverify --list-checks`.

>Note: SRA Verify contains checks for several services, but may not contain a check for every consideration of the AWS Security Reference Architecture. Review the [AWS Prescriptive Guidance](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html) for more information on AWS Security Reference Architecture.

## Usage Instructions
SRA Verify is designed to run in AWS CodeBuild in the Organization Audit (Security Tooling) account.

You can use the provided AWS CloudFormation templates to deploy the solution. You can also run it locally or extend the solution using the SRA Verify library.

For information on using SRA Verify as a library, or creating checks review the [SRA Verify readme](./sraverify/README.md).

### Deploy with AWS CloudFormation
In this step, you will deploy SRA Verify on AWS CodeBuild using CloudFormation.

#### Step 1: Deploy prerequisite role
In this step you will deploy the SRAMemberRole to each account in your AWS Organization.

1. Login to your AWS Management account or the [delegated administrator](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-delegated-admin.html) for CloudFormation StackSets.
2. In the navigation bar, choose [AWS CloudShell](https://console.aws.amazon.com/cloudshell/home).
3. Identify which account you will run the SRA Verify scan from. Customers typically use the audit account (also referred to as security tooling). Take note of the account ID for the **SRAVerifyAccountID** parameter.
4. To download the CloudFormation template, enter the following command.

    ```bash
    wget https://raw.githubusercontent.com/awslabs/sra-verify/refs/heads/main/1-sraverify-member-roles.yaml
    ```

5. Deploy the CloudFormation template via CloudFormation StackSets. Update the following parameters:
   - Replace **\<aws-account-id\>** with the account ID you will run SRA Verify from.
   - Replace **\<caller\>** with **DELEGATED_ADMIN** if you are deploying the StackSet from the CloudFormation delegated admin. If you are deploying the CloudFormation from the management account, replace with **SELF**.

    ```bash
    aws cloudformation create-stack-set --template-body file://1-sraverify-member-roles.yaml \
    --stack-set-name sraverify-member-roles \
    --permission-model SERVICE_MANAGED \
    --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameters ParameterKey=SRAVerifyAccountID,ParameterValue=<aws-account-id> \
    --region <region> \
    --call-as <caller>
    ```

6. Use the following command to create stack instances for each account in your organization. You can target a specific OU, or the root OU. Update the following parameters:
   - Replace **\<root-ou\>** with the [organization root ID](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_details.html#orgs_view_root).
   - Replace **\<region\>** with the Region you want to deploy the template to.
   - Replace **\<caller\>** with **DELEGATED_ADMIN** if you are deploying the StackSet from the CloudFormation delegated admin. If you are deploying the CloudFormation from the management account, replace with **SELF**.

    ```bash
    aws cloudformation create-stack-instances --stack-set-name sraverify-member-roles \
    --deployment-targets OrganizationalUnitIds='["<root-ou>"]' \
    --regions '["<region>"]' \
    --operation-preferences FailureTolerancePercentage=100,MaxConcurrentPercentage=100 \
    --region <region> \
    --call-as <caller>
    ```

7. StackSets don't deploy to the Organization management account. To deploy the role to the Organization management account, deploy the CloudFormation template separately in the management account.
   - Replace **\<aws-account-id\>** with the account ID you will run SRA Verify from.

    ```bash
    aws cloudformation deploy \
    --template-file 1-sraverify-member-roles.yaml \
    --stack-name sraverify-member-roles \
    --parameter-overrides \
    SRAVerifyAccountID=<aws-account-id> \
    --capabilities CAPABILITY_NAMED_IAM
    ```

#### Step 2: Deploy the SRA Verify solution
In this step, you will deploy the Cloudformation template to create the CodeBuild job to run SRA Verify. After the CloudFormation template is deployed, the CodeBuild job will be automatically started.

>Note: Make sure you switched to the account you specified will run SRA Verify.

1. Login to your audit account.

2. To download the template, open AWS CloudShell in the **Audit account** and enter the following command.

    ```bash
    wget https://raw.githubusercontent.com/awslabs/sra-verify/refs/heads/main/2-sraverify-codebuild-deploy.yaml
    ```

3. Use the following command to deploy the template in the Audit account. Update the following parameters
   - Replace **\<audit-account-id\>** with the audit account id
   - Replace **\<log-account-id\>** with the log archive account id
   - Replace **\<regions\>** with a comma-separated list of regions to scan (default: us-east-1,us-east-2,us-west-2).  Example "IncludeRegions=us-east-1,us-west-2,eu-west-1"

    ```bash
    aws cloudformation deploy \
    --template-file 2-sraverify-codebuild-deploy.yaml \
    --stack-name sra \
    --parameter-overrides \
    AuditAccountID=<audit-account-id> \
    LogArchiveAccountID=<log-account-id> \
    IncludeRegions=<regions> \
    --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM
    ```

## Review the results
After the solution is deployed, a Lambda function starts the CodeBuild project. After the CodeBuild project is finished building, the SRA Verify results will be uploaded to the created Amazon S3 bucket.

You can monitor the progress from the [CodeBuild console](https://console.aws.amazon.com/codesuite/codebuild/projects).

To review the results, follow these steps.

1. Navigate to the Amazon S3 console in the account you deployed SRA Verify.

2. Select the bucket that contains **bucketsraverifyfindings**

3. Choose the **sraverify** folder.

4. Choose the **reports** folder.

5. Select the **consolidated** or **raw** folder.

6. Download the CSV file and review the findings.

### Review the results with the dashboard
You can use the SRA Verify dashboard to get a summary of the findings.

1. In the S3 console under s3://$S3_SRA_RESULTS_BUCKET/sraverify/reports/consolidated/, select **sra-verify-dashboard.html** and choose **Open**.
2. In the S3 console at the same location, select the **csv** file and choose **Actions**, **Share with a presigned URL**.
   >Note: Do not share your presigned URL with anyone. A presigned URL uses security credentials to grant time-limited permission to download objects. The URL can be entered in a browser or used by a program to download the object. The credentials used by the presigned URL are those of the AWS user who generated the URL. For more information, review [Sharing objects with presigned URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ShareObjectPreSignedURL.html).
3. For **Number of minutes**, enter **1**.
4. In the dashboard, paste the URL that was copied to your clipboard and choose **Load URL**.
5. Review an example dashboard output in [docs/sra-verify-dashboard-example.png](/docs/sra-verify-dashboard-example.png)

### Review the results with generative AI
You can use generative AI to further summarize your findings.

1. In the dashboard, select **Copy generative AI prompt**. This will copy a markdown formatted version of the findings and example prompt to your clipboard.
2. Paste the prompt into a generative AI chat.
   >Note: The copied prompt will contain your organizations findings. Consider your organization's security policies before pasting the prompt into a generative AI tool.
3. To use Amazon Bedrock, follow [Generate responses in the console using playgrounds](https://docs.aws.amazon.com/bedrock/latest/userguide/playgrounds.html) in the Amazon Bedrock user guide.
4. Review an example generative AI chat output in [docs/sra-verify-generative-ai-example.md](/docs/sra-verify-generative-ai-example.md)


## Run SRA Verify locally
In this step, you will run SRA Verify locally. Running locally is useful to run a specific test or the tests for a specific account type. You will have to manage credentials into each account.

### Step 1: Download and run SRA Verify
In this step you will clone the Github repository and run the tool.

1. Clone the repository with the following command

    ```bash
    git clone <repository-url>
    ```

2. Create and activate virtual environment:
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # On Windows use: venv\Scripts\activate
    ```
3. Install development dependencies:
    ```bash
    pip install -r sraverify/requirements.txt
    ```

4. Install sraverify
   1. Install

        ```bash
        pip install ./sraverify
        ```

    2. Install for development

        ```bash
        pip install -e ./sraverify
        ```

5. Run sraverify

    ```bash
    usage: sraverify [-h] [--profile PROFILE] [--role ROLE] [--regions REGIONS]
                     [--output OUTPUT] [--check CHECK] [--service SERVICE]
                     [--account-type {application,audit,log-archive,management,all}]
                     [--audit-account ACCOUNTID1,ACCOUNTID2]
                     [--log-archive-account ACCOUNTID1,ACCOUNTID2] [--list-checks]
                     [--list-services] [--debug]
                     [--connect-timeout CONNECT_TIMEOUT]
                     [--read-timeout READ_TIMEOUT] [--max-attempts MAX_ATTEMPTS]
                     [--max-pool-connections MAX_POOL_CONNECTIONS]

    SRA Verify - Security Rule Assessment Verification Tool

    options:
      -h, --help            show this help message and exit
      --profile PROFILE     AWS profile to use
      --role ROLE           ARN of IAM role to assume
      --regions REGIONS     Comma-separated list of AWS regions to check
      --output OUTPUT       Output file name (default: sraverify_findings.csv)
      --check CHECK         Run a specific check (e.g., SRA-GUARDDUTY-01)
      --service SERVICE     Run checks for a specific service (e.g., GuardDuty)
      --account-type {application,audit,log-archive,management,all}
                            Type of accounts to run checks against: application,
                            audit, log-archive, management, all (default: all)
      --audit-account ACCOUNTID1,ACCOUNTID2
                            AWS accounts used for Audit/Security Tooling, use
                            comma separated values
      --log-archive-account ACCOUNTID1,ACCOUNTID2
                            AWS accounts used for Logging, use comma separated
                            values
      --list-checks         List available checks
      --list-services       List available services
      --debug               Enable debug logging
      --connect-timeout CONNECT_TIMEOUT
                            boto3 connect timeout in seconds (default: 10)
      --read-timeout READ_TIMEOUT
                            boto3 read timeout in seconds (default: 30)
      --max-attempts MAX_ATTEMPTS
                            boto3 retry max_attempts (default: 3)
      --max-pool-connections MAX_POOL_CONNECTIONS
                            boto3 max_pool_connections (default: 50)
    ```

6. Review these detailed examples
   - Run specific service checks. `--service` is case-insensitive but matches the service
     name in full, so `--service Security` matches nothing:
   ```bash
   sraverify --service CloudTrail --regions us-east-1
   ```

   - Run a single check. Check IDs are matched exactly and are case-sensitive:
   ```bash
   sraverify --check SRA-CLOUDTRAIL-01 --regions us-east-1
   ```

   - Run the checks for one account type, supplying the account IDs the checks compare
     against:
   ```bash
   sraverify --account-type audit --audit-account 111122223333 --regions us-east-1
   ```

   - List the catalog. Both of these exit immediately without making any AWS API call, so
     they need no credentials:
   ```bash
   sraverify --list-checks
   sraverify --list-services
   ```

### Output file naming
When `--output` is omitted, a timestamp is inserted before the extension, producing
`sraverify_findings_YYYYmmdd_HHMMSS.csv`. Supplying `--output` with any other path writes to
that path unchanged.

### Exit codes
Wrap `sraverify` in automation using these codes rather than by parsing its output.

| Code  | Meaning                                                                                                                                                                                                                                                    |
| ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **0** | A report was written. This holds regardless of how many FAIL or ERROR rows it contains — a FAIL is the tool working, not the tool failing.                                                                                                                 |
| **1** | The scan ran but the output file could not be written. The path and reason are logged, and no scan summary is printed. Often transient (a full disk, a stale working directory) and worth a retry.                                                         |
| **2** | Usage error, raised before any AWS call. **No file is created.** Either `--check` named an unknown ID (up to three near-miss suggestions are logged) or the filter combination matched no checks, for example `--account-type audit --service CloudTrail`. |

Exit 0 on a report full of FAILs is deliberate. The CodeBuild deployment fans `sraverify`
out across every active account with GNU `parallel`, so a non-zero status from one member
account would be treated as a failed job. A non-zero code means only "this invocation
produced no usable report", which is what lets the consolidation step tell a missing CSV
from an empty one.

### Run the tests
The test suite needs no AWS credentials and makes no AWS API calls.

```bash
cd sraverify && pytest -q
```
