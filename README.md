# SRA Verify: AWS Security Reference Architecture Verification Tool

SRA Verify is a security assessment tool that automates the verification of [AWS Security Reference Architecture (SRA)](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html) implementations across multiple AWS accounts and regions. It provides detailed findings and actionable remediation steps to ensure your AWS environment follows security best practices.

The tool performs automated security checks across multiple AWS services including CloudTrail, GuardDuty, IAM Access Analyzer, AWS Config, Security Hub, and S3. It supports multi-account environments and can run checks specific to management, audit, and log archive accounts while providing detailed findings with remediation guidance.

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
    wget https://raw.githubusercontent.com/awslabs/aws-sraverify/main/1-sraverify-member-roles.yaml
    ```

5. Deploy the CloudFormation template via CloudFormation StackSets. Update the following parameters:
   - Replace **\<aws-account-id\>** with the account ID you will run SRA Verify from.

    ```bash
    aws cloudformation create-stack-set --template-body file://1-sraverify-member-roles.yaml \
    --stack-set-name sraverify-member-roles \
    --permission-model SERVICE_MANAGED \
    --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameters ParameterKey=SRAVerifyAccountID,ParameterValue=<aws-account-id> \
    --region <region>
    ```

6. Use the following command to create stack instances for each account in your organization. You can target a specific OU, or the root OU. Update the following parameters:
   - Replace **\<root-ou\>** with the [organization root ID](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_details.html#orgs_view_root). 
   - Replace **\<region\>** with the Region you want to deploy the template to.

    ```bash
    aws cloudformation create-stack-instances --stack-set-name sraverify-member-roles \
    --deployment-targets OrganizationalUnitIds='["<root-ou>"]' \
    --regions '["<region>"]' \
    --operation-preferences FailureTolerancePercentage=100,MaxConcurrentPercentage=100 \
    --region <region>
    ```

#### Step 2: Deploy the SRA Verify solution
In this step, you will deploy the Cloudformation template to create the CodeBuild job to run SRA Verify. After the CloudFormation template is deployed, the CodeBuild job will be automatically started.

>Note: Make sure you switched to the account you specified will run SRA Verify.

1. Login to your audit account.

2. To download the template, open AWS CloudShell in the **Audit account** and enter the following command.

    ```bash
    wget https://raw.githubusercontent.com/awslabs/aws-sraverify/main/2-sraverify-codebuild.yaml
    ```

3. Use the following command to deploy the template in the Audit account. Update the following parameters
   - Replace **\<audit-account-id\>** with the audit account id
   - Replace **\<log-account-id\>** with the log archive account id

    ```bash
    aws cloudformation deploy 
    --template-file 2-sraverify-codebuild-deploy.yaml \
    --stack-name sra \
    --parameter-overrides \
    AuditAccountID=<audit-account-id> \
    LogArchiveAccountID=<log-account-id> \
    --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM
    ```

### Run SRA Verify locally
In this step, you will run SRA Verify locally. Running locally is useful to run a specific test or the tests for a specific account type. You will have to manage credentials into each account.

#### Step 1: Download and run SRA Verify
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
    usage: sraverify [-h] [--profile PROFILE] [--role ROLE] [--regions REGIONS] [--output OUTPUT] [--check CHECK]
                    [--service SERVICE] [--account-type {application,audit,log-archive,management,all}]
                    [--audit-account ACCOUNTID1,ACCOUNTID2] [--log-archive-account ACCOUNTID1,ACCOUNTID2] [--list-checks]
                    [--list-services] [--debug]

    SRA Verify - Security Rule Assessment Verification Tool

    options:
    -h, --help            show this help message and exit
    --profile PROFILE     AWS profile to use
    --role ROLE           ARN of IAM role to assume
    --regions REGIONS     Comma-separated list of AWS regions to check
    --output OUTPUT       Output file name (default: sraverify_findings.csv)
    --check CHECK         Run a specific check (e.g., SRA-GD-1)
    --service SERVICE     Run checks for a specific service (e.g., GuardDuty)
    --account-type {application,audit,log-archive,management,all}
                            Type of accounts to run checks against: application, audit, log-archive, management, or all
                            (default: all)
    --audit-account ACCOUNTID1,ACCOUNTID2
                            AWS accounts used for Audit/Security Tooling, use comma separated values
    --log-archive-account ACCOUNTID1,ACCOUNTID2
                            AWS accounts used for Logging, use comma separated values
    --list-checks         List available checks
    --list-services       List available services
    --debug               Enable debug logging
    ```

6. Review these detailed examples
   - Run specific service checks:
   ```bash
   sraverify --service CloudTrail --regions us-east-1
   ```

   - Run a single check:
   ```bash
   sraverify --check SRA-CT-1 --regions us-east-1
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