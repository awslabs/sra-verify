# SRA Verify

A security assessment tool for AWS infrastructure.

## Description

SRA Verify is a security auditing tool that helps assess your configuration against the [Security Reference Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html). 

## Features

- AWS security best practices assessment
- AWS API based checks
- Extensible security check framework
- Security findings reporting
- Easy to install via pip

## Installation

```bash
pip install ./sraverify
```

## Quick Start

```bash
# Configure AWS credentials
aws configure

# Run sraverify
sraverify
```

## Running Verify

1. Clone the repository:
```bash
git clone https://github.com/yourusername/sraverify.git
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
                 [--service SERVICE] [--check-type {account,management,all}] [--list-checks] [--list-services]
                 [--debug]

SRA Verify - Security Rule Assessment Verification Tool

options:
  -h, --help            show this help message and exit
  --profile PROFILE     AWS profile to use
  --role ROLE           ARN of IAM role to assume
  --regions REGIONS     Comma-separated list of AWS regions to check
  --output OUTPUT       Output file name (default: sraverify_findings.csv)
  --check CHECK         Run a specific check (e.g., SRA-GD-1)
  --service SERVICE     Run checks for a specific service (e.g., GuardDuty)
  --check-type {account,management,all}
                        Type of checks to run: account, management, or all (default: all)
  --list-checks         List available checks
  --list-services       List available services
  --debug               Enable debug logging
```

## Deploy on CodeBuild
1. Deploy 1-sraverify-member-roles.yaml as stackset to member accounts in one Region
2. Deploy 1-sraverify-member-roles.yaml as stack to management account (stack sets don't apply)
3. Run s3_sync_command.sh (change bucket name) to sync files to S3.
4. `aws cloudformation deploy --template-file 2-sraverify-codebuild-deploy.yaml --stack-name sra --parameter-overrides S3SRASourceBucket=sra-source-schiefj --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM`
5. Start the CodeBuild job.