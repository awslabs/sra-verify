#!/usr/bin/env python3
"""
Script to extract boto3 API calls from client.py files and generate a least-privilege IAM policy.
"""

import os
import re
import json
import ast
import yaml
from typing import Dict, List, Set, Tuple

def find_client_files(base_dir: str = "./sraverify") -> List[str]:
    """Find all client.py files in the project."""
    client_files = []
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file == "client.py":
                client_files.append(os.path.join(root, file))
    return client_files

def extract_service_name(file_path: str) -> str:
    """Extract AWS service name from file path."""
    # Assuming the structure is .../services/service_name/client.py
    parts = file_path.split(os.sep)
    for i, part in enumerate(parts):
        if part == "services" and i + 1 < len(parts):
            return parts[i + 1]
    return "unknown"

def extract_boto3_calls(file_path: str) -> Dict[str, Set[str]]:
    """Extract boto3 API calls from a Python file."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # List of boto3 internal methods that aren't actual AWS API calls
    boto3_internal_methods = {
        'get_paginator', 'get_waiter', 'can_paginate', 
        'generate_presigned_url', 'generate_presigned_post'
    }
    
    # Initialize result dictionary
    result = {}
    
    # Find all client initializations - multiple patterns
    # Pattern 1: self.something = self.session.client('service_name')
    client_pattern1 = r'self\.(\w+)\s*=\s*(?:self\.)?session\.client\([\'"](\w+)[\'"]'
    client_matches1 = re.findall(client_pattern1, content)
    
    # Pattern 2: service_client = self.session.client('service_name')
    client_pattern2 = r'(\w+_client)\s*=\s*(?:self\.)?session\.client\([\'"](\w+)[\'"]'
    client_matches2 = re.findall(client_pattern2, content)
    
    # Combine all client matches
    all_client_matches = client_matches1 + client_matches2
    
    # Map client variable names to service names
    client_to_service = {}
    for client_var, service_name in all_client_matches:
        client_to_service[client_var] = service_name
        if service_name not in result:
            result[service_name] = set()
    
    # Find API calls for each specific client variable
    for client_var, service_name in client_to_service.items():
        # Pattern: exact client_var.method_name( (with word boundaries to avoid partial matches)
        api_pattern = rf'\b{re.escape(client_var)}\.([a-zA-Z0-9_]+)\('
        api_calls = re.findall(api_pattern, content)
        result[service_name].update(call for call in api_calls if call not in boto3_internal_methods)
        
        # Find paginator calls - pattern: exact client_var.get_paginator('operation_name')
        paginator_pattern = rf'\b{re.escape(client_var)}\.get_paginator\([\'"]([a-zA-Z0-9_]+)[\'"]'
        paginator_calls = re.findall(paginator_pattern, content)
        result[service_name].update(paginator_calls)
    
    return result

def generate_iam_policy(service_calls: Dict[str, Set[str]]) -> Dict:
    """Generate a least-privilege IAM policy from the extracted API calls."""
    statements = []
    
    # Special case: if s3control is used, we need to add s3 permissions instead
    if "s3control" in service_calls:
        if "s3" not in service_calls:
            service_calls["s3"] = set()
        
        # Map s3control methods to their s3 equivalents
        s3control_to_s3 = {
            "get_public_access_block": "get_account_public_access_block"
        }
        
        for call in service_calls["s3control"]:
            if call in s3control_to_s3:
                service_calls["s3"].add(s3control_to_s3[call])
            else:
                # For any other s3control methods, add them directly to s3
                service_calls["s3"].add(call)
        
        # Remove s3control as we've mapped its permissions to s3
        service_calls.pop("s3control")
    
    # Remove get_paginator from the API calls as it's not a valid IAM permission
    for service, calls in service_calls.items():
        if "get_paginator" in calls:
            calls.remove("get_paginator")
    
    # Add required dependent permissions
    for service, calls in service_calls.items():
        if service == "wafv2" and "get_web_acl_for_resource" in calls:
            calls.add("get_web_acl")  # GetWebAclForResource requires GetWebAcl permission
    
    # Sort services alphabetically for consistent policy output
    for service in sorted(service_calls.keys()):
        calls = service_calls[service]
        if not calls:
            continue
            
        # Convert service name to proper AWS service prefix
        service_prefix = service
        # Handle special cases
        service_mapping = {
            "s3": "s3",
            "ec2": "ec2", 
            "guardduty": "guardduty",
            "securityhub": "securityhub",
            "cloudtrail": "cloudtrail",
            "config": "config",
            "macie2": "macie2",
            "accessanalyzer": "access-analyzer",
            "inspector2": "inspector2",
            "organizations": "organizations",
            "shield": "shield",
            "lambda": "lambda",
            "wafv2": "wafv2",
            "cloudfront": "cloudfront",
            "elbv2": "elasticloadbalancing"
        }
        
        service_prefix = service_mapping.get(service, service)
        
        # Special handling for API Gateway which uses HTTP verbs instead of specific actions
        if service == "apigateway":
            # API Gateway uses GET action for read operations
            actions = ["apigateway:GET"]
        else:
            actions = [f"{service_prefix}:{convert_to_api_action(call)}" for call in calls]
        
        statements.append({
            "Sid": f"{service.capitalize()}Permissions",
            "Effect": "Allow",
            "Action": sorted(actions),
            "Resource": "*"  # In a real scenario, you might want to restrict resources
        })
    
    policy = {
        "Version": "2012-10-17",
        "Statement": statements
    }
    
    return policy

def convert_to_api_action(method_name: str) -> str:
    """Convert boto3 method name to IAM policy action name."""
    # Convert camelCase or snake_case to PascalCase
    if "_" in method_name:
        parts = method_name.split("_")
        pascal_case = "".join(part.capitalize() for part in parts)
    else:
        # Handle camelCase
        pascal_case = method_name[0].upper() + method_name[1:]
    
    return pascal_case

def main():
    client_files = find_client_files()
    service_calls = {}
    
    for file_path in client_files:
        service_file = extract_service_name(file_path)
        api_calls_by_service = extract_boto3_calls(file_path)
        
        # Process each service's API calls
        for service, calls in api_calls_by_service.items():
            if service not in service_calls:
                service_calls[service] = set()
            service_calls[service].update(calls)
    
    # Print summary of API calls by service
    print("=== Boto3 API Calls by Service ===")
    for service, calls in sorted(service_calls.items()):
        print(f"\n{service.upper()}:")
        for call in sorted(calls):
            print(f"  - {call}")
    
    # Generate IAM policy
    policy = generate_iam_policy(service_calls)
    
    # Save policy to JSON file
    with open("generated_sraverify_iam_policy.json", "w") as f:
        json.dump(policy, indent=2, fp=f)
    
    # Create CloudFormation YAML snippet
    cf_policy = {
        "SRAVerifyLeastPrivilege": {
            "Type": "AWS::IAM::ManagedPolicy",
            "Properties": {
                "ManagedPolicyName": "SRAVerifyLeastPrivilege",
                "Description": "Least privilege policy for SRA Verify tool",
                "PolicyDocument": policy
            }
        }
    }
    
    # Custom YAML representer for better formatting
    class NoAliasDumper(yaml.SafeDumper):
        def ignore_aliases(self, data):
            return True
    
    # Save policy to YAML file for CloudFormation
    with open("generated_sraverify_cf_policy.yaml", "w") as f:
        yaml.dump(cf_policy, f, default_flow_style=False, sort_keys=False, Dumper=NoAliasDumper)
    
    print("\n=== Least-Privilege IAM Policy (JSON) ===")
    print(json.dumps(policy, indent=2))
    
    print("\n=== CloudFormation YAML Snippet ===")
    print(yaml.dump(cf_policy, default_flow_style=False, sort_keys=False, Dumper=NoAliasDumper))
    
    print("\nPolicy saved to generated_sraverify_iam_policy.json")
    print("CloudFormation snippet saved to generated_sraverify_cf_policy.yaml")

if __name__ == "__main__":
    main()
