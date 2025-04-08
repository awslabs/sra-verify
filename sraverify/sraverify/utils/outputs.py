"""
Output handling for sraverify scan results.
"""
import csv
from typing import List, Dict, Any

# Required fields as per developer guide
REQUIRED_FIELDS = [
    'AccountId',
    'Region',
    'CheckId',
    'Status',
    'Severity',
    'Title',
    'Description',
    'ResourceId',
    'ResourceType',
    'CheckedValue',
    'ActualValue',
    'Remediation',
    'Service',
    'CheckLogic',
    'AccountType'  # Changed from CheckType to AccountType
]


def write_csv_output(findings: List[Dict[str, Any]], output_file: str):
    """
    Write scan findings to a CSV file ensuring all required fields are present.
    
    Args:
        findings: List of finding dictionaries
        output_file: Path to output CSV file
    """
    # Always create the CSV file, even if there are no findings
    if not findings:
        findings = []
    
    # Ensure each finding has all required fields
    for finding in findings:
        for field in REQUIRED_FIELDS:
            if field not in finding:
                finding[field] = ''  # Add empty string for missing fields
        
        # Handle the case where a finding might have CheckType but not AccountType
        if 'CheckType' in finding and 'AccountType' not in finding:
            finding['AccountType'] = finding['CheckType']
            del finding['CheckType']
    
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=REQUIRED_FIELDS)
        writer.writeheader()
        for finding in findings:
            # Only write the required fields, in the correct order
            row = {field: finding.get(field, '') for field in REQUIRED_FIELDS}
            writer.writerow(row)
