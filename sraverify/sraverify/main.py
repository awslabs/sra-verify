"""
SRA Verify - Security Reference Architecture Verification Tool

This module provides both the library interface and CLI functionality.
The SRAVerify class implements the core functionality that can be used
as a library, while the CLI functions use this class to provide the
command-line interface.
"""
import argparse
import datetime
from boto3 import Session
from typing import Dict, List, Any, Optional

from sraverify.core.session import get_session
from sraverify.core.logging import logger, configure_logging
from sraverify.utils.outputs import write_csv_output
from sraverify.utils.progress import ScanProgress
from sraverify.utils.banner import print_banner
from sraverify.services.guardduty import CHECKS as guardduty_checks
from sraverify.services.cloudtrail import CHECKS as cloudtrail_checks
from sraverify.services.accessanalyzer import CHECKS as accessanalyzer_checks
from sraverify.services.config import CHECKS as config_checks
from sraverify.services.securityhub import CHECKS as securityhub_checks
from sraverify.services.s3 import CHECKS as s3_checks
from sraverify.services.inspector import CHECKS as inspector_checks
from sraverify.services.ec2 import CHECKS as ec2_checks
from sraverify.services.macie import CHECKS as macie_checks
from sraverify.services.shield import CHECKS as shield_checks
from sraverify.services.waf import CHECKS as waf_checks
from sraverify.services.account import CHECKS as account_checks
from sraverify.services.auditmanager import CHECKS as auditmanager_checks

# Collect all checks from different services
ALL_CHECKS = {
    **guardduty_checks,
    **cloudtrail_checks,
    **accessanalyzer_checks,
    **config_checks,
    **securityhub_checks,
    **s3_checks,
    **inspector_checks,
    **ec2_checks,
    **macie_checks,
    **shield_checks,
    **waf_checks,
    **account_checks,
    **auditmanager_checks
    # Add more service checks here as they're implemented
    # **config_checks,
    # etc.
}

class SRAVerify:
    """Main class for SRA Verify functionality."""
    
    def __init__(self, profile: Optional[str] = None, role_arn: Optional[str] = None,
                 regions: Optional[List[str]] = None, session: Optional[Session] = None,
                 debug: bool = False):
        """
        Initialize SRA Verify.
        
        Args:
            profile: AWS profile to use
            role_arn: ARN of IAM role to assume
            regions: List of AWS regions to check
            session: Existing AWS session to use (if provided)
            debug: Enable debug logging
        """
        configure_logging(debug)
        self.regions = regions
        self.session = session if session else get_session(profile=profile, role_arn=role_arn)
        self.progress = None
        
    def get_available_checks(self, account_type: str = 'all') -> Dict[str, Dict[str, str]]:
        """
        Get all available checks, optionally filtered by account type.
        
        Args:
            account_type: Type of accounts to list checks for ('application', 'audit', 'log-archive', 'management', or 'all')
            
        Returns:
            Dictionary mapping check IDs to check information
        """
        checks = {}
        for check_id, check_class in sorted(ALL_CHECKS.items()):
            check = check_class()
            if account_type == 'all' or check.account_type == account_type:
                checks[check_id] = {
                    'name': check.check_name,
                    'service': check.service,
                    'account_type': check.account_type,
                    'description': check.description,
                    'severity': check.severity
                }
        return checks
    
    def get_available_services(self) -> List[str]:
        """
        Get all available services.
        
        Returns:
            List of service names
        """
        services = set()
        for check_class in ALL_CHECKS.values():
            check = check_class()
            services.add(check.service)
        return sorted(list(services))
    
    def run_checks(self, account_type: str = 'all', service: Optional[str] = None,
                  check_id: Optional[str] = None, audit_accounts: Optional[List[str]] = None,
                  log_archive_accounts: Optional[List[str]] = None,
                  show_progress: bool = False) -> List[Dict[str, Any]]:
        """
        Run security checks.
        
        Args:
            account_type: Type of accounts to check ('application', 'audit', 'log-archive', 'management', or 'all')
            service: Run checks for a specific service
            check_id: Run a specific check
            audit_accounts: List of AWS accounts used for Audit/Security Tooling
            log_archive_accounts: List of AWS accounts used for Logging
            show_progress: Whether to show progress bar
            
        Returns:
            List of findings
        """
        # Start with all checks or filtered by account type
        if account_type == 'all':
            checks_to_run = ALL_CHECKS.copy()
        else:
            logger.debug(f"Filtering checks by account type: {account_type}")
            checks_to_run = {
                check_id: check_class for check_id, check_class in ALL_CHECKS.items()
                if check_class().account_type == account_type
            }
        
        # Filter by specific check if provided
        if check_id:
            logger.debug(f"Filtering for specific check: {check_id}")
            if check_id not in ALL_CHECKS:
                logger.error(f"Check {check_id} not found")
                return []
            
            check = ALL_CHECKS[check_id]()
            if account_type != 'all' and check.account_type != account_type:
                logger.error(f"Check {check_id} is for {check.account_type} accounts, but account_type is set to {account_type}")
                return []
                
            checks_to_run = {check_id: ALL_CHECKS[check_id]}
        
        # Filter by service if provided
        if service:
            logger.debug(f"Filtering checks by service: {service}")
            service_checks = {}
            for check_id, check_class in checks_to_run.items():
                check = check_class()
                if check.service.lower() == service.lower():
                    service_checks[check_id] = check_class
            
            if not service_checks:
                logger.error(f"No {account_type} checks found for service {service}")
                return []
            
            checks_to_run = service_checks
        
        # Check if there are any checks after filtering
        if not checks_to_run:
            logger.error("No checks found with selected filters")
            return []
            
        all_findings = []
        
        # Group checks by service for better organization
        service_checks = {}
        for check_id, check_class in checks_to_run.items():
            check = check_class()
            if check.service not in service_checks:
                service_checks[check.service] = []
            service_checks[check.service].append((check_id, check_class))
        
        # Set up progress tracking if requested
        if show_progress:
            self.progress = ScanProgress(len(checks_to_run))
        
        # Run checks by service
        for service_name, checks in service_checks.items():
            if self.progress:
                self.progress.update(service_name)
            logger.debug(f"Running {len(checks)} checks for service {service_name}")

            for check_id, check_class in checks:
                logger.debug(f"Initializing check {check_id}")
                check = check_class()
                check.initialize(self.session, regions=self.regions)
                
                # Pass audit and log archive accounts to the check if it needs them
                if audit_accounts:
                    check._audit_accounts = audit_accounts
                if log_archive_accounts:
                    check._log_archive_accounts = log_archive_accounts
                
                try:
                    logger.debug(f"Executing check {check_id}: {check.check_name}")
                    findings = check.execute()
                    all_findings.extend(findings)
                    logger.debug(f"Check {check_id} completed with {len(findings)} findings")
                except Exception as e:
                    logger.error(f"Error running check {check_id}: {e}", exc_info=True)
                    # Add a failure finding
                    all_findings.append({
                        "CheckId": check_id,
                        "Status": "ERROR",
                        "Region": "global",
                        "Severity": "UNKNOWN",
                        "Title": f"Error running {check_id}",
                        "Description": f"An error occurred while running check {check_id}",
                        "ResourceId": None,
                        "ResourceType": None,
                        "AccountId": None,
                        "CheckedValue": None,
                        "ActualValue": str(e),
                        "Remediation": "Check the error message and try again",
                        "Service": service_name,
                        "CheckLogic": None,
                        "AccountType": check.account_type
                    })
                
                if self.progress:
                    self.progress.increment()
        
        if self.progress:
            self.progress.finish()
            
        return all_findings


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='SRA Verify - Security Rule Assessment Verification Tool')
    parser.add_argument('--profile', type=str, help='AWS profile to use')
    parser.add_argument('--role', type=str, help='ARN of IAM role to assume')
    parser.add_argument('--regions', type=str, help='Comma-separated list of AWS regions to check')
    parser.add_argument('--output', type=str, default='sraverify_findings.csv', 
                        help='Output file name (default: sraverify_findings.csv)')
    parser.add_argument('--check', type=str, help='Run a specific check (e.g., SRA-GD-1)')
    parser.add_argument('--service', type=str, help='Run checks for a specific service (e.g., GuardDuty)')
    parser.add_argument('--account-type', type=str, 
                        choices=['application', 'audit', 'log-archive', 'management', 'all'], 
                        default='all',
                        help='Type of accounts to run checks against: application, audit, log-archive, management, or all (default: all)')
    parser.add_argument('--audit-account', type=str, metavar='ACCOUNTID1,ACCOUNTID2', 
                        help='AWS accounts used for Audit/Security Tooling, use comma separated values')
    parser.add_argument('--log-archive-account', type=str, metavar='ACCOUNTID1,ACCOUNTID2',
                        help='AWS accounts used for Logging, use comma separated values')
    parser.add_argument('--list-checks', action='store_true', help='List available checks')
    parser.add_argument('--list-services', action='store_true', help='List available services')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()
    
    # Create SRAVerify instance
    regions = [r.strip() for r in args.regions.split(',')] if args.regions else None
    sra = SRAVerify(profile=args.profile, role_arn=args.role, regions=regions, debug=args.debug)
    
    if args.list_checks:
        checks = sra.get_available_checks(args.account_type)
        print("Available checks:")
        for check_id, info in checks.items():
            print(f"  {check_id}: {info['name']} ({info['service']}) [{info['account_type']}]")
        return
    
    if args.list_services:
        services = sra.get_available_services()
        print("Available services:")
        for service in services:
            print(f"  {service}")
        return
    
    # Parse audit accounts if provided
    audit_accounts = None
    if args.audit_account:
        audit_accounts = [a.strip() for a in args.audit_account.split(',')]
        logger.debug(f"Using audit accounts: {', '.join(audit_accounts)}")
    
    # Parse log archive accounts if provided
    log_archive_accounts = None
    if args.log_archive_account:
        log_archive_accounts = [a.strip() for a in args.log_archive_account.split(',')]
        logger.debug(f"Using log archive accounts: {', '.join(log_archive_accounts)}")
    
    # Generate output filename with timestamp if not specified
    output_file = args.output
    if output_file == 'sraverify_findings.csv':
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"sraverify_findings_{timestamp}.csv"
    
    # Display banner with session information
    print_banner(
        profile=args.profile or 'default', 
        region=sra.session.region_name, 
        session=sra.session,
        regions=regions,
        account_type=args.account_type,
        checks_count=len(sra.get_available_checks(args.account_type)),
        output_file=output_file,
        role=args.role
    )
    
    # Run checks
    findings = sra.run_checks(
        account_type=args.account_type,
        service=args.service,
        check_id=args.check,
        audit_accounts=audit_accounts,
        log_archive_accounts=log_archive_accounts,
        show_progress=True
    )
    
    # Write output
    logger.debug(f"Writing findings to {output_file}")
    write_csv_output(findings, output_file)
    
    # Print summary
    pass_count = sum(1 for f in findings if f.get('Status') == 'PASS')
    fail_count = sum(1 for f in findings if f.get('Status') == 'FAIL')
    error_count = sum(1 for f in findings if f.get('Status') == 'ERROR')

    logger.debug("Scan complete")
    print("\n-> Scan complete!")
    print(f"  · Total findings: {len(findings)}")
    print(f"  · Pass: {pass_count}")
    print(f"  · Fail: {fail_count}")
    print(f"  · Error: {error_count}")
    print(f"  · Output: {output_file}")


if __name__ == "__main__":
    main()
