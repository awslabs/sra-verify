"""
SRA Verify - Security Reference Architecture Verification Tool
"""
import argparse
import datetime
import sys
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

# Collect all checks from different services
ALL_CHECKS = {
    **guardduty_checks,
    **cloudtrail_checks,
    **accessanalyzer_checks,
    **config_checks,
    **securityhub_checks,
    **s3_checks,
    **inspector_checks
    # Add more service checks here as they're implemented
    # **config_checks,
    # etc.
}


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


def list_checks(account_type='all'):
    """
    List all available checks, optionally filtered by account type.
    
    Args:
        account_type: Type of accounts to list checks for ('application', 'audit', 'log-archive', 'management', or 'all')
    """
    logger.info("Listing available checks")
    print("Available checks:")
    for check_id, check_class in sorted(ALL_CHECKS.items()):
        check = check_class()
        if account_type == 'all' or check.account_type == account_type:
            print(f"  {check_id}: {check.check_name} ({check.service}) [{check.account_type}]")


def list_services():
    """List all available services."""
    logger.info("Listing available services")
    services = set()
    for check_class in ALL_CHECKS.values():
        check = check_class()
        services.add(check.service)
    
    print("Available services:")
    for service in sorted(services):
        print(f"  {service}")


def get_checks_to_run(args) -> Dict[str, Any]:
    """
    Determine which checks to run based on command line arguments.
    
    Args:
        args: Command line arguments
        
    Returns:
        Dictionary mapping check IDs to check classes
    """
    logger.debug("Determining checks to run based on command line arguments")
    
    # Start with all checks or filtered by account type
    if args.account_type == 'all':
        checks_to_run = ALL_CHECKS.copy()
    else:
        logger.debug(f"Filtering checks by account type: {args.account_type}")
        checks_to_run = {
            check_id: check_class for check_id, check_class in ALL_CHECKS.items()
            if check_class().account_type == args.account_type
        }
    
    # Filter by specific check if provided
    if args.check:
        logger.debug(f"Filtering for specific check: {args.check}")
        if args.check not in ALL_CHECKS:
            logger.error(f"Check {args.check} not found")
            sys.exit(1)
        
        check = ALL_CHECKS[args.check]()
        if args.account_type != 'all' and check.account_type != args.account_type:
            logger.error(f"Check {args.check} is for {check.account_type} accounts, but --account-type is set to {args.account_type}")
            sys.exit(1)
            
        return {args.check: ALL_CHECKS[args.check]}
    
    # Filter by service if provided
    if args.service:
        logger.debug(f"Filtering checks by service: {args.service}")
        service_checks = {}
        for check_id, check_class in checks_to_run.items():
            check = check_class()
            if check.service.lower() == args.service.lower():
                service_checks[check_id] = check_class
        
        if not service_checks:
            logger.error(f"No {args.account_type} checks found for service {args.service}")
            sys.exit(1)
        
        return service_checks
    
    # Check if there are any checks after filtering
    if checks_to_run is None or len(checks_to_run) == 0:
        logger.error("No checks found with selected filters")
        sys.exit(1)

    logger.debug(f"Selected {len(checks_to_run)} checks to run")
    return checks_to_run


def run_checks(checks_to_run: Dict[str, Any], regions: Optional[List[str]] = None, 
               profile: Optional[str] = None, role_arn: Optional[str] = None,
               session: Optional[Session] = None, audit_accounts: Optional[List[str]] = None,
               log_archive_accounts: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """
    Run the specified checks.
    
    Args:
        checks_to_run: Dictionary mapping check IDs to check classes
        regions: List of AWS regions to check
        profile: AWS profile to use
        role_arn: ARN of IAM role to assume
        session: Existing AWS session to use (if provided)
        audit_accounts: List of AWS accounts used for Audit/Security Tooling
        log_archive_accounts: List of AWS accounts used for Logging
        
    Returns:
        List of findings
    """
    all_findings = []
    # Use provided session or create a new one
    if session:
        aws_session = session
    else:
        logger.debug("Creating new AWS session")
        aws_session = get_session(profile=profile, role_arn=role_arn)
    
    logger.debug(f"Running {len(checks_to_run)} checks")
    if regions:
        logger.debug(f"Checking regions: {', '.join(regions)}")
    
    # Group checks by service for better progress reporting
    service_checks = {}
    for check_id, check_class in checks_to_run.items():
        check = check_class()
        if check.service not in service_checks:
            service_checks[check.service] = []
        service_checks[check.service].append((check_id, check_class))
    
    # Set up progress tracking
    progress = ScanProgress(len(checks_to_run))
    
    # Run checks by service
    for service, checks in service_checks.items():
        progress.update(service)
        logger.debug(f"Running {len(checks)} checks for service {service}")

        for check_id, check_class in checks:
            logger.debug(f"Initializing check {check_id}")
            check = check_class()
            check.initialize(aws_session, regions=regions)
            
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
                    "Service": service,
                    "CheckLogic": None,
                    "AccountType": check.account_type
                })
            
            progress.increment()
    
    progress.finish()
    logger.debug(f"All checks completed with {len(all_findings)} total findings")
    return all_findings


def main():
    """Main entry point."""
    args = parse_args()
    
    # Configure logging based on debug flag
    configure_logging(args.debug)
    
    if args.list_checks:
        list_checks(args.account_type)
        return
    
    if args.list_services:
        list_services()
        return
    
    # Parse regions if provided
    regions = None
    if args.regions:
        regions = [r.strip() for r in args.regions.split(',')]
    
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
    
    # Determine which checks to run
    checks_to_run = get_checks_to_run(args)
    
    # Generate output filename with timestamp if not specified
    output_file = args.output
    if output_file == 'sraverify_findings.csv':
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"sraverify_findings_{timestamp}.csv"
    
    # Create session for banner display and reuse for checks
    logger.debug("Creating AWS session")
    session = get_session(profile=args.profile, role_arn=args.role)
    
    # Display banner with session information
    print_banner(
        profile=args.profile or 'default', 
        region=session.region_name, 
        session=session,
        regions=regions,
        account_type=args.account_type,
        checks_count=len(checks_to_run),
        output_file=output_file,
        role=args.role
    )
    
    # Run checks (reusing the session we already created)
    findings = run_checks(
        checks_to_run, 
        regions, 
        args.profile, 
        args.role, 
        session=session,
        audit_accounts=audit_accounts,
        log_archive_accounts=log_archive_accounts
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
