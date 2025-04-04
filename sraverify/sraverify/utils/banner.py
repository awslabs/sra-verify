"""
Banner display for SRA Verify tool.
"""
from colorama import Fore, Style
import datetime
import boto3
from typing import Optional, List, Dict, Any


def print_banner(profile: str, region: str, session: boto3.Session = None, 
                 regions: Optional[List[str]] = None, account_type: str = 'all',
                 checks_count: int = 0, output_file: str = None, role: Optional[str] = None):
    """
    Print the SRAVerify banner and initial execution information.
    
    Args:
        profile: AWS profile name
        region: AWS region name
        session: AWS session
        regions: List of AWS regions to check
        account_type: Type of accounts to run checks against
        checks_count: Number of checks to run
        output_file: Output file name
        role: ARN of IAM role being assumed
    """
    # ASCII art banner - using raw string to avoid escape sequence issues
    print(fr"""
                    _____ _____         ___       ___        _  __       
                   / ____|  __ \     /\ \  \     /  /       (_)/ _|      
                  | (___ | |__) |   /  \ \  \   /  /__  _ __ _| |_ _   _ 
                   \___ \|  _  /   / /\ \ \   v   / _ \| '__| |  _| | | |
                   ____) | | \ \  / ____ \ \     /  __/| |  | | | | |_| |
                  |_____/|_|  \_\/_/    \_\ \___/ \___||_|  |_|_|  \__, |
                                                                   __/ |
                                                                  |___/ {Fore.BLUE}
                        the security reference architecture verifier tool{Style.RESET_ALL}
    """)

    print(f"{Fore.YELLOW}Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}\n")

    # Print AWS credentials information
    print("-> Using the AWS credentials below:")
    print(f"  · AWS-CLI Profile: {profile or 'default'}")
    print(f"  · AWS Region: {region}")
    
    if session:
        try:
            sts = session.client('sts')
            caller_identity = sts.get_caller_identity()
            print(f"  · AWS Account: {caller_identity['Account']}")
            print(f"  · User Id: {caller_identity['UserId']}")
            print(f"  · Caller Identity ARN: {caller_identity['Arn']}")
        except Exception as e:
            print(f"  · Unable to retrieve identity information: {str(e)}")
    
    # Print scan information
    print("\n-> Starting SRA Verify scan...")
    if role:
        print(f"  · Assuming Role: {role}")
    print(f"  · Regions: {', '.join(regions) if regions else 'all enabled regions'}")
    print(f"  · Account Type: {account_type}")
    print(f"  · Checks: {checks_count}")
    if output_file:
        print(f"  · Output: {output_file}")
    print()
