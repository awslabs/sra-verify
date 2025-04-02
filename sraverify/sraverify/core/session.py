"""
AWS session management.
"""
from typing import Optional
import boto3


def get_session(region: Optional[str] = None, profile: Optional[str] = None, 
                role_arn: Optional[str] = None) -> boto3.Session:
    """
    Get AWS session with optional region, profile, and role.
    
    Args:
        region: AWS region name
        profile: AWS profile name
        role_arn: ARN of IAM role to assume
        
    Returns:
        AWS session
        
    Raises:
        Exception: If session creation fails
    """
    try:
        # First create a session with the provided profile or default credentials
        session = boto3.Session(region_name=region, profile_name=profile)
        
        # If a role ARN is provided, assume that role
        if role_arn:
            sts_client = session.client('sts')
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='sraverify-session'
            )
            
            # Create a new session with the assumed role credentials
            credentials = response['Credentials']
            return boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
        
        return session
    except Exception as e:
        raise Exception(f"Failed to create AWS session: {str(e)}")