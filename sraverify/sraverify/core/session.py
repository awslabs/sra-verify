"""
AWS session management.
"""
from typing import Optional
import boto3

from sraverify.core.regions import resolve_scan_region


def get_session(region: Optional[str] = None, profile: Optional[str] = None,
                role_arn: Optional[str] = None) -> boto3.Session:
    """
    Get AWS session with optional region, profile, and role.

    With ``role_arn``, ``sts:AssumeRole`` is sent to the scan Region's STS --
    ``region`` when given, else the base session's Region -- so the role is
    assumed in the scan's partition, and the assumed session carries that same
    Region. When neither supplies a Region, ``PartitionUndeterminedError`` is
    raised before any STS call. Without ``role_arn`` the base session is
    returned as-is and no Region is required here.

    Args:
        region: AWS region name
        profile: AWS profile name
        role_arn: ARN of IAM role to assume

    Returns:
        AWS session

    Raises:
        PartitionUndeterminedError: ``role_arn`` was given and no Region can be
            determined. Propagated unwrapped, so the CLI can map it to exit 2.
        Exception: If session creation or AssumeRole fails
    """
    try:
        # First create a session with the provided profile or default credentials
        base = boto3.Session(region_name=region, profile_name=profile)
    except Exception as e:
        raise Exception(f"Failed to create AWS session: {str(e)}")

    if not role_arn:
        return base

    # Outside any wrapper: a usage error, propagated unwrapped, before STS.
    sts_region = resolve_scan_region([region] if region is not None else None, base)

    try:
        sts_client = base.client("sts", region_name=sts_region)
        response = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName="sraverify-session"
        )
        # Create a new session with the assumed role credentials
        credentials = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=sts_region,
        )
    except Exception as e:
        raise Exception(f"Failed to create AWS session: {str(e)}")
