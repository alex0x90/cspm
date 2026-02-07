"""
AWS Client Factory Module

Provides centralized Boto3 client and session creation with
error handling and credential validation.
"""

import sys
import boto3
from botocore.exceptions import (
    ClientError,
    NoCredentialsError,
    EndpointConnectionError,
    ProfileNotFound,
)

# Add project root to path so config can be imported
sys.path.insert(0, __file__.rsplit("/src/", 1)[0])
from config.aws_config import get_aws_session_kwargs


_session_cache = {}


def get_session(profile=None, region=None):
    """
    Get or create a cached boto3 Session.

    Args:
        profile: AWS profile name.
        region: AWS region name.

    Returns:
        boto3.Session: A configured session.
    """
    cache_key = (profile, region)
    if cache_key not in _session_cache:
        kwargs = get_aws_session_kwargs(profile=profile, region=region)
        _session_cache[cache_key] = boto3.Session(**kwargs)
    return _session_cache[cache_key]


def get_client(service_name, profile=None, region=None):
    """
    Create a Boto3 client for the given AWS service.

    Args:
        service_name: AWS service name (e.g., 's3', 'ec2', 'rds').
        profile: AWS profile name override.
        region: AWS region override.

    Returns:
        boto3.client: A configured service client.
    """
    session = get_session(profile=profile, region=region)
    return session.client(service_name)


def validate_credentials(profile=None, region=None):
    """
    Validate that AWS credentials are properly configured by
    calling STS get_caller_identity().

    Args:
        profile: AWS profile name override.
        region: AWS region override.

    Returns:
        dict: Caller identity information on success.

    Raises:
        SystemExit: If credentials are invalid or missing.
    """
    try:
        sts_client = get_client("sts", profile=profile, region=region)
        identity = sts_client.get_caller_identity()
        return {
            "account": identity["Account"],
            "arn": identity["Arn"],
            "user_id": identity["UserId"],
        }
    except NoCredentialsError:
        print("ERROR: No AWS credentials found.")
        print("Configure credentials via:")
        print("  - AWS CLI: aws configure")
        print("  - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
        print("  - .env file in the project root")
        raise
    except ProfileNotFound as e:
        print(f"ERROR: {e}")
        raise
    except ClientError as e:
        print(f"ERROR: AWS credential validation failed: {e}")
        raise
    except EndpointConnectionError as e:
        print(f"ERROR: Could not connect to AWS: {e}")
        raise

