"""
AWS Configuration Module

Loads AWS credentials and configuration from environment variables
or a .env file. Provides defaults for region and profile.
"""

import os
from dotenv import load_dotenv

# Load .env file if it exists
load_dotenv()

# AWS Configuration Defaults
DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
AWS_PROFILE = os.getenv("AWS_PROFILE", None)
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", None)
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", None)
AWS_SESSION_TOKEN = os.getenv("AWS_SESSION_TOKEN", None)

# Sensitive ports for EC2 security group checks
SENSITIVE_PORTS = [22, 3389, 3306, 1433, 5432, 27017]

# Known latest RDS engine versions (for engine version checks)
LATEST_ENGINE_VERSIONS = {
    "mysql": "8.0",
    "postgres": "16",
    "mariadb": "10.11",
    "oracle-ee": "19",
    "oracle-se2": "19",
    "sqlserver-ee": "16.00",
    "sqlserver-se": "16.00",
    "sqlserver-ex": "16.00",
    "sqlserver-web": "16.00",
    "aurora-mysql": "8.0",
    "aurora-postgresql": "16",
}


def get_aws_session_kwargs(profile=None, region=None):
    """
    Build keyword arguments for creating a boto3 Session.

    Args:
        profile: AWS profile name override.
        region: AWS region override.

    Returns:
        dict: Keyword arguments for boto3.Session().
    """
    kwargs = {}

    effective_profile = profile or AWS_PROFILE
    if effective_profile:
        kwargs["profile_name"] = effective_profile

    effective_region = region or DEFAULT_REGION
    kwargs["region_name"] = effective_region

    # Only pass explicit credentials if no profile is set
    if not effective_profile:
        if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
            kwargs["aws_access_key_id"] = AWS_ACCESS_KEY_ID
            kwargs["aws_secret_access_key"] = AWS_SECRET_ACCESS_KEY
            if AWS_SESSION_TOKEN:
                kwargs["aws_session_token"] = AWS_SESSION_TOKEN

    return kwargs

