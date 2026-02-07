"""
Error Handler Module

Provides utilities for handling common AWS API errors gracefully,
determining error types, and deciding retry strategies.
"""

from botocore.exceptions import (
    ClientError,
    NoCredentialsError,
    EndpointConnectionError,
    ParamValidationError,
)


# Error codes that indicate permission issues
PERMISSION_ERROR_CODES = [
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedAccess",
    "AuthorizationError",
    "Forbidden",
    "InvalidClientTokenId",
    "SignatureDoesNotMatch",
]

# Error codes that indicate transient/retryable issues
RETRYABLE_ERROR_CODES = [
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "ServiceUnavailable",
    "ServiceUnavailableException",
    "InternalError",
    "InternalServiceError",
    "RequestTimeout",
    "RequestTimeoutException",
]


def handle_aws_error(error):
    """
    Parse and format an AWS error into a human-readable message.

    Args:
        error: The exception that was raised.

    Returns:
        dict: Parsed error information with keys:
            - error_type: Category of the error
            - error_code: AWS error code (if applicable)
            - message: Human-readable error message
            - retryable: Whether the operation should be retried
    """
    if isinstance(error, ClientError):
        error_code = error.response["Error"]["Code"]
        error_message = error.response["Error"]["Message"]

        if is_permission_error(error):
            return {
                "error_type": "PERMISSION",
                "error_code": error_code,
                "message": f"Permission denied: {error_message}. "
                           f"Ensure your IAM policy includes the required permissions.",
                "retryable": False,
            }

        if should_retry(error):
            return {
                "error_type": "TRANSIENT",
                "error_code": error_code,
                "message": f"Transient AWS error: {error_message}. "
                           f"The operation may succeed if retried.",
                "retryable": True,
            }

        # Check for resource not found errors
        if error_code in ("NoSuchBucket", "NoSuchKey", "NotFoundException",
                          "ResourceNotFoundException", "DBInstanceNotFound"):
            return {
                "error_type": "NOT_FOUND",
                "error_code": error_code,
                "message": f"Resource not found: {error_message}",
                "retryable": False,
            }

        return {
            "error_type": "CLIENT_ERROR",
            "error_code": error_code,
            "message": f"AWS API error ({error_code}): {error_message}",
            "retryable": False,
        }

    if isinstance(error, NoCredentialsError):
        return {
            "error_type": "CREDENTIALS",
            "error_code": "NoCredentials",
            "message": "No AWS credentials found. Configure credentials via "
                       "AWS CLI, environment variables, or .env file.",
            "retryable": False,
        }

    if isinstance(error, EndpointConnectionError):
        return {
            "error_type": "NETWORK",
            "error_code": "EndpointConnectionError",
            "message": f"Could not connect to AWS endpoint: {error}. "
                       f"Check your network connection and region setting.",
            "retryable": True,
        }

    if isinstance(error, ParamValidationError):
        return {
            "error_type": "VALIDATION",
            "error_code": "ParamValidationError",
            "message": f"Invalid parameter: {error}",
            "retryable": False,
        }

    # Generic fallback
    return {
        "error_type": "UNKNOWN",
        "error_code": type(error).__name__,
        "message": f"Unexpected error: {error}",
        "retryable": False,
    }


def is_permission_error(error):
    """
    Check if an error is a permission/authorization error.

    Args:
        error: The exception to check.

    Returns:
        bool: True if the error is permission-related.
    """
    if isinstance(error, ClientError):
        error_code = error.response["Error"]["Code"]
        return error_code in PERMISSION_ERROR_CODES
    return False


def should_retry(error):
    """
    Determine if an operation should be retried based on the error type.

    Args:
        error: The exception to check.

    Returns:
        bool: True if the operation should be retried.
    """
    if isinstance(error, ClientError):
        error_code = error.response["Error"]["Code"]
        return error_code in RETRYABLE_ERROR_CODES

    if isinstance(error, EndpointConnectionError):
        return True

    return False

