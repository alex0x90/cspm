"""
Check Constants

Shared constants used by security check implementations.
"""

# Sensitive ports for EC2 security group checks
SENSITIVE_PORTS = [22, 3389, 3306, 1433, 5432, 27017]

# Known latest RDS engine major versions (for engine version checks)
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
