"""Domain-specific exit codes for pkg-defender CLI.

Exit code ranges:
- 0: Success
- 1: General error
- 2: Usage/argument error
- 3+: Domain-specific codes
"""

# Standard exit codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_USAGE_ERROR = 2

# Domain-specific exit codes
EXIT_COOLDOWN = 3
EXIT_THREAT_DETECTED = 4
EXIT_REGISTRY_UNREACHABLE = 5
EXIT_CONFIG_ERROR = 6
EXIT_DB_ERROR = 7
EXIT_PARTIAL_FAILURE = 8
EXIT_SIGINT = 130

# Mapping of exit codes to descriptions for --help exit-codes option
EXIT_CODE_DESCRIPTIONS = {
    EXIT_SUCCESS: "Success",
    EXIT_GENERAL_ERROR: "General error",
    EXIT_USAGE_ERROR: "Invalid arguments or usage error",
    EXIT_COOLDOWN: "Package version is in cooldown period",
    EXIT_THREAT_DETECTED: "Threat or vulnerability detected",
    EXIT_REGISTRY_UNREACHABLE: "Registry or network unreachable",
    EXIT_CONFIG_ERROR: "Configuration error",
    EXIT_DB_ERROR: "Database error",
    EXIT_PARTIAL_FAILURE: "Setup completed with warnings (partial failure)",
    EXIT_SIGINT: "Interrupted by signal (SIGINT)",
}
