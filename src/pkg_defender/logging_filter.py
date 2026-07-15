# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Secret redaction filter for logging."""

import logging
import re
from contextlib import suppress
from re import Pattern

# Patterns that likely contain secrets
SECRET_PATTERNS: list[Pattern[str]] = [
    # Generic API keys (various services)
    re.compile(
        r"(?i)(api[_-]?key|apikey|api[_-]?token)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
        re.IGNORECASE,
    ),
    # AWS keys
    re.compile(
        r"(?i)(aws[_-]?(access[_-]?key|secret))['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{20,})",
        re.IGNORECASE,
    ),
    # Bearer tokens
    re.compile(r"(?i)Bearer\s+([a-zA-Z0-9_\-\.]+)", re.IGNORECASE),
    # Generic tokens (JWT, etc)
    re.compile(
        r"(?i)(token|jwt|secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{16,})",
        re.IGNORECASE,
    ),
    # GitHub tokens
    re.compile(r"(gh[pousr]_[a-zA-Z0-9]{36,})", re.IGNORECASE),
    # Generic secret values in env vars
    re.compile(r"(?i)(SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)[:=]([^\s]+)", re.IGNORECASE),
]

# Patterns to redact that appear alone (not in key=value format)
STANDALONE_SECRETS: list[Pattern[str]] = [
    re.compile(r"(gh[pousr]_[a-zA-Z0-9]{36,})", re.IGNORECASE),
    re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),  # JWT
]


class SecretRedactingFilter(logging.Filter):
    """Logging filter that redacts potential secrets from log messages.

    Scans log records for patterns that likely contain sensitive data
    and replaces the secret portion with [REDACTED].
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact secrets from the log record's message.

        Args:
            record: The log record to filter.

        Returns:
            True to allow the record through.
        """
        if record.msg:
            # Convert to string in case of non-string message
            message = str(record.msg)
            redacted = self._redact_message(message)
            record.msg = redacted

            # Also redact in args if present
            if record.args:
                with suppress(Exception):
                    record.args = tuple(self._redact_message(str(arg)) if arg else arg for arg in record.args)

        return True

    def _redact_message(self, message: str) -> str:
        """Redact secrets from a single message string."""
        result = message

        # Apply key=value pattern redactions
        for pattern in SECRET_PATTERNS:
            result = pattern.sub(self._replacement_func, result)

        # Apply standalone secret redactions
        for pattern in STANDALONE_SECRETS:
            result = pattern.sub(r"[REDACTED]", result)

        return result

    @staticmethod
    def _replacement_func(match: re.Match[str]) -> str:
        """Create replacement string keeping context but redacting secret."""
        groups = match.groups()
        if len(groups) >= 2:
            # Has key and value - keep key, redact value
            key = groups[0]
            return f"{key}=[REDACTED]"
        elif len(groups) == 1:
            # Has only the secret value
            return "[REDACTED]"
        return match.group(0)
