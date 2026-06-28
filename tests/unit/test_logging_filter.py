"""Tests for the secret redaction logging filter (pkg_defender.logging_filter)."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from pkg_defender.logging_filter import (
    SECRET_PATTERNS,
    SecretRedactingFilter,
)


class TestReplacementFunc:
    """Direct unit tests for the static _replacement_func method."""

    def test_returns_key_equals_redacted_when_two_or_more_groups(self) -> None:
        """_replacement_func returns key=[REDACTED] when >= 2 capture groups present."""
        match = MagicMock()
        match.groups.return_value = ("api_key", "abcdefghijklmnopqrst")
        result = SecretRedactingFilter._replacement_func(match)
        assert result == "api_key=[REDACTED]"

    def test_returns_redacted_when_one_group(self) -> None:
        """_replacement_func returns [REDACTED] when exactly one capture group."""
        match = MagicMock()
        match.groups.return_value = ("secretvalue",)
        result = SecretRedactingFilter._replacement_func(match)
        assert result == "[REDACTED]"

    def test_returns_full_match_when_zero_groups(self) -> None:
        """_replacement_func returns the full match text when no capture groups."""
        match = MagicMock()
        match.groups.return_value = ()
        match.group.return_value = "full_match_text"
        result = SecretRedactingFilter._replacement_func(match)
        assert result == "full_match_text"
        match.group.assert_called_once_with(0)


class TestRedactMessage:
    """Integration tests for the _redact_message method."""

    def test_redacts_api_key_pattern(self) -> None:
        """_redact_message replaces api_key=value with api_key=[REDACTED]."""
        filt = SecretRedactingFilter()
        message = "api_key=abcdefghijklmnopqrst"
        result = filt._redact_message(message)
        assert result == "api_key=[REDACTED]"

    def test_redacts_bearer_token(self) -> None:
        """_redact_message replaces a Bearer token with [REDACTED]."""
        filt = SecretRedactingFilter()
        message = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9"
        result = filt._redact_message(message)
        assert result == "Authorization: [REDACTED]"

    def test_redacts_github_token(self) -> None:
        """_redact_message redacts a GitHub-style token in key=value format."""
        filt = SecretRedactingFilter()
        # ghp_ prefix + 36 chars — matches the GitHub token pattern
        token_value = "ghp_" + "a" * 36
        message = f"token={token_value}"
        result = filt._redact_message(message)
        assert result == "token=[REDACTED]"

    def test_preserves_clean_message(self) -> None:
        """_redact_message returns the original message when no secrets are present."""
        filt = SecretRedactingFilter()
        message = "Processing package requests for numpy==1.24.0"
        result = filt._redact_message(message)
        assert result == message

    def test_redacts_multiple_secrets_in_one_message(self) -> None:
        """_redact_message redacts both an API key and a Bearer token in one pass."""
        filt = SecretRedactingFilter()
        message = "api_key=abcdefghijklmnopqrst and Authorization: Bearer eyJhbGciOiJIUzI1NiJ9"
        result = filt._redact_message(message)
        assert "api_key=[REDACTED]" in result
        assert "[REDACTED]" in result
        assert "abcdefghijklmnopqrst" not in result
        assert "eyJhbGciOiJIUzI1NiJ9" not in result


class TestSecretRedactingFilterFilter:
    """Integration tests for SecretRedactingFilter.filter()."""

    @pytest.fixture
    def filter_instance(self) -> SecretRedactingFilter:
        """Return a fresh SecretRedactingFilter for each test."""
        return SecretRedactingFilter()

    def _make_record(
        self,
        msg: str | None,
        args: tuple | None = None,
        level: int = logging.INFO,
    ) -> logging.LogRecord:
        """Build a LogRecord for testing."""
        return logging.LogRecord(
            name="test",
            level=level,
            pathname=__file__,
            lineno=100,
            msg=msg,
            args=args,
            exc_info=None,
        )

    def test_redacts_message_in_record(self, filter_instance: SecretRedactingFilter) -> None:
        """filter() redacts the msg field of a LogRecord containing a secret."""
        record = self._make_record("api_key=abcdefghijklmnopqrst")
        result = filter_instance.filter(record)
        assert result is True
        assert record.msg == "api_key=[REDACTED]"

    def test_redacts_record_args(self, filter_instance: SecretRedactingFilter) -> None:
        """filter() redacts secrets found in record.args."""
        record = self._make_record(
            msg="Secret: %s",
            args=("api_key=abcdefghijklmnopqrst",),
        )
        result = filter_instance.filter(record)
        assert result is True
        # msg stays the format string — no secret in it
        assert record.msg == "Secret: %s"
        # the arg is redacted
        assert record.args == ("api_key=[REDACTED]",)

    def test_handles_non_string_args(self, filter_instance: SecretRedactingFilter) -> None:
        """filter() handles mixed-type args (int + string with secret) without crashing."""
        record = self._make_record(
            msg="Item %d has %s",
            args=(42, "api_key=abcdefghijklmnopqrst"),
        )
        result = filter_instance.filter(record)
        assert result is True
        assert record.args is not None
        # integer arg is stringified but redaction is a no-op on it
        assert "42" in str(record.args)
        # string arg containing a secret is redacted
        assert "api_key=[REDACTED]" in str(record.args)

    def test_does_not_crash_on_none_msg(self, filter_instance: SecretRedactingFilter) -> None:
        """filter() returns True without crashing when record.msg is None."""
        record = self._make_record(msg=None)
        result = filter_instance.filter(record)
        assert result is True

    def test_always_returns_true(self, filter_instance: SecretRedactingFilter) -> None:
        """filter() always returns True — it never drops log records."""
        # Record with no secrets
        clean = self._make_record("Clean message with no secrets")
        assert filter_instance.filter(clean) is True

        # Record with secrets
        secret = self._make_record("api_key=abcdefghijklmnopqrst")
        assert filter_instance.filter(secret) is True


class TestActualPatterns:
    """Real regex patterns matched against known secret formats."""

    def test_actual_secret_patterns_catch_known_formats(self) -> None:
        """Each SECRET_PATTERNS regex matches a known format and the replacement is correct."""
        test_cases: list[tuple[int, str, str]] = [
            # (pattern_index, input_text, expected_output)
            (
                0,
                "api_key=abcdefghijklmnopqrst",
                "api_key=[REDACTED]",
            ),
            (
                1,
                "aws_secret=AKIAIOSFODNN7EXAMPLE",
                "aws_secret=[REDACTED]",
            ),
            (
                2,
                "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.dGVzdA",
                "Authorization: [REDACTED]",
            ),
            (
                3,
                "password=SuperSecretVal1234567",
                "password=[REDACTED]",
            ),
            (
                4,
                "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
                "[REDACTED]",
            ),
            (
                5,
                "SECRET=my_secret_key_here_1234",
                "SECRET=[REDACTED]",
            ),
        ]

        for pattern_index, input_text, expected in test_cases:
            pattern = SECRET_PATTERNS[pattern_index]
            result = pattern.sub(SecretRedactingFilter._replacement_func, input_text)
            assert result == expected, (
                f"SECRET_PATTERNS[{pattern_index}] failed on {input_text!r}: expected {expected!r}, got {result!r}"
            )
