"""Custom Click ParameterTypes for pkg-defender CLI."""

from __future__ import annotations

import re
from typing import Any

import click


class PackageSpecifier(click.ParamType[str]):
    """Click parameter type for package specifiers.

    Valid formats:
    - name@version (e.g., axios@1.0.0, lodash@4.17.21)
    - name==version (e.g., requests==2.28.0)
    - @scope/name@version (e.g., @types/node@18.0.0)

    Raises:
        click.UsageError: If the package specifier format is invalid.
    """

    name = "package_specifier"

    # Pattern for valid package specifiers
    # Matches: name@version, name==version, @scope/name@version, @scope/name==version
    _PATTERN = re.compile(r"^(?:@[^/]+/)?[^@=]+(?:@|==)\S+$")

    def convert(
        self,
        value: Any,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> str:
        """Validate and return the package specifier.

        Args:
            value: The input value to validate.
            param: The parameter this is being converted for.
            ctx: The current click context.

        Returns:
            The validated package specifier string.

        Raises:
            click.UsageError: If format is invalid.
        """
        if not isinstance(value, str):
            self.fail(f"{value!r} is not a string", param, ctx)

        if "@" not in value and "==" not in value:
            self.fail(
                f"Invalid package specifier '{value}'. Expected format: name@version or name==version",
                param,
                ctx,
            )

        if not self._PATTERN.match(value):
            self.fail(
                f"Invalid package specifier '{value}'. Expected format: name@version or name==version",
                param,
                ctx,
            )

        return value


# Singleton instance for use in @click.argument decorators
PACKAGE_SPECIFIER = PackageSpecifier()
