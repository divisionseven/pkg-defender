# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""CI environment detection utilities."""

from __future__ import annotations

import os

CI_ENV_VARS = (
    "CI",
    "GITHUB_ACTIONS",
    "TF_BUILD",
    "GITLAB_CI",
    "CIRCLECI",
    "JENKINS_URL",
    "TRAVIS",
    "CODEBUILD_BUILD_ID",
    "BITBUCKET_COMMIT",
    "BUILDKITE",
    "TEAMCITY_VERSION",
    "SYSTEM_ACCESSTOKEN",
)


def is_ci_environment() -> bool:
    """Detect if running in a CI environment.

    Checks for known CI provider environment variables.
    This is used automatically when --ci flag is not explicitly passed,
    allowing pkgd to detect CI environments and skip interactive prompts.

    Returns:
        True if running in a CI environment, False otherwise.
    """
    return any(os.environ.get(var) for var in CI_ENV_VARS)


def get_ci_provider() -> str | None:
    """Get the name of the CI provider if running in CI.

    Returns:
        Name of CI provider (e.g., "github_actions", "azure_pipelines"),
        or None if not in a CI environment.
    """
    for var in CI_ENV_VARS:
        if os.environ.get(var):
            return var.lower()
    return None
