"""Regression test for test isolation issue.

This test verifies that patching a module function works correctly
even when the module was previously removed and re-imported from sys.modules.

The issue: test_lazy_imports.py previously removed pkg_defender.intel.x_twitter
from sys.modules, causing subsequent tests to get a new module object on re-import.
Patching pkg_defender.intel.x_twitter._api_get would patch the OLD (removed) module,
not the NEW re-imported one.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestIsolationRegression:
    """Tests for test isolation between modules."""

    @pytest.mark.asyncio
    async def test_patch_survives_module_reload(self) -> None:
        """Verify patch works after module reload.

        This test simulates the scenario that was failing:
        1. Module X is removed from sys.modules
        2. Module X is re-imported
        3. Patch is applied to module.X.function
        4. Code uses re-imported module, patch should apply
        """
        # Remove from sys.modules (simulating teardown)
        sys.modules.pop("pkg_defender.intel.x_twitter", None)

        # Re-import (what test_intel_twitter.py does)
        from pkg_defender.intel.x_twitter import XTwitterFeed, _api_get  # noqa: F401

        # Now apply patch (what test_intel_twitter.py tests do)
        with patch("pkg_defender.intel.x_twitter._api_get", new_callable=AsyncMock) as mock_api:
            mock_api.return_value = {
                "data": [
                    {
                        "id": "123",
                        "author_id": "111",
                        "created_at": (datetime.now() - timedelta(hours=1)).isoformat() + "Z",
                        "text": "Found malware `test-package`",
                    }
                ],
                "includes": {"users": []},
            }

            feed = XTwitterFeed()
            config = MagicMock()
            config.feeds.x_twitter_bearer_token = "test_token"
            config.feeds.x_twitter_keywords = ["malware"]
            config.feeds.x_twitter_trusted_accounts = []
            config.feeds.x_twitter_max_age_hours = 24
            config.feeds.http_timeout = 15

            result = await feed.fetch(config=config)

        # Verify the mock WAS called (this is what was failing before the fix)
        assert mock_api.called, "Patch was not applied - module object mismatch"
        assert len(result.records) == 1, f"Expected 1 record, got {len(result.records)}"
