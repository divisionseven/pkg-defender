# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Intelligence feed layer."""

from pkg_defender.intel.aggregator import FeedAggregator, OSVFeedAdapter
from pkg_defender.intel.base import FeedSource
from pkg_defender.intel.ghsa import GHSAFeed
from pkg_defender.intel.mastodon import MastodonFeed
from pkg_defender.intel.npm_advisory import NpmAdvisoryFeed
from pkg_defender.intel.ossf_malicious import OSSFMaliciousFeed
from pkg_defender.intel.reddit import RedditFeed
from pkg_defender.intel.rss_feed import RSSFeed
from pkg_defender.intel.x_twitter import XTwitterFeed

# Feed registry: feed name -> adapter class
FEED_REGISTRY = {
    "osv": OSVFeedAdapter,
    "ghsa": GHSAFeed,
    "socket": None,  # Point-query only (no bulk fetch) — not registered as a sync feed.
    "npm_advisory": NpmAdvisoryFeed,
    "mastodon": MastodonFeed,
    "reddit": RedditFeed,
    "rss": RSSFeed,
    "x_twitter": XTwitterFeed,
    "ossf_malicious": OSSFMaliciousFeed,
}

__all__ = [
    "FeedAggregator",
    "FeedSource",
    "GHSAFeed",
    "MastodonFeed",
    "NpmAdvisoryFeed",
    "OSSFMaliciousFeed",
    "OSVFeedAdapter",
    "RedditFeed",
    "RSSFeed",
    "XTwitterFeed",
    "FEED_REGISTRY",
]
