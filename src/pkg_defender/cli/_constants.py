"""Constants for version handling with security semantics."""

VERSION_UNSPECIFIED = ""  # User didn't specify a version - check vulnerabilities by package name only
VERSION_WILDCARD = "*"  # Check ALL versions (for audits)
VERSION_LATEST = "latest"

# When True, display source URLs in threat feed sync output.
SHOW_SOURCE_URLS = False
