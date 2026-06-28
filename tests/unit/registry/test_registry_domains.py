"""Tests for pkg_defender.core.registry_domains module.

Tests the registry domain allowlist security functions:
- REGISTRY_ALLOWLIST constants
- _extract_domain helper
- is_domain_allowed security check
- get_registry_url function
- get_allowed_domains function
"""

from __future__ import annotations

import pytest

from pkg_defender.core import registry_domains


class TestRegistryAllowlist:
    """Tests for the REGISTRY_ALLOWLIST constant."""

    def test_npm_domains_in_allowlist(self) -> None:
        """npm ecosystem has the expected domains."""
        domains = registry_domains.REGISTRY_ALLOWLIST["npm"]
        assert "registry.npmjs.org" in domains
        assert "registry.npmmirror.com" in domains

    def test_pypi_domains_in_allowlist(self) -> None:
        """pypi ecosystem has the expected domains."""
        domains = registry_domains.REGISTRY_ALLOWLIST["pypi"]
        assert "pypi.org" in domains
        assert "files.pythonhosted.org" in domains

    def test_rubygems_domains_in_allowlist(self) -> None:
        """rubygems ecosystem has the expected domains."""
        domains = registry_domains.REGISTRY_ALLOWLIST["rubygems"]
        assert "rubygems.org" in domains

    def test_homebrew_domains_in_allowlist(self) -> None:
        """homebrew ecosystem has the expected domains."""
        domains = registry_domains.REGISTRY_ALLOWLIST["homebrew"]
        assert "formulae.brew.sh" in domains
        assert "github.com" in domains
        assert "raw.githubusercontent.com" in domains

    def test_cargo_domains_in_allowlist(self) -> None:
        """cargo ecosystem has the expected domains."""
        domains = registry_domains.REGISTRY_ALLOWLIST["cargo"]
        assert "crates.io" in domains
        assert "github.com" in domains

    def test_apt_domains_in_allowlist(self) -> None:
        """apt ecosystem has the expected domains."""
        domains = registry_domains.REGISTRY_ALLOWLIST["apt"]
        assert "archive.ubuntu.com" in domains
        assert "security.ubuntu.com" in domains

    def test_conda_domains_in_allowlist(self) -> None:
        """conda ecosystem has the expected domains."""
        domains = registry_domains.REGISTRY_ALLOWLIST["conda"]
        assert "repo.anaconda.com" in domains
        assert "conda-forge.org" in domains

    def test_yarn_registry_includes_npm(self) -> None:
        """yarn uses the npm registry."""
        domains = registry_domains.REGISTRY_ALLOWLIST["yarn"]
        assert "registry.npmjs.org" in domains


class TestExtractDomain:
    """Tests for _extract_domain helper function."""

    def test_extract_full_https_url(self) -> None:
        """Extracts domain from full HTTPS URL."""
        domain = registry_domains._extract_domain("https://registry.npmjs.org/package")
        assert domain == "registry.npmjs.org"

    def test_extract_full_http_url(self) -> None:
        """Extracts domain from full HTTP URL."""
        domain = registry_domains._extract_domain("http://example.com/path")
        assert domain == "example.com"

    def test_extract_protocol_relative_url(self) -> None:
        """Extracts domain from protocol-relative URL."""
        domain = registry_domains._extract_domain("//registry.npmjs.org/path")
        assert domain == "registry.npmjs.org"

    def test_extract_bare_domain(self) -> None:
        """Extracts domain from bare domain."""
        domain = registry_domains._extract_domain("registry.npmjs.org")
        assert domain == "registry.npmjs.org"

    def test_extract_bare_domain_with_subdomain(self) -> None:
        """Extracts domain from bare domain with subdomains."""
        domain = registry_domains._extract_domain("download.fedoraproject.org")
        assert domain == "download.fedoraproject.org"

    def test_extract_empty_string(self) -> None:
        """Returns None for empty string."""
        domain = registry_domains._extract_domain("")
        assert domain is None

    def test_extract_with_port_number(self) -> None:
        """Extracts domain from URL with port."""
        domain = registry_domains._extract_domain("https://example.com:8443/path")
        assert domain == "example.com:8443"

    def test_extract_normalizes_to_lowercase(self) -> None:
        """Normalizes domain to lowercase."""
        domain = registry_domains._extract_domain("https://REGISTRY.NPMJS.ORG/package")
        assert domain == "registry.npmjs.org"

    def test_extract_with_query_string(self) -> None:
        """Extracts domain from URL with query string."""
        domain = registry_domains._extract_domain("https://example.com?key=value")
        assert domain == "example.com"

    def test_extract_with_fragment(self) -> None:
        """Extracts domain from URL with fragment."""
        domain = registry_domains._extract_domain("https://example.com#section")
        assert domain == "example.com"


class TestIsDomainAllowed:
    """Tests for is_domain_allowed security function."""

    def test_npm_registry_allowed(self) -> None:
        """npm registry domain is allowed."""
        result = registry_domains.is_domain_allowed("npm", "https://registry.npmjs.org/lodash")
        assert result is True

    def test_npm_mirror_allowed(self) -> None:
        """npm mirror domain is allowed."""
        result = registry_domains.is_domain_allowed("npm", "https://registry.npmmirror.com/package")
        assert result is True

    def test_pypi_registry_allowed(self) -> None:
        """PYPI registry domain is allowed."""
        result = registry_domains.is_domain_allowed("pypi", "https://pypi.org/project/numpy")
        assert result is True

    def test_pypi_files_allowed(self) -> None:
        """PYPI files domain is allowed."""
        result = registry_domains.is_domain_allowed("pypi", "https://files.pythonhosted.org/packages/source")
        assert result is True

    def test_malicious_domain_rejected(self) -> None:
        """Malicious domain is rejected."""
        result = registry_domains.is_domain_allowed("npm", "https://evil.com/malicious")
        assert result is False

    def test_unknown_manager_rejected(self) -> None:
        """Unknown package manager is rejected."""
        result = registry_domains.is_domain_allowed("unknown-manager", "https://example.com")
        assert result is False

    def test_manager_name_normalized(self) -> None:
        """Manager name is normalized (lowercase, trimmed)."""
        result1 = registry_domains.is_domain_allowed("  NPM  ", "https://registry.npmjs.org")
        result2 = registry_domains.is_domain_allowed("npm", "https://registry.npmjs.org")
        assert result1 is True
        assert result2 is True

    def test_ftp_url_rejected(self) -> None:
        """FTP URL is rejected due to no http scheme."""
        result = registry_domains.is_domain_allowed("npm", "ftp://registry.npmjs.org")
        assert result is False

    def test_invalid_url_rejected(self) -> None:
        """Invalid URL is rejected."""
        result = registry_domains.is_domain_allowed("npm", "not-a-valid-url")
        assert result is False


class TestGetRegistryUrl:
    """Tests for get_registry_url function."""

    def test_get_npm_registry_url(self) -> None:
        """Returns the npm registry URL."""
        url = registry_domains.get_registry_url("npm")
        assert url == "https://registry.npmjs.org"

    def test_get_pypi_registry_url(self) -> None:
        """Returns the pypi registry URL."""
        url = registry_domains.get_registry_url("pypi")
        assert url == "https://pypi.org"

    def test_get_rubygems_registry_url(self) -> None:
        """Returns the rubygems registry URL."""
        url = registry_domains.get_registry_url("rubygems")
        assert url == "https://rubygems.org"

    def test_get_homebrew_registry_url(self) -> None:
        """Returns the homebrew registry URL."""
        url = registry_domains.get_registry_url("homebrew")
        assert url == "https://formulae.brew.sh"

    def test_get_cargo_registry_url(self) -> None:
        """Returns the cargo registry URL."""
        url = registry_domains.get_registry_url("cargo")
        assert url == "https://crates.io"

    def test_get_conda_registry_url(self) -> None:
        """Returns the conda registry URL."""
        url = registry_domains.get_registry_url("conda")
        assert url == "https://repo.anaconda.com"

    def test_unknown_manager_raises_error(self) -> None:
        """Raises ValueError for unknown manager."""
        with pytest.raises(ValueError) as exc_info:
            registry_domains.get_registry_url("unknown-manager")

        assert "Unknown package manager" in str(exc_info.value)
        assert "unknown-manager" in str(exc_info.value)

    def test_manager_name_normalized(self) -> None:
        """Manager name is normalized (lowercase, trimmed)."""
        url = registry_domains.get_registry_url("  NPM  ")
        assert url == "https://registry.npmjs.org"


class TestGetAllowedDomains:
    """Tests for get_allowed_domains function."""

    def test_get_npm_allowed_domains(self) -> None:
        """Returns the allowed domains for npm."""
        domains = registry_domains.get_allowed_domains("npm")
        assert isinstance(domains, frozenset)
        assert "registry.npmjs.org" in domains

    def test_get_pypi_allowed_domains(self) -> None:
        """Returns the allowed domains for pypi."""
        domains = registry_domains.get_allowed_domains("pypi")
        assert isinstance(domains, frozenset)
        assert "pypi.org" in domains

    def test_get_unknown_manager_returns_empty(self) -> None:
        """Returns empty frozenset for unknown manager."""
        domains = registry_domains.get_allowed_domains("unknown")
        assert domains == frozenset()

    def test_manager_name_normalized(self) -> None:
        """Manager name is normalized (lowercase, trimmed)."""
        domains = registry_domains.get_allowed_domains("  NPM  ")
        assert "registry.npmjs.org" in domains


class TestSecurityProperties:
    """Security-focused tests to verify the allowlist is effective."""

    def test_allowlist_is_frozenset(self) -> None:
        """Allowlist is a frozenset (immutable)."""
        allowlist = registry_domains.REGISTRY_ALLOWLIST["npm"]
        # frozenset should not have add method behavior
        assert isinstance(allowlist, frozenset)
        # Verify it's actually immutable by checking no add attribute works like list
        assert not hasattr(allowlist, "add") or not callable(getattr(allowlist, "add", None))

    def test_no_wildcard_domains(self) -> None:
        """No wildcard or catch-all domains in allowlist."""
        for _manager, domains in registry_domains.REGISTRY_ALLOWLIST.items():
            for domain in domains:
                # Should not have overly permissive domains
                assert not domain.startswith("*")
                assert "*" not in domain

    def test_localhost_not_allowed(self) -> None:
        """Localhost is not in any allowlist."""
        for _manager, domains in registry_domains.REGISTRY_ALLOWLIST.items():
            assert "localhost" not in domains
            assert "127.0.0.1" not in domains

    def test_private_network_not_allowed(self) -> None:
        """Private network domains not in allowlist."""
        for _manager, domains in registry_domains.REGISTRY_ALLOWLIST.items():
            assert "192.168." not in domains
            assert "10." not in domains
            assert "172.16." not in domains


class TestAliasesMapping:
    """Tests for manager alias mapping (pip, uv, pipx -> pypi)."""

    def test_pip_aliases_to_pypi(self) -> None:
        """pip maps to pypi domains."""
        domains = registry_domains.get_allowed_domains("pip")
        assert domains == registry_domains.get_allowed_domains("pypi")

    def test_uv_aliases_to_pypi(self) -> None:
        """uv maps to pypi domains."""
        domains = registry_domains.get_allowed_domains("uv")
        assert domains == registry_domains.get_allowed_domains("pypi")

    def test_pipx_aliases_to_pypi(self) -> None:
        """pipx maps to pypi domains."""
        domains = registry_domains.get_allowed_domains("pipx")
        assert domains == registry_domains.get_allowed_domains("pypi")

    def test_brew_aliases_to_homebrew(self) -> None:
        """brew maps to homebrew domains."""
        domains = registry_domains.get_allowed_domains("brew")
        assert domains == registry_domains.get_allowed_domains("homebrew")

    def test_gem_aliases_to_rubygems(self) -> None:
        """gem maps to rubygems domains."""
        domains = registry_domains.get_allowed_domains("gem")
        assert domains == registry_domains.get_allowed_domains("rubygems")

    def test_gem_aliases_to_rubygems_registry_url(self) -> None:
        """gem has same registry URL as rubygems."""
        gem_url = registry_domains.get_registry_url("gem")
        rubygems_url = registry_domains.get_registry_url("rubygems")
        assert gem_url == rubygems_url

    def test_yarn_and_pnpm_share_registry_domains(self) -> None:
        """yarn and pnpm use npm registry."""
        yarn_domains = registry_domains.get_allowed_domains("yarn")
        pnpm_domains = registry_domains.get_allowed_domains("pnpm")
        assert yarn_domains == pnpm_domains

    def test_pip3_aliases_to_pypi(self) -> None:
        """pip3 maps to pypi domains."""
        domains = registry_domains.get_allowed_domains("pip3")
        assert domains == registry_domains.get_allowed_domains("pypi")

    def test_pipenv_aliases_to_pypi(self) -> None:
        """pipenv maps to pypi domains."""
        domains = registry_domains.get_allowed_domains("pipenv")
        assert domains == registry_domains.get_allowed_domains("pypi")

    def test_poetry_aliases_to_pypi(self) -> None:
        """poetry maps to pypi domains."""
        domains = registry_domains.get_allowed_domains("poetry")
        assert domains == registry_domains.get_allowed_domains("pypi")

    def test_bun_aliases_to_npm(self) -> None:
        """bun maps to npm domains."""
        domains = registry_domains.get_allowed_domains("bun")
        assert domains == registry_domains.get_allowed_domains("npm")

    def test_bundler_aliases_to_rubygems(self) -> None:
        """bundler maps to rubygems domains."""
        domains = registry_domains.get_allowed_domains("bundler")
        assert domains == registry_domains.get_allowed_domains("rubygems")

    def test_composer_has_packagist(self) -> None:
        """composer maps to packagist.org."""
        domains = registry_domains.get_allowed_domains("composer")
        assert "packagist.org" in domains

    def test_pip3_is_domain_allowed(self) -> None:
        """is_domain_allowed works for pip3 manager."""
        assert registry_domains.is_domain_allowed("pip3", "https://pypi.org/project/requests")
        assert not registry_domains.is_domain_allowed("pip3", "https://evil.com/malicious")

    def test_poetry_is_domain_allowed(self) -> None:
        """is_domain_allowed works for poetry manager."""
        assert registry_domains.is_domain_allowed("poetry", "https://pypi.org/project/fastapi")
        assert not registry_domains.is_domain_allowed("poetry", "https://evil.com/malicious")

    def test_bun_is_domain_allowed(self) -> None:
        """is_domain_allowed works for bun manager."""
        assert registry_domains.is_domain_allowed("bun", "https://registry.npmjs.org/lodash")
        assert not registry_domains.is_domain_allowed("bun", "https://evil.com/malicious")

    def test_bundler_is_domain_allowed(self) -> None:
        """is_domain_allowed works for bundler manager."""
        assert registry_domains.is_domain_allowed("bundler", "https://rubygems.org/gems/rails")
        assert not registry_domains.is_domain_allowed("bundler", "https://evil.com/malicious")

    def test_composer_is_domain_allowed(self) -> None:
        """is_domain_allowed works for composer manager."""
        assert registry_domains.is_domain_allowed("composer", "https://packagist.org/packages/laravel")
        assert not registry_domains.is_domain_allowed("composer", "https://evil.com/malicious")

    def test_apt_includes_snapshot_debian(self) -> None:
        """apt allowlist includes snapshot.debian.org for publish-time lookups."""
        apt_domains = registry_domains.get_allowed_domains("apt")
        assert "snapshot.debian.org" in apt_domains

    def test_pnpm_includes_npmmirror(self) -> None:
        """pnpm allowlist includes npmmirror for Chinese users."""
        pnpm_domains = registry_domains.get_allowed_domains("pnpm")
        assert "registry.npmmirror.com" in pnpm_domains

    def test_yarn_includes_npmmirror(self) -> None:
        """yarn allowlist includes npmmirror for Chinese users."""
        yarn_domains = registry_domains.get_allowed_domains("yarn")
        assert "registry.npmmirror.com" in yarn_domains

    def test_yum_allowlist_includes_repodata_domains(self) -> None:
        """yum allowlist includes all 11 verified RPM repo domains."""
        yum_domains = registry_domains.get_allowed_domains("yum")
        # Fedora / EPEL
        assert "dl.fedoraproject.org" in yum_domains
        # RPM clones
        assert "mirror.stream.centos.org" in yum_domains
        assert "download.rockylinux.org" in yum_domains
        assert "repo.almalinux.org" in yum_domains
        assert "yum.oracle.com" in yum_domains
        assert "repo.openeuler.org" in yum_domains
        assert "mirrors.kernel.org" in yum_domains
        assert "download.opensuse.org" in yum_domains
        assert "download1.rpmfusion.org" in yum_domains
        assert "cdn.amazonlinux.com" in yum_domains

    def test_yum_allowlist_includes_koji_and_bodhi(self) -> None:
        """yum allowlist includes Koji and Bodhi domains."""
        yum_domains = registry_domains.get_allowed_domains("yum")
        assert "koji.fedoraproject.org" in yum_domains
        assert "bodhi.fedoraproject.org" in yum_domains

    def test_yum_allowlist_includes_mirrorlist_centos(self) -> None:
        """yum allowlist includes mirrorlist.centos.org (not bare 'mirrorlist')."""
        yum_domains = registry_domains.get_allowed_domains("yum")
        assert "mirrorlist.centos.org" in yum_domains
        assert "mirrorlist" not in yum_domains  # bare string is not a valid domain

    def test_dnf_same_as_yum(self) -> None:
        """dnf and yum share the same domain set."""
        yum_domains = registry_domains.get_allowed_domains("yum")
        dnf_domains = registry_domains.get_allowed_domains("dnf")
        assert yum_domains == dnf_domains
        # Verify the set is non-trivial (not just the original 3 domains)
        assert len(yum_domains) >= 14

    def test_yum_is_domain_allowed_repodata_domains(self) -> None:
        """is_domain_allowed works for yum with repodata domains."""
        assert registry_domains.is_domain_allowed(
            "yum",
            "https://dl.fedoraproject.org/pub/fedora/linux/development/rawhide"
            "/Everything/x86_64/os/repodata/repomd.xml",
        )
        assert registry_domains.is_domain_allowed("yum", "https://koji.fedoraproject.org/kojihub")
        assert registry_domains.is_domain_allowed("yum", "https://bodhi.fedoraproject.org/updates/")
        assert not registry_domains.is_domain_allowed("yum", "https://evil.com/malicious")
