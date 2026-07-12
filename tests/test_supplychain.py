"""Supply-chain opt-in check — deterministic, no live network calls (fetch is injected)."""
from __future__ import annotations

import pytest

from mcpgawk.supplychain import check, check_npm, check_pypi, extract_package


def test_extract_package_npx_scoped():
    assert extract_package("npx", ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]) == \
        ("npm", "@modelcontextprotocol/server-filesystem")


def test_extract_package_uvx():
    assert extract_package("uvx", ["some-mcp-server"]) == ("pypi", "some-mcp-server")


def test_extract_package_unrecognised_command_returns_none():
    # A bare local binary — we don't guess, we skip (never a false "clean").
    assert extract_package("/usr/local/bin/my-server", ["--flag"]) is None


def test_npm_deprecated_flagged():
    fake = {"dist-tags": {"latest": "2.88.2"},
            "versions": {"2.88.2": {"deprecated": "request has been deprecated, see ..."}}}
    f = check_npm("request", fetch=lambda url: fake)
    assert f.deprecated is True
    assert f.version == "2.88.2"
    assert "deprecated" in f.detail


def test_npm_clean_package_not_flagged():
    fake = {"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {}}}
    f = check_npm("some-clean-pkg", fetch=lambda url: fake)
    assert f.deprecated is False
    assert f.error is None


def test_npm_pinned_version_used_over_latest():
    fake = {"dist-tags": {"latest": "2.0.0"},
            "versions": {"1.0.0": {"deprecated": "old"}, "2.0.0": {}}}
    f = check_npm("pkg@1.0.0", fetch=lambda url: fake)
    assert f.version == "1.0.0" and f.deprecated is True


def test_npm_scoped_pinned_version_parses_correctly():
    fake = {"dist-tags": {"latest": "9.9.9"}, "versions": {"1.2.3": {}}}
    f = check_npm("@scope/pkg@1.2.3", fetch=lambda url: fake)
    assert f.package == "@scope/pkg" and f.version == "1.2.3"


def test_npm_lookup_failure_never_raises_and_never_false_flags():
    def boom(url):
        raise TimeoutError("registry unreachable")
    f = check_npm("whatever", fetch=boom)
    assert f.deprecated is False
    assert f.error is not None


def test_pypi_yanked_flagged():
    fake = {"info": {"version": "1.0.0"},
            "releases": {"1.0.0": [{"yanked": True, "yanked_reason": "security issue"}]}}
    f = check_pypi("some-pkg", fetch=lambda url: fake)
    assert f.deprecated is True and f.detail == "security issue"


def test_pypi_not_yanked():
    fake = {"info": {"version": "2.0.0"}, "releases": {"2.0.0": [{"yanked": False}]}}
    f = check_pypi("some-pkg", fetch=lambda url: fake)
    assert f.deprecated is False


def test_check_dispatches_npm_vs_pypi():
    calls = []
    def fetch(url):
        calls.append(url)
        return {"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {}},
                "info": {"version": "1.0.0"}, "releases": {"1.0.0": [{}]}}
    check("npx", ["-y", "pkg"], fetch=fetch)
    assert "registry.npmjs.org" in calls[0]
    calls.clear()
    check("uvx", ["pkg"], fetch=fetch)
    assert "pypi.org" in calls[0]


def test_check_returns_none_for_unrecognised_launch():
    assert check("/opt/my-binary", [], fetch=lambda url: {}) is None
