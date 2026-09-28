"""Supply-chain opt-in check — deterministic, no live network calls (fetch is injected)."""
from __future__ import annotations

import urllib.error
from datetime import datetime, timezone

from mcpgawk.supplychain import check, check_npm, check_pypi, extract_package, registry_target


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


# ── slopsquatting: a name that does not exist, and a name that is too young to trust ──────────
NOW = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)


def _404(url):
    raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)


def test_npm_404_is_missing_not_an_error():
    f = check_npm("some-postgres-mcp", fetch=_404, now=NOW)
    assert f.missing is True
    assert f.error is None and f.deprecated is False


def test_pypi_404_is_missing_not_an_error():
    f = check_pypi("some-postgres-mcp", fetch=_404, now=NOW)
    assert f.missing is True and f.error is None


def test_other_http_status_is_could_not_check_never_missing():
    def rate_limited(url):
        raise urllib.error.HTTPError(url, 429, "Too Many Requests", {}, None)
    for checker in (check_npm, check_pypi):
        f = checker("pkg", fetch=rate_limited, now=NOW)
        assert f.missing is False and f.error is not None


def test_timeout_is_could_not_check_never_missing():
    def boom(url):
        raise TimeoutError("registry unreachable")
    f = check_npm("pkg", fetch=boom, now=NOW)
    assert f.missing is False and f.error is not None


def test_npm_young_name_flagged_from_time_created():
    fake = {"dist-tags": {"latest": "0.0.2"},
            "versions": {"0.0.1": {}, "0.0.2": {}, "0.0.3": {}},
            "time": {"created": "2026-09-20T08:00:00.000Z", "modified": "2026-09-21T08:00:00.000Z"}}
    f = check_npm("new-pkg", fetch=lambda url: fake, now=NOW)
    assert f.young is True
    assert f.first_published == "2026-09-20" and f.age_days == 8
    assert f.release_count == 3


def test_npm_old_name_with_rich_history_not_young():
    fake = {"dist-tags": {"latest": "3.0.0"},
            "versions": {"1.0.0": {}, "2.0.0": {}, "3.0.0": {}},
            "time": {"created": "2020-01-01T00:00:00.000Z"}}
    f = check_npm("old-pkg", fetch=lambda url: fake, now=NOW)
    assert f.young is False and f.age_days > 30


def test_young_boundary_is_thirty_days():
    def fake_at(created):
        return {"dist-tags": {"latest": "3"}, "versions": {"1": {}, "2": {}, "3": {}},
                "time": {"created": created}}
    at_30 = check_npm("p", fetch=lambda url: fake_at("2026-08-29T12:00:00Z"), now=NOW)
    at_29 = check_npm("p", fetch=lambda url: fake_at("2026-08-30T12:00:00Z"), now=NOW)
    assert at_30.age_days == 30 and at_30.young is False
    assert at_29.age_days == 29 and at_29.young is True


def test_thin_history_flagged_even_when_old():
    fake = {"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {}, "1.0.1": {}},
            "time": {"created": "2021-01-01T00:00:00Z"}}
    f = check_npm("thin-pkg", fetch=lambda url: fake, now=NOW)
    assert f.young is True and f.release_count == 2 and f.age_days > 30


def test_pypi_first_publish_is_earliest_upload_across_releases():
    fake = {"info": {"version": "0.3.0"},
            "releases": {
                "0.3.0": [{"upload_time_iso_8601": "2026-09-25T00:00:00.000000Z"}],
                "0.1.0": [{"upload_time_iso_8601": "2026-09-10T09:00:00.000000Z"}],
                "0.2.0": [{"upload_time_iso_8601": "2026-09-18T00:00:00.000000Z"}],
            }}
    f = check_pypi("young-py", fetch=lambda url: fake, now=NOW)
    assert f.first_published == "2026-09-10" and f.age_days == 18
    assert f.release_count == 3 and f.young is True


def test_pypi_without_upload_times_is_not_young_and_not_an_error():
    # Real responses always carry upload times; a fixture without them must not trip the
    # KeyError branch (a false "could not check") nor invent an age.
    fake = {"info": {"version": "2.0.0"},
            "releases": {"1.0.0": [{}], "1.5.0": [{}], "2.0.0": [{"yanked": False}]}}
    f = check_pypi("some-pkg", fetch=lambda url: fake, now=NOW)
    assert f.error is None and f.first_published is None and f.young is False


def test_pypi_pinned_spec_queries_the_bare_name():
    seen = []
    def fetch(url):
        seen.append(url)
        return {"info": {"version": "1.2.3"}, "releases": {"1.2.3": [{}]}}
    f = check_pypi("pkg==1.2.3", fetch=fetch, now=NOW)
    assert seen == ["https://pypi.org/pypi/pkg/json"]
    assert f.package == "pkg" and f.version == "1.2.3"
    seen.clear()
    check_pypi("pkg[extra]@1.0", fetch=fetch, now=NOW)
    assert seen == ["https://pypi.org/pypi/pkg/json"]


def test_registry_target_resolves_runner_subcommands_and_skips_non_packages():
    assert registry_target("npm", ["exec", "--yes", "pkg"]) == ("npm", "pkg")
    assert registry_target("pnpm", ["dlx", "@scope/pkg@1.0.0"]) == ("npm", "@scope/pkg@1.0.0")
    assert registry_target("yarn", ["dlx", "pkg"]) == ("npm", "pkg")
    assert registry_target("npx", ["-p", "real-pkg", "bin-name"]) == ("npm", "real-pkg")
    assert registry_target("uv", ["tool", "run", "pkg"]) == ("pypi", "pkg")
    assert registry_target("uvx", ["--from", "real-pkg", "cmd"]) == ("pypi", "real-pkg")
    assert registry_target("uvx", ["--python", "3.12", "pkg"]) == ("pypi", "pkg")
    assert registry_target("uvx", ["pkg==1.0"]) == ("pypi", "pkg==1.0")
    # Not a registry package — a path, a script, a local project run. Never reaches the registry.
    assert registry_target("uv", ["run", "server.py"]) is None
    assert registry_target("uv", ["--directory", "/x", "run", "foo"]) is None
    assert registry_target("npm", ["run", "start"]) is None
    assert registry_target("npx", ["./local/server.js"]) is None
    assert registry_target("uvx", ["--from", "git+https://github.com/o/r", "cmd"]) is None
    assert registry_target("node", ["server.js"]) is None


def test_check_never_queries_the_registry_for_a_non_package():
    def must_not_fetch(url):
        raise AssertionError(f"queried {url}")
    assert check("uv", ["--directory", "/x", "run", "foo"], fetch=must_not_fetch) is None
    assert check("npm", ["run", "start"], fetch=must_not_fetch) is None


def test_check_passes_now_through():
    fake = {"dist-tags": {"latest": "1"}, "versions": {"1": {}},
            "time": {"created": "2026-09-27T12:00:00Z"}}
    f = check("npx", ["-y", "fresh"], fetch=lambda url: fake, now=NOW)
    assert f.age_days == 1 and f.young is True
