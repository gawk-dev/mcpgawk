"""Anti-drift canary for the skills host registry — same mechanism as test_canary_scan.py's
SUPPORTED_CLIENTS canary: a skill path added without registering its host (or a host registered
with no path behind it) cannot pass CI. Coverage cannot silently rot in either direction."""
from __future__ import annotations

from mcpgawk import skills


def _hosts_in_path_tables() -> set[str]:
    return (
        {h for h, _ in skills._HOME_SKILL_DIRS}
        | {h for h, _ in skills._HOME_SKILL_GLOBS}
        | {h for h, _ in skills._SYSTEM_SKILL_DIRS}
        | {h for h, _ in skills._DARWIN_SKILL_DIRS}
    )


def test_every_path_table_host_is_registered():
    unregistered = _hosts_in_path_tables() - set(skills.SUPPORTED_SKILL_HOSTS)
    assert not unregistered, (
        f"skill paths exist for unregistered host(s) {sorted(unregistered)} — "
        f"add them to SUPPORTED_SKILL_HOSTS")


def test_every_registered_host_has_at_least_one_path():
    pathless = set(skills.SUPPORTED_SKILL_HOSTS) - _hosts_in_path_tables()
    assert not pathless, (
        f"SUPPORTED_SKILL_HOSTS lists host(s) with no path in any table {sorted(pathless)} — "
        f"a registered host with no path is claimed coverage that does not exist")


def test_home_relative_paths_are_actually_relative():
    for host, rel in skills._HOME_SKILL_DIRS + skills._HOME_SKILL_GLOBS:
        assert not rel.startswith("/"), f"{host}: {rel!r} is absolute — belongs in the system table"
    for host, ap in skills._SYSTEM_SKILL_DIRS + skills._DARWIN_SKILL_DIRS:
        assert ap.startswith("/"), f"{host}: {ap!r} is relative — belongs in the home table"
