"""A SAVED consent must not hide the coverage gap.

`_protect` populated `local_servers` only inside `if choice is None:`. A SAVED consent (or the
saved-launch -> remote-only downgrade) skips that branch, so on those runs `local_servers` stayed
`[]` and the end-of-run report printed "Protected: N server(s)" with NO mention of the local
servers nobody launched — the exact omission ea82ea1 fixed, reintroduced for the saved-consent
case. The existing coverage test drove protection_report with a hand-built list, so it could not
see this: the gap was in what `_protect` passes, not in protection_report itself.

This drives `_protect` through the real saved-consent path and captures what it passes.
"""
from __future__ import annotations

import mcpgawk.cli as cli
import mcpgawk.discover as discover
import mcpgawk.protect as protect


def test_a_saved_remote_only_consent_still_names_the_skipped_local_server(monkeypatch):
    captured = {}

    monkeypatch.setattr(protect, "load_consent", lambda: protect.REMOTE_ONLY)   # a SAVED consent
    monkeypatch.setattr(discover, "discover_servers",
                        lambda *a, **k: {"acme-fs": {"command": "npx -y @acme/fs"}})
    monkeypatch.setattr(cli, "_dispatch", lambda *a, **k: 0)                     # skip the real scan
    monkeypatch.setattr(cli, "_store_or_say_why", lambda: ({}, None))
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: False)                 # skip verify

    def _capture(store, guard_line, unchecked=None):
        captured["unchecked"] = unchecked
        return "report"
    monkeypatch.setattr(protect, "protection_report", _capture)

    cli._protect()

    unchecked = captured["unchecked"]
    names = [n for n, _why in (unchecked or [])]
    assert "acme-fs" in names, (
        f"a saved remote-only consent hid the unchecked local server: {unchecked}")
