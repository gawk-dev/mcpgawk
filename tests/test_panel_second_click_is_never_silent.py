"""A button click that cannot run must SAY so — a silent no-op reads as a broken panel.

Founder report, 2026-08-13: "the panel is not working as anticipated … it is running in the
background throughout whenever we click on any button." Root cause reproduced: while an action
runs, `_run_action_bg` dropped every other click with a bare `return`, so during a two-minute scan
the whole panel felt dead while the banner said "Running scan…" on each self-refresh. The dropped
click now lands on the running banner and clears when the action completes.
"""
from __future__ import annotations

import threading
import time


def test_a_second_click_is_acknowledged_and_cleared(monkeypatch):
    from mcpgawk import panel

    gate = threading.Event()
    monkeypatch.setattr(panel, "run_scan",
                        lambda: (gate.wait(5), {"ok": True, "message": "done"})[1])
    panel._ACTION.update(running=False, label="", message="", rows=[], notice="", at="")

    panel._run_action_bg("scan")
    time.sleep(0.2)
    panel._run_action_bg("verify", "srv")          # the click that used to vanish

    banner = panel._action_banner(dict(panel._ACTION))
    assert "verify · srv" in banner and "not started" in banner, \
        "a second click while an action runs left no visible trace"
    assert "Running" in banner, "the running state itself must still be shown"

    gate.set()
    for _ in range(100):
        if not panel._ACTION["running"]:
            break
        time.sleep(0.05)
    assert not panel._ACTION["running"], "the first action never finished — vacuous below"
    assert not panel._ACTION.get("notice"), "the stale notice survived the action completing"
    assert "done" in panel._action_banner(dict(panel._ACTION)), "the result banner was lost"
