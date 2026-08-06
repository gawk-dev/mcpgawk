"""Suite-wide setup for the public engine's tests.

Added 2026-08-06, after a sync took this suite from 1 failure to 9. None of the eight was a
regression: the canonical tests arrived without the conditions they were written against, met the
human-presence gate, and were refused — correctly.

The gate lives at the trust-store WRITES (`history.approve`, `baseline.publish`) rather than at the
commands, so every test that approves anything now meets it. A pytest run has no TTY and is usually
launched from inside an agent session, which is exactly what the gate exists to stop.
`MCPGAWK_APPROVE_NONINTERACTIVE` is the documented CI hatch: it emulates "a human authorised this
pipeline", which is the true state of a CI run.

Set here, once and visibly, rather than sprinkled through twenty tests — and NOT a way of disabling
the gate. Any test asserting the REFUSAL clears this with monkeypatch first, and monkeypatch wins.

Deliberately NOT a copy of the platform repo's conftest: that one builds paid licence state and
imports `gawk_platform`, which does not exist in this repo and must never be published into it.
This file carries only what the FREE suite needs. The canonical original, and the full reasoning,
is `tests/conftest.py` in the platform repo.
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture(scope="session", autouse=True)
def _the_suite_is_the_documented_ci_override():
    prior = os.environ.get("MCPGAWK_APPROVE_NONINTERACTIVE")
    os.environ["MCPGAWK_APPROVE_NONINTERACTIVE"] = "1"
    try:
        yield
    finally:
        if prior is None:
            os.environ.pop("MCPGAWK_APPROVE_NONINTERACTIVE", None)
        else:
            os.environ["MCPGAWK_APPROVE_NONINTERACTIVE"] = prior
