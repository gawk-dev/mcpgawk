"""The verify audit log must not store the credential the engine just convicted a server for.

Last sink of the 2026-08-13 persistence sweep. `--audit-log` appends one JSONL line per
reproduction attempt to `~/.gawk/verify-runs/<run>/audit.jsonl`, each carrying
`resultTextExcerpt` — 2000 characters of whatever the tool returned. The event's own docstring
conceded those responses "may contain the target's own data" and treated TRUNCATION as the
mitigation. Measured: verifying `tests/fixtures/toy_mcp_server.py`, whose `get_config` returns
`api_key: sk-…`, produced a CONVICTION for credential-exposure and wrote that same key into the
audit log in cleartext. The detector was storing the evidence it exists to warn about.

Driven through the SHIPPED ENGINE, not the TypeScript source: `verify.py` prefers the repo dev
build in a checkout and the wheel-bundled copy outside one, and this repo has shipped a fix that
lived only in sources before. The engine-side unit tests are `packages/verify/test/redact.test.ts`;
this one exists because passing those would not prove the built artefact does it.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "toy_mcp_server.py"
SECRET = "sk-LIVEFIXTURESECRETVALUE1234"          # what the fixture's get_config returns


@pytest.fixture(scope="module")
def observations() -> list[dict]:
    from mcpgawk import verify as verify_mod

    if verify_mod.unavailable_reason() is not None:
        pytest.skip(f"verify unavailable here: {verify_mod.unavailable_reason()}")
    tmp = Path(tempfile.mkdtemp(prefix="verify-audit-"))
    cfg = tmp / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "toy": {"command": sys.executable, "args": [str(FIXTURE)]}}}), encoding="utf-8")
    audit = tmp / "audit.jsonl"
    verify_mod.run([str(cfg), "--audit-log", str(audit)], timeout=300)
    assert audit.is_file(), "no audit log was written — every assertion below would be vacuous"
    lines = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines, "the audit log is empty — nothing was observed, so nothing is being asserted"
    return lines


def test_the_audit_log_does_not_store_the_tools_credential(observations: list[dict]):
    assert SECRET not in json.dumps(observations), \
        "the audit log stored the very credential the engine convicts servers for exposing"


def test_the_convicted_tool_still_has_a_trail(observations: list[dict]):
    """Masked, not dropped. A spot-check trail with the observation missing would be worse than one
    with the secret in it — the operator would have no way to see the tool was reached at all."""
    seen = [o for o in observations if o.get("tool") == "get_config"]
    assert seen, "the observation for the leaking tool vanished from the trail"
    assert seen[0]["resultTextExcerpt"] == "[REDACTED]", seen[0]
    assert seen[0]["ok"] is True and seen[0]["attempt"] >= 1, "measurements must survive intact"


def test_ordinary_tool_output_is_still_recorded_verbatim(observations: list[dict]):
    """Over-masking would empty the trail of everything an operator reads it for."""
    inbox = [o for o in observations if o.get("tool") == "read_inbox"]
    assert inbox, "sanity: the fixture's ordinary tool was observed"
    assert inbox[0]["resultTextExcerpt"] == "you have 3 new messages", inbox[0]
