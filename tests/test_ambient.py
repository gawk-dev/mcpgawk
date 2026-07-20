"""Ambient credentials — what a launched MCP server inherits that no config declares.

Found by comparing this scanner against a general-purpose agent (2026-07-21): the agent reported
that ~/.npmrc holds a plaintext npm token which every `npx -y ...` server inherits. This scanner
reported only the env var NAMES a config declares, which reads as the credential surface and is a
fraction of it.

The invariant that matters most here is the one about restraint: this module must never read a
credential file. A scanner that opens your secrets to tell you they exist has become the thing it
warns about.
"""
from __future__ import annotations

import inspect

from mcpgawk import ambient
from mcpgawk.ambient import AmbientExposure, detect_ambient, summarize


def _home(tmp_path, *rels: str):
    for rel in rels:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("SECRET-VALUE-THAT-MUST-NEVER-BE-READ")
    return tmp_path


# --- It must never read a value ---------------------------------------------------------------

def test_never_opens_a_credential_file():
    """Enforced against the source, not just behaviour: a future edit that adds .read_text() here
    would turn a safety tool into an exfiltration surface."""
    src = inspect.getsource(ambient)
    for forbidden in ("read_text(", "open(", "read_bytes(", "readlines("):
        assert forbidden not in src, f"ambient.py calls {forbidden} — it must only ever stat"


def test_reports_paths_and_consequences_never_contents(tmp_path):
    exposure = detect_ambient(home=_home(tmp_path, ".npmrc"), environ={})
    assert exposure.files == [("~/.npmrc", "publish npm packages as you")]
    assert "SECRET-VALUE" not in str(exposure.as_dict())


def test_environment_variables_are_named_never_valued():
    exposure = detect_ambient(home=None, environ={"GITHUB_TOKEN": "ghp_realvalue",
                                                  "AWS_SECRET_ACCESS_KEY": "abc123",
                                                  "EDITOR": "vim"})
    assert exposure.env_names == ["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"]
    assert "ghp_realvalue" not in str(exposure.as_dict())
    assert "abc123" not in str(exposure.as_dict())


# --- What counts ------------------------------------------------------------------------------

def test_finds_the_real_machine_shape(tmp_path):
    home = _home(tmp_path, ".npmrc", ".pypirc", ".config/gh/hosts.yml", ".docker/config.json")
    exposure = detect_ambient(home=home, environ={})
    paths = [p for p, _ in exposure.files]
    assert paths == ["~/.npmrc", "~/.pypirc", "~/.config/gh/hosts.yml", "~/.docker/config.json"]
    # The consequence, not the filename, is what makes a reader care.
    assert dict(exposure.files)["~/.pypirc"] == "publish Python packages as you"


def test_absent_files_are_not_invented(tmp_path):
    assert detect_ambient(home=tmp_path, environ={}).files == []


def test_ordinary_variables_are_not_credential_shaped():
    exposure = detect_ambient(home=None, environ={"PATH": "/usr/bin", "HOME": "/x", "LANG": "en"})
    assert exposure.env_names == []


def test_the_inventory_is_stable_between_runs():
    """An inventory that reshuffles cannot be diffed, and diffing is the whole point."""
    env = {"B_TOKEN": "1", "A_SECRET": "2", "C_API_KEY": "3"}
    assert detect_ambient(home=None, environ=env).env_names == \
           detect_ambient(home=None, environ=dict(reversed(list(env.items())))).env_names


# --- The report line is about a PAIRING, not a machine ----------------------------------------

def test_silent_when_no_local_server_would_be_launched(tmp_path):
    """Credentials with nothing to inherit them is not a finding. Saying it anyway is the noise
    that teaches people to ignore the tool."""
    exposure = detect_ambient(home=_home(tmp_path, ".npmrc"), environ={})
    assert summarize(exposure, launched=0, exfil_capable=0) == []


def test_silent_when_there_is_nothing_to_inherit():
    assert summarize(AmbientExposure(), launched=5, exfil_capable=3) == []


def test_says_what_is_inherited_and_what_it_grants(tmp_path):
    exposure = detect_ambient(home=_home(tmp_path, ".npmrc", ".pypirc"), environ={"GH_TOKEN": "x"})
    lines = summarize(exposure, launched=8, exfil_capable=42)
    joined = "\n".join(lines)
    assert "8 local servers run as you" in lines[0]
    assert "no MCP config declares" in lines[0]
    # The CONSEQUENCE must travel with the path — "~/.pypirc" alone tells a reader nothing.
    assert "~/.npmrc — publish npm packages as you" in joined
    assert "~/.pypirc — publish Python packages as you" in joined
    assert "1 credential-shaped environment variable" in joined
    assert "42 of their tools can send data outward" in joined


def test_every_line_fits_a_terminal(tmp_path):
    """The fleet view holds an invariant that no row runs off screen. A warning that wraps into
    soup is one people skip — and this one exists precisely to be read at a glance."""
    home = _home(tmp_path, ".npmrc", ".pypirc", ".netrc", ".aws/credentials",
                 ".config/gh/hosts.yml", ".docker/config.json", ".kube/config")
    lines = summarize(detect_ambient(home=home, environ={"X_TOKEN": "1"}), 12, 99)
    assert max(len(ln) for ln in lines) <= 100


def test_the_credential_inventory_never_enters_the_JSON_PAYLOAD():
    """The highest-consequence invariant in this module.

    `fleet.to_json` is what the IDE extensions read AND what `mcpgawk-mcp` returns when an agent
    calls it. To be precise about the mechanism: the MCP server itself sends nothing anywhere — it
    answers the local client over stdio. But the CLIENT then puts that tool result into the
    conversation, and forwards it to whatever model is in use on the next turn. With a hosted model
    that means the content leaves the machine; with a local one it does not.

    So a list of which credential files exist on someone's machine must not be in that payload. It
    is rendered to the user's own terminal and nowhere else.

    If a future change adds ambient data to the payload, this fails — and it should, loudly.
    """
    import json

    from mcpgawk.fleet import FleetRow, to_json

    payload = to_json([
        FleetRow(name="a", state="SKIPPED", detail="local `npx` — not launched (needs --yes)"),
        FleetRow(name="b", state="CLEAN", detail="1 tool · 115 tok", url="https://x/mcp"),
    ])
    blob = json.dumps(payload)
    for leaked in (".npmrc", ".pypirc", ".ssh", ".aws", ".docker", "id_rsa", "id_ed25519"):
        assert leaked not in blob, f"{leaked} reached the JSON payload — it would be sent to a model"


def test_the_module_performs_no_network_or_process_work():
    """Zero egress, zero execution: it stats files and reads env var names. Anything else here would
    make a credential-inventory tool itself a thing that phones home or runs code."""
    src = inspect.getsource(ambient)
    for forbidden in ("requests", "urllib", "httpx", "socket", "subprocess", "Popen", "system("):
        assert forbidden not in src, f"ambient.py references {forbidden}"
