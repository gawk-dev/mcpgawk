"""`mcpgawk login KEY` on a FREE install fetches and installs the paid engine itself.

[FOUNDER 2026-09-12] "There should not be free beta and paid path .. everything should be
seamless." Before this, a paying customer who typed the command every page told them to type got
exit 3 and "the Platform isn't installed in this environment yet" — the key alone did nothing,
and the one-liner that did the work lived in an email. Now `login` IS the one-liner.

THE NON-NEGOTIABLES, each pinned below and mutation-checked at build time:
  1. The paid engine never ships in the public wheel (the existing artefact verifier owns this;
     `login` only ever FETCHES it, behind a valid key, from the token-gated endpoint).
  2. `login` never installs a wheel whose sha256 differs from the manifest's. A mismatch refuses,
     deletes the download, exits non-zero and never says "installed".
  3. 403 names the ONE missing step (the key is not eligible) and exits 3 — the documented
     "cannot run". 503 says try again and exits 4 — "incomplete", never 0.
  4. The key travels ONLY in the POST body. Never in a URL, never on a shell command line except
     the one the customer typed themselves (the re-exec after install).
  5. The wheel is installed WHERE THE RUNNING INTERPRETER LIVES — one rule, no fallback ladder.
     `install.sh` chooses where the free package goes; `login` puts the paid engine in the same
     place. Two install routes would be a second definition of "where mcpgawk is".
  6. After a successful install `login` re-execs itself through the new binary, so the platform's
     own `login` saves the key; the old process never imports the engine it just installed.

Every test drives the real entry point, `cli.main(["login", KEY])`, with the network and the
installer captured — no endpoint, no bucket, no real key.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from mcpgawk import cli, engine_fetch

KEY = "gawk-beta.test|2026-09-22|2026-10-15." + "0123456789abcdef" * 2   # the real grant shape; not a real key
WHEEL_BYTES = b"PK\x03\x04 not really a wheel, but bytes with a sha256"
SHA = hashlib.sha256(WHEEL_BYTES).hexdigest()


class Net:
    """Captures what `login` asked the network for, and answers as the endpoint would."""

    def __init__(self, status=200, body=None):
        self.status, self.body = status, body
        self.posts: list[tuple[str, dict]] = []
        self.gets: list[str] = []

    def post(self, url: str, payload: dict) -> tuple[int, dict]:
        self.posts.append((url, payload))
        if self.body is None:
            return self.status, {"ok": True, "version": "9.9.9", "filename": "mcpgawk-9.9.9-py3-none-any.whl",
                                 "sha256": SHA, "url": "https://bucket.example/signed/mcpgawk-9.9.9.whl?token=abc"}
        return self.status, self.body

    def get(self, url: str) -> bytes:
        self.gets.append(url)
        return WHEEL_BYTES


@pytest.fixture
def free_install(monkeypatch, tmp_path):
    """A FREE install: gawk_platform is not importable, downloads land in tmp, the installer and
    the re-exec are captured instead of run."""
    monkeypatch.setitem(sys.modules, "gawk_platform", None)
    monkeypatch.setitem(sys.modules, "gawk_platform.cli", None)
    net = Net()
    monkeypatch.setattr(engine_fetch, "_post", net.post)
    monkeypatch.setattr(engine_fetch, "_get", net.get)
    runs: list[list[str]] = []
    captures: list[bool] = []             # whether each _run was asked to hold its output
    installed: list[bytes] = []          # the wheel's bytes AS THE INSTALLER SAW THEM (it is deleted after)

    def run(argv, capture=False):
        runs.append(list(argv))
        captures.append(capture)
        if argv[-1].endswith(".whl"):
            installed.append(Path(argv[-1]).read_bytes())
        return 0

    monkeypatch.setattr(engine_fetch, "_run", run)
    net.captures = captures
    monkeypatch.setattr(engine_fetch, "_download_dir", lambda: tmp_path)
    net.installed = installed
    return net, runs


def test_login_on_a_free_install_fetches_verifies_installs_and_reexecs(free_install, capsys):
    net, runs = free_install
    rc = cli.main(["login", KEY])
    out = capsys.readouterr().out
    assert rc == 0, out
    # 4 — the key is in the POST body and nowhere else
    assert net.posts == [(engine_fetch.ENDPOINT, {"licenseKey": KEY, "want": "engine"})]
    assert KEY not in net.posts[0][0] and all(KEY not in u for u in net.gets)
    # the signed URL was fetched, the bytes verified, and the wheel installed then re-exec'd
    assert net.gets == ["https://bucket.example/signed/mcpgawk-9.9.9.whl?token=abc"]
    assert len(runs) == 2, runs
    install, reexec = runs
    assert install[-1].endswith("mcpgawk-9.9.9-py3-none-any.whl") and net.installed == [WHEEL_BYTES]
    assert not Path(install[-1]).exists(), "the downloaded wheel was left on disk after install"
    assert reexec[-2:] == ["login", KEY], reexec
    # the install runs CAPTURED (chatter held), the re-exec STREAMS (the user sees login's output)
    assert net.captures == [True, False], net.captures
    assert "installed" in out.lower()


def test_a_wheel_whose_sha256_does_not_match_is_refused_and_deleted(free_install, capsys):
    net, runs = free_install
    net.body = {"ok": True, "version": "9.9.9", "filename": "mcpgawk-9.9.9-py3-none-any.whl",
                "sha256": "0" * 64, "url": "https://bucket.example/signed/x.whl"}
    rc = cli.main(["login", KEY])
    out = capsys.readouterr()
    text = (out.out + out.err).lower()
    assert rc == 4
    assert runs == [], "an unverified wheel reached the installer"
    assert "installed" not in text and "sha256" in text, text
    assert not list(engine_fetch._download_dir().glob("*.whl")), "the bad download was left on disk"


def test_a_key_that_is_not_eligible_names_the_one_missing_step_and_exits_3(free_install, capsys):
    net, runs = free_install
    net.status, net.body = 403, {"error": "not-eligible"}
    rc = cli.main(["login", KEY])
    out = capsys.readouterr()
    text = (out.out + out.err).lower()
    assert rc == 3 and runs == [] and net.gets == []
    assert "trial" in text or "licence" in text, text
    assert "installed" not in text


def test_an_endpoint_outage_says_try_again_and_exits_4_never_0(free_install, capsys):
    net, runs = free_install
    net.status, net.body = 503, {"error": "try-again"}
    rc = cli.main(["login", KEY])
    out = capsys.readouterr()
    text = (out.out + out.err).lower()
    assert rc == 4 and runs == [] and net.gets == []
    assert "try again" in text and "installed" not in text, text


def test_a_download_that_fails_midway_says_so_and_exits_4(free_install, capsys):
    net, runs = free_install

    def broken(url):
        raise OSError("connection reset")

    net.get = broken
    import mcpgawk.engine_fetch as ef
    ef._get = broken
    rc = cli.main(["login", KEY])
    out = capsys.readouterr()
    text = (out.out + out.err).lower()
    assert rc == 4 and runs == []
    assert "try again" in text and "installed" not in text, text


def test_an_installer_that_exits_nonzero_never_reexecs_and_never_says_installed(free_install, monkeypatch, capsys):
    net, runs = free_install
    monkeypatch.setattr(engine_fetch, "_run", lambda argv, capture=False: (runs.append(list(argv)), 1)[1])
    rc = cli.main(["login", KEY])
    out = capsys.readouterr()
    text = (out.out + out.err).lower()
    assert rc == 4 and len(runs) == 1, runs          # the installer ran once; NO re-exec
    assert "installed" not in text and "exited 1" in text, text


def test_the_wheel_is_installed_where_the_running_interpreter_lives(monkeypatch, tmp_path):
    """One rule: a uv tool environment (uv-receipt.toml beside the prefix) installs with uv; a
    pipx venv with pipx; anything else with THIS interpreter's pip. No ladder, no guessing."""
    wheel = tmp_path / "w.whl"
    wheel.write_bytes(b"x")
    # uv tool env
    prefix = tmp_path / "uv" / "tools" / "mcpgawk"
    prefix.mkdir(parents=True)
    (prefix / "uv-receipt.toml").write_text("[tool]\n")
    monkeypatch.setattr(engine_fetch.sys, "prefix", str(prefix))
    monkeypatch.setattr(engine_fetch.shutil, "which", lambda name: "/usr/local/bin/uv" if name == "uv" else None)
    assert engine_fetch.install_argv(wheel)[:4] == ["/usr/local/bin/uv", "tool", "install", "--force"]
    # pipx venv
    monkeypatch.setattr(engine_fetch.sys, "prefix", str(tmp_path / "pipx" / "venvs" / "mcpgawk"))
    monkeypatch.setattr(engine_fetch.shutil, "which", lambda name: "/usr/local/bin/pipx" if name == "pipx" else None)
    assert engine_fetch.install_argv(wheel)[:3] == ["/usr/local/bin/pipx", "install", "--force"]
    # plain venv / pip
    monkeypatch.setattr(engine_fetch.sys, "prefix", str(tmp_path / "somewhere"))
    argv = engine_fetch.install_argv(wheel)
    assert argv[:4] == [sys.executable, "-m", "pip", "install"] and "--force-reinstall" in argv
    # a plain venv WITHOUT pip (`uv venv` makes one) and uv on PATH: uv installs into THIS
    # interpreter. Measured on the published 0.1.52: the engine was fetched, then "No module
    # named pip" — a customer on `uv venv && uv pip install mcpgawk` got nothing.
    monkeypatch.setattr(engine_fetch, "_has_pip", lambda: False)
    monkeypatch.setattr(engine_fetch.shutil, "which", lambda name: "/usr/local/bin/uv" if name == "uv" else None)
    argv = engine_fetch.install_argv(wheel)
    assert argv[:2] == ["/usr/local/bin/uv", "pip"] and argv[argv.index("--python") + 1] == sys.executable
    assert "tool" not in argv, "not a uv tool env — do not create one"
    # no pip AND no uv: the pip command stays, so the failure is loud and names the missing step
    monkeypatch.setattr(engine_fetch.shutil, "which", lambda name: None)
    assert engine_fetch.install_argv(wheel)[:3] == [sys.executable, "-m", "pip"]


def test_login_without_a_key_on_a_free_install_names_the_key_as_the_one_missing_step(monkeypatch, capsys):
    """The old message pointed at a purchase email and a one-liner that slice 1 deleted."""
    monkeypatch.setitem(sys.modules, "gawk_platform", None)
    monkeypatch.setitem(sys.modules, "gawk_platform.cli", None)
    rc = cli.main(["login"])
    err = capsys.readouterr().err
    assert rc == 3 and "mcpgawk login '<license-key>'" in err, err
    assert "email has the one-line" not in err and "installed" not in err.lower(), err
    # -h on a free install prints usage and exits 0, exactly as the paid `login -h` does
    rc = cli.main(["login", "--help"])
    out = capsys.readouterr().out
    assert rc == 0 and out.startswith("usage: mcpgawk login '<license-key>'"), out


def test_a_key_the_shell_split_at_a_pipe_is_caught_before_any_network_call(free_install, capsys):
    """The trial key is `gawk-beta.<name>|<date>|<date>.<32 hex>`. Pasted unquoted, the shell
    splits it at the first `|` (measured 2026-09-15 on the released 0.1.45): `login` receives
    `gawk-beta.<name>`. That must not reach the endpoint as a 403 that says "check the key" —
    it must name the fix: single quotes."""
    net, runs = free_install
    rc = cli.main(["login", "gawk-beta.sri"])
    out = capsys.readouterr()
    text = (out.out + out.err).lower()
    assert rc == 3 and net.posts == [] and runs == []
    assert "single quotes" in text and "installed" not in text, text
    # a complete grant of the right shape is NOT caught by the shape check
    assert not engine_fetch.looks_truncated("gawk-beta.sri|2026-09-22|2026-10-15." + "a" * 32)
    assert engine_fetch.looks_truncated("gawk-beta.sri|2026-09-22|2026-10-15")
    # a name with a dot in it is a valid key, not a truncated one (the body is matched greedily)
    assert not engine_fetch.looks_truncated("gawk-beta.j. doe|2026-09-22|2026-10-15." + "a" * 32)
    # the shell-safe shape (v2, `_`-separated body) passes the same check
    assert not engine_fetch.looks_truncated("gawk-beta.sri_2026-09-22_2026-10-15." + "a" * 32)


def test_the_request_body_is_exactly_what_the_endpoint_reads():
    """`license-status.js` reads `licenseKey` and `want`. A renamed field would be a 400 in prod
    and a green suite here — so the shape is pinned as data, not as a mock."""
    assert json.loads(engine_fetch.request_body(KEY)) == {"licenseKey": KEY, "want": "engine"}


def test_the_installer_is_quiet_on_success_and_shows_its_output_on_failure(capsys):
    """The chatter fix: with capture=True a successful install prints nothing (uv's package list
    and PATH warning stay out of the two login success lines), and a FAILED one shows exactly what
    the child said, because that is what a broken install needs to surface."""
    rc = engine_fetch._run([sys.executable, "-c", "print('INSTALLER-CHATTER')"], capture=True)
    out = capsys.readouterr()
    assert rc == 0 and "INSTALLER-CHATTER" not in (out.out + out.err), "chatter leaked on success"
    rc = engine_fetch._run([sys.executable, "-c", "import sys; print('BOOM'); sys.exit(2)"], capture=True)
    out = capsys.readouterr()
    assert rc == 2 and "BOOM" in (out.out + out.err), "a failed install must show its output"
