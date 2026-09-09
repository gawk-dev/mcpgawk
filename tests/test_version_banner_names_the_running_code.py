"""The version banner must name the code that is RUNNING, not a distribution beside it.

WHY THIS FILE EXISTS. On 2026-09-09 `python -m mcpgawk --version` printed
`0.1.34 — OUT OF DATE. Upgrade: uv tool install --force mcpgawk` while executing 0.1.40 source.
Every word was wrong, on the one command a person runs to find out what they are running.

`importlib.metadata` answers "what distribution is installed", which is a DIFFERENT question from
"which copy did Python import". They agree right up until a source tree is ahead of an older
install on sys.path — or until an editable install's pyproject is bumped, since its recorded
version is fixed at install time. There were FOUR separate answers to "what version am I"
(`__init__`, `cli._installed_version`, `staleness.currency_line`, and the scan banner). There is
now one, and the others import it.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap


def _run(code: str, cwd) -> str:
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code)], cwd=str(cwd),
                          capture_output=True, text=True, timeout=90).stdout.strip()


def test_a_source_tree_reports_its_own_pyproject_version(tmp_path):
    """The reproduction. A package next to a pyproject.toml is a source tree, and that file is the
    truth about the code — whatever some installed distribution's metadata says."""
    root = tmp_path / "repo"
    (root / "src" / "mcpgawk").mkdir(parents=True)
    (root / "pyproject.toml").write_text('[project]\nname = "mcpgawk"\nversion = "9.9.9"\n')
    import mcpgawk
    src = (root / "src" / "mcpgawk" / "__init__.py")
    src.write_text(open(mcpgawk.__file__, encoding="utf-8").read(), encoding="utf-8")
    for mod in ("probe", "measure", "label"):        # the __init__ imports these eagerly
        (root / "src" / "mcpgawk" / f"{mod}.py").write_text(
            "ServerSnapshot=probe_stdio=probe_http=probe_sse=probe_url=None\n"
            "Measurement=measure=build_label=None\n")
    out = _run(f"""
        import sys; sys.path.insert(0, {str(root / 'src')!r})
        import mcpgawk; print(mcpgawk.__version__)
    """, cwd=root)
    assert out == "9.9.9", out


def test_an_installed_copy_still_uses_metadata(tmp_path):
    """NARROWNESS — the half that must not break. A wheel in site-packages has no pyproject above
    it, so metadata stays the answer. If this ever reads a stray pyproject from a parent directory,
    every installed user gets a version from someone else's repo."""
    from importlib.metadata import version

    import mcpgawk
    # This checkout IS a source tree, so prove the fallback directly rather than faking site-packages.
    assert mcpgawk._source_tree_version() is not None, "this repo has a pyproject; the test is wrong"
    # And that the resolver prefers it over metadata, which is the whole point.
    assert mcpgawk.__version__ == mcpgawk._source_tree_version()
    assert version("mcpgawk"), "metadata must still be readable — it is the installed-user path"


def test_the_staleness_line_compares_the_running_version():
    """The second half of the same lie: `currency_line` read metadata itself, so it could announce
    OUT OF DATE about a copy nobody ran, complete with an upgrade command that would do nothing."""
    import inspect

    from mcpgawk import staleness
    # `staleness.version` deliberately SHADOWS importlib.metadata.version module-wide, so every
    # caller and every pre-existing test in that module gets the corrected answer through the seam
    # they already use. What matters is that it delegates rather than re-deriving.
    assert "from . import __version__" in inspect.getsource(staleness.version)
    import mcpgawk
    assert staleness.version("mcpgawk") == mcpgawk.__version__


def test_every_surface_asks_the_one_definition():
    """A rule in one file is not a rule. `cli._installed_version` is what `--version` prints."""
    import inspect

    from mcpgawk import cli
    src = inspect.getsource(cli._installed_version)
    assert "from . import __version__" in src
    assert 'version("mcpgawk")' not in src


def test_a_version_resolver_never_raises(monkeypatch):
    """It runs on every import. An unreadable pyproject must degrade, not break the whole CLI."""
    import mcpgawk

    monkeypatch.setattr(mcpgawk, "_source_tree_version",
                        lambda: (_ for _ in ()).throw(OSError("disk gone")))
    assert mcpgawk._resolve_version()          # falls back to metadata, does not raise
