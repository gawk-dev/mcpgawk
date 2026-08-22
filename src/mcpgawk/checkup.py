"""`mcpgawk checkup` — one command that exercises the WHOLE product and captures the result.

`report` captures what already ran. That is the wrong shape for a beta: a tester who never
reaches `verify` produces an honest, empty bundle, and we learn nothing about the surfaces
they never touched — which are exactly the surfaces most likely to hold bugs.

So checkup DRIVES the product, in the order we intend it to be used, and records what each
step did. Three properties matter more than the feature list:

* **It drives the real shipped binary**, one subprocess per step. An in-process call would
  test the functions; a beta needs to test the thing the tester actually installed,
  including its argument parsing, its consent prompts and its exit codes.
* **A failing step is the finding, not the end.** Nothing aborts the walk. The bundle from
  the machine where step 3 crashed is the most valuable bundle we can receive.
* **The order IS the intended workflow**, so where a tester stops tells us the flow is
  wrong. That is recorded as data, not inferred later from a screenshot.

The panel is rendered rather than screenshotted: it is server-rendered HTML, so every tab
can be produced against the tester's real data and put in the bundle. We then see the
empty states, wrong counts and broken layouts on data we can never reproduce here.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import report
from .report_redact import clean_text, scrub_paths

OK = "ok"
FAILED = "failed"
DECLINED = "declined"
TIMED_OUT = "timed out"
INTERRUPTED = "interrupted"
CRASHED = "crashed"


@dataclass
class Step:
    name: str
    what: str
    command: list[str] = field(default_factory=list)
    outcome: str = ""
    exit_code: int | None = None
    seconds: float = 0.0
    detail: str = ""


def _binary() -> list[str]:
    """Drive the installed entry point, falling back to this interpreter's module.

    `shutil.which` first because that is the command the tester actually types; if mcpgawk
    is not on PATH that is itself worth recording, and `-m` still lets the walk continue.
    """
    import shutil

    found = shutil.which("mcpgawk")
    return [found] if found else [sys.executable, "-m", "mcpgawk"]


def _step_body(command: list[str], stdout: str, stderr: str, strict: bool) -> str:
    """The text written to `steps/<name>.txt`, per mode.

    Comprehensive keeps the output — that IS the diagnosis. But `scan`/`verify` stdout names
    each server by host, the packages it launches and the arguments it carries, and this is
    free text, not a structured record `redact_record` can walk field by field. `clean_text`'s
    strict pass masks only `scheme://` URLs, so a bare `host:port`, a `@scope/pkg@1.2.3` and a
    `--host internal.corp` survive it — the exact identifiers `--strict` promises to remove.
    There is no safe bare-host scrubber for arbitrary text (the attempt is this repo's recorded
    over-matching failure), so in strict the body is WITHHELD whole rather than shipped
    host-bearing under a promise we cannot keep. The command SHAPE (mcpgawk's own subcommand,
    already home-path scrubbed) and the exit code in walkthrough.json still say what ran."""
    header = f"$ {' '.join(command)}\n\n"
    if strict:
        return (f"{header}<withheld for --strict: this step's output names hosts, package "
                f"names and launch arguments — {len(stdout) + len(stderr)} chars>\n")
    return clean_text(f"{header}{stdout}\n{stderr}")


def _run(step: Step, args: list[str], timeout: float, outputs: dict[str, str],
         strict: bool = False) -> Step:
    # Scrubbed at the point it is STORED, not only where it is printed: the raw list went
    # into walkthrough.json via asdict() and carried an absolute home path with it.
    step.command = [scrub_paths(part) for part in _binary() + args]
    started = time.monotonic()
    try:
        # errors="replace": a scanned server that emits a single non-UTF-8 byte used to raise
        # UnicodeDecodeError (a ValueError, so it slipped past the OSError handler below) and
        # abort the ENTIRE walk with no bundle — on precisely the machine whose bundle is worth
        # the most. Decoding must never end the walk; a stray byte becomes U+FFFD in the log.
        proc = subprocess.run(_binary() + args, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        step.outcome, step.seconds = TIMED_OUT, time.monotonic() - started
        step.detail = f"still running after {int(timeout)}s — recorded, not killed silently"
        outputs[f"steps/{step.name}.txt"] = step.detail + "\n"
        return step
    except KeyboardInterrupt:
        raise
    except Exception as exc:                                      # noqa: BLE001
        # Nothing a single step can do may end the walk (the stated guarantee). Was OSError only,
        # which let any other subprocess exception abort everything; recorded, never swallowed.
        step.outcome, step.seconds = CRASHED, time.monotonic() - started
        step.detail = clean_text(f"{type(exc).__name__}: {exc}")
        return step
    step.seconds = time.monotonic() - started
    step.exit_code = proc.returncode
    # Exit 0 is the step running cleanly; ANY nonzero is a finding to surface, not a false OK.
    # This used to be `in (0, 1)` for every step, on the theory that `scan` exits 1 on findings —
    # but `scan --yes` (no --fail-on-findings, which checkup does not pass) exits 0 even WITH
    # findings; they live in its output. A nonzero `verify` means servers FAILED, and recording
    # that as OK produced a walk that read all-green off a run whose flagship step failed.
    step.outcome = OK if proc.returncode == 0 else FAILED
    outputs[f"steps/{step.name}.txt"] = _step_body(step.command, proc.stdout, proc.stderr, strict)
    step.detail = f"exit {proc.returncode}"
    return step


_PANEL_WITHHELD = (
    "<!doctype html><meta charset=utf-8><title>panel withheld in --strict</title>"
    "<p>The panel is withheld in <code>--strict</code> mode: it names each server's host, the "
    "packages it launches and the arguments they carry (egress lists and argv), which "
    "<code>--strict</code> removes. It is a rendered document, not a structured record that can "
    "be host-redacted field by field, so it is withheld rather than shipped under that promise. "
    "Run <code>mcpgawk checkup</code> without <code>--strict</code> to include the full panel.</p>"
)


def _panel_tabs(outputs: dict[str, str], strict: bool = False) -> Step:
    """Render the panel against this machine's real data.

    No browser and no screenshot: the panel is server-rendered, so the HTML in the bundle is
    what the tester would have seen, on data we can never reproduce here.

    ONE render, not one per tab. The nav is CSS-driven — `_radio_tabs` only moves which radio
    is `checked` — so every tab's content is already in a single document. The first version
    of this wrote nine byte-identical 214 KB copies; caught by listing the zip rather than
    trusting the step's own success message.

    In --strict the rendered page is WITHHELD: the panel names hosts, packages and launch
    arguments by construction, and unlike a structured record it cannot be host-redacted field
    by field. `scrub_paths` (the old treatment) only removed home paths, so a strict bundle
    shipped every internal host under a mode line that promised none. Comprehensive mode — the
    default, what testers are told to run — still carries the full panel.
    """
    step = Step("panel", "render the panel against your real data")
    started = time.monotonic()
    try:
        from .panel import _TAB_LABELS, collect, render

        page = render(collect())
        kb = len(page) // 1024
        if strict:
            outputs["panel/panel.html"] = _PANEL_WITHHELD
            step.detail = f"withheld in --strict ({kb} KB not shipped)"
        else:
            outputs["panel/panel.html"] = scrub_paths(page)
            step.detail = (f"{kb} KB, one document containing all "
                           f"{len(_TAB_LABELS)} tabs (the nav is CSS-only)")
        step.outcome = OK
    except Exception as exc:                                      # noqa: BLE001
        step.outcome = CRASHED
        step.detail = clean_text(f"{type(exc).__name__}: {exc}")
    step.seconds = time.monotonic() - started
    return step


def _ask(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        return False
    try:
        return input(f"{prompt} [y/N] ").strip().lower() in {"y", "yes"}
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def run(output: str | None = None, note: str | None = None, assume_yes: bool = False,
        strict: bool = False) -> int:
    from .report_redact import reset_pseudonyms, set_strict

    set_strict(strict)
    reset_pseudonyms()

    print("mcpgawk checkup — exercising the whole product on this machine\n")
    print("  It runs each command in turn and records what happened. A step that fails is")
    print("  kept, not hidden — that is the point. Nothing is uploaded.\n")

    launch = _ask(
        "  scan and verify LAUNCH your local MCP servers, which runs their code.\n"
        "  Run those steps?", assume_yes)
    if not launch:
        print("  → skipping the steps that launch anything. Everything else still runs.\n")

    outputs: dict[str, str] = {}
    steps: list[Step] = []
    interrupted = False

    plan: list[tuple[str, str, list[str], float, bool]] = [
        ("version", "which build is installed, and is it current", ["--version"], 120, False),
        ("status-before", "what is watching, before anything runs", ["status"], 180, False),
        ("scan", "measure every server this machine can see", ["scan", "--yes"], 900, True),
        ("verify", "run each server and watch what it actually does", ["verify"], 1800, True),
        ("status-after", "what changed once the tools had run", ["status"], 180, False),
        ("runs", "the run history this walk just added to", ["runs", "--limit", "50"], 120, False),
    ]

    for name, what, args, timeout, needs_launch in plan:
        step = Step(name, what)
        if needs_launch and not launch:
            step.outcome = DECLINED
            step.detail = "you declined to launch local servers — recorded, not a failure"
            steps.append(step)
            print(f"  -- {name:<14} declined")
            continue
        print(f"  .. {name:<14} {what}")
        try:
            steps.append(_run(step, args, timeout, outputs, strict))
        except KeyboardInterrupt:
            step.outcome = INTERRUPTED
            step.detail = "you stopped it here — the bundle is still written"
            steps.append(step)
            interrupted = True
            print(f"\n  ^C at {name} — writing what we have so far.\n")
            break
        print(f"  {'ok' if steps[-1].outcome == OK else '!!'} {name:<14} "
              f"{steps[-1].outcome} ({steps[-1].seconds:.0f}s) {steps[-1].detail}")

    # The Ctrl-C guarantee ("the bundle is still written") used to cover ONLY the step loop above.
    # A ^C during the panel render or while gathering the rest of the bundle — the slow phases on a
    # big machine, and where an impatient tester is most likely to press it — escaped to the CLI
    # with a traceback and NO file, immediately after the program promised one. Each remaining
    # phase now converts a ^C into "stop early, write what we have" rather than losing everything.
    if not interrupted:
        print("  .. panel          render every tab against your real data")
        try:
            steps.append(_panel_tabs(outputs, strict))
            print(f"  {'ok' if steps[-1].outcome == OK else '!!'} {'panel':<14} {steps[-1].detail}")
        except KeyboardInterrupt:
            interrupted = True
            print("\n  ^C during the panel — writing what we have so far.\n")

    walkthrough = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "launched_local_servers": launch,
        "stopped_early": interrupted,
        "steps": [asdict(s) for s in steps],
    }
    outputs["walkthrough.json"] = json.dumps(walkthrough, indent=2)

    try:
        bundle = report.collect(note)
    except KeyboardInterrupt:
        interrupted = True
        print("\n  ^C while gathering the rest — writing the checkup steps only.\n")
        bundle = report.Bundle()
    for name, body in outputs.items():
        bundle.add(report.Section(f"walk:{name}", report.INCLUDED, "from this checkup run"),
                   name, body)

    dest = Path(output) if output else Path.cwd() / f"mcpgawk-checkup-{report._utc()}.zip"
    try:
        written = report.write_bundle(bundle, dest, note)
    except OSError as exc:
        print(f"\ncould not write the bundle to {scrub_paths(str(dest))}: {exc}", file=sys.stderr)
        return 1

    print("\n  WHAT HAPPENED\n")
    width = max(len(s.name) for s in steps)
    for s in steps:
        mark = {OK: "ok ", DECLINED: "-- "}.get(s.outcome, "!! ")
        print(f"    {mark}{s.name:<{width}}  {s.outcome:<12} {s.detail}")
    if interrupted:
        print("\n    You stopped part-way. That is recorded and the bundle is still complete")
        print("    for everything up to that point — send it exactly as it is.")
    size_kb = max(1, written.stat().st_size // 1024)
    print(f"\n  written: {written}  ({size_kb} KB)")
    print(f"  send it to {report.SUPPORT_ADDRESS} — nothing was uploaded.")
    return 0
