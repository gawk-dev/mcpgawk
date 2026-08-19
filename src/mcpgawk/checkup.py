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


def _run(step: Step, args: list[str], timeout: float, outputs: dict[str, str]) -> Step:
    # Scrubbed at the point it is STORED, not only where it is printed: the raw list went
    # into walkthrough.json via asdict() and carried an absolute home path with it.
    step.command = [scrub_paths(part) for part in _binary() + args]
    started = time.monotonic()
    try:
        proc = subprocess.run(_binary() + args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        step.outcome, step.seconds = TIMED_OUT, time.monotonic() - started
        step.detail = f"still running after {int(timeout)}s — recorded, not killed silently"
        outputs[f"steps/{step.name}.txt"] = step.detail + "\n"
        return step
    except KeyboardInterrupt:
        raise
    except OSError as exc:
        step.outcome, step.seconds = CRASHED, time.monotonic() - started
        step.detail = clean_text(f"{type(exc).__name__}: {exc}")
        return step
    step.seconds = time.monotonic() - started
    step.exit_code = proc.returncode
    # Exit codes are not all failures here: `scan` exits 1 when it FINDS something, which is
    # the tool working. The walk records the code and lets a human read it, rather than
    # inventing a verdict the command never gave.
    step.outcome = OK if proc.returncode in (0, 1) else FAILED
    body = f"$ {' '.join(step.command)}\n\n{proc.stdout}\n{proc.stderr}"
    outputs[f"steps/{step.name}.txt"] = clean_text(body)
    step.detail = f"exit {proc.returncode}"
    return step


def _panel_tabs(outputs: dict[str, str]) -> Step:
    """Render the panel against this machine's real data.

    No browser and no screenshot: the panel is server-rendered, so the HTML in the bundle is
    what the tester would have seen, on data we can never reproduce here.

    ONE render, not one per tab. The nav is CSS-driven — `_radio_tabs` only moves which radio
    is `checked` — so every tab's content is already in a single document. The first version
    of this wrote nine byte-identical 214 KB copies; caught by listing the zip rather than
    trusting the step's own success message.
    """
    step = Step("panel", "render the panel against your real data")
    started = time.monotonic()
    try:
        from .panel import _TAB_LABELS, collect, render

        page = render(collect())
        outputs["panel/panel.html"] = scrub_paths(page)
        step.outcome = OK
        step.detail = (f"{len(page) // 1024} KB, one document containing all "
                       f"{len(_TAB_LABELS)} tabs (the nav is CSS-only)")
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
            steps.append(_run(step, args, timeout, outputs))
        except KeyboardInterrupt:
            step.outcome = INTERRUPTED
            step.detail = "you stopped it here — the bundle is still written"
            steps.append(step)
            interrupted = True
            print(f"\n  ^C at {name} — writing what we have so far.\n")
            break
        print(f"  {'ok' if steps[-1].outcome == OK else '!!'} {name:<14} "
              f"{steps[-1].outcome} ({steps[-1].seconds:.0f}s) {steps[-1].detail}")

    if not interrupted:
        print("  .. panel          render every tab against your real data")
        steps.append(_panel_tabs(outputs))
        print(f"  {'ok' if steps[-1].outcome == OK else '!!'} {'panel':<14} {steps[-1].detail}")

    walkthrough = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "launched_local_servers": launch,
        "stopped_early": interrupted,
        "steps": [asdict(s) for s in steps],
    }
    outputs["walkthrough.json"] = json.dumps(walkthrough, indent=2)

    bundle = report.collect(note)
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
