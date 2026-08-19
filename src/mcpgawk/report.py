"""`mcpgawk report` — one command, one file, everything we need to diagnose a tester's machine.

Why this exists: mcpgawk is local-first and uploads nothing, which is the promise — and the
direct consequence is that when a beta tester hits a problem we can see NOTHING. The old
answer was "run these three commands and hunt through two hidden directories", which in
practice returns half an answer and a round-trip.

Three rules shape it:

1. **It works in every machine state.** A fresh install with no state at all, a corrupt
   database, no hooks installed, zero runs — each of those is a MANIFEST LINE, never a
   crash. Every collector is isolated: one failing collector costs its own section and
   nothing else. The bundle from a broken machine is the bundle we most need.

2. **It distinguishes empty from unlooked-at.** Every section lands in the manifest as
   `included`, `empty` or `unavailable` with a reason. A bundle that quietly omitted a
   store would let us read "nothing there" off a place nobody opened — the exact failure
   this codebase spent a session removing from every other surface.

3. **It carries the diagnosis and none of the tester's data.** See `report_redact`. Server
   responses are dropped by field name, home directories become `~`, and every URL keeps
   its parameter names and loses their values.

Nothing is uploaded. The command prints the path to a file and stops; sending it is the
tester's decision, and they can read it first.
"""

from __future__ import annotations

import json
import os
import platform
import sqlite3
import sys
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .report_redact import clean_text, redact_jsonl, redact_record, scrub_paths

INCLUDED = "included"
EMPTY = "empty"
UNAVAILABLE = "unavailable"

#: Where a tester sends the file. Printed, never contacted.
SUPPORT_ADDRESS = "hello@nativerse-ventures.com"


@dataclass
class Section:
    """One collected thing, and the honest state of it."""

    name: str
    state: str
    detail: str = ""
    source: str = ""
    bytes: int = 0
    records: int | None = None
    undecodable: int = 0


@dataclass
class Bundle:
    sections: list[Section] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)

    def add(self, section: Section, filename: str | None = None, body: str | None = None) -> None:
        self.sections.append(section)
        if filename and body is not None:
            self.files[filename] = body
            section.bytes = len(body.encode("utf-8"))


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("mcpgawk")
    except Exception:
        return "0+unknown (not installed as a distribution)"


def _install_method() -> str:
    """How this copy got here. Best-effort and always a sentence, never an exception.

    The tester who reported seeing 0.1.7 could not be diagnosed because nothing recorded
    HOW mcpgawk was installed or WHICH binary answered — so both go in the bundle.
    """
    try:
        from importlib.metadata import distribution

        dist = distribution("mcpgawk")
        installer = (dist.read_text("INSTALLER") or "").strip()
        location = str(getattr(dist, "_path", "") or "")
        if any(Path(p).name == "uv-receipt.toml" for p in _parents_with_receipt()):
            return f"uv tool (installer metadata: {installer or 'none'})"
        if "pipx" in location:
            return f"pipx (installer metadata: {installer or 'none'})"
        if installer:
            return installer
        return "unknown (no INSTALLER metadata)"
    except Exception as exc:                                    # noqa: BLE001 — never fail
        return f"could not determine ({type(exc).__name__})"


def _parents_with_receipt() -> list[str]:
    try:
        here = Path(__file__).resolve()
        return [str(p / "uv-receipt.toml") for p in here.parents
                if (p / "uv-receipt.toml").exists()]
    except Exception:                                            # noqa: BLE001
        return []


def _collect(bundle: Bundle, name: str, fn: Callable[[], tuple[Section, str | None, str | None]]) -> None:
    """Run one collector under isolation. A collector that raises costs only its section."""
    try:
        section, filename, body = fn()
    except Exception as exc:                                     # noqa: BLE001 — by design
        bundle.add(Section(name=name, state=UNAVAILABLE,
                           detail=f"collector raised {type(exc).__name__}: "
                                  f"{clean_text(str(exc))[:300]}"))
        return
    bundle.add(section, filename, body)


# --------------------------------------------------------------------------- collectors

def _env_value(value: str) -> str:
    """Ship the NAME always; ship the VALUE only when it is a path.

    Our own env vars are the obvious place a credential sits: beta testers export
    `GAWK_BETA_KEY` because that is how a grant is delivered, and a paid user may export
    `GAWK_LICENSE_KEY`. Neither is a shape `redact()` recognises — a signed grant is just
    text — so a detector would pass them straight through into a file the tester may paste
    into a public issue.

    So the rule is structural, like the URL one: knowing an override is SET is the whole
    diagnosis; its value only matters when it redirects a store, and those are paths. A
    short toggle (`"1"`) still reads as set from its length.
    """
    scrubbed = scrub_paths(value)
    if "/" in scrubbed or "~" in scrubbed or "\\" in scrubbed:
        return scrubbed
    return f"<set: {len(value)} chars>"


def _environment() -> tuple[Section, str, str]:
    from .staleness import currency_line

    try:
        currency = currency_line()
    except Exception as exc:                                     # noqa: BLE001
        currency = f"could not check ({type(exc).__name__})"

    env_overrides = {
        key: _env_value(value)
        for key, value in sorted(os.environ.items())
        if key.startswith(("MCPGAWK_", "GAWK_"))
    }
    data = {
        "mcpgawk_version": _version(),
        "currency": currency,
        "install_method": scrub_paths(_install_method()),
        "executable_on_path": scrub_paths(_which_mcpgawk()),
        "module_file": scrub_paths(str(Path(__file__).resolve())),
        "python": sys.version.split()[0],
        "python_executable": scrub_paths(sys.executable),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "env_overrides": env_overrides,
        "paid_engine_importable": _platform_importable(),
    }
    return (Section("environment", INCLUDED, "version, install method, OS, env overrides"),
            "environment.json", json.dumps(data, indent=2))


def _which_mcpgawk() -> str:
    import shutil

    return shutil.which("mcpgawk") or "not on PATH"


def _platform_importable() -> bool:
    try:
        import importlib.util

        return importlib.util.find_spec("gawk_platform") is not None
    except Exception:                                            # noqa: BLE001
        return False


def _status_text() -> tuple[Section, str, str]:
    from .status import collect_and_render

    text = collect_and_render()
    if not text.strip():
        return Section("status", EMPTY, "`mcpgawk status` produced no output"), "status.txt", ""
    return (Section("status", INCLUDED, "verbatim `mcpgawk status`"),
            "status.txt", scrub_paths(text))


def _hooks() -> tuple[Section, str, str]:
    from .status import hook_health_by_client

    health = hook_health_by_client()
    if not health:
        return (Section("hooks", EMPTY, "no hook-capable agent is known to this build"),
                "hooks.json", "{}")
    # Report the BREAKDOWN, never the total. `hook_health_by_client` enumerates every client
    # this build knows how to hook, present or not — so "6 hook-capable client(s)" reads as
    # six agents found when the honest answer on a fresh machine is six known, none hooked.
    installed = sorted(k for k, v in health.items() if v == "ok")
    broken = sorted(k for k, v in health.items() if v == "broken")
    absent = sorted(k for k, v in health.items() if v not in {"ok", "broken"})
    detail = (f"{len(installed)} hooked ({', '.join(installed) or 'none'})"
              f" · {len(broken)} broken ({', '.join(broken) or 'none'})"
              f" · {len(absent)} not hooked, of {len(health)} client(s) this build can hook")
    state = INCLUDED if installed or broken else EMPTY
    return (Section("hooks", state, detail),
            "hooks.json", json.dumps(health, indent=2, sort_keys=True))


def _runs() -> tuple[Section, str, str]:
    from . import runlog

    try:
        runlog.reconcile_stale()
    except Exception:                                            # noqa: BLE001 — read-only path still works
        pass
    rows = runlog.list_runs(limit=5000)
    payload = [redact_record(asdict(row)) for row in rows]
    state = INCLUDED if payload else EMPTY
    detail = (f"{len(payload)} run(s), newest first" if payload
              else "the run registry exists but holds no runs")
    section = Section("runs", state, detail, source=scrub_paths(runlog.default_path()),
                      records=len(payload))
    return section, "runs.json", json.dumps(payload, indent=2)


def _calls() -> tuple[Section, str, str]:
    from .spool import spool_path, summarise

    path = Path(spool_path())
    counts: dict[str, Any]
    try:
        counts = summarise()
    except Exception as exc:                                     # noqa: BLE001
        counts = {"_summarise_failed": f"{type(exc).__name__}"}
    if not path.exists():
        section = Section("calls", UNAVAILABLE,
                          "no call spool on this machine — the guard hook has never recorded "
                          "a call (not installed, or installed and never used)",
                          source=scrub_paths(str(path)))
        return section, "calls-summary.json", json.dumps(redact_record(counts), indent=2, default=str)
    body, records, undecodable = redact_jsonl(path)
    state = INCLUDED if records else EMPTY
    section = Section("calls", state,
                      f"{records} call(s), entire log, arguments never recorded by design",
                      source=scrub_paths(str(path)), records=records, undecodable=undecodable)
    return section, "calls.jsonl", body


def _calls_summary() -> tuple[Section, str, str]:
    from .spool import recorder_health, summarise

    data: dict[str, Any] = {"summary": summarise()}
    try:
        health = recorder_health()
    except Exception as exc:                                     # noqa: BLE001
        health = f"could not read ({type(exc).__name__})"
    data["recorder_health"] = health
    data["_note"] = ("recorder_health is non-null when the counts above may be INCOMPLETE — "
                     "read it before trusting `checked` vs `deferred`")
    return (Section("calls-summary", INCLUDED, "seen / checked / deferred / denied counters"),
            "calls-summary.json", json.dumps(redact_record(data), indent=2, default=str))


def _trust_store() -> tuple[Section, str, str]:
    from .history import default_path, load_checked, pending

    path = default_path()
    store, error = load_checked(path)
    if error:
        section = Section("trust-store", UNAVAILABLE,
                          f"could not read the approved-baseline store: {clean_text(error)}",
                          source=scrub_paths(path))
        return section, "trust-store.json", json.dumps({"error": clean_text(error)}, indent=2)
    servers = (store or {}).get("servers", {}) or {}
    waiting = set(pending(store or {}))
    summary = {
        "servers_total": len(servers),
        "servers_at_an_approved_baseline": len([k for k in servers if k not in waiting]),
        "servers_pending": sorted(clean_text(k) for k in waiting),
        "server_keys": sorted(clean_text(k) for k in servers),
    }
    state = INCLUDED if servers else EMPTY
    return (Section("trust-store", state, f"{len(servers)} server(s) known to the trust store",
                    source=scrub_paths(path), records=len(servers)),
            "trust-store.json", json.dumps(summary, indent=2))


def _monitor_alerts() -> tuple[Section, str, str]:
    """Open drift alerts, read-only.

    Opened `mode=ro` deliberately: a normal connection would migrate and WAL-ify the
    operator's database, so a diagnostic command would change the thing it is reporting on.
    """
    db = os.environ.get("GAWK_MONITOR_DB") or str(Path.home() / ".gawk" / "monitor.db")
    if not Path(db).exists():
        return (Section("monitor-alerts", UNAVAILABLE,
                        "no monitor database — deep monitoring has never run here",
                        source=scrub_paths(db)),
                "monitor-alerts.json", json.dumps({"open_alerts": None}, indent=2))
    uri = f"file:{Path(db).as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=2.0) as conn:
        rows = conn.execute(
            "SELECT * FROM open_alerts").fetchall()
        names = [d[0] for d in (conn.execute("SELECT * FROM open_alerts LIMIT 0").description or [])]
    payload = [redact_record(dict(zip(names, row))) for row in rows]
    state = INCLUDED if payload else EMPTY
    return (Section("monitor-alerts", state, f"{len(payload)} OPEN alert(s)",
                    source=scrub_paths(db), records=len(payload)),
            "monitor-alerts.json", json.dumps(payload, indent=2, default=str))


def _verify_runs(bundle: Bundle) -> None:
    """Every verify run's audit log, entire, redacted. One section per run, isolated."""
    try:
        from .panel import behaviour_profile_path

        root = behaviour_profile_path().parent / "verify-runs"
    except Exception as exc:                                     # noqa: BLE001
        bundle.add(Section("verify-runs", UNAVAILABLE,
                           f"could not resolve the verify-runs directory ({type(exc).__name__})"))
        return
    if not root.is_dir():
        bundle.add(Section("verify-runs", UNAVAILABLE,
                           "no verify-runs directory — `mcpgawk verify` has never run here",
                           source=scrub_paths(str(root))))
        return
    run_dirs = sorted((d for d in root.iterdir() if d.is_dir()), key=lambda d: d.name)
    if not run_dirs:
        bundle.add(Section("verify-runs", EMPTY, "the directory exists but holds no runs",
                           source=scrub_paths(str(root))))
        return
    total = 0
    for run_dir in run_dirs:
        audit = run_dir / "audit.jsonl"
        name = f"verify-runs/{run_dir.name}.jsonl"
        if not audit.exists():
            bundle.add(Section(f"verify-run {run_dir.name}", UNAVAILABLE,
                               "run directory has no audit.jsonl"))
            continue
        try:
            body, records, undecodable = redact_jsonl(audit)
        except Exception as exc:                                 # noqa: BLE001
            bundle.add(Section(f"verify-run {run_dir.name}", UNAVAILABLE,
                               f"could not read ({type(exc).__name__})"))
            continue
        total += records
        bundle.add(Section(f"verify-run {run_dir.name}",
                           INCLUDED if records else EMPTY,
                           f"{records} observation(s), server responses redacted",
                           records=records, undecodable=undecodable),
                   name, body)
    bundle.add(Section("verify-runs", INCLUDED,
                       f"{len(run_dirs)} run(s), {total} observation(s) in total, entire logs",
                       source=scrub_paths(str(root)), records=total))


def _state_inventory() -> tuple[Section, str, str]:
    """Both state roots, listed by name with size and mtime — nothing read.

    Listed even when a root is missing: knowing `~/.mcpgawk` does not exist is itself the
    answer on a fresh machine, and it is the state we can never reproduce here.
    """
    inventory: dict[str, Any] = {}
    for root in (Path.home() / ".mcpgawk", Path.home() / ".gawk"):
        label = "~/" + root.name
        if not root.exists():
            inventory[label] = "does not exist"
            continue
        entries: dict[str, Any] = {}
        for item in sorted(root.rglob("*")):
            try:
                stat = item.stat()
                entries[scrub_paths(str(item.relative_to(root)))] = {
                    "bytes": stat.st_size if item.is_file() else None,
                    "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                    "kind": "dir" if item.is_dir() else "file",
                }
            except OSError as exc:
                entries[scrub_paths(str(item.name))] = f"could not stat ({exc.errno})"
        inventory[label] = entries
    return (Section("state-inventory", INCLUDED, "both state roots, listed by name"),
            "state-inventory.json", json.dumps(inventory, indent=2))


# --------------------------------------------------------------------------- assembly

def collect(note: str | None = None) -> Bundle:
    """Collect everything. Never raises: a failure becomes a manifest line."""
    bundle = Bundle()
    _collect(bundle, "environment", _environment)
    _collect(bundle, "status", _status_text)
    _collect(bundle, "hooks", _hooks)
    _collect(bundle, "runs", _runs)
    _collect(bundle, "calls-summary", _calls_summary)
    _collect(bundle, "calls", _calls)
    _collect(bundle, "trust-store", _trust_store)
    _collect(bundle, "monitor-alerts", _monitor_alerts)
    _collect(bundle, "state-inventory", _state_inventory)
    try:
        _verify_runs(bundle)
    except Exception as exc:                                     # noqa: BLE001
        bundle.add(Section("verify-runs", UNAVAILABLE, f"{type(exc).__name__}"))

    if note:
        bundle.add(Section("note", INCLUDED, "what the tester was doing"),
                   "note.txt", clean_text(note))
    return bundle


def render_summary(bundle: Bundle, note: str | None = None) -> str:
    """The human-readable head of the bundle — and what the tester can paste into an email."""
    lines: list[str] = ["mcpgawk report", "=" * 60, ""]
    env = bundle.files.get("environment.json")
    if env:
        try:
            data = json.loads(env)
            for key in ("mcpgawk_version", "currency", "install_method",
                        "executable_on_path", "python", "platform"):
                lines.append(f"  {key:<20} {data.get(key)}")
        except ValueError:
            lines.append("  (environment.json could not be re-read)")
    lines += ["", "WHAT IS IN THIS FILE", ""]
    # Per-run verify sections are rolled up: on a machine with 36 verify runs they push
    # everything that needs attention off the screen. They stay in full in manifest.json,
    # and any run we could NOT read is still printed — that is the half worth seeing.
    shown = [s for s in bundle.sections
             if not (s.name.startswith("verify-run ") and s.state != UNAVAILABLE)]
    rolled = len(bundle.sections) - len(shown)
    width = max((len(s.name) for s in shown), default=10)
    for section in shown:
        mark = {INCLUDED: "ok ", EMPTY: "-- ", UNAVAILABLE: "!! "}.get(section.state, "?? ")
        lines.append(f"  {mark}{section.name:<{width}}  {section.state:<12} {section.detail}")
        if section.undecodable:
            lines.append(f"     {'':<{width}}  {section.undecodable} line(s) could not be parsed "
                         f"and were replaced, not dropped")
    if rolled:
        lines.append(f"     {'':<{width}}  ({rolled} individual verify run(s) rolled up — "
                     f"see manifest.json)")
    unavailable = [s for s in bundle.sections if s.state == UNAVAILABLE]
    lines += ["", f"  {len(unavailable)} section(s) could not be collected. "
                  "'unavailable' means NOBODY LOOKED — it never means 'nothing there'.", ""]
    if note:
        lines += ["WHAT THE TESTER WAS DOING", "", "  " + clean_text(note), ""]
    lines += [
        "PRIVACY", "",
        "  Server responses are removed by field name, home directories appear as ~, and",
        "  every URL keeps its parameter names and loses their values. Tool arguments are",
        "  never recorded by the guard in the first place. Read this file before sending it.",
        "",
    ]
    return "\n".join(lines)


def write_bundle(bundle: Bundle, dest: Path, note: str | None = None) -> Path:
    summary = render_summary(bundle, note)
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mcpgawk_version": _version(),
        "sections": [asdict(s) for s in bundle.sections],
    }
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("summary.txt", summary)
        archive.writestr("manifest.json", json.dumps(manifest, indent=2))
        for name, body in bundle.files.items():
            archive.writestr(name, body)
    try:
        from .state import harden

        harden(dest)
    except Exception:                                            # noqa: BLE001 — the file still exists
        pass
    return dest


def run(output: str | None = None, note: str | None = None, strict: bool = False) -> int:
    from .report_redact import set_strict

    set_strict(strict)
    bundle = collect(note)
    dest = Path(output) if output else Path.cwd() / f"mcpgawk-report-{_utc()}.zip"
    try:
        written = write_bundle(bundle, dest, note)
    except OSError as exc:
        print(f"could not write the report to {scrub_paths(str(dest))}: {exc}", file=sys.stderr)
        print("try `mcpgawk report --output ~/mcpgawk-report.zip`", file=sys.stderr)
        return 1
    print(render_summary(bundle, note))
    mode = ("STRICT — hosts, package names and command arguments removed as well"
            if strict else
            "full — run with --strict if your employer will not let internal hostnames leave")
    print(f"  redaction: {mode}")
    size_kb = max(1, written.stat().st_size // 1024)
    print(f"  written: {written}  ({size_kb} KB)")
    print(f"  send it to {SUPPORT_ADDRESS} — nothing was uploaded.")
    return 0
