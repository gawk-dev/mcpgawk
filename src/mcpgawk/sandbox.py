"""Harness-grade sandbox runner — the isolation surface for executing UNTRUSTED
MCP servers during verification (design §3, FR-VER-3, NFR-SEC-2).

This is the single highest-risk surface in the system. It applies the Anthropic
`defending-code-reference-harness` discipline: a fresh, disposable, egress-locked,
resource-capped, non-root container per run; only validated evidence crosses back;
timeouts at every layer; every failure degrades to a structured result — nothing
here may raise into the pipeline uncaught.

Two implementations:
  * DockerSandbox      — production. gVisor/Docker isolation. Use in all real runs.
  * SubprocessSandbox  — DEV ONLY. NOT isolated. Guarded so it cannot run unless
                         explicitly opted in; never a silent fallback in prod.

Verify depends only on `SandboxRunner`, so the substrate is swappable.

The `Evidence` this module returns is redacted before it crosses back into the pipeline
(`adapters/pulled/invariant_redact.py`, Apache-2.0 attributed) — a reproduction command or
captured stdout/stderr must never leak a CLI-flag-carried secret or an absolute filesystem path
into a returned/persisted `VerifiedFinding`.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Protocol, Sequence

from .adapters.pulled.invariant_redact import redact_absolute_paths, redact_command_args
from .evidence import Evidence


# --------------------------------------------------------------------------- #
# Contracts
# --------------------------------------------------------------------------- #
class NetworkMode(str, Enum):
    NONE = "none"          # default: no egress at all (the no-egress invariant)
    PROXY = "proxy"        # allow-list egress via an explicit proxy (SSRF repro only)


@dataclass(frozen=True)
class SandboxLimits:
    """Hard caps. Exceeding any of these kills the run and records it (not fatal)."""

    wall_clock_s: float = 30.0
    memory_mb: int = 512
    cpus: float = 1.0
    pids: int = 128
    tmpfs_mb: int = 64                 # the only writable space; rootfs is read-only
    network: NetworkMode = NetworkMode.NONE
    egress_allow: tuple[str, ...] = ()  # only consulted when network == PROXY

    def __post_init__(self) -> None:
        if self.wall_clock_s <= 0 or self.memory_mb <= 0 or self.cpus <= 0 or self.pids <= 0:
            raise ValueError("SandboxLimits values must be positive")
        if self.network is NetworkMode.PROXY and not self.egress_allow:
            raise ValueError("PROXY network mode requires a non-empty egress_allow list")


@dataclass(frozen=True)
class ServerSpec:
    """How to launch the target MCP server inside the sandbox."""

    image: str                          # container image with the server + runtime
    command: Sequence[str]              # argv to start the server / run the PoC
    env: dict[str, str] = field(default_factory=dict)   # NON-secret only


class SandboxOutcome(str, Enum):
    COMPLETED = "completed"             # ran to completion (any exit code)
    TIMEOUT = "timeout"                 # killed on wall-clock
    RESOURCE_EXCEEDED = "resource_exceeded"
    INFRA_FAILURE = "infra_failure"     # couldn't even start (image/daemon) — caller degrades


@dataclass
class SandboxResult:
    """Structured result. `ok` means the run executed and produced evidence; an
    INFRA_FAILURE is `ok=False` and tells Verify to mark the candidate `unverified`.
    A non-zero exit or a crash is `ok=True` — that is *evidence*, not failure."""

    outcome: SandboxOutcome
    evidence: Optional[Evidence] = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.outcome in (SandboxOutcome.COMPLETED, SandboxOutcome.TIMEOUT, SandboxOutcome.RESOURCE_EXCEEDED)


class SandboxRunner(Protocol):
    def run(self, spec: ServerSpec, limits: SandboxLimits) -> SandboxResult:
        """Execute the server/PoC under isolation and return a structured result.
        MUST NOT raise for expected failures (timeout, crash, resource, infra).
        MAY raise only for programmer error (bad arguments)."""
        ...


_OUTPUT_CAP = 64_000  # keep in lockstep with Evidence.output_excerpt cap


def _bounded(text: str) -> str:
    return text if len(text) <= _OUTPUT_CAP else text[:_OUTPUT_CAP] + "\n...[truncated]"


def _redacted_repro_command(command: Sequence[str]) -> str:
    """The reproduction command as it will appear in evidence — flag values and bare
    filesystem paths redacted BEFORE quoting/joining, so a secret passed as a CLI arg
    (a common launch pattern: `server --api-key sk-...`) never appears verbatim."""
    return " ".join(map(shlex.quote, redact_command_args(list(command))))


def _redacted_output(text: str) -> str:
    """Captured stdout/stderr as it will appear in evidence — absolute paths redacted so a
    crash traceback doesn't leak the machine's directory layout / username."""
    return redact_absolute_paths(text) or ""


# --------------------------------------------------------------------------- #
# Production implementation
# --------------------------------------------------------------------------- #
class DockerSandbox:
    """Disposable, locked-down container per run.

    Isolation flags (each maps to a threat in design §3):
      --network none        no egress                 (no-egress invariant)
      --read-only           immutable rootfs          (no persistence/tamper)
      --tmpfs /work         only writable space, capped
      --user 65534:65534    non-root (nobody)
      --cap-drop ALL        no Linux capabilities
      --security-opt no-new-privileges
      --pids-limit / --memory / --cpus                resource caps
      --rm                  auto-remove               (disposable)
    Prefer the gVisor runtime (`--runtime=runsc`) when available for kernel isolation.
    """

    def __init__(self, docker_bin: str = "docker", runtime: Optional[str] = None) -> None:
        self._docker = docker_bin
        # If runsc (gVisor) is installed, use it; else fall back to the default runtime.
        self._runtime = runtime if runtime is not None else self._detect_runtime()

    def _detect_runtime(self) -> Optional[str]:
        try:
            out = subprocess.run(
                [self._docker, "info", "--format", "{{.Runtimes}}"],
                capture_output=True, text=True, timeout=10,
            )
            return "runsc" if "runsc" in (out.stdout or "") else None
        except (subprocess.SubprocessError, OSError):
            return None

    def _build_argv(self, spec: ServerSpec, limits: SandboxLimits, name: str) -> list[str]:
        argv = [self._docker, "run", "--rm", "--name", name,
                "--read-only", f"--tmpfs=/work:rw,size={limits.tmpfs_mb}m",
                "--user", "65534:65534", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--pids-limit", str(limits.pids),
                "--memory", f"{limits.memory_mb}m", "--memory-swap", f"{limits.memory_mb}m",
                "--cpus", str(limits.cpus),
                "--workdir", "/work"]
        if self._runtime:
            argv += ["--runtime", self._runtime]
        if limits.network is NetworkMode.NONE:
            argv += ["--network", "none"]
        else:  # PROXY — egress only via the configured allow-list proxy
            argv += ["--env", "HTTP_PROXY=http://egress-proxy:8080",
                     "--env", "HTTPS_PROXY=http://egress-proxy:8080",
                     "--network", "gawk-egress"]
        for k, v in spec.env.items():
            argv += ["--env", f"{k}={v}"]
        argv += [spec.image, *spec.command]
        return argv

    def run(self, spec: ServerSpec, limits: SandboxLimits) -> SandboxResult:
        if not spec.image or not spec.command:
            raise ValueError("ServerSpec requires image and command")  # programmer error

        name = f"gawk-verify-{uuid.uuid4().hex[:12]}"
        argv = self._build_argv(spec, limits, name)
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=limits.wall_clock_s,
            )
        except subprocess.TimeoutExpired as exc:
            self._force_kill(name)
            out = _bounded((exc.stdout or "") + (exc.stderr or "") if isinstance(exc.stdout, str) else "")
            return SandboxResult(
                outcome=SandboxOutcome.TIMEOUT,
                evidence=Evidence(reproduction_command=_redacted_repro_command(spec.command),
                                  output_excerpt=_redacted_output(out), crash_type="timeout"),
                detail=f"killed after {limits.wall_clock_s}s",
            )
        except FileNotFoundError:
            return SandboxResult(SandboxOutcome.INFRA_FAILURE, detail=f"{self._docker} not found")
        except (subprocess.SubprocessError, OSError) as exc:
            self._force_kill(name)
            return SandboxResult(SandboxOutcome.INFRA_FAILURE, detail=str(exc))

        combined = _bounded((proc.stdout or "") + (proc.stderr or ""))
        # Docker uses 125-127 for its own launch failures (image missing, exec fail) →
        # that's INFRA, not evidence about the server.
        if proc.returncode in (125, 126, 127) and "gawk" not in combined.lower():
            return SandboxResult(SandboxOutcome.INFRA_FAILURE,
                                 detail=f"container launch failed rc={proc.returncode}: {combined[:400]}")
        # OOM kill surfaces as rc 137 (128+SIGKILL) — record as resource_exceeded.
        outcome = SandboxOutcome.RESOURCE_EXCEEDED if proc.returncode == 137 else SandboxOutcome.COMPLETED
        return SandboxResult(
            outcome=outcome,
            evidence=Evidence(
                reproduction_command=_redacted_repro_command(spec.command),
                exit_code=proc.returncode,
                output_excerpt=_redacted_output(combined),
                crash_type=("oom" if outcome is SandboxOutcome.RESOURCE_EXCEEDED
                            else ("crash" if proc.returncode not in (0,) else None)),
            ),
        )

    def _force_kill(self, name: str) -> None:
        """Best-effort teardown; never raises (cleanup must not mask the result)."""
        for cmd in (["kill", name], ["rm", "-f", name]):
            try:
                subprocess.run([self._docker, *cmd], capture_output=True, timeout=10)
            except (subprocess.SubprocessError, OSError):
                pass


# --------------------------------------------------------------------------- #
# Dev-only fallback — NOT isolated. Guarded.
# --------------------------------------------------------------------------- #
class SubprocessSandbox:
    """Runs the command as a plain local subprocess with a timeout and (best-effort)
    resource limits. **NO container isolation, NO egress lock.** For local unit tests
    against trusted fixtures only. Refuses to run unless GAWK_ALLOW_UNSANDBOXED=1, so it
    can never become a silent production fallback (NFR-SEC-2)."""

    def __init__(self) -> None:
        if os.environ.get("GAWK_ALLOW_UNSANDBOXED") != "1":
            raise RuntimeError(
                "SubprocessSandbox is unsafe for untrusted code. "
                "Set GAWK_ALLOW_UNSANDBOXED=1 to use it in a trusted dev context."
            )

    def run(self, spec: ServerSpec, limits: SandboxLimits) -> SandboxResult:
        if not spec.command:
            raise ValueError("ServerSpec requires command")
        try:
            proc = subprocess.run(
                list(spec.command), capture_output=True, text=True,
                timeout=limits.wall_clock_s,
                env={**os.environ, **spec.env}, preexec_fn=_apply_rlimits(limits),
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(SandboxOutcome.TIMEOUT, Evidence(crash_type="timeout"),
                                 detail=f"killed after {limits.wall_clock_s}s")
        except (FileNotFoundError, OSError) as exc:
            return SandboxResult(SandboxOutcome.INFRA_FAILURE, detail=str(exc))
        out = _bounded((proc.stdout or "") + (proc.stderr or ""))
        return SandboxResult(
            SandboxOutcome.COMPLETED,
            Evidence(reproduction_command=_redacted_repro_command(spec.command),
                     exit_code=proc.returncode, output_excerpt=_redacted_output(out),
                     crash_type="crash" if proc.returncode not in (0,) else None),
        )


def _apply_rlimits(limits: SandboxLimits):
    """Return a preexec_fn that applies POSIX rlimits (best-effort; Unix only)."""

    def _set() -> None:  # pragma: no cover - exercised only in a child process
        try:
            import resource
            mem = limits.memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            resource.setrlimit(resource.RLIMIT_CPU, (int(limits.wall_clock_s) + 1, int(limits.wall_clock_s) + 1))
            resource.setrlimit(resource.RLIMIT_NPROC, (limits.pids, limits.pids))
        except (ImportError, ValueError, OSError):
            pass

    return _set
