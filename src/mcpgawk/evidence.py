"""Evidence — what a sandboxed verification actually observed.

Moved into the free layer with the sandbox (BUILD_PLAN B1, implementing Task 0: free installs run
behavioural verification). This is the ONE type that crosses the sandbox boundary back into any
pipeline, free or paid — the paid schema re-exports THIS class rather than keeping a twin, because
two definitions of "evidence" is the two-implementations drift this repo keeps paying for.

Stdlib-only, like everything the free layer ships. `validate()` raises ValueError; the paid
schema's `SchemaError` subclasses ValueError, and its callers wrap where they need the narrower
type.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Evidence:
    """What a verification actually observed. Only validated evidence crosses the
    sandbox boundary back into the pipeline (FR-VER-3, design §3)."""

    poc_ref: Optional[str] = None        # path/handle to the reproduction input
    reproduction_command: Optional[str] = None
    exit_code: Optional[int] = None
    output_excerpt: str = ""             # bounded, fenced server-controlled text
    crash_type: Optional[str] = None     # a crash is evidence, not an error
    artifacts: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if len(self.output_excerpt) > 64_000:
            raise ValueError("Evidence.output_excerpt exceeds 64KB cap")
