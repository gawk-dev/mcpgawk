"""BOUND — measure a snapshot. Pure, offline, deterministic.

The EXACT/INDEX/BOUNDED wall (enforced here):
  * EXACT  — structural capability facts + integrity pin. Facts, not estimates.
  * INDEX  — token cost via a *named* tokenizer (cl100k). A comparable ranking index, NOT
             an absolute Claude count (tiktoken undercounts Claude ~15-20%). Honestly labelled.
  * BOUNDED— heuristic risk signals. NOT in v1 (security is a 0-FP fast-follow). Kept out of
             this module entirely so an estimate can never contaminate a fact.

No network. No LLM. Scanning the inventory is pure computation.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from .probe import ServerSnapshot

TOKENIZER_NAME = "cl100k_base (approx index; not Claude-exact)"

# Structural capability detectors — deliberately conservative, fact-level only.
_WRITE = re.compile(
    r"\b(create|delete|remove|write|update|send|post|put|patch|execute|run|modify|drop|"
    r"insert|upload|push|merge|deploy|revoke|grant|edit|rename|move|set|add)\b", re.I)
_EXFIL_PARAM = re.compile(r"\b(url|uri|endpoint|webhook|href|callback|redirect)\b", re.I)
_EXFIL_NAME = re.compile(r"\b(fetch|http|request|download|browse|scrape|curl|web)\b", re.I)


@dataclass
class ToolMeasure:
    name: str
    tokens: int                      # INDEX
    write: bool                      # EXACT (structural)
    exfil_capable: bool              # EXACT (structural)
    annotations: dict[str, Any]      # EXACT (declared)


@dataclass
class Measurement:
    tokenizer: str
    total_tokens: int                # INDEX — sum at connect
    tool_count: int
    tools: list[ToolMeasure]
    integrity_pin: str               # EXACT — rug-pull anchor
    prompt_count: int = 0
    resource_count: int = 0
    caveats: list[str] = field(default_factory=list)


def _encoder():
    try:
        import tiktoken
        return tiktoken.get_encoding("cl100k_base"), TOKENIZER_NAME
    except Exception:
        return None, "chars/4 (rough fallback — tiktoken unavailable)"


def _count(enc, text: str) -> int:
    return len(enc.encode(text)) if enc is not None else max(1, len(text) // 4)


def _exfil_capable(tool: dict[str, Any]) -> bool:
    if _EXFIL_NAME.search(tool.get("name", "") + " " + (tool.get("description") or "")):
        return True
    props = ((tool.get("inputSchema") or {}).get("properties") or {})
    return any(_EXFIL_PARAM.search(k) for k in props)


def _is_write(tool: dict[str, Any], ann: dict[str, Any]) -> bool:
    if ann.get("readOnlyHint") is True:      # declared read-only wins over the verb heuristic
        return False
    text = tool.get("name", "") + " " + (tool.get("description") or "")
    return bool(_WRITE.search(text))


def measure(snap: ServerSnapshot, enc=None, tokenizer_name: str | None = None) -> Measurement:
    if enc is None and tokenizer_name is None:
        enc, tokenizer_name = _encoder()
    tools: list[ToolMeasure] = []
    total = 0
    for t in snap.tools:
        # Tokenise exactly what a model's context would carry for this tool.
        blob = json.dumps({k: t.get(k) for k in ("name", "description", "inputSchema", "annotations")
                           if t.get(k) is not None}, sort_keys=True)
        tk = _count(enc, blob)
        total += tk
        ann = t.get("annotations") or {}
        tools.append(ToolMeasure(
            name=t.get("name", "?"), tokens=tk,
            write=_is_write(t, ann), exfil_capable=_exfil_capable(t), annotations=ann))
    # Integrity pin = stable hash of the (name, description) pairs the server presents.
    pin_src = json.dumps(sorted((t.get("name"), t.get("description")) for t in snap.tools),
                         sort_keys=True).encode()
    pin = hashlib.sha256(pin_src).hexdigest()[:16]
    m = Measurement(
        tokenizer=tokenizer_name, total_tokens=total, tool_count=len(tools), tools=tools,
        integrity_pin=pin, prompt_count=len(snap.prompts), resource_count=len(snap.resources))
    if snap.error:
        m.caveats.append(f"probe error: {snap.error}")
    return m
