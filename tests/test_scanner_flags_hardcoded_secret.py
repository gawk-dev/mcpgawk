"""The `mcpgawk scan` path (signals.detect → label) must flag a hardcoded provider credential
baked into a tool/prompt description, MASK it in the evidence, and — load-bearing — NEVER render
such a server as CLEAN, even when it is cheap and read-only. That last property is the exact
self-contradiction the injection gate was written to prevent (a cheap read-only server with a
real finding rendering ● CLEAN); a secret is another such finding.
"""
from __future__ import annotations

from mcpgawk import label as label_mod
from mcpgawk.signals import Finding, _scan_text, as_dicts, detect


class _Snap:
    def __init__(self, tools=None, prompts=None):
        self.tools = tools or []
        self.prompts = prompts or []


STRIPE = "sk_live_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7"


def test_scan_flags_a_baked_secret_in_a_description():
    findings = detect(_Snap(tools=[{"name": "charge", "description": f"Bills the card. key={STRIPE}"}]))
    kinds = [f.kind for f in findings]
    assert "secret:hardcoded" in kinds, f"the scanner missed a hardcoded Stripe key: {kinds}"


def test_the_evidence_is_masked_never_the_raw_secret():
    findings = _scan_text(f"key={STRIPE}", "t")
    hit = next(f for f in findings if f.kind == "secret:hardcoded")
    assert STRIPE not in hit.evidence, f"the raw secret leaked into scan evidence: {hit.evidence}"
    assert "Stripe live secret key" in hit.evidence


def test_a_clean_description_is_not_flagged():
    findings = detect(_Snap(tools=[
        {"name": "get_weather", "description": "Forecast for a city. Example id abc123def456."},
        {"name": "run_sql", "description": "Read-only query, e.g. SELECT id FROM t LIMIT 5."},
    ]))
    assert not any(f.kind.startswith("secret:") for f in findings)


def _label_for(signals, *, write=0, exfil=0, cost=120):
    x = {"x-mcpgawk": {
        "tools": [{"name": "charge"}], "tool_count": 1, "cost_index_tokens": cost,
        "trust_surface": {"write_count": write, "exfil_count": exfil},
        "annotation_completeness": {"declared": 1, "total": 1},
        "caveats": [], "bounded_signals": [{"tool": s.tool, "kind": s.kind, "evidence": s.evidence}
                                           for s in signals],
    }}
    return label_mod.build_narrative(x)


def test_a_cheap_read_only_server_with_a_hardcoded_secret_is_not_clean():
    # Cheap (120 tok) and read-only (no write/exfil): has_risk and heavy are both False, so ONLY the
    # secret gate can stop CLEAN. This is the regression the whole test exists for.
    sigs = _scan_text(f"key={STRIPE}", "charge")
    narr = _label_for(sigs)
    assert narr["verdict"] != "CLEAN", f"a server shipping a live key rendered {narr['verdict']}"
    assert narr["state"] == "review"
    assert any("credential" in t.lower() for t, _ in
               [(c["title"], c["body"]) for c in narr["concerns"]]), "no concern names the credential"


def test_fleet_state_agrees_a_secret_server_is_not_clean():
    from mcpgawk import fleet
    sigs = _scan_text(f"key={STRIPE}", "charge")
    x = {"x-mcpgawk": {"tool_count": 1, "cost_index_tokens": 120,
         "trust_surface": {"write_count": 0, "exfil_count": 0},
         "annotation_completeness": {"declared": 1, "total": 1},
         "bounded_signals": [{"tool": s.tool, "kind": s.kind, "evidence": s.evidence} for s in sigs]}}
    verdict, detail = fleet.state_of(x)
    assert verdict != "CLEAN", f"fleet disagrees with the label: {verdict}"
    assert "secret" in detail.lower()
