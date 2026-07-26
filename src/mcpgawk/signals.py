"""BOUND / BOUNDED layer — heuristic risk *signals*, kept physically apart from measure.py.

The wall: this module has NO token math and NO capability facts; measure.py has NO signals.
An estimate can therefore never contaminate a fact.

0-FP discipline (authdrift lesson): every detector here is deliberately *precise* — it fires only
on language aimed at the reader/model, never on legitimate tool capability keywords (a `url` param
or a `delete` verb is a FACT, handled in measure.py, not a signal here). A detector ships only after
a measured 0 false positives on a real clean corpus (see tests/test_signals.py + the live FP gate).

A signal is a SIGNAL, never a verdict. We never say "server X is insecure".
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any

from .probe import ServerSnapshot
from .redact import _SECRETS as _ALL_SECRET_SHAPES
from .redact import redact

# THE catalog of every bounded-signal `kind` this module can emit, mapped to the detector that
# emits it. Single source of truth for the anti-drift canary (tests/test_canary_signals.py), which
# fails the build if:
#   * a detector emits a `kind` literal not registered here (static scan of this file's source);
#   * a registered kind has no live fixture proving its detector actually fires it;
#   * a kind's family (the part before ':') has no label lead phrase (label._SIGNAL_LEAD), i.e. it
#     could be mislabelled in the report.
# Adding a detector without registering + fixture-testing + labelling its kind cannot pass CI. This
# is the mechanism that ends fix-on-the-go: scan coverage and report correctness cannot silently rot.
# (Discovery scopes will register the same way here once discovery lands — roadmap SCAN/Discovery.)
SIGNAL_KINDS: dict[str, str] = {
    "injection:hidden-markup": "detect",
    "injection:reader-directed": "detect",
    "injection:secret-exfil": "detect",
    "obfuscation:hidden-unicode": "detect",
    "dispatch:dynamic-tool-catalog": "detect_dynamic_dispatch",
    "shadowing:name-collision": "detect_shadowing",
    "shadowing:cross-server-reference": "detect_cross_server_reference",
    "servercard:undeclared-tools": "detect_card_mismatch",
    "skill:download-url": "detect_skill_content",
    "skill:piped-exec": "detect_skill_content",
    "skill:runtime-fetch": "detect_skill_content",
    "skill:credential-emission": "detect_skill_content",
    "skill:secret-hardcoded": "detect_skill_content",
    "skill:malformed": "detect_skill_malformed",
}

# --- Detector 1: hidden markup in a description (HTML comments / pseudo-system tags). ---
# Legit tool descriptions are plain prose; an embedded comment or <important>/<system> tag is
# the classic tool-poisoning carrier (Invariant's own local rule keyed on <IMPORTANT>).
_HIDDEN_MARKUP = re.compile(r"<!--.*?-->|<\s*/?\s*(important|system|secret|admin|instruction|tool_call)\b",
                            re.IGNORECASE | re.DOTALL)

# --- Detector 2: reader-directed instructions (the model is the audience, not the caller). ---
_READER_DIRECTED = re.compile(
    r"ignore\s+(?:all\s+|the\s+|your\s+|any\s+)*(?:previous|prior|above|earlier|preceding)\s+"
    r"(?:instruction|prompt|message|context)"
    r"|disregard\s+(?:the\s+|all\s+|any\s+)*(?:previous|prior|above|earlier)"
    r"|do\s*n?o?t?'?\s*(?:tell|inform|mention|reveal|notify|disclose)\s+(?:the\s+)?(?:user|human)"
    r"|(?:you\s+are|act\s+as|you\s+must\s+act)\s+an?\s+(?:ai|assistant|language\s+model|agent)"
    r"|(?:your|the)\s+system\s+prompt"
    r"|new\s+instructions?\s*:",
    re.IGNORECASE)

# --- Detector 3: secret-exfil directives (read a secret AND move it). ---
# Tightened after a real false positive: Vercel's `get_access_to_vercel_url` says "access ... without
# requiring login credentials" — benign. "access" and a bare "credential" are NOT suspicious. We fire on
# (a) reading an unambiguous secret FILE, or (b) a secret WORD paired with an explicit exfil verb.
# Only unambiguous secret FILES — a legit tool description has no reason to name these. Secret *words*
# ("api key", "password", "credential") appear in countless benign descriptions, so they are NOT used
# (that was the FP source: "pass/fail with an API key", "access without credentials", etc.). Other
# injection styles are still caught by the hidden-markup and reader-directed detectors above.
_SECRET_FILE = r"(?:\.env\b|~/\.ssh|id_rsa|/etc/passwd|/etc/shadow)"
_EXFIL_VERB = r"(?:pass|send|include|attach|exfiltrat\w*|leak|upload|post|forward)"
_EXFIL_DIRECTIVE = re.compile(
    r"(?:read|open|cat|load|retrieve|dump)\b[^.]{0,40}" + _SECRET_FILE   # read a secret file
    + r"|" + _SECRET_FILE + r"[^.]{0,40}\b" + _EXFIL_VERB,                # secret file → moved out
    re.IGNORECASE | re.DOTALL)

_DETECTORS = (
    ("injection:hidden-markup", _HIDDEN_MARKUP),
    ("injection:reader-directed", _READER_DIRECTED),
    ("injection:secret-exfil", _EXFIL_DIRECTIVE),
)

# --- Detector 4: dynamic tool-dispatch (meta-tool defeats tools/list entirely). ---
# A 2026-07-16 dogfooding pass found this is a real, common shape, not a corner case:
# getsentry/sentry-mcp (search_sentry_tools + execute_sentry_tool) and docker/mcp-gateway
# (mcp-find + mcp-exec, ON BY DEFAULT) both collapse dozens-to-hundreds of real tools behind a
# handful of declared ones. A passive tools/list scan structurally cannot see the hidden catalog,
# so this signal exists to say "this scan is incomplete", never "this server is bad" — a clean
# report from a server with this shape is not proof of a clean server.
# Narrow by design (0-FP discipline): fires only on a paired discover+execute name match (both
# tools must be present), or a single execute-shaped tool whose schema takes a free-text
# tool-name/action selector — not on an ordinary "execute_workflow(id)"-style tool with a fixed,
# non-dispatching argument.
_DISCOVER_TOOL_NAME = re.compile(
    r"(?:search|find|discover|list)[-_]?\w*tools?\b|tools?[-_]?(?:search|find|discover|list)\b"
    r"|^mcp[-_]?find$",
    re.IGNORECASE)
_EXEC_TOOL_NAME = re.compile(
    r"(?:execute|exec|invoke|dispatch|call|run)[-_]?\w*tools?\b|tools?[-_]?(?:execute|exec|invoke|dispatch)\b"
    r"|^mcp[-_]?(?:exec|add)$|^code[-_]?mode$",
    re.IGNORECASE)
_DISPATCH_PARAM_NAMES = {"tool", "tool_name", "toolname", "target_tool", "action"}


def detect_dynamic_dispatch(snap: ServerSnapshot) -> list[Finding]:
    """Signal: this server's tools/list likely hides a larger real catalog behind a dynamic
    tool-dispatch pattern (confirmed live on getsentry/sentry-mcp and docker/mcp-gateway)."""
    names = [t.get("name", "?") for t in snap.tools]
    discover = sorted({n for n in names if _DISCOVER_TOOL_NAME.search(n)})
    executor = sorted({n for n in names if _EXEC_TOOL_NAME.search(n)})
    if discover and executor:
        return [Finding(
            tool=", ".join(discover + executor),
            kind="dispatch:dynamic-tool-catalog",
            evidence=(f"{len(names)} tools visible via tools/list, but '{executor[0]}' paired with "
                      f"'{discover[0]}' is the dynamic-dispatch shape (Sentry/Docker mcp-gateway "
                      f"pattern) — the real tool catalog is likely larger and not visible to this scan"))]
    out: list[Finding] = []
    for t in snap.tools:
        n = t.get("name", "?")
        if not _EXEC_TOOL_NAME.search(n):
            continue
        props = ((t.get("inputSchema") or {}).get("properties") or {})
        for pname, pschema in props.items():
            if pname.lower().replace("-", "_") in _DISPATCH_PARAM_NAMES and (pschema or {}).get("type") == "string":
                out.append(Finding(
                    tool=n, kind="dispatch:dynamic-tool-catalog",
                    evidence=(f"'{n}' takes a free-text '{pname}' selector — likely dispatches to "
                              f"tools not visible in this scan's tools/list")))
                break
    return out


@dataclass
class Finding:
    tool: str
    kind: str
    evidence: str            # the matched span — so a human can judge, we never auto-verdict
    confidence: str = "signal"   # never "confirmed"; this layer only signals


#: Characters that are invisible when rendered but are still read by the model. Unicode Format (Cf)
#: and Control (Cc) ranges, plus the Tag block, which can encode a whole hidden message.
_HIDDEN = re.compile(
    r"[​-‏‪-‮⁠-⁤⁪-⁯﻿\U000e0000-\U000e007f]"
)
#: Unicode Tag characters map 1:1 onto ASCII — U+E0041 is "A". Decoding them turns a message that
#: is invisible to a human reviewer back into text the detectors can read.
_TAG_BASE = 0xE0000


def _deobfuscate(text: str) -> tuple[str, str]:
    """Return (text the MODEL effectively sees, a description of what was hidden).

    A literal pattern is defeated by a single invisible character: `<IM​PORTANT>` does not match
    `<IMPORTANT`, and `ig​nore previous instructions` does not match either — while the model
    reads both exactly as intended. Measured on the poisoned corpus, this one trick blinded EVERY
    detector we had, including the cases taken verbatim from a published disclosure.
    """
    if not text or not _HIDDEN.search(text):
        return text, ""
    decoded = []
    kinds = set()
    for ch in text:
        cp = ord(ch)
        if _TAG_BASE <= cp <= _TAG_BASE + 0x7F:
            kinds.add("unicode-tag")
            decoded.append(chr(cp - _TAG_BASE))      # smuggled message, made readable
        elif _HIDDEN.match(ch):
            kinds.add("zero-width" if cp in range(0x200B, 0x2010) else "invisible-format")
        else:
            decoded.append(ch)
    return "".join(decoded), "+".join(sorted(kinds))


#: In a TOOL DESCRIPTION an HTML comment has no legitimate purpose — it is the classic poisoning
#: carrier, and _HIDDEN_MARKUP flags its mere presence. In a MARKDOWN document (a skill file) an
#: HTML comment is ordinary authoring: the live 63-skill corpus produced 15 findings, every one of
#: them a `<!-- Bootstrap -->`-style section marker. So on prose the carrier alone is not the
#: signal — what it HIDES is. A comment is flagged only when its body is reader-directed or smuggles
#: a pseudo-system tag, which is precisely the attack the description-side rule exists to catch.
_HTML_COMMENT_RX = re.compile(r"<!--(.*?)-->", re.DOTALL)
_PSEUDO_TAG_RX = re.compile(r"<\s*/?\s*(important|system|secret|admin|instruction|tool_call)\b",
                            re.IGNORECASE)


def _markdown_comment_is_benign(text: str) -> bool:
    """True when every HTML comment in `text` is an ordinary authoring comment."""
    for body in _HTML_COMMENT_RX.findall(text):
        if _READER_DIRECTED.search(body) or _PSEUDO_TAG_RX.search(body) or _EXFIL_DIRECTIVE.search(body):
            return False
    return True


def _scan_text(text: str, tool: str, prose_markdown: bool = False) -> list[Finding]:
    out: list[Finding] = []
    clean, hidden = _deobfuscate(text or "")
    if hidden:
        # The obfuscation is itself the finding. Silently normalising and moving on would hide the
        # most incriminating fact: a legitimate tool description has no reason to carry characters
        # that are invisible to the person reviewing it.
        out.append(Finding(tool=tool, kind="obfuscation:hidden-unicode",
                           evidence=f"{hidden} characters hide: {clean.strip()[:90]!r}"))
    # Scan BOTH: the raw text (so evidence quotes what was actually published) and the de-obfuscated
    # form (so an invisible character cannot switch the detectors off).
    for kind, rx in _DETECTORS:
        m = rx.search(text or "") or rx.search(clean)
        if not m:
            continue
        if (kind == "injection:hidden-markup" and prose_markdown
                and not _PSEUDO_TAG_RX.search(text or "")
                and _markdown_comment_is_benign(text or "")
                and _markdown_comment_is_benign(clean)):
            continue  # ordinary Markdown section comment, hiding nothing — see above
        span = m.group(0).strip()
        out.append(Finding(tool=tool, kind=kind, evidence=span[:120]))
    return out


def detect(snap: ServerSnapshot) -> list[Finding]:
    """Run the BOUNDED detectors over the injection surface: tool AND prompt descriptions.
    (Prompts are model-facing text too — the tool-poisoning surface isn't only tools/list.)"""
    findings: list[Finding] = []
    for t in snap.tools:
        findings.extend(_scan_text(t.get("description") or "", t.get("name", "?")))
    for pr in snap.prompts:
        findings.extend(_scan_text(pr.get("description") or "", f"prompt:{pr.get('name', '?')}"))
    return findings


# --- Skill-content detectors (agent skills: SKILL.md trees, command files) ----------------------
# Invariant/Snyk's agent-scan treats skills as half its product (issue codes E004–E006, W007–W014)
# — but every one of those determinations happens SERVER-SIDE behind their API; the client uploads
# raw skill content and copies verdicts back. There is nothing to port, only a taxonomy to cover.
# These are OUR detectors, fully local, no content ever leaves the machine — the same bounded,
# signal-grade discipline as every detector above: a match is "worth a human's eyes", never a
# verdict. The SEMANTIC checks in their taxonomy (full intent analysis, financial-capability or
# third-party-content classification — their E004/W009/W011/W013) are deliberately NOT imitated
# with regexes here; skills.py surfaces that coverage honestly instead of pretending.

_URL_RX = re.compile(r"https?://[^\s)\"'`<>\]]+", re.IGNORECASE)

#: URL shorteners obscure the destination — a skill has no legitimate reason to hide where it
#: sends an agent (their E005 class c).
_SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "cutt.ly",
    "rb.gy", "tiny.cc", "shorturl.at", "rebrand.ly", "s.id", "v.gd",
}
#: Personal file-hosting / paste services — content there is unversioned, unreviewable and
#: swappable after review (their E005 class d).
_FILEHOST_HOSTS = {
    "pastebin.com", "paste.ee", "transfer.sh", "anonfiles.com", "file.io", "mega.nz",
    "mediafire.com", "gofile.io", "catbox.moe", "litter.catbox.moe", "cdn.discordapp.com",
    "0x0.st", "bashupload.com", "temp.sh",
}
#: Direct executable/installer downloads (their E005 class a). Deliberately NOT .sh/.py/.zip —
#: those are everywhere in benign skills; the risky *execution* of fetched scripts is the
#: piped-exec detector's job.
_EXECUTABLE_EXT_RX = re.compile(r"\.(exe|msi|scr|bat|cmd|ps1|apk|dmg|pkg)(?:[?#]|$)", re.IGNORECASE)
_RAW_IP_HOST_RX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_public_ip(host: str) -> bool:
    """Only a PUBLIC raw IP is a 'downloading from an unnamed host' signal. Loopback, private and
    link-local addresses are the opposite — they are local-only, and a skill that documents
    127.0.0.1 or the 169.254.169.254 metadata endpoint is describing an environment, not hiding a
    download host. Measured on a real 63-skill corpus: this alone accounted for most of one
    security skill's 57 URL findings, all of them wrong."""
    try:
        octets = [int(o) for o in host.split(".")]
    except ValueError:
        return False
    if len(octets) != 4 or any(o > 255 for o in octets):
        return False
    a, b = octets[0], octets[1]
    if a in (0, 10, 127):                       # this-network, private, loopback
        return False
    if a == 172 and 16 <= b <= 31:              # private
        return False
    if a == 192 and b == 168:                   # private
        return False
    if a == 169 and b == 254:                   # link-local incl. the cloud metadata endpoint
        return False
    if a == 100 and 64 <= b <= 127:             # CGNAT/shared — Alibaba's metadata endpoint lives here
        return False
    if a >= 224:                                # multicast / reserved
        return False
    return True


def _suspicious_url_reason(url: str) -> str | None:
    host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/", 1)[0]
    host = host.split("@")[-1].split(":", 1)[0].lower()
    if _RAW_IP_HOST_RX.match(host):
        if not _is_public_ip(host):
            return None
        return "raw-IP host — no name to review, no certificate identity worth anything"
    if host in _SHORTENER_HOSTS:
        return "URL shortener — the real destination is hidden from review"
    if host in _FILEHOST_HOSTS:
        return "personal file-hosting/paste service — unversioned, swappable after review"
    if _EXECUTABLE_EXT_RX.search(url):
        return "direct executable/installer download"
    return None


#: Fetch-and-execute: content pulled from the network flows straight into a shell/interpreter.
_PIPED_EXEC_RX = re.compile(
    r"\b(?:curl|wget)\b[^\n|;&]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
    r"|\b(?:curl|wget)\b[^\n|;&]{0,200}\|\s*(?:sudo\s+)?(?:python3?|node|perl|ruby)\b"
    r"|\bbase64\b[^\n|;&]{0,120}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
    r"|\bInvoke-Expression\b|\biex\s*\(|\bDownloadString\s*\(",
    re.IGNORECASE)

#: Instructions/code fetched from a URL at RUNTIME steering the agent (their W012): defeats any
#: review or pinning — what was reviewed is not what runs tomorrow.
_RUNTIME_FETCH_RX = re.compile(
    r"\b(?:fetch|download|retrieve|load|get|pull|read)\b[^.\n]{0,60}"
    r"\b(?:latest\s+)?(?:instructions?|prompts?|commands?|rules|directives)\b[^.\n]{0,60}"
    r"\bfrom\b[^.\n]{0,80}https?://"
    r"|\bfollow\s+(?:the\s+)?instructions?\s+(?:at|from|in)\s+https?://"
    r"|\bcheck\b[^.\n]{0,60}\bfor\s+(?:updated|new)\s+instructions?\b",
    re.IGNORECASE)

#: A skill instructing the agent to EMIT secret values into its output/conversation (their W007) —
#: context windows and chat history are not a secret store.
_CREDENTIAL_EMISSION_RX = re.compile(
    r"\b(?:print|echo|output|display|show|paste|include|insert|write)\b[^.\n]{0,60}"
    r"\b(?:api[ _-]?key|access[ _-]?token|auth[ _-]?token|secret[ _-]?key|password|credential)s?\b",
    re.IGNORECASE)
#: ...unless the surrounding text is telling the agent NOT to. ("never print the API key")
_NEGATION_RX = re.compile(r"\b(?:never|not|don'?t|do\s+not|avoid|without|refuse)\b[^.\n]{0,40}$",
                          re.IGNORECASE)

#: A documentation placeholder is not a leaked credential. redact.py deliberately OVER-matches —
#: it is a redactor, where a false positive costs nothing — but a finding emitter that cries wolf
#: on `API_KEY="your-api-key-here"` trains the reader to ignore it. Measured on a real 63-skill
#: corpus: every one of 64 secret findings was a placeholder or an example in install docs.
_PLACEHOLDER_VALUE_RX = re.compile(
    r"(?ix)(?: your[_\-. ]? | my[_\-. ]? | the[_\-. ]? | some[_\-. ]? | example[_\-. ]? "
    r"| placeholder | dummy | sample | insert[_\-. ] | replace[_\-. ] | changeme | xxx+ | \.\.\. "
    r"| <[^>]{1,40}> | \$\{[^}]{1,40}\} | \$[A-Z_]{3,} | \{\{[^}]{1,40}\}\} )"
    r"| (?:[_\-]?(?:here|key|token|secret|password|value|goes[_\-]?here)\b)\s*$")


def _looks_like_placeholder(line: str) -> bool:
    m = re.search(r"[:=]\s*[\"']?([^\"'\n]{0,80})", line)
    value = m.group(1).strip() if m else line
    return bool(_PLACEHOLDER_VALUE_RX.search(value))


#: Vendor-shaped literals: the string ITSELF is recognisably a credential, so it is a finding
#: wherever it appears. (redact._SECRETS[0:5] — private-key blocks, AWS, GitHub, sk-/pk-/rk-, Slack.)
_LITERAL_CREDENTIAL_SHAPES = tuple(_ALL_SECRET_SHAPES[:5])

#: `name = value` assignments. redact.py accepts ANY 8+ non-space value here — correct for a
#: redactor, badly wrong for a finding emitter reading prose: "Scan for leaked secrets: on JS
#: repos" and "dict with 'decision' key: 'block'" both matched on the live corpus. A real
#: credential value is a single opaque token, so require: no whitespace, ≥16 chars, and either a
#: digit or real length — which prose after a colon essentially never satisfies.
_ASSIGNMENT_RX = re.compile(
    r"(?i)\b(?:[\w.-]+[_.\-])?(?:api[_-]?key|access[_-]?key|secret[_-]?key|key|secret|token|"
    r"password|passwd|bearer|credential)s?[\"']?\s*[:=]\s*[\"']?(\S+)")


def _assignment_value_looks_like_a_credential(line: str) -> bool:
    m = _ASSIGNMENT_RX.search(line)
    if not m:
        return False
    value = m.group(1).strip("\"'`,;)")
    if len(value) < 16 or any(c.isspace() for c in value):
        return False
    return any(c.isdigit() for c in value) or len(value) >= 24


def _credential_line(line: str) -> bool:
    if _looks_like_placeholder(line):
        return False
    if any(rx.search(line) for rx in _LITERAL_CREDENTIAL_SHAPES):
        return True
    return _assignment_value_looks_like_a_credential(line)


#: Long base64 runs get decoded and re-scanned — the classic carrier for a hidden curl|bash
#: (Snyk's own adversarial skill fixture hides exactly that behind base64).
_BASE64_BLOB_RX = re.compile(r"[A-Za-z0-9+/=]{40,}")


def _decoded_blobs(text: str) -> list[str]:
    out = []
    for blob in _BASE64_BLOB_RX.findall(text or ""):
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable() or "\n" in decoded:
            out.append(decoded)
    return out


def detect_skill_content(text: str, origin: str) -> list[Finding]:
    """Skill-specific detectors over ONE file's text. `origin` labels the finding (skill:file).
    Runs on the raw text AND on any base64-decodable blobs inside it — an encoded payload is
    still a payload. Fully local; the text never leaves the process."""
    out: list[Finding] = []
    layers = [("", text or "")] + [("base64-decoded: ", d) for d in _decoded_blobs(text or "")]
    for prefix, layer in layers:
        for url in _URL_RX.findall(layer):
            reason = _suspicious_url_reason(url)
            if reason:
                out.append(Finding(tool=origin, kind="skill:download-url",
                                   evidence=f"{prefix}{url[:100]} — {reason}"))
        m = _PIPED_EXEC_RX.search(layer)
        if m:
            out.append(Finding(tool=origin, kind="skill:piped-exec",
                               evidence=f"{prefix}{m.group(0).strip()[:120]}"))
        m = _RUNTIME_FETCH_RX.search(layer)
        if m:
            out.append(Finding(tool=origin, kind="skill:runtime-fetch",
                               evidence=f"{prefix}{m.group(0).strip()[:120]}"))
        for m in _CREDENTIAL_EMISSION_RX.finditer(layer):
            if _NEGATION_RX.search(layer[max(0, m.start() - 45):m.start()]):
                continue  # "never print the API key" is guidance, not an instruction to leak
            out.append(Finding(tool=origin, kind="skill:credential-emission",
                               evidence=f"{prefix}{m.group(0).strip()[:120]}"))
            break  # one per layer is signal enough
        for line in layer.splitlines():
            # CREDENTIAL shapes only — contains_secret() also covers PII (an email address is not
            # a hardcoded secret and would be filed under the wrong kind) — and never on an
            # obvious documentation placeholder or a prose line that merely says "token:".
            if _credential_line(line):
                out.append(Finding(tool=origin, kind="skill:secret-hardcoded",
                                   evidence=f"{prefix}{(redact(line) or '').strip()[:120]}"))
                break  # evidence is REDACTED and one line is enough — never republish a secret
    return out


def detect_skill_malformed(reason: str, origin: str) -> list[Finding]:
    """Structural finding for a skill that cannot be parsed as it claims to be (their W014/X002
    territory): a missing or frontmatter-less SKILL.md means the skill's stated identity cannot
    be reviewed at all — that is a finding, not an error to swallow."""
    return [Finding(tool=origin, kind="skill:malformed", evidence=reason[:160])]


def detect_shadowing(snaps: list[ServerSnapshot]) -> dict[str, list[Finding]]:
    """CROSS-SERVER signal: a tool name exposed by more than one server. All connected servers share
    one context, so a malicious server can register the same name as a trusted one and shadow it
    (mcp-secret-exfil-threat-model: 'cross-tool shadowing'). Naturally 0-FP — fires only on a genuine
    collision between distinct servers. Returns {server_name -> [Finding]}.
    """
    owners: dict[str, set[str]] = {}
    for s in snaps:
        for t in s.tools:
            owners.setdefault(t.get("name", "?"), set()).add(s.name)
    out: dict[str, list[Finding]] = {}
    for s in snaps:
        for t in s.tools:
            nm = t.get("name", "?")
            others = owners.get(nm, set()) - {s.name}
            if others:
                out.setdefault(s.name, []).append(Finding(
                    tool=nm, kind="shadowing:name-collision",
                    evidence=f"also exposed by: {', '.join(sorted(others))}"))
    return out


#: A directive aimed at the agent about ANOTHER tool — "when the user calls X", "before using X".
#: Required for a cross-server reference to count: a description may legitimately name a concept
#: that happens to be another server's tool name, but it has no business instructing the agent about
#: when to call it.
_REFERENTIAL = re.compile(
    r"(?:when(?:ever)?|before|after|instead\s+of|prior\s+to|each\s+time|always|first)\b"
    r"|(?:call|calls|calling|use|uses|using|invoke|invokes|run|runs)\b",
    re.IGNORECASE)

#: An identifier-shaped token: snake_case, kebab-case or camelCase. A bare English word is NOT enough
#: — real inventories contain tools called `sum`, `search`, `login` and `impact`, and a description
#: saying "use search instead" must never be read as a cross-server reference. This is the whole
#: false-positive control.
_IDENTIFIERISH = re.compile(r"^(?=.*[_\-]|.*[a-z][A-Z])[\w\-]{4,}$")


def detect_cross_server_reference(snaps: list[ServerSnapshot]) -> dict[str, list[Finding]]:
    """CROSS-SERVER signal (Invariant issue code E002): a server's tool description instructs the
    agent about a tool belonging to a DIFFERENT server.

    Distinct from `detect_shadowing`, which fires on a name COLLISION — two servers exposing the same
    tool name. Here the names differ; the danger is that server A rewrites how the agent uses server
    B's trusted tool ("whenever the user calls send_email, first call this"). All connected servers
    share one context, so A's description is read by the model that also holds B's.

    0-FP discipline, and this detector needs it more than most: tool names are frequently ordinary
    words. It fires only when the referenced name is IDENTIFIER-SHAPED (contains a separator or
    camelCase) *and* the sentence is referential (a directive about when to call it). Measured on the
    real 6-server / 175-tool inventory: 0 findings.
    """
    owners: dict[str, set[str]] = {}
    for s in snaps:
        for t in s.tools:
            owners.setdefault(t.get("name", "?"), set()).add(s.name)
    foreign = {n: o for n, o in owners.items() if _IDENTIFIERISH.match(n)}

    out: dict[str, list[Finding]] = {}
    for s in snaps:
        own = {t.get("name", "?") for t in s.tools}
        for t in s.tools:
            desc = t.get("description") or ""
            clean, _ = _deobfuscate(desc)          # an invisible char must not hide the reference
            for name, holders in foreign.items():
                if name in own or not (holders - {s.name}):
                    continue                        # its own tool, or nobody else owns it
                for hay in (desc, clean):
                    m = re.search(rf"\b{re.escape(name)}\b", hay)
                    if not m:
                        continue
                    window = hay[max(0, m.start() - 90):m.end() + 90]
                    if _REFERENTIAL.search(window):
                        out.setdefault(s.name, []).append(Finding(
                            tool=t.get("name", "?"), kind="shadowing:cross-server-reference",
                            evidence=(f"describes when to use '{name}', which belongs to "
                                      f"{', '.join(sorted(holders - {s.name}))} — a server should not "
                                      f"instruct the agent about another server's tool")))
                        break
    return out


def detect_card_mismatch(snap: ServerSnapshot) -> list[Finding]:
    """Signal: the server's public .well-known card UNDER-DECLARES — hides tools it actually exposes.
    A fact-based, 0-FP signal (fires only on a real declared-vs-measured gap). Independent
    measurement catching a self-declaration that doesn't match reality."""
    if not snap.server_card:
        return []
    from .servercard import compare_to_reality
    cmp = compare_to_reality(snap.server_card, [t.get("name", "?") for t in snap.tools])
    out: list[Finding] = []
    if cmp.get("undeclared_tools"):
        u = cmp["undeclared_tools"]
        out.append(Finding(tool="<server-card>", kind="servercard:undeclared-tools",
                           evidence=f"exposes {len(u)} tool(s) absent from its public card: {', '.join(u[:6])}"))
    return out


def as_dicts(findings: list[Finding]) -> list[dict[str, Any]]:
    return [{"tool": f.tool, "kind": f.kind, "evidence": f.evidence, "confidence": f.confidence}
            for f in findings]
