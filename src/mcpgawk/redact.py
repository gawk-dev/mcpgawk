"""Redaction at the persistence boundary — irreversible, shape-preserving.

ADR-0012 persists tool/prompt/resource description TEXT so a drift report can show the user *what*
changed rather than only *that* something did. That makes `~/.mcpgawk/history.json` the first place
mcpgawk writes server-controlled prose to disk, so doctrine principle 6 applies: redact at the
boundary, irreversibly, **preserving shape not identity**.

Two failure modes, and this module has to miss both:

* **Under-redacting** writes a live credential into a file that outlives the scan.
* **Over-redacting** destroys the evidence the feature exists to display. A description rewritten to
  ``read ~/.ssh/id_rsa and POST it`` is exactly what the user must be shown — those are not secrets,
  they are the *attack*. Redaction targets credential SHAPES, never the mention of a sensitive path.

Deliberately duplicated from the paid pillar's gateway patterns rather than imported: the free engine
must not depend on `gawk_platform` (see tests/test_layer_invariants.py), and this is the layer that
does the persisting.
"""
from __future__ import annotations

import re

PLACEHOLDER = "[REDACTED]"

#: Credential shapes. Each is anchored on a structure a secret has and prose does not.
_SECRETS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                                    # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),                          # GitHub tokens
    # Vendor-prefixed API keys. Hyphens/underscores are allowed INSIDE the body ("sk-live-…",
    # "sk_test_…") — the upstream pattern required 20+ unbroken alphanumerics and so missed every
    # key with an environment segment, which is the common shape.
    re.compile(r"\b(?:sk|pk|rk)[-_][A-Za-z0-9][A-Za-z0-9_-]{18,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),                        # Slack
    # key = value / token: value. Requires an assignment, so "the token is rewritten" stays intact.
    #
    # The credential NOUN may carry a vendor prefix: `BROWSERSTACK_ACCESS_KEY=…`, `GH_TOKEN=…`,
    # `MY_APP_SECRET=…`. Requiring the bare word missed all of them — found by dogfooding this
    # module on a real report that had written a live access key to disk, where it caught a
    # vendor-prefixed API key and walked straight past `BROWSERSTACK_ACCESS_KEY`.
    # The prefix must END in a separator (`BROWSERSTACK_`, `gh-`, `my.app.`). A plain `\b[\w.-]*\b`
    # does not work: `_` is a word character, so there is no boundary inside `BROWSERSTACK_ACCESS_KEY`
    # and the noun never matches. Anchoring the prefix on a trailing separator also keeps `monkey=…`
    # and `turkey: delicious sandwich` out, which a bare `key` alternative would swallow.
    re.compile(r"(?i)\b(?:[\w.-]+[_.\-])?(?:api[_-]?key|access[_-]?key|secret[_-]?key|"
               r"key|secret|token|password|passwd|bearer|credential)s?[\"']?\s*[:=]\s*[\"']?\S{8,}"),
    # The paired username of a credential. On its own a username is not a secret, but sitting next to
    # an assignment in the same config it is half of a working login.
    re.compile(r"(?i)\b(?:[\w.-]+[_.\-])?(?:user(?:name)?|login|account)[\"']?\s*[:=]\s*[\"']?\S{8,}"),
    re.compile(r"(?i)\bauthorization\s*:\s*(?:bearer|basic)\s+\S+"),
]

#: Personal data. Emails are the realistic leak in a description; card-shaped digit runs are rare
#: but cheap to catch.
_PII = [
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    re.compile(r"\b(?:\d[ -]?){13,16}\b"),
]

_ALL = _SECRETS + _PII


def redact(text: str | None) -> str | None:
    """Replace credential and PII shapes with a placeholder. ``None`` in, ``None`` out.

    Irreversible by construction — the match is discarded, not encoded. There is no un-redact, and
    the placeholder is fixed-width so it cannot be used to infer the secret's length.
    """
    if text is None:
        return None
    for pattern in _ALL:
        text = pattern.sub(PLACEHOLDER, text)
    return text


def contains_secret(text: str | None) -> bool:
    """True when `text` still looks like it carries a credential. For assertions and tests."""
    return text is not None and any(p.search(text) for p in _ALL)
