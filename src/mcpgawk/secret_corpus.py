"""Curated hardcoded-secret signatures + safe masking — shared by the free scanner
(`mcpgawk scan`, via signals.py) and the paid audit rubric (gawk_platform detectors).

WHY A DEDICATED CORPUS, SEPARATE FROM redact._SECRETS. Redaction over-matches ON PURPOSE
(better to mask a non-secret than leak one). A DETECTOR must not: a false "this server ships a
live credential" is a scary, credibility-damaging finding. So this corpus is curated for
PRECISION — only anchored, provider-distinctive signatures (a real `sk_live_`/`AIza`/`glpat-`
prefix), never the loose `keyword.{0,20}=value` shapes. That keyword shape stays in redact where
over-matching is the right trade. (Lesson: a redactor's over-matching is not a detector — reusing
one gave 64/64 false positives.)

Lives in the FREE package because the free scanner is where it primarily runs; the paid engine
imports from here (paid may depend on free, never the reverse). Curated from the Claude-OSINT
corpus (2026-08-22), keeping the high-precision signatures and dropping the loose ones.
"""

from __future__ import annotations

import re

#: (provider label, compiled signature). Each anchored on a provider-distinctive prefix/shape with
#: a near-zero false-positive rate. Order matters only for which label a rare overlap reports.
SECRET_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    # --- cloud ---
    ("AWS access key id",          re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("Google API key",             re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b")),
    ("Google OAuth access token",  re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}")),
    ("GCP service-account JSON",   re.compile(r"\"type\"\s*:\s*\"service_account\"")),
    ("Azure storage AccountKey",   re.compile(r"AccountKey=[A-Za-z0-9+/]{86}==")),
    ("DigitalOcean token",         re.compile(r"\bdop_v1_[a-f0-9]{64}\b")),
    ("HashiCorp Vault token",      re.compile(r"\bhvs\.[A-Za-z0-9_\-]{90,120}\b")),
    # --- source hosting / CI / registries ---
    ("GitHub token",               re.compile(r"\bgh[posur]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained PAT",    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("GitLab PAT",                 re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b")),
    ("npm token",                  re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("PyPI token",                 re.compile(r"\bpypi-AgEN[A-Za-z0-9_\-]{40,}")),
    ("Docker Hub PAT",             re.compile(r"\bdckr_pat_[A-Za-z0-9_\-]{27,}\b")),
    ("RubyGems key",               re.compile(r"\brubygems_[a-f0-9]{48}\b")),
    ("JFrog API key",              re.compile(r"\bAKCp[A-Za-z0-9]{50,70}\b")),
    ("Terraform Cloud token",      re.compile(r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-=]{60,70}\b")),
    ("Postman API key",            re.compile(r"\bPMAK-[A-Za-z0-9]{24,64}\b")),
    # --- AI / LLM providers ---
    ("Anthropic API key",          re.compile(r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93,}")),
    ("OpenAI project key",         re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{40,}")),
    ("OpenAI key",                 re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b")),
    ("HuggingFace token",          re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    # --- payments / commerce ---
    ("Stripe live secret key",     re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")),
    ("Stripe test secret key",     re.compile(r"\bsk_test_[0-9A-Za-z]{24,}\b")),
    ("Square access token",        re.compile(r"\bsq0atp-[0-9A-Za-z\-_]{22}\b")),
    ("Square OAuth secret",        re.compile(r"\bsq0csp-[0-9A-Za-z\-_]{43}\b")),
    ("Shopify access token",       re.compile(r"\bshpat_[a-fA-F0-9]{32}\b")),
    ("Shopify shared secret",      re.compile(r"\bshpss_[a-fA-F0-9]{32}\b")),
    # --- comms / messaging ---
    ("Slack token",                re.compile(r"\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b")),
    ("Slack app-level token",      re.compile(r"\bxapp-1-[A-Za-z0-9\-]{20,}")),
    ("Slack webhook",              re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    ("SendGrid key",               re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("Twilio API key",             re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("Discord bot token",          re.compile(r"\b[MN][A-Za-z0-9]{23}\.[\w\-]{6}\.[\w\-]{27}\b")),
    ("Telegram bot token",         re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")),
    ("Facebook access token",      re.compile(r"\bEAA[A-Za-z0-9]{90,}")),
    # --- tooling / observability / secrets mgmt ---
    ("Linear API key",             re.compile(r"\blin_api_[A-Za-z0-9]{40}\b")),
    ("Databricks PAT",             re.compile(r"\bdapi[0-9a-f]{32}(?:-\d)?\b")),
    ("Doppler token",              re.compile(r"\bdp\.pt\.[A-Za-z0-9]{40,44}\b")),
    ("Dropbox short-lived token",  re.compile(r"\bsl\.[A-Za-z0-9_\-]{130,140}\b")),
    ("Grafana Cloud token",        re.compile(r"\bglc_[A-Za-z0-9+/]{32,}={0,2}\b")),
    ("New Relic key",              re.compile(r"\b(?:NRAA|NRAK|NRBR)-[A-F0-9]{27}\b")),
    ("Sentry DSN",                 re.compile(r"https://[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io/[0-9]+")),
    # --- generic high-signal shapes ---
    ("private key block",          re.compile(r"-----BEGIN (?:RSA |EC |DSA |PGP |OPENSSH )?PRIVATE KEY-----")),
    ("JSON Web Token",             re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("basic-auth URL",             re.compile(r"https?://[^/\s:@]+:[^/\s:@]{3,}@[^/\s]+")),
]


def mask(secret: str) -> str:
    """A safe fingerprint: never the secret. A short prefix so a human recognises which key, the
    length, and a 4-char tail — not enough to reconstruct it."""
    s = secret.strip()
    if len(s) <= 12:
        return f"…({len(s)} chars)"
    return f"{s[:6]}…{s[-4:]} ({len(s)} chars)"


def find_secret(text: str) -> tuple[str, str] | None:
    """Return (provider_label, masked_fingerprint) for the FIRST signature that hits, else None.
    The raw secret is never returned — callers cannot accidentally echo it."""
    if not text:
        return None
    for label, pat in SECRET_SIGNATURES:
        m = pat.search(text)
        if m:
            return label, mask(m.group(0))
    return None
