// GENERATED FROM src/mcpgawk/secret_corpus.py — DO NOT EDIT BY HAND.
//
// Regenerate with:  .venv/bin/python scripts/gen_secret_signatures_ts.py
//
// These are the provider signatures the DETECTOR knows. The redactor must mask everything the
// detector can name — it may mask more, never less. Python enforces that by importing the corpus
// directly; TypeScript cannot, so it is generated from the same one definition instead of
// hand-copied. A copied list drifts the day somebody adds a provider, which is exactly how an AWS
// temporary credential came to be detected, reported as a hardcoded secret, and then printed
// verbatim (2026-09-11).
//
// tests/test_secret_signatures_are_generated_not_copied.py fails the build when this file is stale.
export const SECRET_SIGNATURES = [
    // AWS access key id
    /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    // Google API key
    /\bAIza[0-9A-Za-z_\-]{35}\b/g,
    // Google OAuth client secret
    /\bGOCSPX-[A-Za-z0-9_\-]{28}\b/g,
    // Google OAuth access token
    /\bya29\.[0-9A-Za-z_\-]{20,}/g,
    // GCP service-account JSON
    /\"type\"\s*:\s*\"service_account\"/g,
    // Azure storage AccountKey
    /AccountKey=[A-Za-z0-9+\/]{86}==/g,
    // DigitalOcean token
    /\bdop_v1_[a-f0-9]{64}\b/g,
    // HashiCorp Vault token
    /\bhvs\.[A-Za-z0-9_\-]{90,120}\b/g,
    // GitHub token
    /\bgh[posur]_[A-Za-z0-9]{36,}\b/g,
    // GitHub fine-grained PAT
    /\bgithub_pat_[A-Za-z0-9_]{82}\b/g,
    // GitLab PAT
    /\bglpat-[A-Za-z0-9_\-]{20}\b/g,
    // npm token
    /\bnpm_[A-Za-z0-9]{36}\b/g,
    // PyPI token
    /\bpypi-AgEN[A-Za-z0-9_\-]{40,}/g,
    // Docker Hub PAT
    /\bdckr_pat_[A-Za-z0-9_\-]{27,}\b/g,
    // RubyGems key
    /\brubygems_[a-f0-9]{48}\b/g,
    // JFrog API key
    /\bAKCp[A-Za-z0-9]{50,70}\b/g,
    // Terraform Cloud token
    /\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-=]{60,70}\b/g,
    // Postman API key
    /\bPMAK-[A-Za-z0-9]{24,64}\b/g,
    // Anthropic API key
    /\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93,}/g,
    // OpenAI project key
    /\bsk-proj-[A-Za-z0-9_\-]{40,}/g,
    // OpenAI key
    /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g,
    // HuggingFace token
    /\bhf_[A-Za-z0-9]{30,}\b/g,
    // Stripe live secret key
    /\bsk_live_[0-9A-Za-z]{24,}\b/g,
    // Stripe test secret key
    /\bsk_test_[0-9A-Za-z]{24,}\b/g,
    // Square access token
    /\bsq0atp-[0-9A-Za-z\-_]{22}\b/g,
    // Square OAuth secret
    /\bsq0csp-[0-9A-Za-z\-_]{43}\b/g,
    // Shopify access token
    /\bshpat_[a-fA-F0-9]{32}\b/g,
    // Shopify shared secret
    /\bshpss_[a-fA-F0-9]{32}\b/g,
    // Slack token
    /\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b/g,
    // Slack app-level token
    /\bxapp-1-[A-Za-z0-9\-]{20,}/g,
    // Slack webhook
    /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    // SendGrid key
    /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/g,
    // Twilio API key
    /\bSK[0-9a-fA-F]{32}\b/g,
    // Discord bot token
    /\b[MN][A-Za-z0-9]{23}\.[\w\-]{6}\.[\w\-]{27}\b/g,
    // Telegram bot token
    /\b\d{8,10}:[A-Za-z0-9_\-]{35}\b/g,
    // Facebook access token
    /\bEAA[A-Za-z0-9]{90,}/g,
    // Linear API key
    /\blin_api_[A-Za-z0-9]{40}\b/g,
    // Databricks PAT
    /\bdapi[0-9a-f]{32}(?:-\d)?\b/g,
    // Doppler token
    /\bdp\.pt\.[A-Za-z0-9]{40,44}\b/g,
    // Dropbox short-lived token
    /\bsl\.[A-Za-z0-9_\-]{130,140}\b/g,
    // Grafana Cloud token
    /\bglc_[A-Za-z0-9+\/]{32,}={0,2}\b/g,
    // New Relic key
    /\b(?:NRAA|NRAK|NRBR)-[A-F0-9]{27}\b/g,
    // Sentry DSN
    /https:\/\/[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io\/[0-9]+/g,
    // private key block
    /-----BEGIN (?:RSA |EC |DSA |PGP |OPENSSH )?PRIVATE KEY-----/g,
    // JSON Web Token
    /\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g,
    // basic-auth URL
    /https?:\/\/[^\/\s:@]+:[^\/\s:@]{3,}@[^\/\s]+/g,
];
//# sourceMappingURL=secret-signatures.js.map