// Portions adapted from Invariant Labs invariant-analyzer (Apache-2.0, © 2025 Invariant Labs AG),
//   github.com/invariantlabs-ai/invariant @ fa3ece5ee70f86e9d6a95361eaa8c4ff57b365b2
//   (invariant/analyzer/runtime/utils/secrets.py). Modified by the gawk platform: ported the
//   pattern data only, translated to TypeScript/RegExp and gawk's own named-marker convention
//   (matching `packages/verify/src/checks.ts`'s SECRET_MARKERS shape). No cloud-egress paths
//   existed in this file to remove. See THIRD_PARTY_LICENSES.md.
// SPDX-License-Identifier: Apache-2.0
/**
 * Structured secret-detection patterns, ported from Invariant's `secrets.py`.
 *
 * Upstream credits its own patterns to https://github.com/Yelp/detect-secrets (also permissively
 * licensed). The value over gawk's prior list is the CONTEXTUAL pattern below — the AWS generic
 * secret only fires near a key/token/password keyword, unlike a bare 40-char-base64 regex alone.
 */
export const INVARIANT_SECRET_MARKERS = [
    // GitHub tokens, full prefix set (upstream is broader than a ghp_-only pattern).
    { name: "github-token", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b/ },
    // AWS access key ID, all known prefixes.
    { name: "aws-access-key", re: /\b(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[0-9A-Z]{16}\b/ },
    // AWS generic secret — CONTEXTUAL: only matches near a key/pwd/password/pass/token keyword.
    {
        name: "aws-generic-secret",
        re: /aws.{0,20}?(?:key|pwd|pw|password|pass|token).{0,20}?['"]([0-9a-zA-Z/+]{40})['"]/i,
    },
    // Azure storage account key.
    { name: "azure-storage-key", re: /AccountKey=[a-zA-Z0-9+/=]{88}/ },
    // Slack tokens and incoming-webhook URLs.
    { name: "slack-token", re: /\bxox(?:a|b|p|o|s|r)-(?:\d+-)+[a-z0-9]+\b/i },
    {
        name: "slack-webhook-url",
        re: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/i,
    },
];
//# sourceMappingURL=invariant-secrets.js.map