"""Fetch deprecation status and npm download counts for the archived MCP reference servers.

Usage: python scripts/fetch.py > data/snapshot-YYYY-MM-DD.json
Standard library only. npm's daily series sometimes reports whole days as zero; those are gaps, not drops.
"""
import collections
import json
import urllib.parse
import urllib.request

PACKAGES = [
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-brave-search",
    "@circleci/mcp-server-circleci",
]
START, END = "2025-06-01", "2026-11-03"


def get(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)


out = {}
for pkg in PACKAGES:
    meta = get("https://registry.npmjs.org/" + urllib.parse.quote(pkg, safe="@"))
    latest = meta["dist-tags"]["latest"]
    days = get(f"https://api.npmjs.org/downloads/range/{START}:{END}/{pkg}")["downloads"]
    monthly = collections.Counter()
    for d in days:
        monthly[d["day"][:7]] += d["downloads"]
    out[pkg] = {
        "latest": latest,
        "published": meta["time"].get(latest),
        "deprecated": meta["versions"][latest].get("deprecated"),
        "monthly": dict(sorted(monthly.items())),
        "zero_days": [d["day"] for d in days if d["downloads"] == 0],
        "daily": {d["day"]: d["downloads"] for d in days},
    }
print(json.dumps(out, indent=1))
