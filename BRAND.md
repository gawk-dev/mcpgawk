# mcpgawk — brand spec (Nativerse / gawk.dev family)

mcpgawk is a **gawk.dev-family** open tool under **Nativerse Ventures**. Its identity inherits the Nativerse
system — it does **not** invent its own. (The legacy "gawk black/teal" is superseded by the royal-blue convergence.)

## Palette (locked to Nativerse tokens — `nativerse-site/styles.css`)
| Token | Hex | Use |
|---|---|---|
| Surface (dark) | `#16160F` | product / social / OG background — the family is dark on these surfaces |
| Accent — royal blue | `#2A33C2` | the **only** brand accent (`--blue`) |
| Blue strong | `#1F2799` | pressed / deeper accent (`--blue-strong`) |
| Accent on dark | `#7B83F0` | same hue lightened for legibility on `#16160F` |
| Status — live/open | `#36C28B` | semantic green only (the `●` status dot; "clean / scanned / open") |
| Ink | `#16160F` on light; near-white `#ECEBE3` on dark | text |
| Rules | hairline grey | dividers only |

One accent. Semantic green for status only. Hairline rules. Generous whitespace. Editorial restraint.

## Type (the family stack — Fontshare)
- **Wordmark & display:** **Sentient** (`--font-display`, serif) — the lowercase `mcpgawk` wordmark is set in
  Sentient, exactly like the parent `nativerse` wordmark, so it sits flush in the family. **Not monospace.**
  (Raw mono for the name read out of place next to the Sentient-led family — corrected.)
- **Text/UI:** **Supreme** (`--font-text`, geometric sans).
- **Data/proof/kickers:** **Tabular** (`--font-mono`) — this is where mono lives: the scan output, numbers,
  labels. Reserved for data, never the name.

## Mark
- **Primary mark = the real Nativerse interlocking-N hex-shield** (`assets/brand/nativerse-mark.svg`, single
  fill `#2A33C2`). Per family rule: **recoloured white on dark surfaces**, `#2A33C2` on light.
- **Lockup** = mark + `mcpgawk` Sentient wordmark (horizontal). Wordmark-led (Linear/Stripe/Vercel discipline).
- **Favicon / avatar** = the white mark on a `#2A33C2` tile (the documented family avatar).
- The CLI's `●` status dot (green `#36C28B`) stays as an in-product motif in data contexts — not the logo.

## Lockups needed
1. Wordmark `● mcpgawk` — light-on-dark (primary, product surfaces) + dark-on-white (docs).
2. Favicon — the `●` dot.
3. GitHub social preview (1280×640) — dark surface, `● mcpgawk`, one-line promise, hairline rule.

## Production note (before push)
The `wordmark-*.svg` and `social-preview.svg` reference **Sentient**, which loads on the site but **not** in
GitHub's README `<img>` sandbox or on PyPI (they'll show the serif fallback). For pixel-true assets, render
them through the family pipeline — `~/nativerse-site/brand/logo/render-lockups.sh` bakes Sentient in — and
commit the resulting **PNGs** (plus a `.png` social preview, which GitHub's social-preview upload requires).
Until then the SVGs are correct in direction (real mark + serif wordmark), just not the exact face on GitHub.

## Voice
Precise, honest, terminal-native, no hype. "gawk at it before you trust it." Trust through reproducibility,
never adjectives.
