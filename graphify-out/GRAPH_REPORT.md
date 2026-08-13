# Graph Report - .  (2026-08-13)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 2406 nodes · 4408 edges · 139 communities (122 shown, 17 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 120 edges (avg confidence: 0.67)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `f2978b6e`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- Community 0
- Community 1
- Community 2
- Community 3
- Community 4
- Community 5
- Community 6
- Community 7
- Community 8
- Community 9
- Community 10
- Community 11
- Community 12
- Community 13
- Community 14
- Community 15
- Community 16
- Community 17
- Community 18
- Community 19
- Community 20
- Community 21
- Community 22
- Community 23
- Community 24
- Community 25
- Community 26
- Community 27
- Community 28
- Community 29
- Community 30
- Community 31
- Community 32
- Community 33
- Community 34
- Community 35
- Community 36
- Community 37
- Community 38
- Community 39
- Community 40
- Community 41
- Community 42
- Community 43
- Community 44
- Community 45
- Community 46
- Community 47
- Community 48
- Community 49
- Community 50
- Community 51
- Community 52
- Community 53
- Community 54
- Community 55
- Community 56
- Community 57
- Community 58
- Community 59
- Community 60
- Community 61
- Community 62
- Community 63
- Community 64
- Community 65
- Community 66
- Community 67
- Community 68
- Community 69
- Community 70
- Community 71
- Community 72
- Community 73
- Community 74
- Community 75
- Community 76
- Community 77
- Community 78
- Community 79
- Community 80
- Community 81
- Community 82
- Community 83
- Community 84
- Community 85
- Community 86
- Community 87
- Community 88
- Community 89
- Community 90
- Community 91
- Community 92
- Community 93
- Community 94
- Community 95
- Community 96
- Community 97
- Community 98
- Community 99
- Community 100
- Community 101
- Community 102
- Community 103
- Community 104
- Community 105
- Community 106
- Community 107
- Community 108
- Community 109
- Community 110
- Community 111
- Community 112
- Community 113
- Community 114
- Community 115
- Community 116
- Community 117
- Community 118
- Community 119
- Community 120
- Community 121
- Community 122
- Community 123
- Community 124
- Community 125
- Community 126
- Community 127
- Community 128
- Community 129
- Community 130
- Community 131
- Community 132
- Community 133
- Community 134
- Community 135
- Community 136

## God Nodes (most connected - your core abstractions)
1. `ServerSnapshot` - 79 edges
2. `_dispatch()` - 47 edges
3. `_write()` - 40 edges
4. `measure()` - 36 edges
5. `_rec()` - 34 edges
6. `discover_servers()` - 30 edges
7. `render()` - 29 edges
8. `_discover()` - 28 edges
9. `_snap()` - 27 edges
10. `Changelog` - 25 edges

## Surprising Connections (you probably didn't know these)
- `test_a_capable_machine_is_not_nagged_about_degradation()` --calls--> `collect_and_render()`  [INFERRED]
  tests/test_first_run.py → src/mcpgawk/status.py
- `_fp_of()` --calls--> `fingerprint()`  [INFERRED]
  tests/test_credential_identity.py → src/mcpgawk/credentials.py
- `test_kimi_servers_are_discovered()` --calls--> `discover_servers()`  [INFERRED]
  tests/test_agents_multi.py → src/mcpgawk/discover.py
- `test_missing_or_corrupt_store_defers()` --calls--> `decide()`  [EXTRACTED]
  tests/test_guard.py → src/mcpgawk/guard_hook.py
- `test_no_risk_score_in_v1()` --calls--> `build_label()`  [INFERRED]
  tests/test_measure.py → src/mcpgawk/label.py

## Import Cycles
- None detected.

## Communities (139 total, 17 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.05
Nodes (62): _gemini_adapter(), _kimi_adapter(), CompletedProcess, parametrize, Path, Multi-agent adapters — Cursor and Codex, over the SAME decision core. `status`…, THE one that matters. Cursor ALLOWS the call when a hook errors unless…, VS Code and Claude Desktop genuinely cannot block a call. Saying nothing would… (+54 more)

### Community 1 - "Community 1"
Cohesion: 0.06
Nodes (58): Connection, PathLike, Row, _behaviour_tool_count(), _front_door_verify(), main(), What this scan was pointed at, for the run log's `target` column. A fleet scan…, Entry point. Wraps the real dispatch in a run-log record so `mcpgawk runs` can… (+50 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (47): _act(), _c(), _fail(), _note(), CompletedProcess, Path, `mcpgawk demo` — the whole story in a throwaway sandbox, offline, in seconds. A…, A directory of redirected state and the env that points every mcpgawk path at… (+39 more)

### Community 3 - "Community 3"
Cohesion: 0.09
Nodes (55): _guard_is_installed(), Best-effort: never let a status probe break a completed scan., _atomic_write(), _backup(), configured_commands(), _cursor_install(), _gemini_install(), GuardError (+47 more)

### Community 4 - "Community 4"
Cohesion: 0.08
Nodes (35): Enum, Protocol, _is_path(), Redact absolute file paths (Unix, Windows, `~/`) in a string, preserving…, Redact values of flag-style arguments and bare filesystem paths — ours,…, redact_absolute_paths(), redact_command_args(), Evidence (+27 more)

### Community 5 - "Community 5"
Cohesion: 0.06
Nodes (43): _discovery_problems(), _headers(), _label_for(), _load_config(), _NoMatchingServers, _offer_batched_auth(), Exception, mcpgawk CLI — one command, zero config. mcpgawk scan <mcp.json> [--only a,b]… (+35 more)

### Community 6 - "Community 6"
Cohesion: 0.12
Nodes (37): _discover(), Path, SCAN / Discovery — zero-config discovery of MCP servers across IDE clients.…, Same URL, different bearer token = a different account's data. Deduped on the…, The other direction, so the split above is not just 'never dedup a remote…, Same binary, different credentials is a DIFFERENT server. Two GitHub orgs, two…, The docs show a list; real files are commonly a map. Picking one would silently…, The other half — dedup must keep working, or every multi-client user gets… (+29 more)

### Community 7 - "Community 7"
Cohesion: 0.06
Nodes (19): _age_and_orphan(), db(), _dead_pid(), fixture, The run registry — the seam that makes a cross-pillar timeline possible. Its…, A slow verify on a loaded machine must not be mislabelled while it is still…, The unfinished one is exactly the run worth keeping., Two pillars running at once is the normal case, not an edge case. (+11 more)

### Community 8 - "Community 8"
Cohesion: 0.07
Nodes (32): The last line the server printed that looks like a real message. Only consulted…, _stderr_tail(), build_app(), build_server(), main(), Server, Starlette, The SAME toy MCP server as toy_mcp_server.py, served over a REAL HTTP… (+24 more)

### Community 9 - "Community 9"
Cohesion: 0.09
Nodes (33): _live_server(), _post(), _post_full(), parametrize, `mcpgawk decide` — the free tier's only UI, and the one screen a human is…, Found in real use: a curl to /decide returned the FULL page — 60 lines of CSS…, THE gate, tested against the SERVER. Without it an agent approves its own…, The gate above is worthless if the page hands the token to whoever asks for it.… (+25 more)

### Community 10 - "Community 10"
Cohesion: 0.10
Nodes (34): _mark_muted_findings(), Stamp `muted: True` onto every bounded signal the human has recorded as wrong…, append(), identity_change(), InvalidServerKey, _mask_ident(), _may_adopt(), _migrate() (+26 more)

### Community 11 - "Community 11"
Cohesion: 0.11
Nodes (34): approved_for(), `{tool: hash}` approved for this server, or None when nothing has been approved…, _fp_of(), Path, Same server, two logins: approving one must never approve the other. The bug…, R5. The key lands in history.json and in the guard projection, both on disk. It…, A per-run salt would re-identify every server on every scan — a drift alarm…, Upgrade path. A pre-upgrade store has ONE conflated record under… (+26 more)

### Community 12 - "Community 12"
Cohesion: 0.10
Nodes (35): _action_banner(), _action_buttons(), _agent_rows(), _esc(), _fixblock(), _gateway_pane(), gateway_tools(), _issue_key_form() (+27 more)

### Community 13 - "Community 13"
Cohesion: 0.07
Nodes (19): Popen, Panel, fixture, Path, E2E: the panel driven as a customer drives it — a separate process, over plain…, Scan 1, from the terminal, exactly as the beta flow has the tester do it., Scan/verify run behind a 303 in a background thread — poll the STORE, not the…, The untokened page shows state but carries no controls and no token — the… (+11 more)

### Community 14 - "Community 14"
Cohesion: 0.11
Nodes (31): behavioural_checking(), Can THIS machine actually run behavioural checking? — asked, answered, never…, (available, what is missing). Available means both halves of the free…, _download(), find_node(), install_hint(), install_node(), Path (+23 more)

### Community 15 - "Community 15"
Cohesion: 0.10
Nodes (30): One stderr line when this install is stale (journey plan: every run, cached,…, _staleness_advisory(), advisory(), _cache_path(), _latest(), _parse(), Is THIS install stale? — the check the journey plan requires on every run. The…, Newest published version, through the cache. Any failure is cached as a MISS… (+22 more)

### Community 16 - "Community 16"
Cohesion: 0.12
Nodes (31): _count(), _encoder(), _exfil_capable(), _is_write(), measure(), Any, BOUND — measure a snapshot. Pure, offline, deterministic. The…, create" -> "creates", "modify" -> "modifies", "patch" -> "patches". English,… (+23 more)

### Community 17 - "Community 17"
Cohesion: 0.07
Nodes (32): _action_store(), _connect_card(), declared_vs_observed(), _esc_attr(), _fchip(), _foldnote(), load_last_action(), _now() (+24 more)

### Community 18 - "Community 18"
Cohesion: 0.07
Nodes (23): detect(), Run the BOUNDED detectors over the injection surface: tool AND prompt…, _fire_covert_recipient(), _fire_cross_server_reference(), _fire_dynamic_dispatch(), _fire_hidden_markup(), _fire_hidden_unicode(), _fire_reader_directed() (+15 more)

### Community 19 - "Community 19"
Cohesion: 0.10
Nodes (31): detect_unscannable(), _drop_trailing_commas(), _extract(), _identity(), _is_disabled(), _normalise_entry(), project_dirs(), Any (+23 more)

### Community 20 - "Community 20"
Cohesion: 0.12
Nodes (29): cost_phrase(), _cost_score(), Grade, _is_annotated(), _is_underdocumented(), _letter(), A transparent CRAFT grade for an MCP server. Design (accuracy-critical, see…, tokens/tool -> 0-100. Piecewise-linear bands fit to the roster (Cloudflare… (+21 more)

### Community 21 - "Community 21"
Cohesion: 0.09
Nodes (30): main(), A fixture server that puts a CREDENTIAL-SHAPED value in every server-controlled…, _call(), _handler(), _list_tools(), fixture, mcpgawk as an MCP server — the surface every agent (and Zed) reaches it…, Tool descriptions are model-visible text — the exact surface this product scans… (+22 more)

### Community 22 - "Community 22"
Cohesion: 0.09
Nodes (27): _event(), CompletedProcess, Path, The runtime evidence spool — every decision the agent hook makes. Closes the…, Same mislabelling class as Cursor: each agent's decisions must carry its own…, The default format records the adapter registry key, so spool rows line up with…, The hook only judges MCP calls; logging a Bash or Edit call would be…, Two agent sessions run at once routinely. O_APPEND makes a record this size… (+19 more)

### Community 23 - "Community 23"
Cohesion: 0.14
Nodes (28): discover_skills(), _find_skill_md(), parse_skill(), Path, Deterministic bounded walk — depth/count enforcement happens in parse_skill., One skill directory → snapshot + findings. Never raises: unreadable/unparseable…, Find and parse every skill. `explicit_paths` entries may be: a skill directory…, _sha256() (+20 more)

### Community 24 - "Community 24"
Cohesion: 0.10
Nodes (30): `transport:name` identity meant renaming a server in mcp.json started a fresh…, ADR-0012 persists description TEXT so the user can be shown what changed.…, A sticky alarm with no way to clear it is worse than no alarm: the user…, The quoted span is server-controlled text. Unbounded, a server could push the…, `approve --all` is what a frustrated team runs to clear a red pipeline, and a…, The other half. If everything is an attack, nothing is — and the alarm gets…, The half that was missing, and it is the half a user reads. `hostile` was…, The failure this guards is a FLEET-WIDE false alarm. If a future version… (+22 more)

### Community 25 - "Community 25"
Cohesion: 0.07
Nodes (18): CompletedProcess, Path, `mcpgawk guard` — the PreToolUse hook that puts the approved baseline in the…, guard_hook cannot import the package, so PROJECTION_NAME is repeated there. Pin…, Never non-zero: a non-zero PreToolUse exit is an error condition, and our own…, The hot path runs on EVERY MCP tool call. Importing the package pulls the MCP…, guard_hook re-reads history.json instead of importing mcpgawk.baseline, for…, Eval 1.6, driven through the hook itself rather than the renderer. A call the… (+10 more)

### Community 26 - "Community 26"
Cohesion: 0.07
Nodes (25): Also, Contributing to mcpgawk, Dev setup, The two invariants, CI gate — GitHub Action, Contributing, Develop, Features (+17 more)

### Community 27 - "Community 27"
Cohesion: 0.09
Nodes (27): adapter_for(), AgentAdapter, _deny_claude(), _deny_cursor(), _deny_gemini(), _deny_kimi(), deny_payload(), _deny_windsurf() (+19 more)

### Community 28 - "Community 28"
Cohesion: 0.12
Nodes (26): BaseException, ClientSession, _bounded(), _dump(), _kind_of(), _no_redirect_http_client(), probe_http(), probe_sse() (+18 more)

### Community 29 - "Community 29"
Cohesion: 0.11
Nodes (27): approved_for_detail(), _approved_from_projection(), behaviour_path(), history_path(), _load_behaviour(), _load_sibling(), main(), parse_mcp_tool_name() (+19 more)

### Community 30 - "Community 30"
Cohesion: 0.09
Nodes (28): behaviour_profile_path(), _build_identity(), _ensure_role(), finding_timeline(), gateway_roles(), gateway_status(), _merge_verify_report(), monitor_status() (+20 more)

### Community 31 - "Community 31"
Cohesion: 0.12
Nodes (27): detect_dynamic_dispatch(), detect_shadowing(), Signal: this server's tools/list likely hides a larger real catalog behind a…, CROSS-SERVER signal: a tool name exposed by more than one server. All connected…, _fire_shadowing(), _pair(), BOUNDED signal discipline: 0 false positives on legit tools, real detection on…, The whole FP control. Real inventories contain tools called `sum`, `search`,… (+19 more)

### Community 32 - "Community 32"
Cohesion: 0.13
Nodes (23): AmbientExposure, detect_ambient(), Path, AMBIENT CREDENTIALS — what a launched server inherits that nobody declared.…, What a stdio server launched from here would inherit., Enumerate inheritable credential sources. Pure and injectable, so it is…, Report lines, or [] when there is nothing worth saying. Deliberately…, summarize() (+15 more)

### Community 33 - "Community 33"
Cohesion: 0.13
Nodes (27): decide(), (hook output or None to defer, stderr note or None)., The full decision including WHICH BASIS produced it, so the record carries the…, _approved(), The enforcing reader must not fail open in silence. `drift.compare` refuses a…, Two approved servers sharing an alias must not be resolved by iteration order.…, The fail-open the CLI route produced, found by driving it. The store keys a…, A server approved under its asserted identity must still match the config name… (+19 more)

### Community 34 - "Community 34"
Cohesion: 0.11
Nodes (26): export_log_jsonl(), The raw append-only log, verbatim — the same bytes `cat ~/.mcpgawk/calls.jsonl`…, append(), note_failure(), The runtime evidence spool — every decision the agent hook makes, appended.…, Mask credential shapes in one spool record, on the way to disk. Returns a NEW…, Append one decision. Returns True if written. NEVER raises. This runs inside a…, Prose redaction for the recorder's own failure note. Same dual-context loader… (+18 more)

### Community 35 - "Community 35"
Cohesion: 0.08
Nodes (25): @gawk/oracle, @gawk/sandbox, @modelcontextprotocol/sdk, dist, bin, gawk-verify, dependencies, @gawk/oracle (+17 more)

### Community 36 - "Community 36"
Cohesion: 0.14
Nodes (25): as_authenticated_remote(), auth_needed(), _auth_needed_path(), consent_text(), has_stored_login(), login_url(), Any, Path (+17 more)

### Community 37 - "Community 37"
Cohesion: 0.10
Nodes (24): _free_and_paid_modules(), The walls between layers, enforced by CI instead of by docstring. Written…, Every production module in both packages, parsed from source (not imported):…, `history.json` has ONE owner. This repo carried five readers of the store and…, The hook's freshness check may `os.stat` the store; it must never read or parse…, Statements that execute at IMPORT time: module body, descending into top-level…, Package-wide, not per-module: a free install has no `gawk_platform` on disk…, cli.py is the deliberate seam: the licence gate hands over to… (+16 more)

### Community 38 - "Community 38"
Cohesion: 0.09
Nodes (23): fixture, parametrize, Path, Every server-controlled field that reaches `history.json` is masked — measured,…, A rot check that enumerates the property, not one caller: `save` is the…, The store on disk after a real `scan --track` against the canary server., Masked, not destroyed. Over-redaction would break the feature the store exists…, The risk this fix introduces: the item key IS the identity drift compares on,… (+15 more)

### Community 39 - "Community 39"
Cohesion: 0.13
Nodes (22): _assignment_value_looks_like_a_credential(), _credential_line(), _deobfuscate(), detect_cross_server_reference(), detect_skill_malformed(), Finding, _is_public_ip(), _looks_like_placeholder() (+14 more)

### Community 40 - "Community 40"
Cohesion: 0.13
Nodes (15): BaseHTTPRequestHandler, _DecideServer, _diff_block(), _esc(), _Handler, Any, `mcpgawk decide` — the one screen a human is actually required for. WHY A UI AT…, The whole UI. One file, no assets, no network — it must work on a machine with… (+7 more)

### Community 41 - "Community 41"
Cohesion: 0.15
Nodes (23): export(), publish(), The whole approved baseline, in the shape other runtimes read. Only APPROVED…, Write an approval INTO the spine from another pillar. The read path (`export`)…, Map a name the user typed to the key the baseline is stored under. A server's…, resolve(), _approve(), _baseline() (+15 more)

### Community 42 - "Community 42"
Cohesion: 0.14
Nodes (21): explain(), is_extension(), _launch_strings(), Any, Claude Desktop EXTENSION servers — what their manifest variables mean, and what…, Was this server declared by a Claude Desktop extension manifest?, The placeholders we cannot fill, in the order they appear. Empty means…, A launchable copy of this entry, or None when it honestly cannot be launched.… (+13 more)

### Community 43 - "Community 43"
Cohesion: 0.18
Nodes (21): _graded(), Two gaps found by putting this scanner side by side with a general-purpose…, The case that matters most, and the one the first cut of this fix missed.…, It must NOT live in signals.py. That module fires only on language aimed at the…, Adding it to the grade would shift every existing letter, making "we improved…, The upstream bug. `place_order` was not classified as changing data, so a…, _snap(), test_a_dangling_entry_is_not_launched_and_is_typed() (+13 more)

### Community 44 - "Community 44"
Cohesion: 0.10
Nodes (21): discover_servers(), Find every scannable MCP server configured on this machine, deduped by launch…, test_kimi_servers_are_discovered(), REGRESSION (found live): ~/.claude.json holds servers in TWO places — top-level…, Codex is the one client that keeps its config in TOML. Its servers were…, Extensions are a separate install channel — they are NEVER written into…, Attribution is what lets the fleet view group by IDE — and what tells a user…, Anthropic ships an official Linux build but documents no config path. Reading… (+13 more)

### Community 45 - "Community 45"
Cohesion: 0.10
Nodes (11): `mcpgawk` (bare) — the front door, and the consent decision behind it. The…, Absence of a finding must never read as a clean bill of health., The framing IS the argument: these servers are already in the agent's config,…, Returning None (not a default) is the point: the caller then degrades to…, Anything we cannot read must not authorise launching code. The same default-…, Bumping CONSENT_VERSION must invalidate stored consent. A tool that carries…, test_a_non_interactive_run_never_invents_a_decision(), test_an_answer_to_a_DIFFERENT_question_is_not_reused() (+3 more)

### Community 46 - "Community 46"
Cohesion: 0.11
Nodes (19): _behavioural_capability_note(), _dispatch(), B5 — never a silent fallback: a scan on a machine that cannot run behavioural…, Delegate an account command to gawk Platform, or explain honestly that it isn't…, Delegate a non-pillar Platform command, or explain honestly that it isn't here.…, Delegate to gawk Platform if it is installed, else say so honestly and exit 3.…, _run_account_command(), _run_platform_capability() (+11 more)

### Community 47 - "Community 47"
Cohesion: 0.11
Nodes (17): problem_lines(), Human lines for every source that existed but could not be fully used — the…, collect(), export_findings_csv(), first_party(), _identity_tokens(), Everything the panel shows, gathered from the owning modules. Each probe is…, Every finding, spreadsheet-shaped — the same rows the Findings screen shows,… (+9 more)

### Community 48 - "Community 48"
Cohesion: 0.12
Nodes (10): DriftReport, What the new description GAINED, if the change was purely additive. The common…, What the description LOST. A rug-pull does not have to add an instruction —…, Tokenise into words AND the whitespace between them, so a diff over the tokens…, Is the protocol move a FORWARD spec upgrade — i.e. the server adopting a newer…, Annotation changes that WIDEN what the model will permit. Not every hint change…, Split the typed `{kind}.{name}` keys back out for rendering., Mark the changes whose INSERTED text trips the injection detectors. Reuses… (+2 more)

### Community 49 - "Community 49"
Cohesion: 0.19
Nodes (18): Wrap to a terminal-safe width with a hanging indent. Prose has to wrap or the…, render_cli(), _wrap(), test_kind_renders_as_itself_not_as_prompt_injection(), _label(), The 5-axis report: top_heavy_tools / trust_surface / annotation_completeness /…, Security-tool cardinal sin: a scan that FAILED must never read as CLEAN / all-…, _snap() (+10 more)

### Community 50 - "Community 50"
Cohesion: 0.11
Nodes (17): no_platform(), fixture, parametrize, What a FREE install does when someone types a paid capability. Public-safe by…, The help said 'Read-only — every action lives in `mcpgawk decide`' long after…, Simulate a free-only install even when the paid engine happens to be importable., A free user should SEE what the subscription adds without installing anything., An ImportError reaching the user is the failure mode this replaced. (+9 more)

### Community 51 - "Community 51"
Cohesion: 0.15
Nodes (18): clicks(), _free_port(), oauth_base(), fixture, The `--login` OAuth round-trip, driven for real against a real authorization…, Exactly what `mcpgawk scan --http <url> --login` does: build the provider,…, The whole point: after signing in, the server is MEASURED — not merely…, Sign in ONCE. A tool that re-prompts on every scan is one people stop running. (+10 more)

### Community 52 - "Community 52"
Cohesion: 0.17
Nodes (10): HTTPServer, OAuthClientInformationFull, OAuthClientProvider, OAuthToken, build_login_provider(), FileTokenStorage, `gawk scan --login` — trigger the OAuth login for a remote MCP server,…, Construct an OAuthClientProvider that opens the system browser for approval and… (+2 more)

### Community 53 - "Community 53"
Cohesion: 0.16
Nodes (17): build_rows(), parse_auth_selection(), Any, The fleet view — one screen for every MCP server on the machine. MCP is a fleet…, A server we deliberately did NOT scan (consent withheld) must still be VISIBLE.…, A capability that exists but that no local scan can reach. Listed, never…, `entries` carries the config each server came from — the auth step needs the…, Parse the batched auth answer into 0-based indices. Accepts 'all', 'a',… (+9 more)

### Community 54 - "Community 54"
Cohesion: 0.20
Nodes (16): _b64url_decode(), _bearer_token(), inspect(), Any, OAUTH SCOPES — opt-in, local-only inspection of a user-supplied bearer token.…, None if there's no bearer token to inspect at all., _jwt(), OAuth-scopes opt-in check — pure local decode, no network, no signature… (+8 more)

### Community 55 - "Community 55"
Cohesion: 0.14
Nodes (18): _clean(), _poisoned(), Redaction must preserve SHAPE, not erase the evidence — the whole point of…, An attacker who can make a server fail to probe must not thereby erase the…, Already holds — pinned here because a false drift alarm from a dependency…, A history file written before ADR-0012 has no `texts`. The report must still…, THE invariant. Before ADR-0012 a rug-pull was reported exactly ONCE: the…, Back-compat must not become blindness: the surfaces the old record DID cover… (+10 more)

### Community 56 - "Community 56"
Cohesion: 0.16
Nodes (15): _capture_run(), _no_real_home(), fixture, parametrize, The front door runs behavioural verification by default — and degrades…, HANDOFF 38c: this path printed "in the sandbox" for weeks while nothing ever…, Stub the engine; capture the synthesised config it was handed., test_completed_run_reports_the_real_observed_count() (+7 more)

### Community 57 - "Community 57"
Cohesion: 0.15
Nodes (16): everything, fetch, filesystem, git, memory, sequential-thinking, time, npx (+8 more)

### Community 58 - "Community 58"
Cohesion: 0.15
Nodes (16): The one sentence every surface shares, or None when behavioural checking can…, unavailable_line(), agents_on_this_machine(), collect_and_render(), _hook_capable(), hook_health_by_client(), _label(), Any (+8 more)

### Community 59 - "Community 59"
Cohesion: 0.17
Nodes (8): _group_or_other_bits(), _mode(), One user's local state must not be readable by other users on the machine.…, A 'secure default' that relaxes someone's deliberate 0400 is a downgrade…, -wal and -shm carry the same rows mid-transaction; protecting only the main…, The property that matters. A helper nobody calls is the bug this replaces., TestTheHelper, TestTheStoresActuallyUseIt

### Community 60 - "Community 60"
Cohesion: 0.12
Nodes (16): config(), fixture, Path, A credential in a configured URL must not reach any surface. Measured, not…, A rot check that enumerates the WRITERS, not just the one in front of it.…, A pasted key is not a URL — and the panel takes pasted keys. The 2026-08-13…, The single string every failure surface echoes. Masked here, masked everywhere…, The rendered report — text AND json — for a server that could not be reached,… (+8 more)

### Community 61 - "Community 61"
Cohesion: 0.17
Nodes (15): annotations_recorded(), approved_annotations(), approved_pin(), approved_record(), approved_tools(), Any, The one answer to "what did this server look like when I trusted it". The…, # NOTE: `signals` is deliberately CARRIED FORWARD by the spread above, not… (+7 more)

### Community 62 - "Community 62"
Cohesion: 0.12
Nodes (15): _consent_agents(), _protect(), The client names behind the discovered fleet, for the consent question. Reads…, `mcpgawk wrong` — design-contract item 4, the false-positive affordance. Same…, Bare `mcpgawk` — find the fleet, ask once, scan, turn runtime checking on,…, _wrong(), approval_blocked_reason(), ApprovalBlocked (+7 more)

### Community 63 - "Community 63"
Cohesion: 0.18
Nodes (15): Scan agent skills. Local-only by construction: skills.py has no network imports…, _skills(), build_server(), _label_of(), main(), Any, Server, mcpgawk AS an MCP server — so any agent can audit the MCP servers it is sitting… (+7 more)

### Community 64 - "Community 64"
Cohesion: 0.16
Nodes (16): build_record(), _hash(), _item_annotations(), _item_hashes(), _item_props(), _item_schemas(), _item_texts(), _iter_items() (+8 more)

### Community 65 - "Community 65"
Cohesion: 0.26
Nodes (15): compare(), None if there's no prior record (first sighting — nothing to drift from)., Drift / rug-pull detection: no drift on identical, real detection on…, CONTRACT CHANGED 2026-07-30, deliberately: this asserted that ANY protocol move…, The migration half: a nameless server recorded over stdio then seen over http…, _rec(), test_a_record_predating_transport_storage_does_not_false_alarm(), test_detects_added_and_removed() (+7 more)

### Community 66 - "Community 66"
Cohesion: 0.17
Nodes (15): compare_to_reality(), What the card declares vs what we actually measured., detect_card_mismatch(), Signal: the server's public .well-known card UNDER-DECLARES — hides tools it…, _fire_card_mismatch(), Server Card reader: URL derivation, tolerant parse, card-vs-reality, under-…, SECURITY: the public card fetch must never carry the user's bearer, and must…, _snap() (+7 more)

### Community 67 - "Community 67"
Cohesion: 0.12
Nodes (16): _decoded_blobs(), detect_skill_content(), Skill-specific detectors over ONE file's text. `origin` labels the finding…, Regression from the first live 63-skill run: 127.0.0.1 and the 169.254.169.254…, Regression from the same run: all 64 secret findings were placeholders or…, Second pass on the live corpus: after the placeholder fix, 44 findings remained…, contains_secret() also covers PII; an email address filed under skill:secret-…, Alibaba Cloud's metadata endpoint 100.100.100.200 sits in 100.64.0.0/10 shared… (+8 more)

### Community 68 - "Community 68"
Cohesion: 0.13
Nodes (12): fixture, Path, One baseline, read by every pillar. The product kept three memories of "what…, Identity key and configured name are different strings, and the same server is…, A sighting must never cross the boundary: handing verify the last thing SEEN…, Never approved' and 'approved as empty' must not collapse: the second reports…, `mcpgawk baseline --json` is the contract verify reads. If this shape moves,…, store() (+4 more)

### Community 69 - "Community 69"
Cohesion: 0.12
Nodes (16): The gap this closes: a tool keeps its description word for word and gains an…, A capability escalation: the tool told the agent it only reads, and now it does…, JSON object order is not semantic. A server that serialises its schema…, THE upgrade hazard. Records written before C1 have no schema/annotation…, Keying on the server's asserted name (N4) means a server that CHANGES that name…, Pins the DETECTION primitive both ways: a config entry that now resolves…, `{}` and "no baseline recorded" are different facts. Conflating them would…, test_c1_a_schema_change_with_an_unchanged_description_is_drift() (+8 more)

### Community 70 - "Community 70"
Cohesion: 0.15
Nodes (14): _attempt_lines(), _free_port(), fixture, A REAL 401, over a REAL transport, through the real prober. Why this file…, A 401 ends the permutation. Continuing would hand a supplied credential to…, The negative control: classification changes nothing for a caller that IS…, A real HTTP MCP server that 401s anything without the token. Readiness is the…, Pins the httpx2 arm DIRECTLY, because the end-to-end tests do not. A review… (+6 more)

### Community 71 - "Community 71"
Cohesion: 0.23
Nodes (13): archive(), _mode(), fixture, Path, Every file and directory in the verify run archive is owner-only. Eighth and…, A real verify run through the panel action — the path that builds the archive., `Path.mkdir(mode=…, parents=True)` applies the mode to the final component…, Non-vacuity, and the contract: a permissions fix that emptied the archive would… (+5 more)

### Community 72 - "Community 72"
Cohesion: 0.15
Nodes (13): discover_report(), _locations(), The full answer: (servers, sources) — what was found AND what was looked at.…, $HOME is in Claude Code's own project map on a real machine (found by running…, test_a_broken_project_config_is_reported_like_any_other_source(), test_absent_project_files_do_not_flood_the_report(), test_disabled_entries_are_skipped_and_reported_not_scanned_as_live(), test_discover_servers_wrapper_is_unchanged_by_the_report() (+5 more)

### Community 73 - "Community 73"
Cohesion: 0.24
Nodes (12): as_metadata(), authorize(), build_app(), main(), protected_resource(), Starlette, A real OAuth-protected MCP server: DCR + PKCE + authorization code, over a real…, Dynamic client registration — the client has no pre-issued id, exactly like a… (+4 more)

### Community 74 - "Community 74"
Cohesion: 0.15
Nodes (11): ADR-0012 architectural constraint test — the non-negotiables of the one…, Silently succeeding on a typo would leave the user believing they had approved…, Caught live: a character-level diff matched stray letters from the old…, Drift used to print AFTER the fleet list, under a wall of token counts — the…, Trust-on-first-use was silent, so the most valuable thing a first scan does —…, A moat you have to remember to switch on produces nothing. `--track` being opt-…, test_a_first_scan_says_it_recorded_a_baseline_and_a_later_one_does_not(), test_approving_an_unknown_server_fails_loudly() (+3 more)

### Community 75 - "Community 75"
Cohesion: 0.23
Nodes (12): parametrize, Path, The runtime decision log must not write a credential, and must not go silent to…, A rot check on the property, not on one caller: `append` is the single write…, Over-redaction would be its own defect: a decision log nobody can read does not…, The regression the gate itself introduced. `guard_hook` loads this module by…, _run_hook(), test_a_credential_shaped_name_is_not_written_to_the_decision_log() (+4 more)

### Community 76 - "Community 76"
Cohesion: 0.17
Nodes (11): [0.1.14] — 2026-07-29, [0.1.16] — 2026-07-29, [0.1.18] — 2026-07-29, [0.1.19] — 2026-07-29, [0.1.1] — 2026-07-08, [0.1.20] — 2026-07-30, [0.1.2] — 2026-07-08, [0.1.5] — 2026-07-21 (+3 more)

### Community 77 - "Community 77"
Cohesion: 0.36
Nodes (11): build_public(), check(), _is_sdist(), _logical(), main(), _members(), Path, Build sdist AND wheel from the public repo. Both are published, so both are… (+3 more)

### Community 78 - "Community 78"
Cohesion: 0.21
Nodes (12): pending_decisions(), One entry per server awaiting a human. Pure — no I/O, no clock, so it is…, approved(), display_name(), last(), pending(), What the USER calls this server — the name in their own config, not our…, Keys whose newest sighting differs from the approved baseline — i.e.… (+4 more)

### Community 79 - "Community 79"
Cohesion: 0.21
Nodes (11): behavioural_deny_reason(), content_hash(), declared_verdict(), deny_reason(), The decision core — the ONE place a runtime verdict is computed. `(call,…, The canonical behavioural denial. Same no-bypass properties as the declared…, The canonical denial text, shared by every path that applies a declared-tier…, The approved-surface fingerprint of one tool's model-visible text. MUST stay… (+3 more)

### Community 80 - "Community 80"
Cohesion: 0.18
Nodes (12): call_breakdown(), classified_servers(), _classify(), export_servers_csv(), The whole panel payload, JSON-safe. One request, because the panel has one view…, One server's tier. Ordered worst-first: the first thing that is true wins., (name, entry, store_key, tier) for every discovered server, sorted worst-first.…, Everything known about ONE server: its approved surface, how it has moved over… (+4 more)

### Community 81 - "Community 81"
Cohesion: 0.18
Nodes (10): Redaction at the persistence boundary — irreversible, shape-preserving.…, Mask a credential inside an IDENTITY string — a tool name, a server name, a…, Mask secret-looking query-string values and any userinfo in a URL, for DISPLAY…, redact_ident(), redact_url(), For DISPLAY, so the credential comes out here rather than at each consumer. A…, The other machine-readable surface, which had its own redaction already —…, The other place a URL hides a secret. Same canary, different shape. (+2 more)

### Community 82 - "Community 82"
Cohesion: 0.30
Nodes (11): _baseline(), _config(), _drift_block(), Path, `compared` in `--json`: a refused baseline must not read as "checked and…, The drift block for our one server, out of the report a consumer actually…, A baseline from a NEWER build. Empty diff lists are correct — the claim must be…, The other direction, so the field is not just a constant `false`: a readable… (+3 more)

### Community 83 - "Community 83"
Cohesion: 0.23
Nodes (11): _label_of(), _probe(), parametrize, A server that runs and then fails is not the same as an address that answers…, The default view for a multi-server fleet. This is where all faults used to…, The beta page's "sits there doing nothing". A short budget keeps the test…, The advice must match the KIND of failure: there is no URL here, and the server…, test_a_server_that_never_answers_is_TIMED_OUT_not_unreachable() (+3 more)

### Community 84 - "Community 84"
Cohesion: 0.17
Nodes (9): The one-paste enrolment card (founder, 2026-08-07 — Natoma's Get Config,…, Connecting the scanner's answers is not protection; the hook is. The card says…, It must be safe on the read-only view: no token, no form, no POST., A card that exists but is never rendered is the dead-code pattern; pin the call…, The Kerno-pattern paste-to-your-agent prompt: it must name the real binary and…, test_render_actually_places_the_card_on_the_hub(), test_the_card_admits_it_enforces_nothing(), test_the_card_is_static_and_token_free() (+1 more)

### Community 85 - "Community 85"
Cohesion: 0.17
Nodes (10): fixture, parametrize, `runs.db` must not record the credential the operator typed on the command…, One real `mcpgawk scan --http <credentialled url>`, then the rows it wrote., The first version of this gate produced `http:///https://…`. An operator has to…, The channel that leaked from the panel: an exception stringifies with whatever…, rows(), test_an_exception_summary_is_masked_too() (+2 more)

### Community 86 - "Community 86"
Cohesion: 0.24
Nodes (10): datetime, ago(), _excerpt(), Drift / rug-pull detection — pure diff over stored measurements. The integrity…, One-line, bounded, quoted. Newlines are collapsed so an inserted block cannot…, The first thing a fleet scan says when something changed. Drift used to print…, 4 days ago" rather than an ISO timestamp. How long a poisoned description has…, render() (+2 more)

### Community 87 - "Community 87"
Cohesion: 0.24
Nodes (10): canonical(), Any, Canonical tool-surface fingerprinting — ONE definition, reused everywhere a…, Order-independent JSON for hashing — a schema's key order is not semantic, so…, The full comparable surface of one tool: what a model READS (name, description)…, Deterministic 16-hex digest over the WHOLE tool surface — changes iff any…, Per-tool `(name, 12-hex surface hash)`, sorted by name — so a diff can name…, surface_hashes() (+2 more)

### Community 88 - "Community 88"
Cohesion: 0.27
Nodes (10): FleetRow, _group_by_client(), Needs-you-first, then alphabetical. A stable, meaningful order matters more…, (client, rows) sections. A server present in several tools is listed under EACH…, The fleet as DATA, for the IDE extension and any other front-end. The state and…, render_fleet(), sort_rows(), to_json() (+2 more)

### Community 89 - "Community 89"
Cohesion: 0.25
Nodes (10): _clear(), parametrize, Approval is the moment trust moves — and it must come from the human. THE HOLE…, CI legitimately has no TTY and no human. The escape hatch exists, but it is an…, The denial goes into the AGENT'S CONTEXT. It is a prompt to a model, so it must…, test_a_human_at_a_terminal_may_approve(), test_a_non_interactive_run_may_not_approve(), test_an_agent_session_may_not_approve() (+2 more)

### Community 90 - "Community 90"
Cohesion: 0.29
Nodes (10): _mode(), fixture, Path, A token store and a monitoring database must be owner-only — created that way,…, The reachable bad state, not a hypothetical: the old code swallowed the chmod…, O_CREAT honours a mode only for a NEW file. An 0644 file left by the old code…, store(), test_a_store_written_before_the_fix_is_repaired_on_the_next_write() (+2 more)

### Community 91 - "Community 91"
Cohesion: 0.33
Nodes (5): clamp(), loop(), place(), rand(), start()

### Community 92 - "Community 92"
Cohesion: 0.22
Nodes (9): _canonical(), _fingerprints(), _item_signals(), Any, `{kind}.{name}` -> detector verdicts, judged on LIVE description text. Public…, Order-independent serialisation. JSON object order is not semantic, so a server…, A record's `{type}.{name}` -> hash map, plus whether it came from the LEGACY…, Which injection detectors each description trips, judged on the LIVE text. THE… (+1 more)

### Community 93 - "Community 93"
Cohesion: 0.25
Nodes (8): Path, LOAD-BEARING CONSTRAINT TEST (ContextKey lesson: written to guard the #1…, Reproducibility invariant: the library never stamps its own time (caller passes…, Module-level import roots (function-local imports are separate; we assert on…, test_inventory_layers_import_no_network_library(), test_measure_and_label_make_zero_connections(), test_no_clock_read_in_library(), _toplevel_imports()

### Community 95 - "Community 95"
Cohesion: 0.36
Nodes (7): Session memory that survives load, rotation, and key drift — Phase 1 task 3.…, _row(), test_read_session_consults_previous_generation(), test_read_session_survives_parallel_session_eviction(), test_session_sources_reach_past_global_cap(), test_status_reports_no_session_calls(), test_summarise_counts_missing_session_identity()

### Community 96 - "Community 96"
Cohesion: 0.22
Nodes (7): observations(), fixture, The verify audit log must not store the credential the engine just convicted a…, Masked, not dropped. A spot-check trail with the observation missing would be…, Over-masking would empty the trail of everything an operator reads it for., test_ordinary_tool_output_is_still_recorded_verbatim(), test_the_convicted_tool_still_has_a_trail()

### Community 97 - "Community 97"
Cohesion: 0.25
Nodes (7): Lockups needed, Mark, mcpgawk — brand spec (Nativerse / gawk.dev family), Palette (locked to Nativerse tokens — `nativerse-site/styles.css`), Production note (before push), Type (the family stack — Fontshare), Voice

### Community 98 - "Community 98"
Cohesion: 0.29
Nodes (7): Requirement, parametrize, The environment running the suite must satisfy the pins the package declares.…, Pins the premise. If dependencies moved or were emptied, the parametrised test…, _runtime_requirements(), test_the_installed_version_satisfies_the_declared_pin(), test_the_pyproject_actually_declares_dependencies()

### Community 99 - "Community 99"
Cohesion: 0.25
Nodes (7): CI-native output and suppressing a reviewed finding, @gawk/verify — behavioural MCP verifier, Honest scope, How it works, Safe by default, Usage, What it checks (behavioural vuln classes)

### Community 100 - "Community 100"
Cohesion: 0.43
Nodes (7): Grade is a transparent CRAFT composite (cost + hygiene), never a capability…, _server(), test_capability_is_not_penalised(), test_fixes_are_actionable_and_only_when_needed(), test_heavy_and_unannotated_fails(), test_lean_and_annotated_scores_high(), test_lean_but_unannotated_is_middling_not_top()

### Community 101 - "Community 101"
Cohesion: 0.38
Nodes (6): fingerprint(), material(), Any, One answer to "does this config entry point at a different account?". Two…, The login-bearing parts of a config entry, in a stable order. Empty when it…, A short, stable digest of the login this entry uses — or None when it uses…

### Community 102 - "Community 102"
Cohesion: 0.40
Nodes (3): dict, _ActionState, The action banner's state, with URL credentials masked ON THE WAY IN. A…

### Community 103 - "Community 103"
Cohesion: 0.40
Nodes (5): ask_consent(), consent_prompt(), `mcpgawk` with no arguments — the whole journey, one command. WHY THIS EXISTS.…, The one question, with full disclosure of what changes and how to undo it. The…, Ask the one question. Returns the choice, or None when we cannot ask (non-…

### Community 104 - "Community 104"
Cohesion: 0.33
Nodes (6): contains_secret(), True when `text` still looks like it carries a credential. For assertions and…, Found the hard way. A subagent wrote a live BrowserStack key to disk; running…, The other direction, and the reason the prefix is anchored on a trailing…, test_the_widened_pattern_does_not_swallow_ordinary_prose(), test_vendor_prefixed_and_json_quoted_credentials_are_redacted()

### Community 105 - "Community 105"
Cohesion: 0.47
Nodes (4): _hosts_in_path_tables(), Anti-drift canary for the skills host registry — same mechanism as…, test_every_path_table_host_is_registered(), test_every_registered_host_has_at_least_one_path()

### Community 106 - "Community 106"
Cohesion: 0.40
Nodes (5): ArgumentParser, build_parser(), _installed_version(), The CLI surface, separated from `main` so the argument CONTRACT can be tested…, The version of the DISTRIBUTION actually installed — read from package…

### Community 107 - "Community 107"
Cohesion: 0.40
Nodes (5): [0.1.6] — 2026-07-22, Added, ⚠️ Behaviour changes — read these two, Fixed, Measured

### Community 108 - "Community 108"
Cohesion: 0.40
Nodes (5): _deny(), This agent's own deny shape. Claude Code and Codex take `permissionDecision`;…, forbid_network(), fixture, Any outbound connection attempt raises, and is recorded.

### Community 109 - "Community 109"
Cohesion: 0.50
Nodes (4): [0.1.13] — 2026-07-28, Added, Fixed, Security

### Community 110 - "Community 110"
Cohesion: 0.50
Nodes (4): activity_rows(), export_log_csv(), Every logged event, newest first, with the five questions answered on each row:…, The log as CSV — every row, every field, for a spreadsheet or an auditor.

### Community 111 - "Community 111"
Cohesion: 0.50
Nodes (3): fixture, CANONICAL SOURCE of the public repo's `tests/conftest.py`. Not used by this…, _the_suite_is_the_documented_ci_override()

### Community 112 - "Community 112"
Cohesion: 0.50
Nodes (3): Full licence text — Apache License, Version 2.0, Incorporated: mc-scan/agent-scan absolute-path redaction (2026-07-12), Third-party licences — mcpgawk (free engine)

### Community 113 - "Community 113"
Cohesion: 0.67
Nodes (3): [0.1.0] — 2026-07-08, Added, Security

### Community 114 - "Community 114"
Cohesion: 0.67
Nodes (3): [0.1.12] — 2026-07-27, Added, Changed

### Community 115 - "Community 115"
Cohesion: 0.67
Nodes (3): [0.1.21] — 2026-08-01, Changed, Fixed

### Community 116 - "Community 116"
Cohesion: 0.67
Nodes (3): [0.1.27] — 2026-08-13, Fixed, Security

### Community 117 - "Community 117"
Cohesion: 0.67
Nodes (3): [0.1.3] — 2026-07-12, Added, Changed

### Community 118 - "Community 118"
Cohesion: 0.67
Nodes (3): [0.1.4] — 2026-07-20, Added, Changed / Fixed

### Community 119 - "Community 119"
Cohesion: 0.67
Nodes (3): [0.1.7] — 2026-07-23, Added, Changed

### Community 120 - "Community 120"
Cohesion: 0.67
Nodes (3): [0.1.8] — 2026-07-26, Changed, Why one command

## Knowledge Gaps
- **99 isolated node(s):** `DISPOSABLE`, `@modelcontextprotocol/server-filesystem`, `@modelcontextprotocol/server-memory`, `@modelcontextprotocol/server-sequential-thinking`, `@modelcontextprotocol/server-everything` (+94 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **17 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ServerSnapshot` connect `Community 5` to `Community 2`, `Community 8`, `Community 10`, `Community 11`, `Community 16`, `Community 18`, `Community 20`, `Community 21`, `Community 24`, `Community 28`, `Community 31`, `Community 39`, `Community 43`, `Community 46`, `Community 48`, `Community 49`, `Community 55`, `Community 62`, `Community 64`, `Community 65`, `Community 66`, `Community 86`, `Community 92`?**
  _High betweenness centrality (0.068) - this node is a cross-community bridge._
- **Why does `measure()` connect `Community 16` to `Community 65`, `Community 5`, `Community 43`, `Community 46`, `Community 49`, `Community 83`, `Community 20`, `Community 87`, `Community 24`, `Community 93`, `Community 63`?**
  _High betweenness centrality (0.028) - this node is a cross-community bridge._
- **Why does `build_login_provider()` connect `Community 52` to `Community 5`?**
  _High betweenness centrality (0.023) - this node is a cross-community bridge._
- **Are the 20 inferred relationships involving `ServerSnapshot` (e.g. with `_NoMatchingServers` and `DriftReport`) actually correct?**
  _`ServerSnapshot` has 20 INFERRED edges - model-reasoned connections that need verification._
- **Are the 5 inferred relationships involving `measure()` (e.g. with `_rec()` and `_label()`) actually correct?**
  _`measure()` has 5 INFERRED edges - model-reasoned connections that need verification._
- **What connects `DISPOSABLE`, `@modelcontextprotocol/server-filesystem`, `@modelcontextprotocol/server-memory` to the rest of the system?**
  _99 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.052917232021709636 - nodes in this community are weakly interconnected._