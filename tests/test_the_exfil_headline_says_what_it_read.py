"""The strong half of exfil detection was dead, and the headline claimed capability for the weak half.

WHY THIS FILE EXISTS. Two defects in one detector, found 2026-09-10 by asking the product WHY it
had flagged each tool on a live 70-tool server rather than trusting the count.

1. **The parameter arm never fired on real schemas.** The rule was
   `re.compile(r"\\b(url|uri|endpoint|...)\\b")` applied to the raw property name — and `_` is a
   WORD character, so `\\burl\\b` cannot match `source_url`. snake_case is the dominant convention
   in MCP input schemas, so the arm only ever matched a property named EXACTLY `url`. Measured:
   it missed `source_url`, `audio_url`, `image_url`, `cta_url`, `meeting_url` — including
   `upload_video`, where the server fetches a URL the CALLER supplies, which is the textbook shape
   the rule exists to catch. The structural signal was dead; the count of 5 was five prose matches.

2. **The headline asserted capability over both arms.** "5 of 70 tools can read your content AND
   reach the network" reads as a measurement. It was a regex over names and descriptions, and two
   of the five matched "request" inside the product's own noun "recording request" while a third,
   `prepare_upload`, matched **"curl"** in a description about browser-direct upload — a tool that
   is inbound-only. A reader given one number over both arms cannot tell which tools to act on, so
   they discount all of them.

Fixed together, because fixing either alone leaves a lie: token-split parameter matching (precise,
not merely wider — `source_url` matches, `file_name` and `curling_urn` do not), and a headline that
names the basis. The real server went 5 -> 8, and the eight now split 5 structural / 3 lexical.

These tests drive `label._concerns` — the function that builds every headline a person reads —
not the predicate alone.
"""
from __future__ import annotations

import pytest

from mcpgawk import label
from mcpgawk.measure import _exfil_basis, _is_destination_param


# --------------------------------------------------------------------------- the parameter arm

@pytest.mark.parametrize("param", [
    "url", "uri", "endpoint", "webhook",                    # the bare forms that always worked
    "source_url", "audio_url", "cta_url", "meeting_url",    # snake_case — every one of these was
    "callback_url", "redirect_uri", "webhook_url",          # missed before, on a REAL server
    "targetUrl", "sourceUri",                               # camelCase
    "source-url", "source.url",                             # kebab and dotted
])
def test_a_caller_supplied_destination_is_seen_however_it_is_spelled(param):
    assert _is_destination_param(param), f"{param} names a destination and must be caught"


@pytest.mark.parametrize("param", [
    # A list of destinations is still destinations. Both of these are real parameters on the
    # live Notion server, and the singular-only rule read neither — the same failure as
    # `\burl\b` against `source_url`, one spelling further on. Measured 2026-09-10.
    "file_urls", "data_source_urls", "webhook_urls", "endpoints", "callbacks",
])
def test_a_list_of_destinations_is_still_destinations(param):
    assert _is_destination_param(param), f"{param} names destinations and must be caught"


@pytest.mark.parametrize("param", [
    # An ID that REFERS to a destination is not a destination. Both of these are real params on
    # the live resend server and both were counted as caller-supplied destinations until
    # 2026-09-10: `remove-webhook` deletes a webhook by ID, and `replay-webhook-event` redelivers
    # to the endpoint that webhook ALREADY holds. Neither lets the caller name a place.
    "webhookId", "webhook_id", "endpointId", "callback_ids",
])
def test_an_id_that_refers_to_a_destination_is_not_one(param):
    assert not _is_destination_param(param), f"{param} selects a destination, it does not name one"


@pytest.mark.parametrize("param", [
    # ...but an explicit url-ish token still wins, so the rule drops references, not spellings.
    "webhook_url_id", "callback_uri_id",
])
def test_a_spelled_out_url_outranks_the_reference_rule(param):
    assert _is_destination_param(param), f"{param} names a URL, whatever else it carries"


@pytest.mark.parametrize("param", [
    "file_name", "file_size_bytes", "title", "video_id",    # real params from the same server
    "curling_urn", "urn", "hurl", "follow_redirects",       # near-misses a looser regex would take
    # `redirect` is excluded from the plural set ON PURPOSE. In the plural it names a policy,
    # not a place, and flagging a boolean as a caller-supplied destination is exactly the
    # overclaim this arm exists to avoid.
    "max_redirects", "redirects",
])
def test_precision_is_not_traded_away_for_reach(param):
    """Dropping `\\b` would have "fixed" the bug by matching `curling_urn`. Splitting does not."""
    assert not _is_destination_param(param), f"{param} is not a destination"


# --------------------------------------------------------------------------- the basis

def _tool(name, desc="", props=None, ann=None):
    return {"name": name, "description": desc,
            "inputSchema": {"properties": {p: {} for p in (props or [])}},
            "annotations": ann or {}}


def test_the_basis_names_the_parameter_and_prefers_it_over_prose():
    # add_watermark on the real server: an `image_url` AND the word "http" in its description.
    # The stronger evidence must be the reported reason.
    assert _exfil_basis(_tool("add_watermark", "Fetch over http", ["image_url"])) == "param:image_url"


def test_the_basis_names_the_word_when_that_is_all_there_was():
    # prepare_upload, verbatim shape: inbound-only, flagged on "curl" in its own prose.
    assert _exfil_basis(_tool("prepare_upload", "e.g. curl the presigned target",
                              ["file_name", "title"])) == "wording:curl"


def test_a_declaration_still_outranks_both_arms():
    t = _tool("get_thing", "fetch over http", ["url"], ann={"readOnlyHint": True})
    assert _exfil_basis(t) == "", "readOnlyHint must silence both arms, not just the prose one"


# --------------------------------------------------------------------------- the rendered sentence

def _headlines(tools):
    """Drive `_concerns` — the function that builds every headline a person reads."""
    payload = [{"name": t["name"], "tokens": 100, "write": True,
                "exfil_capable": bool(t["basis"]), "exfil_basis": t["basis"] or None,
                "annotations": None} for t in tools]
    exfil_c = sum(1 for t in payload if t["exfil_capable"])
    ac = {"annotated": len(payload), "read_only": 0, "destructive": 0}
    return label._concerns(len(payload), 4000, len(payload), exfil_c, ac, payload,
                           heavy=False, injections=[], expensive=False, secrets=[])


def test_the_headline_separates_the_two_arms_instead_of_asserting_capability():
    out = _headlines([
        {"name": "upload_video", "basis": "param:source_url"},
        {"name": "record_meeting", "basis": "param:meeting_url"},
        {"name": "prepare_upload", "basis": "wording:curl"},
        {"name": "get_video", "basis": ""},
    ])
    head = " ".join(h for h, _ in out)
    body = " ".join(" ".join(b) for _, b in out)

    # The COUNT is the structural arm alone. [FOUNDER 2026-09-10] The lexical hit is named in the
    # same breath and explicitly excluded, so a reader can see it without it inflating the number.
    assert "2 of 4 tools take a destination from the caller" in head, head
    assert "1 more matched on wording alone, not counted" in head, head
    # The headline number must never be the sum of the two arms — that was the overclaim.
    assert "3 of 4" not in head, head
    # The overclaim this file exists to remove.
    assert "can read your content AND reach the network" not in head + body

    assert "source_url" in body, "the reader must see WHICH argument"
    assert "curl" in body, "and which word, so a weak match is visibly weak"
    assert "prompt to look, not a finding" in body, "the weak arm must be labelled weak"
    assert "Nothing here was observed" in body and "verify" in body, (
        "the report must point at the thing that actually observes, not pre-empt it")


def test_a_wording_only_server_never_claims_a_destination():
    """The `prepare_upload` case on its own. The sentence must stay true of an inbound-only tool."""
    out = _headlines([{"name": "prepare_upload", "basis": "wording:curl"}])
    head = " ".join(h for h, _ in out)
    assert "mentions network reach in its own text" in head, head
    assert "take a destination" not in head, "nothing here accepts a destination"
    # A wording-only server must STILL be shown. The count is structural, so gating the block on
    # the count would have made this server print nothing at all — "stop counting it" was never
    # "stop showing it".
    assert head.strip(), "a wording-only server must still say something"
    assert "Worth a look, not a finding" in head, head


def test_a_partial_tool_dict_does_not_raise():
    """Callers pass minimal tool dicts, and this block no longer sits behind a count.

    Gating the exfil block on what was FOUND rather than on `exfil_c` means it now runs for
    EVERY server, including callers that build a tool dict with nothing but a name — which is
    the shape `build_narrative`'s own callers use. Indexing `t["exfil_capable"]` there raised
    KeyError and took the whole verdict down with it, turning a clean read-only server into a
    crash. A missing key must read as "nobody said", never as an exception.
    """
    out = label._concerns(1, 120, 0, 0, {"annotated": 1, "read_only": 1, "destructive": 0},
                          [{"name": "get_forecast"}], heavy=False, injections=[],
                          expensive=False, secrets=[])
    assert isinstance(out, list), "a partial tool dict must render, not raise"


def test_a_tool_whose_own_name_names_a_destination_is_not_demoted_to_wording():
    """`fetch_url` advertises the destination in its identifier.

    Grouping it with "a chance word in prose" would understate it — and would have quietly
    weakened `test_the_leak_path_is_explained_as_a_mechanism_not_a_count`, which has guarded the
    mechanism-not-a-statistic rule since long before this change. Same destination vocabulary as
    the parameter arm, applied to the name, so there is one rule in two places rather than two
    lists that drift.
    """
    assert _exfil_basis(_tool("fetch_url", "fetch an external url and read its contents")) \
        == "name:fetch_url"
    # ...and the words that are NOT destinations stay weak.
    assert _exfil_basis(_tool("create_recording_request", "Create a recording request")) \
        == "wording:request"
    assert _exfil_basis(_tool("prepare_upload", "e.g. curl it", ["file_name"])) == "wording:curl"


def test_a_name_that_names_the_object_is_not_a_named_destination():
    """`remove-webhook` names what it acts ON. The endpoint was chosen when it was created.

    Both of these are live resend tools. Until 2026-09-10 the name arm reused the FULL parameter
    vocabulary, so any tool whose identifier merely contained `webhook` was read as advertising a
    destination — and when the reference rule stopped their `webhookId` parameter from firing,
    they fell straight through to this arm and the structural total did not move. Guarding the
    displacement, not just the first rule, is the point of this test.
    """
    assert _exfil_basis(_tool("remove-webhook", "Remove a webhook by ID", ["webhookId"])) == ""
    assert _exfil_basis(
        _tool("replay-webhook-event", "Queue one more delivery of a webhook event to its "
                                      "endpoint", ["eventId", "webhookId"])) == ""
    # The tool that DOES take a destination is still caught, by the arm that should catch it.
    assert _exfil_basis(
        _tool("create-webhook", "receive notifications at a URL", ["endpoint", "events"])) \
        == "param:endpoint"


def test_the_mechanism_is_stated_for_a_named_destination_not_only_a_parameter():
    out = _headlines([{"name": "fetch_url", "basis": "name:fetch_url"}])
    body = " ".join(" ".join(b) for _, b in out)
    assert "leak path" in body, "a declared destination must still explain the mechanism"
    assert "poisoned document" in body, body
