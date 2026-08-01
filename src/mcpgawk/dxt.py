"""Claude Desktop EXTENSION servers — what their manifest variables mean, and what we can honestly
do about them.

An extension's `manifest.json` declares its launch command with host-resolved placeholders:

    {"command": "node", "args": ["${__dirname}/dist/index.js"],
     "env": {"REVOLUTX_CONFIG_DIR": "${user_config.config_dir}"}}

Claude Desktop substitutes these at launch. `discover.py` deliberately keeps them UNEXPANDED so
the consent prompt shows what the host will really run rather than a path we guessed — that is
correct, and this module does not change it.

WHAT WAS WRONG (found 2026-08-01 on the founder's own fleet): those placeholders reach verify,
which tries to LAUNCH the server, and node reports `Cannot find module '.../${__dirname}/dist/
index.js'`. The panel then matched "${" + "Cannot find module" and told the operator *"this config
contains a literal ${...} that nothing expanded — replace it with an absolute path"* — advising
them to edit a config that is perfectly correct for its host. The product blamed the user for our
own blind spot, which is the worst answer a security tool can give.

The split this module draws:

* `${__dirname}` is KNOWABLE — it is the directory the manifest was read from, which discovery now
  records as `_manifest_dir`. Resolve it and the server becomes launchable, and therefore
  verifiable.
* `${user_config.*}` is NOT knowable. It is a value the user typed into Claude Desktop's own
  settings UI, stored by Claude Desktop, and we do not have it. Guessing a config directory for a
  trading server would be worse than declining. So we decline, and say exactly why.
"""
from __future__ import annotations

import re
from typing import Any

#: `${__dirname}` — the extension's own install directory.
_DIRNAME = re.compile(r"\$\{__dirname\}")
#: `${user_config.whatever}` — a value only Claude Desktop holds.
_USER_CONFIG = re.compile(r"\$\{user_config\.([A-Za-z0-9_]+)\}")


def is_extension(entry: dict[str, Any]) -> bool:
    """Was this server declared by a Claude Desktop extension manifest?"""
    return bool(entry.get("_manifest_dir")) or "claude-desktop-extension" in (
        entry.get("_clients") or [])


def _launch_strings(entry: dict[str, Any]) -> list[str]:
    out = [str(entry.get("command") or "")]
    out += [str(a) for a in (entry.get("args") or [])]
    out += [str(v) for v in (entry.get("env") or {}).values()]
    return out


def unresolvable_vars(entry: dict[str, Any]) -> list[str]:
    """The placeholders we cannot fill, in the order they appear. Empty means launchable."""
    found: list[str] = []
    for text in _launch_strings(entry):
        for m in _USER_CONFIG.finditer(text):
            name = f"user_config.{m.group(1)}"
            if name not in found:
                found.append(name)
    return found


def resolve_for_launch(entry: dict[str, Any]) -> dict[str, Any] | None:
    """A launchable copy of this entry, or None when it honestly cannot be launched.

    None is a RESULT, not a failure to try: a server whose command depends on a value only Claude
    Desktop holds cannot be started by us, and pretending otherwise would produce a fabricated
    path and a misleading error. The caller reports why (see `explain`).
    """
    if not is_extension(entry):
        return dict(entry)
    if unresolvable_vars(entry):
        return None
    root = str(entry.get("_manifest_dir") or "")
    if not root:
        return None

    def sub(text: str) -> str:
        return _DIRNAME.sub(root, text)

    out = dict(entry)
    if entry.get("command"):
        out["command"] = sub(str(entry["command"]))
    if entry.get("args"):
        out["args"] = [sub(str(a)) for a in entry["args"]]
    if entry.get("env"):
        out["env"] = {k: sub(str(v)) for k, v in entry["env"].items()}
    return out


def explain(entry: dict[str, Any]) -> str:
    """Why this extension server could not be verified, in the operator's terms. "" if it can be.

    Never tells the user to edit the config: it is correct, and Claude Desktop resolves it at
    launch. The limit is ours and the sentence says so.
    """
    if not is_extension(entry):
        return ""
    missing = unresolvable_vars(entry)
    if missing:
        return (
            "this server is installed as a Claude Desktop extension, and its launch command uses "
            + ", ".join("${" + m + "}" for m in missing)
            + " — settings that live inside Claude Desktop, not in any file we can read. Claude "
              "Desktop fills them in when IT starts the server, so we cannot start it ourselves. "
              "Your config is not broken; this is a limit on our side. To verify it, run the "
              "server's own command with those values filled in and point `mcpgawk verify` at that."
        )
    if not entry.get("_manifest_dir"):
        return ("this server is installed as a Claude Desktop extension and we did not record "
                "which extension directory it came from, so its ${__dirname} cannot be resolved.")
    return ""
