"""Signed approvals on this machine: the approval passphrase and the root-owned anchor.

FOUNDER 2026-11-06 ("1. Yes 2. yes"): docs/design-approve-presence-2026-11-05.md §4.1. Measured the day
before, an agent moved a baseline three ways that every signal missed (markers stripped plus a fake
terminal; editing history.json; a double-fork recorded as the person). What it cannot do is type a
passphrase it was never told, or write a file only root can write. So, once a machine is LOCKED:

  * every approval is signed with an Ed25519 key that only the passphrase unlocks (scrypt + AES-GCM,
    `~/.mcpgawk/approval-key.json`, 0600);
  * the public key every reader checks against lives in a ROOT-OWNED file (the anchor): the agent
    runs as the person and cannot create or change it without the person's admin password;
  * a reader trusts the anchor only when root owns it and neither it nor its folder is writable by
    anyone else. Anything else at that path is ignored and SAID.

NOTHING HERE READS THE ENVIRONMENT (pinned by tests/test_approval_lock.py). An env var is exactly what
an agent with a shell sets: the anchor path is fixed per OS and the passphrase comes from the
terminal, never stdin, never a variable. Tests patch module attributes instead.

Windows has no anchor yet (`%ProgramData%` ACLs are unmeasured): `read_anchor()` says "unsupported",
and the machine stays on the signal-based checks, said as such, never implied to be locked.
"""
from __future__ import annotations

import base64
import json
import os
import stat
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Where the anchor lives. Root-owned directories only (measured 2026-11-06 on macOS:
#: `/Library/Application Support` is root:admin 755 — the admin group cannot write it).
ANCHOR_DIRS: dict[str, Path] = {
    "darwin": Path("/Library/Application Support/mcpgawk"),
    "linux": Path("/etc/mcpgawk"),
}
ANCHOR_FILE = "approval-anchor.json"
ANCHOR_VERSION = 1
KEY_FILE = "approval-key.json"
KEY_VERSION = 1
SIG_VERSION = 1
#: Measured 2026-11-06 on the founder's Mac: n=2^17, r=8, p=1 derives in ~589 ms using 128 MiB. Once per
#: approval for a person; ruinous per guess for anyone trying passphrases against a copied key file.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 17, 8, 1
MIN_PASSPHRASE = 12
#: Binds the ciphertext to its own public key, so a key file cannot be spliced from two others.
_AAD = b"mcpgawk-approval-key-v1"


class NoTerminal(RuntimeError):
    """There is no terminal to type the passphrase into."""


class WrongPassphrase(ValueError):
    """The passphrase does not unlock the approval key."""


class NotTheAnchoredKey(ValueError):
    """The key unlocks, but it is not the key the anchor trusts."""


def _platform() -> str:
    return "darwin" if sys.platform == "darwin" else ("linux" if sys.platform.startswith("linux")
                                                       else sys.platform)


def anchor_path() -> Path | None:
    d = ANCHOR_DIRS.get(_platform())
    return d / ANCHOR_FILE if d else None


def _root_owned(st: os.stat_result) -> bool:
    """Patched in tests only (the test user plays root). Never configurable at run time."""
    return st.st_uid == 0


@dataclass(frozen=True)
class Anchor:
    #: "absent" (not locked) | "trusted" (locked) | "untrusted" (ignored, said) | "unsupported"
    status: str
    public_key: bytes | None = None
    why: str | None = None
    path: Path | None = None


def read_anchor() -> Anchor:
    p = anchor_path()
    if p is None:
        return Anchor("unsupported", why=f"approval locking is not available on {sys.platform} yet")
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return Anchor("absent", path=p)
    except OSError as exc:
        return Anchor("untrusted", why=f"cannot read it ({exc.strerror or exc})", path=p)
    problems: list[str] = []
    if not stat.S_ISREG(st.st_mode):
        problems.append("it is not a regular file")
    if not _root_owned(st):
        problems.append("the file is not owned by root")
    if st.st_mode & 0o022:
        problems.append("the file is writable by group or others")
    try:
        dst = os.stat(p.parent)
        if not _root_owned(dst):
            problems.append("its folder is not owned by root")
        if dst.st_mode & 0o022:
            problems.append("its folder is writable by group or others")
    except OSError as exc:
        problems.append(f"its folder cannot be read ({exc.strerror or exc})")
    if problems:
        return Anchor("untrusted", why="; ".join(problems), path=p)
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
        pub = base64.b64decode(doc["public_key"], validate=True)
    except (OSError, ValueError, KeyError, TypeError):
        return Anchor("untrusted", why="it is not a readable anchor file", path=p)
    if doc.get("v") != ANCHOR_VERSION or len(pub) != 32:
        return Anchor("untrusted", why="it was written by an unknown version", path=p)
    return Anchor("trusted", public_key=pub, path=p)


def locked() -> bool:
    """A trusted anchor is in place: approvals on this machine must be signed."""
    return read_anchor().status == "trusted"


def anchor_document(public_key: bytes) -> dict[str, Any]:
    return {"v": ANCHOR_VERSION, "public_key": base64.b64encode(public_key).decode("ascii"),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def install_anchor_commands(tmp: Path, dest: Path) -> list[list[str]]:
    """The two privileged steps, run through `sudo` in the person's own terminal (sudo asks for
    THEIR password). gid 0 is `wheel` on macOS and `root` on Linux, so one spelling serves both."""
    return [["sudo", "install", "-d", "-m", "0755", "-o", "root", "-g", "0", str(dest.parent)],
            ["sudo", "install", "-m", "0644", "-o", "root", "-g", "0", str(tmp), str(dest)]]


def _run_privileged(cmd: list[str]) -> int:
    """Runs one `sudo` step attached to the person's terminal, so sudo asks for THEIR password.
    Replaced in tests only (the test user plays root)."""
    import subprocess
    return subprocess.run(cmd, check=False).returncode


def install_anchor(public_key: bytes) -> Anchor:
    """Place the anchor where only root can write, via `install_anchor_commands`, then read it back
    through the same trust checks every reader uses. The returned Anchor says whether it took."""
    dest = anchor_path()
    if dest is None:
        return read_anchor()
    fd, tmp = tempfile.mkstemp(prefix="mcpgawk-anchor-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(anchor_document(public_key), f)
        for cmd in install_anchor_commands(Path(tmp), dest):
            if _run_privileged(cmd) != 0:
                return Anchor("absent", why="the admin step did not complete", path=dest)
    finally:
        try:
            os.unlink(tmp)                  # our own temporary file, never anything else
        except OSError:
            pass
    return read_anchor()


def ask(prompt: str) -> str:
    """A visible answer (y/N) from the terminal only — same rule as the passphrase."""
    try:
        tty = _open_tty()
    except OSError as exc:
        raise NoTerminal("there is no terminal to answer in") from exc
    with tty:
        tty.write(prompt)
        tty.flush()
        return tty.readline().strip()


def write_anchor_unprivileged_for_tests(public_key: bytes) -> Path:
    """TESTS ONLY: write the anchor without sudo into a patched ANCHOR_DIRS. Production writes it
    with `install_anchor_commands` and nothing else."""
    dest = anchor_path()
    assert dest is not None
    dest.write_text(json.dumps(anchor_document(public_key)), encoding="utf-8")
    os.chmod(dest, 0o644)
    return dest


# ── the key ───────────────────────────────────────────────────────────────────────────────────────

def key_path(store_path: str | None = None) -> Path:
    try:
        from . import history
    except ImportError as exc:   # loaded by file path (the guard hook), which never asks for the key
        raise RuntimeError("the approval key path needs the mcpgawk package") from exc
    return Path(store_path or history.default_path()).parent / KEY_FILE


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _kek(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def create_key(passphrase: str) -> tuple[dict[str, Any], bytes]:
    """A new Ed25519 key, its 32-byte seed encrypted under scrypt(passphrase). Returns (document,
    public key). The private key never touches disk unencrypted."""
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(passphrase) < MIN_PASSPHRASE:
        raise ValueError(f"the passphrase must be at least {MIN_PASSPHRASE} characters")
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    pub = sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_kek(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)).encrypt(nonce, seed, _AAD + pub)
    doc = {"v": KEY_VERSION, "public_key": _b64(pub),
           "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": _b64(salt)},
           "nonce": _b64(nonce), "ciphertext": _b64(ct)}
    return doc, pub


def write_key(doc: dict[str, Any], path: Path) -> None:
    """Atomically, 0600 from the first byte (never written wider and narrowed after)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".approval-key.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Signer:
    """An unlocked approval key. Exists only in memory, only after the passphrase was typed."""

    def __init__(self, private_key: Any, public_key: bytes) -> None:
        self._sk = private_key
        self.public_key = public_key

    def sign(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"v": SIG_VERSION, "alg": "ed25519", "sig": _b64(self._sk.sign(canonical(payload)))}


def unlock(passphrase: str, store_path: str | None = None, *, require_anchor: bool = True) -> Signer:
    """The Signer the passphrase opens. Raises WrongPassphrase, or NotTheAnchoredKey when the key
    is not the one the anchor trusts (an agent's own keypair dropped where we look for ours)."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        doc = json.loads(key_path(store_path).read_text(encoding="utf-8"))
        kdf = doc["kdf"]
        pub = base64.b64decode(doc["public_key"], validate=True)
        salt = base64.b64decode(kdf["salt"], validate=True)
        nonce = base64.b64decode(doc["nonce"], validate=True)
        ct = base64.b64decode(doc["ciphertext"], validate=True)
        n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise WrongPassphrase(f"the approval key cannot be read ({exc})") from exc
    try:
        seed = AESGCM(_kek(passphrase, salt, n, r, p)).decrypt(nonce, ct, _AAD + pub)
    except InvalidTag as exc:
        raise WrongPassphrase("that passphrase does not unlock the approval key") from exc
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    if require_anchor:
        anchor = read_anchor()
        if anchor.status != "trusted" or anchor.public_key != pub:
            raise NotTheAnchoredKey("this key is not the one this machine's anchor trusts")
    return Signer(sk, pub)


# ── what is signed, and checking it ──────────────────────────────────────────────────────────────

def canonical(payload: dict[str, Any]) -> bytes:
    """Sorted keys, no whitespace, no \\uXXXX escaping: byte-identical in Python and in Node (the
    convention licensing.py already shares with the plugin)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def payload(key: str, tools: Any, props: Any, approved_at: Any) -> dict[str, Any]:
    """THE signed payload — one definition for the writer (history.approval_payload) and the guard
    hook (which rebuilds it from a projection row): the server key, the tool hashes, the approved
    parameter names in the projection's shape, and when. Every input the guard decides on."""
    return {"v": 1, "key": key, "tools": dict(tools or {}), "props": props,
            "approved_at": approved_at}


#: Domain separation for a NAME-ONLY approval (a server mcpgawk has never seen, e.g. one built into
#: the agent): its signed key is never a server key, so the signature cannot stand in for a tracked
#: server's approval — pasted into a `servers` row it signs an empty tool list, which allows nothing.
NAME_ONLY_PREFIX = "name-only:"


def name_only_payload(name: str, approved_at: Any) -> dict[str, Any]:
    """What a name-only approval signs: the name exactly as the agent calls it, and when."""
    return payload(NAME_ONLY_PREFIX + name, {}, None, approved_at)


def trusted_public_key() -> bytes | None:
    """The anchor's public key when this machine is LOCKED, else None."""
    a = read_anchor()
    return a.public_key if a.status == "trusted" else None


def verify(public_key: bytes, payload: dict[str, Any], sig: Any) -> bool:
    if not (isinstance(sig, dict) and sig.get("v") == SIG_VERSION and sig.get("alg") == "ed25519"):
        return False
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            base64.b64decode(sig.get("sig") or "", validate=True), canonical(payload))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ── the terminal ──────────────────────────────────────────────────────────────────────────────────

def _open_tty():
    """The controlling terminal, read+write. NOT `open("/dev/tty", "r+")`: text-mode r+ wraps the
    file in BufferedRandom, which needs a seekable file, and a terminal is not — on a real terminal
    that raised "not seekable" (an OSError) and was reported as "no terminal" (measured 2026-11-06,
    the founder's first `approvals lock`). Opened the way `getpass` opens it."""
    import io
    fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    try:
        raw = io.FileIO(fd, "r+")
    except BaseException:
        os.close(fd)
        raise
    return io.TextIOWrapper(raw, encoding="utf-8", line_buffering=True)


def read_passphrase(prompt: str) -> str:
    """From the controlling terminal ONLY. `getpass` falls back to stdin when there is no /dev/tty;
    here that is a refusal: a passphrase is typed by a person, not piped."""
    import getpass
    try:
        tty = _open_tty()
    except OSError as exc:
        raise NoTerminal("there is no terminal to type the approval passphrase into") from exc
    with tty:
        return getpass.getpass(prompt, stream=tty)


def signer_for(store_path: str | None) -> "tuple[Signer | None, list[str], bool]":
    """What an approving command needs before it moves anything: (signer, lines to say, refused).

    Unlocked machine: (None, [], False) — go ahead, unsigned, exactly as before. A file at the
    anchor path that fails the trust checks is ignored AND said. Locked: the passphrase is read
    from the terminal; any failure refuses, with the reason, and nothing moves."""
    anchor = read_anchor()
    say: list[str] = []
    if anchor.status == "untrusted":
        say.append(f"ignoring the approval anchor at {anchor.path} — {anchor.why}. This machine is "
                   f"treated as NOT locked.")
    if anchor.status != "trusted":
        return None, say, False
    try:
        passphrase = read_passphrase("Approval passphrase (never give it to an agent): ")
    except NoTerminal:
        return None, say + ["refusing — this machine is locked and there is no terminal to type the "
                            "approval passphrase in. Run it yourself, in your own terminal."], True
    try:
        return unlock(passphrase, store_path), say, False
    except (WrongPassphrase, NotTheAnchoredKey) as exc:
        return None, say + [f"refusing — {exc}. Nothing was approved."], True
