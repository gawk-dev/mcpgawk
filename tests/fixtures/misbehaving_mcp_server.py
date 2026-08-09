"""Three ways a real MCP server goes wrong, behind one --mode switch.

The repo has fixtures for servers that WORK (toy, mutable, annotated, oauth) and none for servers
that don't. These are the three failures a beta tester actually hits, and the beta page already
lists the first one ("sits there doing nothing") as known:

  --mode hang            speaks the protocol never; accepts stdin and answers nothing, forever.
                         The nastiest case, because there is no error to report — only a decision
                         to stop waiting.
  --mode crash           dies on launch with a traceback on stderr, like a broken dependency or a
                         bad interpreter.
  --mode missing-secret  exits deliberately because the credential it needs is not in the
                         environment — the single most common "it doesn't work" in a real fleet.

Usage: python misbehaving_mcp_server.py --mode hang|crash|missing-secret
"""
from __future__ import annotations

import argparse
import os
import sys
import time

SECRET_ENV = "DEMO_API_TOKEN"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["hang", "crash", "missing-secret"], required=True)
    args = ap.parse_args()

    if args.mode == "crash":
        # Shape of a real import-time failure: a traceback, then a non-zero exit.
        print("Traceback (most recent call last):\n"
              '  File "server.py", line 1, in <module>\n'
              "    import mcp_vendor_sdk\n"
              "ModuleNotFoundError: No module named 'mcp_vendor_sdk'", file=sys.stderr, flush=True)
        raise SystemExit(1)

    if args.mode == "missing-secret":
        if not os.environ.get(SECRET_ENV):
            print(f"FATAL: {SECRET_ENV} is not set. Create a token and export it before starting "
                  f"this server.", file=sys.stderr, flush=True)
            raise SystemExit(2)
        # With the secret present it would serve normally; this fixture never gets that far.
        raise SystemExit(0)

    # hang: hold the pipe open and answer nothing at all. No output, ever — not even a banner,
    # because a banner is already more than the worst real servers give you.
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
