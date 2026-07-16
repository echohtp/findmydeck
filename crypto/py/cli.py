"""JSON-over-stdio shim so the TS test harness can drive the Python side.

Usage: python cli.py <derive|seal|open|sign|verify>   (JSON on stdin, JSON on stdout)
"""

import json
import sys

import fmsd_crypto as c


def main() -> None:
    cmd = sys.argv[1]
    req = json.load(sys.stdin)
    if cmd == "derive":
        out = c.derive_keys(req["password"], req["salt"], req.get("kdf", c.KDF_V1))
    elif cmd == "seal":
        out = {"blob": c.seal(req["payload"], req["box_pk"])}
    elif cmd == "open":
        out = {"payload": c.seal_open(req["blob"], req["box_sk"])}
    elif cmd == "sign":
        out = c.sign_command(req["command"], req["sign_seed"])
    elif cmd == "verify":
        out = {"ok": c.verify_command(req["payload"], req["sig"], req["sign_pk"])}
    else:
        raise SystemExit(f"unknown command {cmd}")
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
