"""Device-side crypto via ctypes -> libsodium. Zero Python dependencies.

Decky's Python has no PyNaCl (C extension, version-coupled), so the plugin
calls libsodium directly. Search order: bundled .so (shipped in the zip,
built against glibc<=2.33 — fine on SteamOS 3.x), then the system library.

The device only ever needs the PUBLIC halves: crypto_box_seal to box_pk
(reports) and crypto_sign_verify_detached vs sign_pk (commands). No secret
key material exists on this side — nothing here derives, signs, or decrypts.

Wire-compatible with crypto/py/fmsd_crypto.py (PyNaCl) and
crypto/ts/crypto.mjs (libsodium.js) — proven by tests/test_plugin.py
CtypesInteropTest, which round-trips against the PyNaCl implementation.
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.util
import json
import os


def _load() -> ctypes.CDLL:
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "libsodium.so"),   # bundled with the plugin zip
        ctypes.util.find_library("sodium"),   # system (SteamOS/Arch)
        "libsodium.so.26",
        "libsodium.so.23",
    ]
    errors = []
    for cand in candidates:
        if not cand:
            continue
        try:
            lib = ctypes.CDLL(cand)
        except OSError as e:
            errors.append(f"{cand}: {e}")
            continue
        if lib.sodium_init() >= 0:
            return lib
        errors.append(f"{cand}: sodium_init failed")
    raise OSError("libsodium unavailable: " + "; ".join(errors))


_s = _load()
_s.crypto_box_sealbytes.restype = ctypes.c_size_t
_s.crypto_box_publickeybytes.restype = ctypes.c_size_t
_s.crypto_sign_bytes.restype = ctypes.c_size_t
_s.crypto_sign_publickeybytes.restype = ctypes.c_size_t

SEAL_OVERHEAD = _s.crypto_box_sealbytes()          # 48
BOX_PK_LEN = _s.crypto_box_publickeybytes()        # 32
SIG_LEN = _s.crypto_sign_bytes()                   # 64
SIGN_PK_LEN = _s.crypto_sign_publickeybytes()      # 32


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data)


def seal(payload_str: str, box_pk_b64: str) -> str:
    """crypto_box_seal to the enrolled box_pk. Ephemeral sender key: the
    device cannot decrypt its own past reports."""
    pk = b64d(box_pk_b64)
    if len(pk) != BOX_PK_LEN:
        raise ValueError("bad box_pk length")
    msg = payload_str.encode("utf-8")
    out = ctypes.create_string_buffer(len(msg) + SEAL_OVERHEAD)
    rc = _s.crypto_box_seal(out, msg, ctypes.c_ulonglong(len(msg)), pk)
    if rc != 0:
        raise RuntimeError("crypto_box_seal failed")
    return b64e(out.raw)


def seal_report(report: dict, box_pk_b64: str) -> str:
    return seal(json.dumps(report, separators=(",", ":")), box_pk_b64)


def verify_command(payload_str: str, sig_b64: str, sign_pk_b64: str) -> bool:
    """Verify over the exact received payload string. Parse only if True."""
    try:
        sig = b64d(sig_b64)
        pk = b64d(sign_pk_b64)
    except (ValueError, TypeError):
        return False
    if len(sig) != SIG_LEN or len(pk) != SIGN_PK_LEN:
        return False
    msg = payload_str.encode("utf-8")
    return _s.crypto_sign_verify_detached(sig, msg, ctypes.c_ulonglong(len(msg)), pk) == 0
