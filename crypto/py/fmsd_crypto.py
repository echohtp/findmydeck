"""Find My Steam Deck — crypto core (Python side).

Runs in the Decky plugin backend. Wire-compatible with crypto/ts/crypto.mjs.

The device only ever needs the *public* halves (box_pk to seal reports,
sign_pk to verify commands). derive_keys exists here for the interop tests
and for any headless enrollment tooling — the plugin itself derives in the
TS frontend and discards.
"""

from __future__ import annotations

import base64
import json
import secrets

from nacl import bindings, pwhash
from nacl.exceptions import BadSignatureError, CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

# Pinned, versioned KDF params — must match crypto/ts/crypto.mjs KDF_V1.
KDF_V1 = {"v": 1, "alg": "argon2id", "ops": 3, "mem": 268435456}

SALT_BYTES = pwhash.argon2id.SALTBYTES  # 16


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data)


def gen_salt() -> str:
    return b64e(secrets.token_bytes(SALT_BYTES))


def derive_keys(password: str, salt_b64: str, kdf: dict = KDF_V1) -> dict:
    """password + salt + kdf -> both keypairs. Caller discards secrets ASAP."""
    if kdf.get("alg") != "argon2id" or kdf.get("v") != 1:
        raise ValueError(f"unsupported kdf: {kdf!r}")
    salt = b64d(salt_b64)
    if len(salt) != SALT_BYTES:
        raise ValueError("bad salt length")
    seed = pwhash.argon2id.kdf(
        64, password.encode("utf-8"), salt, opslimit=kdf["ops"], memlimit=kdf["mem"]
    )
    box_pk, box_sk = bindings.crypto_box_seed_keypair(seed[:32])
    # Keep the 32-byte sign seed: SigningKey takes the seed, and it is what
    # crypto_sign_seed_keypair on the TS side derives its 64-byte sk from.
    sign_seed = seed[32:64]
    sign_pk = SigningKey(sign_seed).verify_key.encode()
    return {
        "box_pk": b64e(box_pk),
        "sign_pk": b64e(sign_pk),
        "box_sk": b64e(box_sk),
        "sign_seed": b64e(sign_seed),
    }


def seal(payload_str: str, box_pk_b64: str) -> str:
    """Seal a report payload (JSON string) to the enrolled box_pk.

    crypto_box_seal uses an ephemeral sender key: the device cannot decrypt
    its own past reports and blobs are unlinkable by sender.
    """
    box = SealedBox(PublicKey(b64d(box_pk_b64)))
    return b64e(box.encrypt(payload_str.encode("utf-8")))


def seal_open(blob_b64: str, box_sk_b64: str) -> str:
    box = SealedBox(PrivateKey(b64d(box_sk_b64)))
    return box.decrypt(b64d(blob_b64)).decode("utf-8")


def sign_command(command: dict, sign_seed_b64: str) -> dict:
    """Serialize once, sign the exact bytes. Transmit `payload` verbatim."""
    payload = json.dumps(command, separators=(",", ":"))
    sig = SigningKey(b64d(sign_seed_b64)).sign(payload.encode("utf-8")).signature
    return {"payload": payload, "sig": b64e(sig)}


def verify_command(payload_str: str, sig_b64: str, sign_pk_b64: str) -> bool:
    """Verify over the exact received payload string. Parse only if True."""
    try:
        VerifyKey(b64d(sign_pk_b64)).verify(payload_str.encode("utf-8"), b64d(sig_b64))
        return True
    except (BadSignatureError, CryptoError, ValueError):
        return False


def seal_report(report: dict, box_pk_b64: str) -> str:
    """Convenience: dict -> sealed blob."""
    return seal(json.dumps(report, separators=(",", ":")), box_pk_b64)
