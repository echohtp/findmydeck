// Find My Steam Deck — crypto core (TS/JS side).
// Runs in Node (tests) and the browser (dashboard, plugin frontend bundle).
// Wire-compatible with crypto/py/fmsd_crypto.py — see tests/interop.test.mjs.
//
// Invariants (spec §0/§1):
//  - password, seed, box_sk, sign_sk never leave the client.
//  - Reports are sealed boxes to box_pk (X25519, ephemeral sender).
//  - Commands are Ed25519-detached-signed over the EXACT payload string;
//    verify the bytes you received, parse only after verifying.

import _sodium from 'libsodium-wrappers-sumo';

// Pinned KDF params, versioned so they can change without bricking old
// enrollments (each device row stores the kdf it enrolled with).
export const KDF_V1 = Object.freeze({ v: 1, alg: 'argon2id', ops: 3, mem: 268435456 });

async function sodium() {
  await _sodium.ready;
  return _sodium;
}

const B64 = () => _sodium.base64_variants.ORIGINAL;

export async function toB64(bytes) {
  const s = await sodium();
  return s.to_base64(bytes, B64());
}

export async function fromB64(str) {
  const s = await sodium();
  return s.from_base64(str, B64());
}

export async function genSalt() {
  const s = await sodium();
  return s.to_base64(s.randombytes_buf(s.crypto_pwhash_SALTBYTES), B64());
}

/**
 * password + salt + kdf -> both keypairs.
 * Returns pubkeys base64 (safe to store/send) and secret keys as raw
 * Uint8Array (caller must zero with wipe() as soon as done).
 */
export async function deriveKeys(password, saltB64, kdf = KDF_V1) {
  const s = await sodium();
  if (kdf.alg !== 'argon2id' || kdf.v !== 1) {
    throw new Error(`unsupported kdf: ${JSON.stringify(kdf)}`);
  }
  const salt = s.from_base64(saltB64, B64());
  if (salt.length !== s.crypto_pwhash_SALTBYTES) throw new Error('bad salt length');
  const seed = s.crypto_pwhash(
    64, password, salt, kdf.ops, kdf.mem, s.crypto_pwhash_ALG_ARGON2ID13,
  );
  const box = s.crypto_box_seed_keypair(seed.slice(0, 32));
  const sign = s.crypto_sign_seed_keypair(seed.slice(32, 64));
  seed.fill(0);
  return {
    boxPk: s.to_base64(box.publicKey, B64()),
    signPk: s.to_base64(sign.publicKey, B64()),
    boxSk: box.privateKey,   // Uint8Array(32) — wipe after use
    signSk: sign.privateKey, // Uint8Array(64) — wipe after use
  };
}

export function wipe(...keys) {
  for (const k of keys) if (k && k.fill) k.fill(0);
}

/** Seal a report payload (JSON string) to the device's box_pk. */
export async function seal(payloadStr, boxPkB64) {
  const s = await sodium();
  const blob = s.crypto_box_seal(s.from_string(payloadStr), s.from_base64(boxPkB64, B64()));
  return s.to_base64(blob, B64());
}

/** Open a sealed report blob in the owner's browser. Returns JSON string. */
export async function sealOpen(blobB64, boxPkB64, boxSk) {
  const s = await sodium();
  const plain = s.crypto_box_seal_open(
    s.from_base64(blobB64, B64()), s.from_base64(boxPkB64, B64()), boxSk,
  );
  return s.to_string(plain);
}

/**
 * Sign a command. Serialize once here and transmit exactly this
 * `payload` string — never re-serialize on another hop.
 */
export async function signCommand(command, signSk) {
  const s = await sodium();
  const payload = JSON.stringify(command);
  const sig = s.crypto_sign_detached(s.from_string(payload), signSk);
  return { payload, sig: s.to_base64(sig, B64()) };
}

/** Verify over the exact received payload string. Parse only if true. */
export async function verifyCommand(payloadStr, sigB64, signPkB64) {
  const s = await sodium();
  try {
    return s.crypto_sign_verify_detached(
      s.from_base64(sigB64, B64()), s.from_string(payloadStr), s.from_base64(signPkB64, B64()),
    );
  } catch {
    return false;
  }
}
