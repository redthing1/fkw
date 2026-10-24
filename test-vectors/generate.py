#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["argon2-cffi==25.1.0", "cryptography==47.0.0"]
# ///
"""Independent format-2 vectors. All key material here is deliberately public."""
import argparse
import hashlib
import hmac
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def u32(n):
    return n.to_bytes(4, "big")


def frame(parts):
    return u32(len(parts)) + b"".join(u32(len(part)) + part for part in parts)


def digest(*parts):
    return hashlib.sha256(frame(parts)).digest()


def derive(secret, salt, *info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=frame(info)).derive(secret)


def cbor(value):
    def head(major, n):
        if n < 24:
            return bytes([major * 32 + n])
        for code, width in [(24, 1), (25, 2), (26, 4), (27, 8)]:
            if n < 1 << (width * 8):
                return bytes([major * 32 + code]) + n.to_bytes(width, "big")
        raise ValueError("integer too large")
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode()
        return head(3, len(encoded)) + encoded
    return head(4, len(value)) + b"".join(cbor(item) for item in value)


APP = b"vectors.example"
ROOT = bytes(range(32))
RECOVERY = bytes(range(32, 64))
STORE = bytes(range(64, 96))
PRF = bytes(range(96, 128))
PASSWORD = b"correct horse battery staple"
EID = digest(b"envelope")
SALT = digest(b"argon2")[:16]
COST = [65536, 3, 1]
PASSWORD_FACTOR = hash_secret_raw(PASSWORD, SALT, COST[1], COST[0], COST[2], 32, Type.ID, 19)
public = ec.derive_private_key(7, ec.SECP256R1()).public_key().public_numbers()
PUBLIC = public.x.to_bytes(32, "big") + public.y.to_bytes(32, "big")


def make_vector(recipe):
    name = "-".join(map(str, recipe))
    mid = digest(b"method", name.encode())
    nonce = digest(b"nonce", name.encode())[:12]
    kind = recipe[0]
    kdf = COST + [SALT] if kind in (0, 3) else None
    credential = [digest(b"credential", name.encode()), PUBLIC] if kind in (1, 3, 4) else None
    metadata = [mid, "vector " + name, recipe, kdf, credential, nonce]
    context = digest(b"fkw/v2/method", APP, EID, cbor(metadata))
    keys = {role: derive(value, context, b"fkw/v2/factor", role) for role, value in [
        (b"passphrase", PASSWORD_FACTOR), (b"security-key", PRF), (b"keystore", STORE), (b"recovery", RECOVERY)
    ]}
    if kind == 0:
        wrapping_key = keys[b"passphrase"]
    elif kind in (1, 3):
        wrapping_key = keys[b"security-key"]
    elif kind == 2:
        wrapping_key = keys[b"keystore"]
    elif kind == 4:
        wrapping_key = derive(keys[b"security-key"] + keys[b"keystore"], context, b"fkw/v2/combined")
    else:
        wrapping_key = keys[b"recovery"]
    inner = AESGCM(keys[b"passphrase"]).encrypt(nonce, ROOT, context) if kind == 3 else ROOT
    wrapped = AESGCM(wrapping_key).encrypt(nonce, inner, context)
    body = [2, APP.decode(), EID, [metadata + [wrapped]]]
    mac_key = derive(ROOT, EID, b"fkw/v2/envelope", APP)
    mac = hmac.digest(mac_key, cbor(body), "sha256")
    envelope = b"FKWE" + cbor(body + [mac])
    vector = dict(root=ROOT, recovery=RECOVERY, store=STORE, prf=PRF, passphrase=PASSWORD,
                  context=context, prf_salt=digest(b"fkw/v2/prf", context), envelope=envelope,
                  application_key=derive(ROOT, EID, b"fkw/v2/application", APP, b"vector"))
    if kind == 5:
        stream_nonce = digest(b"stream nonce")
        vector["stream_nonce"] = stream_nonce
        for label, plain in [("empty", b""), ("short", b"a short secret\x00\xff"), ("long", b"z" * 131073)]:
            sealed = seal(envelope, stream_nonce, plain)
            if label != "long":
                vector["sealed_" + label] = sealed
                vector["plain_" + label] = plain
            else:
                vector["sealed_long_sha256"] = hashlib.sha256(sealed).digest()
    return name, "# Public deterministic format-2 test vector\n" + "".join(f"{key}={value.hex()}\n" for key, value in vector.items())


def seal(envelope, nonce, plain):
    key = derive(ROOT, nonce, b"fkw/v2/stream", APP, EID)
    context = digest(b"fkw/v2/stream", APP, EID, nonce)
    output = b"FKWS\x02" + u32(len(envelope)) + envelope + nonce
    chunks = [plain[i:i + 65536] for i in range(0, len(plain), 65536)] or [b""]
    for index, chunk in enumerate(chunks):
        last = bytes([int(index == len(chunks) - 1)])
        header = u32(len(chunk)) + last
        iv = b"\x00" * 3 + index.to_bytes(8, "big") + last
        output += header + ChaCha20Poly1305(key).encrypt(iv, chunk, context + header)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if checked-in vectors differ")
    args = parser.parse_args()
    recipes = [[0], [1, 0, 0], [1, 1, 1], [2, 0], [2, 1], [2, 2], [3, 0, 0], [3, 1, 1], [4, 0, 0, 0], [4, 1, 1, 1], [5]]
    for recipe in recipes:
        name, text = make_vector(recipe)
        path = Path(__file__).with_name(f"format-2-{name}.txt")
        if args.check:
            if path.read_text() != text:
                raise SystemExit(f"vector differs: {path.name}")
        else:
            path.write_text(text)
    print(f"{'Verified' if args.check else 'Generated'} {len(recipes)} vectors")


if __name__ == "__main__":
    main()
