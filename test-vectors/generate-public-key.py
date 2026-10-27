#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography==47.0.0"]
# ///
"""Independent recipient/signature vectors. All private material is public test data."""
import argparse
import hashlib
import hmac
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def frame(parts):
    return len(parts).to_bytes(4, "big") + b"".join(len(p).to_bytes(4, "big") + p for p in parts)


def digest(*parts):
    return hashlib.sha256(frame(parts)).digest()


def extract(salt, ikm):
    return hmac.digest(salt or bytes(32), ikm, "sha256")


def expand(prk, info, length):
    out = block = b""
    for counter in range(1, (length + 31) // 32 + 1):
        block = hmac.digest(prk, block + info + bytes([counter]), "sha256")
        out += block
    return out[:length]


def lextract(suite, salt, label, ikm):
    return extract(salt, b"HPKE-v1" + suite + label + ikm)


def lexpand(suite, prk, label, info, length=32):
    return expand(prk, length.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info, length)


KEM = b"KEM\x00\x20"
SUITE = b"HPKE\x00\x20\x00\x01\xff\xff"


def keypair(seed):
    prk = lextract(KEM, b"", b"dkp_prk", seed)
    sk = x25519.X25519PrivateKey.from_private_bytes(lexpand(KEM, prk, b"sk", b""))
    return sk, sk.public_key().public_bytes_raw()


def stream_key(private, peer_public, enc, recipient):
    dh = private.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))
    prk = lextract(KEM, b"", b"eae_prk", dh)
    shared = lexpand(KEM, prk, b"shared_secret", enc + recipient)
    context = b"\0" + lextract(SUITE, b"", b"psk_id_hash", b"") + lextract(SUITE, b"", b"info_hash", b"fkw/recipient/v1/hpke")
    secret = lextract(SUITE, shared, b"secret", b"")
    exporter = lexpand(SUITE, secret, b"exp", context)
    return lexpand(SUITE, exporter, b"sec", b"fkw/recipient/v1/stream")


def make_vector():
    root = bytes(range(32))
    eid = digest(b"envelope")
    app = b"vectors.example"
    seed = expand(extract(eid, root), frame([b"fkw/v2/application", app, b"fkw/recipient/v1/identity"]), 32)
    private, public = keypair(seed)
    ephemeral, enc = keypair(bytes(range(64, 96)))
    secret = stream_key(ephemeral, public, enc, public)
    assert secret == stream_key(private, enc, enc, public)
    recipient = b"FKRP\x01" + public
    fingerprint = digest(b"fkw/recipient/v1/fingerprint", recipient)
    header = b"FKWR\x01" + fingerprint + enc
    context = digest(b"fkw/recipient/v1/payload", header)

    def encrypt(message):
        length = len(message).to_bytes(4, "big") + b"\1"
        nonce = bytes(11) + b"\1"
        return header + length + ChaCha20Poly1305(secret).encrypt(nonce, message, context + length)

    message = b"independent recipient vector"
    signing = ec.derive_private_key(7, ec.SECP256R1())
    public_signing = signing.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]
    verification = b"FKVP\x01" + len(app).to_bytes(2, "big") + app + public_signing
    purpose = b"release"
    signing_message = b"release manifest\n"
    challenge = digest(b"fkw/sign/v1/message", verification, purpose, hashlib.sha256(signing_message).digest())
    authdata = hashlib.sha256(app).digest() + b"\5" + (7).to_bytes(4, "big")
    signature = signing.sign(authdata + challenge, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    credential = b"FKSC\x01" + len(verification).to_bytes(2, "big") + verification + b"test-credential"
    return {
        "recipient": recipient, "fingerprint": fingerprint, "stream_key": secret,
        "recipient_empty": encrypt(b""), "recipient_plaintext": message, "recipient_message": encrypt(message),
        "verification_key": verification, "credential": credential, "purpose": purpose,
        "signing_message": signing_message, "challenge": challenge,
        "signature": b"FKSG\x01" + authdata + signature,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = "# Independent public-key format-1 vector; all secrets are public test data\n"
    output += "".join(f"{key}={value.hex()}\n" for key, value in make_vector().items())
    path = Path(__file__).with_name("public-key-1.txt")
    if args.check:
        if path.read_text() != output:
            raise SystemExit("public-key vector differs")
    else:
        path.write_text(output)


if __name__ == "__main__":
    main()
