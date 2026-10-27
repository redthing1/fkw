# Public-key formats

Recipient encryption and hardware signing use independent version-1 formats.
All integers are unsigned and big endian. Prefixes below consist of four ASCII
bytes and one version byte. Unknown versions are rejected.
`frame(parts)` is the length-prefixed encoding defined in [Format 2](format-v2.md).
Labels and purposes are UTF-8 bytes; labels shown below have no terminating NUL.

## Recipient keys

```text
FKRP || 01 || x25519_public:32
```

The private identity is derived as follows:

```text
seed = UnlockedKey.derive_key("fkw/recipient/v1/identity")
(private, public) = DHKEM(X25519, HKDF-SHA256).DeriveKeyPair(seed)
fingerprint = SHA256(frame(["fkw/recipient/v1/fingerprint", encoded_public]))
```

`derive_key` is the application-key schedule in Format 2; it binds the root,
application, envelope ID, and purpose. `DeriveKeyPair` and X25519 encodings follow
[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html). Key parsing checks the
37-byte representation; encryption also rejects invalid DH results.

## Recipient messages

```text
FKWR || 01 || recipient_fingerprint:32 || encapsulated_key:32 || frames
```

HPKE uses base mode, KEM `0x0020` (DHKEM(X25519, HKDF-SHA256)), KDF `0x0001`
(HKDF-SHA256), and AEAD `0xffff` (export-only). Each encryption generates a fresh
ephemeral key using operating-system randomness. Both sides use:

```text
info = "fkw/recipient/v1/hpke"
stream_key = context.Export("fkw/recipient/v1/stream", 32)
stream_context = SHA256(frame(["fkw/recipient/v1/payload", header]))
```

`header` is the complete 69-byte prefix through the encapsulated key. Frames use
the [Format 2 framing](format-v2.md#sealed-data), with this stream key and context:
ChaCha20-Poly1305, at most 65536 plaintext bytes per frame, and authenticated
counter/final-marker nonces. All framing validation rules apply, including an
authenticated final frame for an empty message. The receiver checks the expected
recipient fingerprint and authenticates the full stream before releasing data.

There is no sender identity or embedded protection envelope. The CLI stores a
protected recipient identity as an empty Format 2 sealed container. Its application,
root, and envelope ID determine the recipient key; access edits preserve it.

## Signing keys and handles

```text
FKVP || 01 || application_length:u16 || application || es256_xy:64
FKSC || 01 || public_key_length:u16 || encoded_public_key || credential_id
```

The application follows Format 2's lowercase DNS-shaped namespace rules
(3–253 bytes). ES256 is ECDSA on P-256 with SHA-256; coordinates are fixed-width
32-byte big-endian X and Y, validated as a curve point. Public keys are 74–324
bytes. Credential IDs are 1–1024 bytes; complete handles are 82–1355 bytes.
The credential ID occupies all bytes after the encoded public key.

The credential is non-discoverable, with required UV, credential protection
level 3, and no `hmac-secret` extension. The handle contains public metadata and
the opaque credential ID, never a plaintext signing private key.

```text
fingerprint = SHA256(frame(["fkw/sign/v1/fingerprint", encoded_public_key]))
```

## Detached signatures

```text
FKSG || 01 || authenticator_data:37 || der_es256_signature
```

The verifier takes a trusted public key, an expected purpose, and the message.
Purpose is 1–128 UTF-8 bytes without control characters. The FIDO client-data
hash is:

```text
challenge = SHA256(frame([
    "fkw/sign/v1/message", encoded_public_key, purpose, SHA256(message)
]))
```

The authenticator signs `authenticator_data || challenge` using ES256. The
37-byte authenticator data contains `SHA256(application)`, one flag byte, and a
32-bit signature counter. Flags must equal `0x05`: presence and user verification
set, all others clear. No extensions or attested credential data are allowed.
The counter is signed but has no freshness semantics in this format.

Signatures are strict DER-encoded ECDSA values of at most 72 bytes, validated
against P-256 scalar bounds. Either valid S value is accepted. Complete signature
files are at most 114 bytes. The purpose is supplied by the caller, never
adopted from the signature.

Independent vectors and their generator are in
[`test-vectors/public-key-1.txt`](../test-vectors/public-key-1.txt) and
[`generate-public-key.py`](../test-vectors/generate-public-key.py).
