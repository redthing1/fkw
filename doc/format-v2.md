# Format 2

Wire format and key schedule. See [design and security](security.md) for rationale.
Recipient encryption and signing have separate [public-key formats](public-key-formats.md).

All integers are unsigned and big endian unless encoded in CBOR.
The suite is fixed by the format version.
Unknown versions and noncanonical encodings are rejected.

## Envelopes

### Encoding and bounds

`FKWE` followed by canonical, definite-length CBOR:

```
[2, application, envelope_id, [method_record, ...], mac]
method_record = [id, label, recipe, kdf, credential, nonce, wrapped]
recipe = [kind, verification?, credential_storage?, store_access?]
kdf = null | [memory_kib, passes, lanes, salt]
credential = null | [credential_id, es256_xy]
```

The application is a lowercase DNS-shaped namespace. Envelope and
method identifiers are independent random 32-byte values. Labels are public
UTF-8, at most 128 bytes, without control characters. Nonces are 12 bytes,
Argon2 salts 16 bytes, ES256 coordinates 64 bytes. Credential IDs are 1–1024
bytes. Envelopes are at most 64 KiB and have 1–32 distinct method IDs.

Kinds: 0 passphrase, 1 security key, 2 keystore, 3 key plus passphrase,
4 key plus keystore, 5 recovery secret. Verification: 0 exact presence,
1 exact user verification. Credential storage: 0 non-discoverable,
1 managed discoverable. Store access: 0 native standard, 1 OS user
authentication, 2 explicit macOS login keychain. Recipe arrays include only
the parameters their kind requires, in the order above.

Only passphrase recipes contain KDF parameters; only key recipes contain
credentials. Store entries are addressed by the application and method ID.
Managed credentials use the method ID as their user ID.

### Factor derivation and root wrapping

`frame(parts)` is a 32-bit part count followed by a 32-bit byte length and
bytes for each part. `context` is SHA-256 of
`frame(["fkw/v2/method", application, envelope_id, metadata])`, where metadata
is the canonical six-element record without `wrapped`.

Argon2id v1.3 produces 32 bytes. Valid parameters are 65536–2097152 KiB,
1–6 passes, 1–4 lanes, memory divisible by four times the lanes. Defaults
are 2097152 KiB (2 GiB), 1 pass, 4 lanes.

The FIDO hmac-secret salt is SHA-256 of
`frame(["fkw/v2/prf", context])`. Native assertions must verify the signature,
credential ID, UP=1, BE=BS=0, and exactly the selected UV bit. Enrollment
requires the corresponding credential-protection level (2 or 3).

Each factor key is HKDF-SHA256(factor, salt=context,
info=`frame(["fkw/v2/factor", role])`, length=32), where role is `passphrase`,
`security-key`, `keystore`, or `recovery`. Random factors are 32 bytes.
Key plus keystore derives a wrapping key with HKDF-SHA256 over the two
factor keys concatenated in that order, salt=context,
info=`frame(["fkw/v2/combined"])`.

AES-256-GCM wraps the random 32-byte root with the record nonce and
context as associated data. Key plus passphrase first wraps with the
passphrase key, then wraps that ciphertext with the security-key key.
The distinct keys use the same record nonce; each key is used once.
All other recipes wrap once. Tags are 16 bytes. Unwrapping the outer
FIDO layer must succeed before asking for a passphrase.

### Envelope authentication and application keys

The envelope MAC is HMAC-SHA256 over the canonical four-element CBOR
body (everything except mac). Its key is HKDF-SHA256(root,
salt=envelope_id, info=`frame(["fkw/v2/envelope", application])`, length=32).
No root or derived application key is returned before this MAC verifies.
Every method, label, ordering and policy is authenticated together.

Application keys use HKDF-SHA256(root, salt=envelope_id,
info=`frame(["fkw/v2/application", application, purpose])`, length=32).
Purpose is nonempty and at most 128 bytes.

## Sealed data

```
FKWS || 02 || envelope_length:u32 || envelope || stream_nonce:32 || frames
frame = plaintext_length:u32 || final:u8 || ciphertext || tag:16
```

The stream nonce is fresh random data. The stream key is HKDF-SHA256(root,
salt=stream_nonce, info=`frame(["fkw/v2/stream", application, envelope_id])`,
length=32). Its context is SHA-256 of
`frame(["fkw/v2/stream", application, envelope_id, stream_nonce])`.

Frames use ChaCha20-Poly1305, at most 65536 plaintext bytes. The nonce is
three zero bytes, the 64-bit frame index (starting at zero), and the final
flag (0 or 1). Associated data is the stream context followed by the
five-byte frame header. Every nonfinal frame is full. The last frame must
have final=1; an empty final frame is permitted only for an empty stream.
Trailing bytes, counter overflow, missing final frames, malformed lengths,
reordering and authentication failures are errors.

The mutable envelope does not appear in payload associated data. Its
authenticated application, envelope ID and root bind it to the payload.
Method changes can replace the header while copying ciphertext unchanged.
They cannot revoke old copies or provide rollback protection.

Stream framing follows [age](https://c2sp.org/age@v1.1.0)'s counter/final-marker
approach, with a different format and key schedule.
