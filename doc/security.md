# Design and security

fkw protects a random root key with one or more unlock methods. Applications can
change those methods while keeping their derived keys and sealed payloads intact.
Separate FIDO2 credentials sign messages for offline verification.
[Format 2](format-v2.md) and [public-key formats](public-key-formats.md) specify
the encodings and key schedules; [library usage](integration.md) covers persistence.

## Recommended protection

Use `KeyAndPassphrase` with `Verification::UserVerified` for protection against
both copied ciphertext and a stolen security key. In the CLI, select
`-w key+passphrase --uv`. Choose a strong passphrase distinct from the token PIN.
A generated `RecoverySecret`, saved separately, provides an alternative when
the primary factors are unavailable.

Any enrolled method can recover the root; combined methods require both factors.
Protection depends on the weakest alternative. Adding a passphrase-only method
enables offline password guessing even when another method requires a security key.

## Threat model

An attacker may copy, modify, truncate, or replace envelopes and sealed files.
Authentication detects tampering but cannot distinguish an older valid copy.

The application, host, selected authenticator, and keystore adapter are trusted
during use. A compromised host can capture factor outputs, unlocked roots, and plaintext.
Labels, methods, credential metadata, and approximate payload length are public.
Keystore guarantees depend on the [platform policy](platform-storage.md).

## Root key and trust boundaries

Creation uses operating-system randomness for a 32-byte root and an independent
32-byte envelope ID. Each method wraps the same root.
[HKDF-SHA256](https://www.rfc-editor.org/rfc/rfc5869.html) derives separate keys
for envelope authentication, application purposes, and payload streams. The API
exposes purpose-derived application keys. Method edits preserve the root and
envelope ID, keeping those keys stable.

`Protector` takes application identity and policy from trusted configuration.
`Envelope::from_bytes` validates structure and canonical encoding; metadata
remains untrusted until unlock. `allow_only` checks every method, including
unselected alternatives. Only the selected route needs available factors.

Each method's context binds the application identity, envelope ID, and all method
metadata, including its policy, KDF parameters, credential, and nonce. Factor keys
are bound to this context and their role. Changing these fields invalidates the
wrapped root, preventing parameter downgrades and credential substitution.

HMAC-SHA256 authenticates the complete envelope, including method ordering and
wrapped roots. Unlock verifies it before returning an `UnlockedKey`. The format
fixes the cryptographic suite and method recipes; callers cannot supply nonces
or custom factor combiners.

## Factor constructions

All factor keys are 32-byte HKDF-SHA256 outputs, using the method context as salt
and a distinct role label in the derivation info.

| Factor key | Input to HKDF |
| --- | --- |
| `P`, passphrase | Argon2id output from the passphrase and a random per-method salt |
| `F`, security key | Credential-specific FIDO `hmac-secret` output for a salt derived from the method context |
| `S`, keystore | Independently generated random secret stored under the selected OS access policy |
| `R`, recovery | Previously generated random recovery secret |

Single-factor methods wrap the root with their factor key using AES-256-GCM.
Below, `wrap` uses the record nonce, authenticates the method context as
associated data, and appends a 16-byte tag:

```text
key + passphrase:
    inner   = wrap(P, root)
    wrapped = wrap(F, inner)

key + keystore:
    K       = HKDF-SHA256(F || S, salt=context,
                         info=frame(["fkw/v2/combined"]), length=32)
    wrapped = wrap(K, root)
```

The outer security-key layer hides the password ciphertext and its tag, blocking
password-only guessing against the record. It authenticates before requesting
the passphrase. Key plus keystore combines two fixed-length, high-entropy factors;
possession of either alone does not provide the wrapping key.

Fresh method IDs and nonces produce fresh wrapping keys even when factors are
reused. The nested construction uses the same nonce under two distinct keys,
each used once, satisfying [GCM's key/nonce uniqueness requirement](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).

### Password guessing and user verification

For `KeyAndPassphrase`, assuming no weaker alternative:

| Attacker has the envelope and… | Remaining protection |
| --- | --- |
| No factors | No practical password-only offline guessing test |
| The correct passphrase | The security-key factor is still required |
| A presence-only token | One successful touch releases the factor; passphrase guesses can then run offline |
| A UV-required token without its PIN or other user verification | Authenticator verification must be satisfied before obtaining the factor |
| The method's security-key factor output | Offline guessing is limited by passphrase entropy and Argon2 cost |

A captured security-key factor permits offline guessing without further token access.
The construction does not require a hardware evaluation per guess.

Presence requires a touch; user verification (UV) also verifies the user through
the authenticator. Enrollment enforces credential protection level 2 for presence
and level 3 for UV.
[CTAP](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-hmac-secret-extension)
uses distinct `hmac-secret` secrets for verified and unverified assertions, making
the exact UV bit part of the cryptographic choice.

Before releasing a factor, the native adapter verifies the assertion signature,
credential identity, exact presence/UV flags, and absence of backup flags. There
is no method fallback, automatic PIN retry, or UV downgrade. Attestation
verification does not establish vendor trust.

### KDF cost

Passphrase methods use Argon2id v1.3 with a 16-byte random salt. The default is
2 GiB, one pass, and four lanes, following
[RFC 9106's primary recommendation](https://www.rfc-editor.org/rfc/rfc9106.html#section-7.4).
This profile targets desktop use, spending memory to raise the cost of offline
guessing. For a fixed defender runtime, the RFC's analysis favors allocating
more memory with one Argon2id pass.

`INTERACTIVE` explicitly selects 64 MiB, three passes, and one lane. Passphrase-only
and combined methods use the same KDF policy, with no automatic cost reduction.

Benchmark optimized builds on supported devices, allowing for concurrent unlocks
and memory pressure. Argon2 raises guessing costs but cannot compensate for a
predictable passphrase. See
[RFC 9106, parameter choice](https://www.rfc-editor.org/rfc/rfc9106.html#section-4).

Costs are stored per method. Application resource ceilings reject excessive work
before interaction. Changing a cost requires replacing the method and saving
the updated envelope; see [library usage](integration.md#methods-and-input).

## Sealed data

Each seal operation derives a stream key from the root, a fresh 32-byte nonce,
application identity, and envelope ID. ChaCha20-Poly1305 encrypts frames of at most
64 KiB. Counter nonces, authenticated lengths, and a final marker detect
reordering, truncation, and trailing data.

Payload authentication binds the root and stable envelope identity, allowing
method updates to preserve ciphertext. `update_file` verifies the complete result
before publishing it.

Opening verifies the entire stream before returning plaintext or publishing an
output. File operations stage plaintext privately on disk to keep memory bounded.
`open_to` verifies before writing to the caller; subsequent writer failures can
leave partial output. Deleting temporary files is not secure erasure. Use trusted
directories and appropriate disk protection.

## Public-key recipients

An unlocked root derives an X25519 identity under the fixed application-key
purpose `fkw/recipient/v1/identity`. Senders receive only its public key.
Encryption uses [HPKE base mode](https://www.rfc-editor.org/rfc/rfc9180.html)
with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and the export-only AEAD identifier.
A fresh ephemeral key establishes a fresh 32-byte stream key through the HPKE
exporter. The shared ChaCha20-Poly1305 framing authenticates the complete
recipient header, including the recipient fingerprint and encapsulated key.

The exporter supplies the per-message key directly; a separate encrypted key
record is unnecessary for one recipient. The fixed suite and domain labels are
specified in [public-key formats](public-key-formats.md).

Authenticate the recipient public key before encrypting: substitution would
send the message to another recipient. Anyone with the public key can create a
valid message, so encryption does not authenticate a sender. Recipient identity
and approximate message length are public.

Access-method changes and recovery preserve the private identity. Decryption
derives it in host memory. When protection uses FIDO, the token gates root recovery;
the host performs X25519. A compromised root exposes recorded messages as well
as future messages to that identity. Rotate the root and distribute the new
public key after exposure. This scheme does not provide forward secrecy against
recipient-key compromise.

## Hardware signatures

Signing uses a separate, non-discoverable ES256 credential with credential
protection level 3. Each operation requires user verification and presence.
The token signs a normal FIDO2 assertion whose challenge binds the application,
verification key, explicit purpose, and SHA-256 digest of the message.
No `hmac-secret` extension is needed for signing.

Offline verification uses the same assertion verifier as protection operations.
It checks the RP hash, ECDSA signature, UP=UV=1, absence of backup and reserved
flags, and the exact message challenge. The signing format permits no assertion
extensions. The signature counter is authenticated but is not treated as a clock
or used to reject repeated verification.

Trust the public verification key independently of the signature. A purpose
separates protocols; it does not enforce application policy. Applications must
encode any action, audience, nonce, or expiry in the signed message and enforce
replay and authorization rules themselves. Touch and PIN authorize a signing
operation; the token has no trusted display of its contents. A compromised host
can request a signature over a different message.

The host never receives a plaintext signing private key. Signing requires the
saved credential handle and the original authenticator; a handle backup cannot
restore access on a replacement token. Revocation and spare signing keys require
application trust updates. Attestation verification establishes a valid enrollment
response, not the token's vendor or provenance.

## Access changes and compromise recovery

Removing a method leaves saved copies and the root unchanged. An attacker who
cracks an old passphrase-only envelope can recover the root and decrypt newer
data protected by it. Captured factors that unlock an old copy have the same
consequence.

After potential root exposure, create a fresh protected key and re-encrypt with
`rotate_file`. Applications using `derive_key` must migrate their data to new keys.
Rotation protects new copies and future data; old copies retain their original protection.
Detecting rollback requires trusted state outside the container.

External-factor deletion requires an authenticated survivor and can disable
backups using that factor. It cannot erase captured factors. Non-discoverable
credentials cannot be individually retired. Deletion is explicit, never performed
in `Drop`; follow the [retirement sequence](integration.md#persistence-and-lifecycle).

Secret buffers are zeroized where supported; swap, dumps, OS buffers, and
application copies may retain secrets.
