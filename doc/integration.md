# Library usage

| Type | Role |
| --- | --- |
| `Protector` | Trusted application identity, allowed methods, limits and adapters |
| `Method` | One supported unlock recipe |
| `Envelope` | Public metadata; decoding checks structure, not authenticity |
| `UnlockedKey` | Authenticated envelope and zeroizing root |

Construct `ApplicationId` from trusted configuration. `Protector::new` permits
all built-in methods; `allow_only` restricts the complete envelope, including
unselected alternatives. Unlocking authenticates the whole envelope before
returning an `UnlockedKey`. Only the selected method needs available factors.

## Methods and input

| Method | Required factors |
| --- | --- |
| `Passphrase` | Passphrase |
| `SecurityKey(options)` | Security key |
| `Keystore(access)` | Random system-keystore factor |
| `KeyAndPassphrase(options)` | Security key and passphrase |
| `KeyAndKeystore(options, access)` | Security key and keystore factor |
| `RecoverySecret` | Previously generated 32-byte recovery secret |

The [recommended method](security.md#recommended-protection) is
`Method::KeyAndPassphrase(KeyOptions::new(Verification::UserVerified))`.

`KeyOptions::new` selects exact `Verification::Presence` or `UserVerified`.
Credentials are non-discoverable unless `.managed()` is selected. Only managed
credentials support individual retirement. Enrollment requires a configured
security-key PIN; presence-only unlocking does not send one.

`Enrollment::new(method, label)` contains no secrets. `Interaction` supplies
secrets and handles touch/selection prompts. Escape unverified labels for display.
`Prompt::target` distinguishes an access method from a signing key.
`Passphrase` and `RecoverySecret` also implement `Interaction` directly. Generate
and save recovery material before enrollment; imported recovery bytes must be
uniformly random. Protect any copies made through `expose`.

`Enrollment::with_kdf_cost` sets Argon2id work; `Protector::with_max_kdf_cost`
bounds execution before prompts. `KdfCost::DEFAULT` uses 2 GiB, one pass,
four lanes; `INTERACTIVE` uses 64 MiB, three passes, one lane.
See [KDF cost](security.md#kdf-cost) for tuning.

Operations are synchronous. `FidoConfig` bounds each native call and device
selection. Cancellation stops the operation, though failed managed enrollment
may request cleanup interaction. PINs are never retried automatically.

## Persistence and lifecycle

`create` enrolls the first method. `add_method`, `replace_method` and
`remove_method` change the handle only on success. Replacement enrolls first;
removing the last method is rejected. Save `key.envelope().to_bytes()` durably,
or use `seal::update_file` for a container.

| Outcome | Caller action |
| --- | --- |
| Enrollment fails | Keep the original handle; `EnrollmentUncertain` identifies a factor that may remain |
| Enrollment succeeds, saving fails | Retain the updated handle and retry saving without re-enrolling; rewind input readers |
| `PublicationUncertain` | Output was published but directory durability is uncertain; verify it before retrying |

For recovery across process termination, persist the envelope before subsequent
work. Files, authenticators and keystores do not share a transaction.

Removing a method leaves its external factors intact. For explicit deletion,
first save and independently unlock a survivor with that method removed.
`retire_credential` and `remove_store_factor` require this survivor and the old
envelope. Keystore cleanup needs no old security key, retains OS authorization,
and returns `Removal::Absent` when already complete. Combined factors can be
retired in either order. Keep the old envelope until finished.

## Sealed data

The `seal` module provides complete encrypted containers:

| API | Behavior |
| --- | --- |
| `seal_bytes` / `open_bytes` | Complete containers for up to 1 MiB of plaintext |
| `seal_file` / `open_file` | Large files with bounded memory and private staging |
| `seal_reader` | Plaintext reader to a new sealed file |
| `open_to` | Verify into a private disk spool, then copy to a writer |
| `inspect_bytes` / `inspect_file` | Read unverified metadata without interaction |
| `verify_file` | Verify a complete container with an unlocked key |
| `update_file` | Replace the access header, preserve payload ciphertext, and verify the complete result before publication |
| `rotate_file` | Re-encrypt using a fresh key from `create`; reuse of the old key is rejected |

File outputs sync and publish without overwriting destinations. Writer failures
after `open_to` verifies can leave partial output. For existing application
protocols, `derive_key(purpose)` supplies a separate 32-byte key per stable purpose.
See [design and security](security.md) for staging, old-copy and rollback limits.

## Public-key encryption

`recipient::Recipient::from_key(&key)` derives a public identity from an
`UnlockedKey`. Save the protection envelope as usual; distribute only the
recipient's `to_bytes()` through an authenticated channel. Senders import it
with `Recipient::from_bytes` and need no unlock factors or native FIDO runtime.

```rust
use fkw::{Result, UnlockedKey, recipient};

fn round_trip(key: &UnlockedKey, message: &[u8]) -> Result<()> {
    let public = recipient::Recipient::from_key(key)?;
    let encrypted = recipient::encrypt_bytes(&public, message)?;
    let opened = recipient::decrypt_bytes(key, &encrypted)?;
    assert_eq!(opened.as_slice(), message);
    Ok(())
}
```

`encrypt_file`, `encrypt_reader`, `decrypt_file`, `decrypt_to`, and `verify_file`
provide the same bounded-memory staging and publication guarantees as `seal`.
Byte operations accept at most 1 MiB of plaintext. Access-method changes and
recovery preserve the recipient identity. Creating a new root changes it;
senders must receive the new public key. Encryption does not identify the sender.

## Hardware signing

`sign::Signer::new(application).create(interaction)` enrolls a dedicated FIDO2
credential requiring PIN and touch. Save the returned `Credential::to_bytes()`
before signing; retry a failed save with the same handle. It addresses the key
on its original token and contains no plaintext private key. Export
`credential.verification_key().to_bytes()` through an authenticated channel.

`Signer::sign`, `sign_file`, and `sign_reader` take the credential, an explicit
purpose, the message, and an `Interaction`. Persist the resulting
`Signature::to_bytes()` separately from the message.

Offline verification imports `VerificationKey` and `Signature` with `from_bytes`,
then calls `verify`, `verify_file`, or `verify_reader` with the expected purpose
and message. Parsing checks structure; obtain the public key from a trusted
source. Verification loads no native runtime. Purposes contain 1–128 UTF-8 bytes
without control characters; choose stable names such as `release` or `approval`.

Signing credentials are non-discoverable and cannot be individually retired or
recovered through a protection envelope. Back up the handle and authorize a
separate signing key if needed. Applications own key trust, revocation, replay
prevention, and any approval or delegation rules.
