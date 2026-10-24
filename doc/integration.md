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

`KeyOptions::new` selects exact `Verification::Presence` or `UserVerified`.
Credentials are non-discoverable unless `.managed()` is selected. Only managed
credentials support individual retirement. Enrollment requires a configured
security-key PIN; presence-only unlocking does not send one.

`Enrollment::new(method, label)` contains no secrets. `Interaction` supplies
secrets and handles touch/selection prompts. Escape unverified labels for display.
`Passphrase` and `RecoverySecret` also implement `Interaction` directly. Generate
and save recovery material before enrollment; imported recovery bytes must be
uniformly random. Protect any copies made through `expose`.

`Enrollment::with_kdf_cost` sets Argon2id work; `Protector::with_max_kdf_cost`
bounds execution before prompts. `KdfCost::DEFAULT` uses 256 MiB, three passes,
four lanes; `INTERACTIVE` uses 64 MiB, three passes, one lane.

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

## Data operations

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
See [security](security.md) for staging, old-copy and rollback limits.
