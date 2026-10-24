# Security

Protection depends on the weakest enrolled alternative. Combined methods require
both factors. A compromised host can capture secrets and plaintext during use.
Passphrase protection depends on entropy and Argon2 work; keystore guarantees
depend on the [selected platform policy](platform-storage.md).

## Authentication

The [format](format-v2.md) fixes cryptographic primitives, key separation and
resource bounds. Callers cannot supply nonces or custom factor combiners.
The complete envelope is authenticated before returning an unlocked key.
Successful opening verifies every payload frame, order and completion before
releasing plaintext. Method updates authenticate the header without checking
the copied payload again.

Security-key results require verified signatures, credential identity and exact
presence/UV flags. There is no method fallback, PIN retry or UV downgrade.
Attestation verification does not establish vendor trust. Native FIDO code is
isolated in its adapter; core and platform storage forbid unsafe Rust.

## Storage and deletion

Secret buffers are zeroized where supported. This does not erase swap, dumps,
OS buffers or application copies. File decryption and stdout spooling stage
plaintext on disk; deletion is not secure erasure. Use trusted directories and
appropriate disk protection. Labels, methods, credential metadata and approximate
payload length are public.

Method removal does not revoke old copies. Explicit factor retirement can also
disable backups using that factor; non-discoverable credentials cannot be
individually retired. Retirement requires an authenticated surviving method.
Nothing deletes external factors in `Drop`. Root rotation re-encrypts data;
rollback detection requires trusted state outside the container.
