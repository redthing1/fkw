# Platform support

Security-key operations dynamically load libfido2 on Linux and macOS. Public-key
encryption and signature verification do not require it. Security-key protection
and signing require FIDO2, ES256, credential protection, and a configured client
PIN. Protection additionally requires `hmac-secret`. Diagnostics report
requirements for the requested operation.

Native keystore factors are random 32-byte values scoped by trusted application
identity, method ID and access policy.

| Access | macOS | Linux |
| --- | --- | --- |
| `Standard` | Data-protection keychain; requires application signing | Default Secret Service collection, encrypted session |
| `UserAuthentication` | Data-protection keychain with OS user authentication | Unsupported |
| `MacosLogin` | Login keychain for unsigned command-line tools | Unsupported |

Unsupported policies fail without fallback. Standard macOS entries use
`WhenUnlockedThisDeviceOnly`; authenticated entries use
`WhenPasscodeSetThisDeviceOnly` with user presence. The OS chooses acceptable
authentication. Login-keychain access follows that keychain's policy. Linux
Secret Service does not promise per-read biometric or PIN authorization.

`Protector::with_keystore` accepts a trusted `Keystore` adapter. Its contract
requires exact access enforcement, create-only writes with verified read-back,
rejection of ambiguous entries, and removal matching the expected factor.
`StateUncertain` reports an unconfirmed mutation. Envelopes cannot select an
arbitrary provider, executable or path. The platform crate's optional `testing`
feature supplies `MemoryStore` for tests.
