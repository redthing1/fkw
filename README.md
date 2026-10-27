# fkw

A Rust library and CLI for protected keys, encryption, and FIDO2 signatures.
Combine security keys, passphrases, system keystores, or recovery secrets.
Change access methods without changing derived keys or re-encrypting payloads.

## Library

```toml
[dependencies]
fkw = { git = "https://github.com/redthing1/fkw" }
```

```rust
use fkw::{ApplicationId, Enrollment, Method, Passphrase, Protector, Result, seal};

fn seal_note(passphrase: Vec<u8>, text: &[u8]) -> Result<Vec<u8>> {
    let protector = Protector::new(ApplicationId::new("notes.example")?);
    let enrollment = Enrollment::new(Method::Passphrase, "personal")?;
    let key = protector.create(&enrollment, &mut Passphrase::new(passphrase)?)?;
    seal::seal_bytes(&key, text)
}
```

Use `derive_key` for application keys, `seal` for protected data, `recipient` for
public-key encryption, and `sign` for hardware signatures with offline verification.

## CLI

```sh
cargo install --git https://github.com/redthing1/fkw --locked

fkw seal archive.tar -w key+passphrase --uv
fkw open archive.tar.fkw -o restored.tar
```

[Library usage](doc/integration.md) · [CLI usage](doc/tool.md) ·
[Design and security](doc/security.md) · [Platforms](doc/platform-storage.md) · [Format](doc/format-v2.md)
