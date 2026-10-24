# fkw

A Rust library and CLI for protecting keys and sealing data with passphrases,
security keys, system keystores, or recovery secrets. Combine factors and change
access methods without re-encrypting payloads.

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

Use `derive_key` for application keys or `seal` for data.

## CLI

```sh
cargo install --git https://github.com/redthing1/fkw --locked

fkw seal archive.tar -w key+passphrase --uv
fkw open archive.tar.fkw -o restored.tar
```

[Library usage](doc/integration.md) · [CLI usage](doc/tool.md) ·
[Design and security](doc/security.md) · [Platforms](doc/platform-storage.md) · [Format](doc/format-v2.md)
