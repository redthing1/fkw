# fkw

Key protection and sealed data, as a Rust library and a compact CLI.

- **Choose your protection:** passphrases, security keys, system keystores, or recovery secrets.
- **Combine factors:** require a security key plus a passphrase or keystore factor; add alternative methods for backup access.
- **Seal text and files:** complete verification before plaintext is released and bounded memory for large files.
- **Load native support on demand:** security keys use libfido2; other methods work without it.

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

Use `derive_key` for application keys or `seal` for complete data operations.
Byte helpers accept up to 1 MiB; file helpers process larger inputs with bounded
memory. See [library usage](doc/integration.md) for methods and lifecycle.

## CLI

```sh
cargo install --git https://github.com/redthing1/fkw --locked

fkw seal --text --armor -w passphrase
fkw seal archive.tar -w key --uv
fkw open archive.tar.fkw -o restored.tar
```

Seal files, pipe data, manage access methods, and create recovery secrets.
See [CLI usage](doc/tool.md) for examples and options.

[Platform support](doc/platform-storage.md) · [Security model](doc/security.md) · [File format](doc/format-v2.md)
