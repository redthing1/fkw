# fido-key-wrap

A Rust library for protecting keys and sealing data with passphrases, security
keys, system keystores, recovery secrets, or key-based two-factor combinations.
Native security-key support loads on demand.

Multiple methods are alternative ways to unlock the same key. Combined methods
require both factors. Unlocking selects one method explicitly, without fallback.

```rust
use fido_key_wrap::{
    ApplicationId, Enrollment, Method, Passphrase, Protector, Result, seal,
};

fn seal_note(passphrase: Vec<u8>, text: &[u8]) -> Result<Vec<u8>> {
    let protector = Protector::new(ApplicationId::new("notes.example")?);
    let mut input = Passphrase::new(passphrase)?;
    let key = protector.create(
        &Enrollment::new(Method::Passphrase, "personal")?,
        &mut input,
    )?;
    seal::seal_bytes(&key, text)
}
```

The byte API handles up to 1 MiB; file APIs use bounded memory. Opening verifies
the complete contents before releasing plaintext. File outputs never overwrite
an existing destination.

## CLI

```sh
cargo install --git https://github.com/redthing1/fido_key_wrap --locked
fkw seal --text --armor -w passphrase
fkw seal archive.tar -w key --uv
fkw open archive.tar.fkw -o restored.tar
```

See [library usage](doc/integration.md), [CLI usage](doc/tool.md),
[platform support](doc/platform-storage.md), and [security](doc/security.md).
The [format](doc/format-v2.md) has not been independently audited.
