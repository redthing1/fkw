# fido-key-wrap

A Rust library for protecting application keys and sealing text or files with
passphrases, security keys, system keystores, recovery secrets, or supported
two-factor combinations. Native security-key support loads on demand.

Multiple methods are alternative ways to unlock the same key. Combined methods
require both factors. Unlocking selects one method explicitly, without fallback.

```rust
use fido_key_wrap::{
    ApplicationId, Enrollment, Method, Passphrase, Protector, Result, seal,
};

fn seal_note(passphrase: Vec<u8>, text: &[u8]) -> Result<Vec<u8>> {
    let protector = Protector::new(ApplicationId::new("notes.example")?)
        .allow_only([Method::Passphrase])?;
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
cargo install --path crates/fkw-tool
fkw seal --text -o note.fkw
fkw open note.fkw
```

See [library usage](doc/integration.md), [CLI usage](doc/tool.md),
[platform support](doc/platform-storage.md), and [security](doc/security.md).
The [format](doc/format-v2.md) has not been independently audited.
