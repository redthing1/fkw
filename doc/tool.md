# CLI usage

```sh
cargo install --git https://github.com/redthing1/fkw --locked
fkw seal --text --armor -w passphrase
fkw seal archive.tar -w key+passphrase --uv -n primary
fkw open archive.tar.fkw -o restored.tar
```

`seal FILE` creates `FILE.fkw`. `open` requires an explicit destination and
verifies the entire file before releasing plaintext. Access edits update the
input file; `-o` writes a separate copy. Explicit destinations must be new files.
Use `fkw COMMAND --help` for all options.

For `seal` and `open`:

| Option | Use |
| --- | --- |
| `-t`, `--text` | Enter a single hidden line; no secret argument |
| Input `-` or omitted | Read piped stdin |
| `-o FILE` | Write a new file |
| `-c`, `--stdout` | Write to stdout; `-o -` also works |
| `--armor` | Seal as printable text; defaults to stdout without an input filename |

Encrypted inputs accept binary or armored data. Files use bounded memory;
some operations need temporary disk space. New files are private on Unix.
Original filenames and permissions are not stored.

Choose protection with `-w` / `--with`, or select interactively: `key`,
`passphrase`, `key+passphrase`, `keystore`, `key+keystore`, or `recovery`.
The [recommended method](security.md#recommended-protection) is
`-w key+passphrase --uv`.

Passphrases and PINs use hidden prompts. Key enrollment always requires a PIN.
Unlocking follows the enrolled policy: touch only, or PIN + touch if enrolled
with `--uv`. `--managed` creates a discoverable credential. Keystore methods
accept `--store-access`; see [platform support](platform-storage.md).

## Public-key encryption

```sh
fkw recipient create identity.fkw -w key+passphrase --uv
fkw seal message.txt --to identity.fkw.pub
fkw open message.txt.fkw --identity identity.fkw -o restored.txt
```

Creation writes the protected identity and its `.pub` file. Senders need only
that public file, obtained through a trusted channel. Keep `identity.fkw` for
decryption; manage its protection and recovery with the same `access` commands
below. `verify FILE --identity identity.fkw` checks ciphertext without output.
Use `recipient public identity.fkw -o recipient.pub` to export the public key again.

## Signing

```sh
fkw signer create signer.key
fkw sign archive.tar --key signer.key
fkw verify archive.tar --signature archive.tar.sig --key signer.key.pub
```

Creation requires PIN and touch, and writes `signer.key` and `signer.key.pub`.
The key file holds the credential handle; the token performs signing. Back up
this file, and give verifiers the `.pub` file through a trusted channel.
Verification needs no token or libfido2 installation.

`sign FILE` writes `FILE.sig`. Use `-o FILE` for another destination; signing
piped stdin requires input `-` and `-o FILE`.

The signature purpose defaults to `file`. Set `--purpose NAME` on both `sign` and
`verify` for another use. `signer public signer.key -o signer.pub` exports the
public key again without the token. Recovery secrets cannot restore signing
credentials on a replacement token.

## Access methods

```sh
fkw access add archive.tar.fkw -w key+passphrase --uv -n spare
fkw recovery backup.key
fkw access add archive.tar.fkw \
  -w recovery -n backup --new-recovery-file backup.key
fkw info archive.tar.fkw
fkw verify archive.tar.fkw -u backup -r backup.key
fkw open archive.tar.fkw -u backup -r backup.key -o recovered.tar
fkw access replace archive.tar.fkw primary -w key+passphrase --uv
fkw access remove archive.tar.fkw primary -u backup -r backup.key
```

Methods are alternative ways to unlock; combined recipes require both factors.
Adding a key first unlocks with an existing method, then prompts for the new key.
`-n` / `--name` sets a unique public label. Labels default to the recipe name,
numbered as needed (`key`, `key-2`, …); replacing keeps the old label.
`-u` / `--using` selects an exact label or a unique ID prefix of at least four
characters. A sole method is selected automatically; otherwise you choose
interactively. `--no-input` disables terminal questions.
`info` lists a protected file's unverified methods; `verify` authenticates it.

Recovery files hold 32 random bytes. Keep them separate from sealed data; Unix
reads require private permissions. `-r` supplies the unlocking secret, or the
secret for a new recovery method. `--new-recovery-file` supplies a separate
secret when adding or replacing a method.

Access edits verify the input and result, then atomically replace the file,
preserving payload ciphertext and binary or armored encoding. Removing a method
in place requires unlocking through a method you are keeping. Use `-o FILE` for
stdin or to keep the original. Older copies and external factors retain access;
retirement and key rotation are library operations.

## Failed saves

A save error reports any retained work. For encryption and access edits, use the
completed `sealed.fkw`, or retry with its `envelope` snapshot:

```sh
fkw seal original.tar --resume work/envelope -o archive.fkw
fkw access restore original.fkw --envelope work/envelope -o updated.fkw
```

Supply the snapshot's factors as usual. Retrying reuses enrollment. Keep the
original input until saving succeeds, then delete the retained work directory.
If snapshot persistence fails or enrollment is interrupted, an external factor
may remain without a usable snapshot.
