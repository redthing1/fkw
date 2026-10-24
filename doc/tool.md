# fkw

```sh
cargo install --git https://github.com/redthing1/fido_key_wrap --locked
fkw seal --text --armor -w passphrase
fkw seal archive.tar -w key --uv
fkw open archive.tar.fkw -o restored.tar
```

`seal FILE` creates `FILE.fkw`. `open` requires an explicit destination and
verifies the entire file before releasing plaintext. Existing files are never
overwritten; originals are preserved. Use `fkw COMMAND --help` for all options.

| Option | Use |
| --- | --- |
| `-t`, `--text` | Enter a single hidden line; no secret argument |
| Input `-` or omitted | Read piped stdin |
| `-o FILE` | Write a new file |
| `-c`, `--stdout` | Write to stdout; `-o -` also works |
| `--armor` | Seal as printable text; defaults to stdout without an input filename |

Binary and armored files work with every reading command. Files use bounded
memory; some operations need temporary disk space. New files are private on Unix.
Original filenames and permissions are not stored. See [security](security.md).

Choose protection with `-w` / `--with`, or select interactively: `key`,
`passphrase`, `key+passphrase`, `keystore`, `key+keystore`, or `recovery`.
Passphrases and PINs use hidden prompts. Keys use touch by default; `--uv` requires
user verification and `--managed` creates a discoverable credential. Enrollment
requires a configured PIN. Keystore methods accept `--store-access`; see
[platform support](platform-storage.md). Policies never fall back to weaker ones.

## Access methods

```sh
fkw recovery backup.key
fkw access add archive.tar.fkw -o backed-up.fkw \
  -w recovery -n backup --new-recovery-file backup.key
fkw info backed-up.fkw
fkw verify backed-up.fkw -u backup -r backup.key
fkw open backed-up.fkw -u backup -r backup.key -o recovered.tar
fkw access replace backed-up.fkw key -o replaced.fkw -w key --uv
fkw access remove backed-up.fkw key -u backup -r backup.key -o updated.fkw
```

Methods are alternative ways to unlock; combined recipes require both factors.
`-n` / `--name` sets a unique public label. Adding defaults to the recipe name;
replacing keeps the old label. `-u` / `--using` selects an exact label or unique
ID prefix of at least four characters. A sole method is selected automatically;
otherwise you choose interactively. `--no-input` disables terminal questions.
`info` lists unverified metadata; `verify` authenticates the complete file.

Recovery files hold 32 random bytes. Keep them separate from sealed data; Unix
reads require private permissions. `-r` supplies the unlocking secret, or the
secret for a new recovery method. `--new-recovery-file` supplies a separate
secret when adding or replacing a method.

Access edits verify the input and result, preserving payload ciphertext.
Removal and replacement affect only the new copy. Older copies and external
factors retain access; retirement and key rotation are library operations.

## Failed saves

A save error identifies retained work and the available recovery option. Use a
completed `sealed.fkw`, or retry with its `envelope` snapshot:

```sh
fkw seal original.tar --resume work/envelope -o archive.fkw
fkw access restore original.fkw --envelope work/envelope -o updated.fkw
```

Supply the snapshot's factors as usual. Retrying reuses enrollment. Keep the
original input until saving succeeds, then delete the retained work directory.
If snapshot persistence fails or enrollment is interrupted, an external factor
may remain without a usable snapshot.
