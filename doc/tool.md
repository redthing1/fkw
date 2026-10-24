# fkw

```sh
cargo install --path crates/fkw-tool
fkw seal --text -o note.fkw
fkw open note.fkw
fkw seal archive.tar -o archive.fkw --method key --uv --managed
fkw open archive.fkw -o restored.tar
```

Passphrases, PINs and `--text` use hidden terminal prompts. Omit the input path
to seal piped stdin. Opening without `-o` writes to stdout after complete
verification. Destinations are never overwritten. Original filenames and
permissions are not preserved.

`--method` accepts `passphrase` (default), `key`, `keystore`, `key-passphrase`,
`key-keystore`, or `recovery`. Key methods accept `--uv` and `--managed`;
enrollment requires a configured PIN. Keystore methods accept
`--store-access standard|user-authentication|macos-login`; see
[platform support](platform-storage.md). `--kdf-memory` accepts 65536–262144 KiB,
divisible by 16, for passphrase methods.

The default application identity is `io.fido-key-wrap.cli`. Use the same
`--application` value when sealing and opening another namespace.

## Recovery and method changes

```sh
fkw recovery backup.key
fkw methods add archive.fkw -o with-backup.fkw \
  --method recovery --new-recovery-file backup.key --label backup
fkw inspect with-backup.fkw
fkw open with-backup.fkw --method-id METHOD_ID --recovery-file backup.key
fkw methods remove with-backup.fkw -o updated.fkw \
  --unlock BACKUP_ID --remove OLD_ID --recovery-file backup.key
```

Keep recovery files separate from encrypted data. They contain 32 random bytes;
Unix reads require private permissions. `inspect` shows unverified metadata.
Multiple methods require an exact ID: `--method-id` to open, `--unlock` to edit.
`methods replace` takes `--remove OLD_ID` and the new method's enrollment options.

Edits write a new container with unchanged payload ciphertext. They authenticate
the old header without rechecking the payload. Verify the saved result before
deleting an old copy. If saving fails after enrollment, external factors may remain.

## Factor retirement

Removing a method leaves its factors intact. Keep the old container and a saved
updated container with that method removed:

```sh
fkw methods retire old.fkw --method-id OLD_ID \
  --survivor updated.fkw --verify-with SURVIVOR_ID --factor credential
```

The command independently unlocks and fully verifies the survivor before deletion.
`--factor credential` requires a managed credential; `--factor keystore` deletes
the stored factor without needing the old security key. Combined factors may be
retired in either order. Repeating keystore cleanup is harmless. Retirement also
affects backups using that factor; a failure does not imply rollback.

`fkw devices` reports native capabilities without creating credentials.
