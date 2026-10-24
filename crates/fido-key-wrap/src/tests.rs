use crate::platform::fake::Device;
use crate::*;
use fido_key_wrap_platform::testing::MemoryStore;
use std::{
    fs,
    sync::{Arc, atomic::Ordering::SeqCst},
};

fn protector() -> Protector {
    Protector::new(ApplicationId::new("vault.example").unwrap())
}
fn enrollment(method: Method) -> Enrollment {
    let e = Enrollment::new(method, "test").unwrap();
    if method.needs_passphrase() {
        e.with_kdf_cost(KdfCost::INTERACTIVE).unwrap()
    } else {
        e
    }
}
fn secret(byte: u8) -> RecoverySecret {
    RecoverySecret::import(&mut [byte; 32])
}
fn recovery_key() -> (Protector, RecoverySecret, UnlockedKey) {
    let protector = protector();
    let secret = secret(1);
    let key = protector
        .create(&enrollment(Method::RecoverySecret), &mut &secret)
        .unwrap();
    (protector, secret, key)
}
fn id(key: &UnlockedKey) -> MethodId {
    key.envelope().methods().next().unwrap().id
}
fn same_key(a: &UnlockedKey, b: &UnlockedKey) {
    assert_eq!(
        a.derive_key("test").unwrap().expose(|k| *k),
        b.derive_key("test").unwrap().expose(|k| *k)
    );
}
#[derive(Default)]
struct UI {
    passwords: usize,
    pins: usize,
    touches: usize,
    cancel: bool,
    mismatch: bool,
}
impl Interaction for UI {
    fn passphrase(&mut self, _: Prompt<'_>, purpose: PassphrasePurpose) -> Result<Passphrase> {
        self.passwords += 1;
        if self.cancel {
            return Err(Error::Cancelled);
        }
        Passphrase::new(if self.mismatch && purpose == PassphrasePurpose::Confirm {
            b"wrong".to_vec()
        } else {
            b"correct horse battery staple".to_vec()
        })
    }
    fn pin(&mut self, _: Prompt<'_>) -> Result<Pin> {
        self.pins += 1;
        Ok(Pin::new("123456").unwrap())
    }
    fn touch(&mut self, _: Prompt<'_>) -> Result<()> {
        self.touches += 1;
        Ok(())
    }
}

#[test]
fn recovery_round_trip_purpose_separation_and_redaction() {
    let (p, s, key) = recovery_key();
    let bytes = key.envelope().to_bytes();
    let envelope = Envelope::from_bytes(&bytes).unwrap();
    let opened = p.unlock(&envelope, id(&key), &mut &s).unwrap();
    same_key(&key, &opened);
    assert_ne!(
        key.derive_key("a").unwrap().expose(|x| *x),
        key.derive_key("b").unwrap().expose(|x| *x)
    );
    assert!(key.derive_key("").is_err());
    assert!(format!("{key:?}").contains("[REDACTED]"));
    assert!(matches!(
        p.unlock(&envelope, id(&key), &mut &secret(9)),
        Err(Error::UnlockFailed)
    ));
}
#[test]
fn passphrase_round_trip_and_confirmation() {
    let p = protector();
    let mut ui = UI::default();
    let key = p.create(&enrollment(Method::Passphrase), &mut ui).unwrap();
    assert_eq!(ui.passwords, 2);
    same_key(&key, &p.unlock(key.envelope(), id(&key), &mut ui).unwrap());
    let bad = Passphrase::new(b"wrong".to_vec()).unwrap();
    assert!(matches!(
        p.unlock(key.envelope(), id(&key), &mut &bad),
        Err(Error::UnlockFailed)
    ));
    let mut mismatch = UI {
        mismatch: true,
        ..UI::default()
    };
    assert!(matches!(
        p.create(&enrollment(Method::Passphrase), &mut mismatch),
        Err(Error::ConfirmationMismatch)
    ));
    assert_eq!(ui.pins, 0);
}
#[test]
fn policy_and_application_reject_before_interaction() {
    let (p, s, mut key) = recovery_key();
    p.add_method(
        &mut key,
        &enrollment(Method::Passphrase),
        &mut UI::default(),
    )
    .unwrap();
    let mut ui = UI::default();
    let wrong = Protector::new(ApplicationId::new("other.example").unwrap());
    assert!(matches!(
        wrong.unlock(key.envelope(), id(&key), &mut ui),
        Err(Error::WrongApplication)
    ));
    let restricted = protector().allow_only([Method::RecoverySecret]).unwrap();
    assert!(matches!(
        restricted.unlock(key.envelope(), id(&key), &mut &s),
        Err(Error::MethodNotAllowed)
    ));
    assert_eq!(ui.passwords + ui.pins + ui.touches, 0);
}
#[test]
fn resource_limits_apply_only_to_selected_route() {
    let (p, s, mut key) = recovery_key();
    let password = p
        .add_method(
            &mut key,
            &enrollment(Method::Passphrase),
            &mut UI::default(),
        )
        .unwrap();
    // Build an authenticated high-cost record without executing its KDF.
    key.envelope
        .records
        .iter_mut()
        .find(|r| r.id == password)
        .unwrap()
        .kdf
        .as_mut()
        .unwrap()
        .cost = KdfCost::MAX;
    key.envelope.sign(&key.root);
    let bounded = protector().with_max_kdf_cost(KdfCost::INTERACTIVE);
    same_key(
        &key,
        &bounded.unlock(key.envelope(), id(&key), &mut &s).unwrap(),
    );
    let mut ui = UI::default();
    assert!(matches!(
        bounded.unlock(key.envelope(), password, &mut ui),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(ui.passwords, 0);
    assert!(matches!(
        bounded.create(
            &Enrollment::new(Method::Passphrase, "new").unwrap(),
            &mut ui
        ),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(ui.passwords, 0);
    // The costly record alone does not prevent decoding.
    Envelope::from_bytes(&key.envelope.to_bytes()).unwrap();
    drop(p);
}
#[test]
fn authenticates_unselected_metadata_and_entire_method_set() {
    let (p, s, mut key) = recovery_key();
    let other = p
        .add_method(
            &mut key,
            &enrollment(Method::RecoverySecret),
            &mut &secret(2),
        )
        .unwrap();
    let original = key.envelope.clone();
    key.envelope
        .records
        .iter_mut()
        .find(|r| r.id == other)
        .unwrap()
        .label = "tampered".into();
    assert!(matches!(
        p.unlock(&key.envelope, id(&key), &mut &s),
        Err(Error::UnlockFailed)
    ));
    key.envelope = original.clone();
    key.envelope.records.reverse();
    assert!(matches!(
        p.unlock(&key.envelope, id(&key), &mut &secret(2)),
        Err(Error::UnlockFailed)
    ));
    key.envelope = original;
    key.envelope.records.pop();
    assert!(matches!(
        p.unlock(&key.envelope, id(&key), &mut &s),
        Err(Error::UnlockFailed)
    ));
}
#[test]
fn edits_are_atomic_and_cannot_remove_last_method() {
    let (p, s, mut key) = recovery_key();
    let first = id(&key);
    let before = key.envelope.to_bytes();
    assert!(matches!(
        p.remove_method(&mut key, first),
        Err(Error::LastMethod)
    ));
    assert!(matches!(
        p.add_method(
            &mut key,
            &enrollment(Method::Passphrase),
            &mut UI {
                cancel: true,
                ..UI::default()
            }
        ),
        Err(Error::Cancelled)
    ));
    assert!(matches!(
        p.replace_method(
            &mut key,
            first,
            &enrollment(Method::Passphrase),
            &mut UI {
                mismatch: true,
                ..UI::default()
            }
        ),
        Err(Error::ConfirmationMismatch)
    ));
    assert_eq!(before, key.envelope.to_bytes());
    let second_secret = secret(2);
    let second = p
        .replace_method(
            &mut key,
            first,
            &enrollment(Method::RecoverySecret),
            &mut &second_secret,
        )
        .unwrap();
    assert!(matches!(
        p.unlock(key.envelope(), first, &mut &s),
        Err(Error::MethodNotFound)
    ));
    same_key(
        &key,
        &p.unlock(key.envelope(), second, &mut &second_secret)
            .unwrap(),
    );
    // A saved old copy remains unlockable; removal is not retroactive revocation.
    same_key(
        &key,
        &p.unlock(&Envelope::from_bytes(&before).unwrap(), first, &mut &s)
            .unwrap(),
    );
}
#[test]
fn all_supported_key_recipes_and_exact_prompt_policy() {
    for verification in [Verification::Presence, Verification::UserVerified] {
        for storage in [
            CredentialStorage::NonDiscoverable,
            CredentialStorage::Managed,
        ] {
            let options = KeyOptions {
                verification,
                storage,
            };
            for method in [
                Method::SecurityKey(options),
                Method::KeyAndPassphrase(options),
                Method::KeyAndKeystore(options, StoreAccess::Standard),
            ] {
                let device = Arc::new(Device::default());
                let p = protector()
                    .with_test_device(device)
                    .with_keystore(MemoryStore::default());
                let mut ui = UI::default();
                let key = p.create(&enrollment(method), &mut ui).unwrap();
                assert_eq!(ui.pins, 1);
                assert_eq!(ui.passwords, if method.needs_passphrase() { 2 } else { 0 });
                ui = UI::default();
                same_key(&key, &p.unlock(key.envelope(), id(&key), &mut ui).unwrap());
                assert_eq!(
                    ui.pins,
                    usize::from(verification == Verification::UserVerified)
                );
                assert_eq!(ui.passwords, usize::from(method.needs_passphrase()));
            }
        }
    }
}
#[test]
fn outer_fido_failure_precedes_password_and_pin_is_never_retried() {
    let device = Arc::new(Device::default());
    let p = protector().with_test_device(Arc::clone(&device));
    let method = Method::KeyAndPassphrase(KeyOptions::new(Verification::UserVerified));
    let key = p.create(&enrollment(method), &mut UI::default()).unwrap();
    let calls = device.calls.load(SeqCst);
    device.wrong_secret.store(true, SeqCst);
    let mut ui = UI::default();
    assert!(matches!(
        p.unlock(key.envelope(), id(&key), &mut ui),
        Err(Error::UnlockFailed)
    ));
    assert_eq!(ui.passwords, 0);
    assert_eq!(ui.pins, 1);
    device.pin_invalid.store(true, SeqCst);
    ui = UI::default();
    assert!(matches!(
        p.unlock(key.envelope(), id(&key), &mut ui),
        Err(Error::Fido(diagnostics::FidoError::PinInvalid { .. }))
    ));
    assert_eq!(ui.pins, 1);
    assert_eq!(ui.passwords, 0);
    assert_eq!(device.calls.load(SeqCst), calls + 2);
}
#[test]
fn failed_managed_enrollment_cleans_up_or_reports_uncertain() {
    let device = Arc::new(Device::default());
    let p = protector().with_test_device(Arc::clone(&device));
    let s = secret(1);
    let mut key = p
        .create(&enrollment(Method::RecoverySecret), &mut &s)
        .unwrap();
    let before = key.envelope.to_bytes();
    let request = enrollment(Method::KeyAndPassphrase(
        KeyOptions::new(Verification::Presence).managed(),
    ));
    let mut ui = UI {
        cancel: true,
        ..UI::default()
    };
    assert!(matches!(
        p.add_method(&mut key, &request, &mut ui),
        Err(Error::Cancelled)
    ));
    assert_eq!(device.cleanups.load(SeqCst), 1);
    device.cleanup_fails.store(true, SeqCst);
    assert!(matches!(
        p.add_method(&mut key, &request, &mut ui),
        Err(Error::EnrollmentUncertain { .. })
    ));
    assert_eq!(before, key.envelope.to_bytes());
}
#[test]
fn recovery_does_not_require_an_unselected_platform_factor() {
    let s = secret(1);
    let p = protector().with_keystore(MemoryStore::default());
    let mut key = p
        .create(
            &enrollment(Method::Keystore(StoreAccess::Standard)),
            &mut (),
        )
        .unwrap();
    same_key(&key, &p.unlock(key.envelope(), id(&key), &mut ()).unwrap());
    let recovery = p
        .add_method(&mut key, &enrollment(Method::RecoverySecret), &mut &s)
        .unwrap();
    same_key(
        &key,
        &protector()
            .unlock(key.envelope(), recovery, &mut &s)
            .unwrap(),
    );
    let stored = id(&key);
    assert!(matches!(
        p.remove_store_factor(key.envelope(), stored, &key),
        Err(Error::InvalidInput(_))
    ));
    let mut survivor = p.unlock(key.envelope(), recovery, &mut &s).unwrap();
    p.remove_method(&mut survivor, stored).unwrap();
    let (_, _, unrelated) = recovery_key();
    assert!(matches!(
        p.remove_store_factor(key.envelope(), stored, &unrelated),
        Err(Error::UnlockFailed)
    ));
    assert_eq!(
        p.remove_store_factor(key.envelope(), stored, &survivor)
            .unwrap(),
        Removal::Removed
    );
    assert!(matches!(
        p.unlock(key.envelope(), stored, &mut ()),
        Err(Error::Store(StoreError::Missing))
    ));
    same_key(&key, &p.unlock(key.envelope(), recovery, &mut &s).unwrap());
}
#[test]
fn combined_store_cleanup_needs_only_an_authenticated_survivor_and_is_retryable() {
    let store = Arc::new(MemoryStore::default());
    let device = Arc::new(Device::default());
    let p = protector()
        .with_test_device(Arc::clone(&device))
        .with_keystore(Arc::clone(&store));
    let mut key = p
        .create(
            &enrollment(Method::KeyAndKeystore(
                KeyOptions::new(Verification::UserVerified).managed(),
                StoreAccess::Standard,
            )),
            &mut UI::default(),
        )
        .unwrap();
    let removed = id(&key);
    let recovery = secret(2);
    let backup = p
        .add_method(
            &mut key,
            &enrollment(Method::RecoverySecret),
            &mut &recovery,
        )
        .unwrap();
    let old = key.envelope().clone();
    p.remove_method(&mut key, removed).unwrap();

    // No access to the original device, as after loss or credential retirement.
    let cleanup = protector().with_keystore(Arc::clone(&store));
    let saved = Envelope::from_bytes(&key.envelope().to_bytes()).unwrap();
    let survivor = cleanup.unlock(&saved, backup, &mut &recovery).unwrap();
    let mut tampered = old.clone();
    tampered.records[0].label = "changed".into();
    assert!(matches!(
        cleanup.remove_store_factor(&tampered, removed, &survivor),
        Err(Error::UnlockFailed)
    ));
    assert!(matches!(
        cleanup.retire_credential(&tampered, removed, &survivor, &mut ()),
        Err(Error::UnlockFailed)
    ));
    assert!(matches!(
        Protector::new(ApplicationId::new("other.example").unwrap())
            .with_keystore(Arc::clone(&store))
            .remove_store_factor(&old, removed, &survivor),
        Err(Error::WrongApplication)
    ));
    let calls = device.calls.load(SeqCst);
    assert_eq!(
        cleanup
            .remove_store_factor(&old, removed, &survivor)
            .unwrap(),
        Removal::Removed
    );
    assert_eq!(
        cleanup
            .remove_store_factor(&old, removed, &survivor)
            .unwrap(),
        Removal::Absent
    );
    assert_eq!(device.calls.load(SeqCst), calls);
    assert!(matches!(
        store.load("vault.example", removed.as_bytes(), StoreAccess::Standard),
        Err(StoreError::Missing)
    ));
    same_key(
        &key,
        &cleanup.unlock(&saved, backup, &mut &recovery).unwrap(),
    );
}
#[test]
fn uncertain_store_creation_preserves_old_envelope() {
    struct Uncertain;
    impl Keystore for Uncertain {
        fn create(
            &self,
            _: &str,
            _: &[u8; 32],
            _: StoreAccess,
            _: &StoreSecret,
        ) -> std::result::Result<(), StoreError> {
            Err(StoreError::StateUncertain)
        }
        fn load(
            &self,
            _: &str,
            _: &[u8; 32],
            _: StoreAccess,
        ) -> std::result::Result<StoreSecret, StoreError> {
            panic!("unexpected load")
        }
        fn remove(
            &self,
            _: &str,
            _: &[u8; 32],
            _: StoreAccess,
            _: &StoreSecret,
        ) -> std::result::Result<Removal, StoreError> {
            panic!("unexpected removal")
        }
    }
    let (p, s, mut key) = recovery_key();
    let before = key.envelope.to_bytes();
    let uncertain = protector().with_keystore(Uncertain);
    assert!(matches!(
        uncertain.add_method(
            &mut key,
            &enrollment(Method::Keystore(StoreAccess::Standard)),
            &mut ()
        ),
        Err(Error::EnrollmentUncertain { .. })
    ));
    assert_eq!(before, key.envelope.to_bytes());
    p.unlock(key.envelope(), id(&key), &mut &s).unwrap();
}
#[test]
fn strict_envelope_parser_rejects_noncanonical_truncated_and_ambiguous_input() {
    let (p, s, key) = recovery_key();
    let bytes = key.envelope.to_bytes();
    for end in 0..bytes.len() {
        assert!(Envelope::from_bytes(&bytes[..end]).is_err());
    }
    let mut extended = bytes.clone();
    extended.push(0);
    assert!(Envelope::from_bytes(&extended).is_err());
    let mut noncanonical = bytes.clone();
    noncanonical.splice(5..6, [0x18, 2]);
    assert!(Envelope::from_bytes(&noncanonical).is_err());
    assert!(Envelope::from_bytes(&vec![0; 65_537]).is_err());
    let mut duplicate = key.envelope.clone();
    duplicate.records.push(duplicate.records[0].clone());
    assert!(Envelope::from_bytes(&duplicate.to_bytes()).is_err());
    let mut wrong_material = key.envelope.clone();
    wrong_material.records[0].method = Method::Passphrase;
    assert!(Envelope::from_bytes(&wrong_material.to_bytes()).is_err());
    for offset in 0..bytes.len() {
        for bit in 0..8 {
            let mut changed = bytes.clone();
            changed[offset] ^= 1 << bit;
            if let Ok(envelope) = Envelope::from_bytes(&changed) {
                assert!(p.unlock(&envelope, id(&key), &mut &s).is_err());
            }
        }
    }
}
#[test]
fn byte_sealing_boundaries_randomization_and_every_truncation() {
    let (p, s, key) = recovery_key();
    for len in [
        0,
        1,
        65_535,
        65_536,
        65_537,
        131_072,
        seal::MAX_PLAINTEXT_BYTES,
    ] {
        let plain = vec![0xa5; len];
        let sealed = seal::seal_bytes(&key, &plain).unwrap();
        assert_eq!(
            *seal::open_bytes(&p, &sealed, id(&key), &mut &s).unwrap(),
            plain
        );
        assert_ne!(sealed, seal::seal_bytes(&key, &plain).unwrap());
    }
    let sealed = seal::seal_bytes(&key, b"short text").unwrap();
    for end in 0..sealed.len() {
        assert!(seal::open_bytes(&p, &sealed[..end], id(&key), &mut &s).is_err());
    }
    for offset in 0..sealed.len() {
        let mut changed = sealed.clone();
        changed[offset] ^= 1;
        assert!(seal::open_bytes(&p, &changed, id(&key), &mut &s).is_err());
    }
    let mut trailing = sealed;
    trailing.push(0);
    assert!(seal::open_bytes(&p, &trailing, id(&key), &mut &s).is_err());
    assert!(matches!(
        seal::seal_bytes(&key, &vec![0; seal::MAX_PLAINTEXT_BYTES + 1]),
        Err(Error::ResourceLimit)
    ));
}
fn payload_offset(bytes: &[u8]) -> usize {
    9 + u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize
}
#[test]
fn corrupt_files_never_publish_plaintext_or_access_updates() {
    let (p, s, key) = recovery_key();
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input");
    let output = directory.path().join("output");
    let sealed = seal::seal_bytes(&key, &vec![0x7a; 180_000]).unwrap();
    let start = payload_offset(&sealed) + 32;
    let frame_len = 5 + 65_536 + 16;
    let mut mutations = vec![
        sealed[..sealed.len() - 1].to_vec(),
        sealed[..start + frame_len].to_vec(),
    ];
    let mut corrupt = sealed.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    mutations.push(corrupt);
    let mut reordered = sealed.clone();
    reordered[start..start + frame_len]
        .copy_from_slice(&sealed[start + frame_len..start + 2 * frame_len]);
    reordered[start + frame_len..start + 2 * frame_len]
        .copy_from_slice(&sealed[start..start + frame_len]);
    mutations.push(reordered);
    let mut wrong_nonce = sealed.clone();
    wrong_nonce[start - 1] ^= 1;
    mutations.push(wrong_nonce);
    for bytes in mutations {
        fs::write(&input, bytes).unwrap();
        assert!(seal::open_file(&p, &input, &output, id(&key), &mut &s).is_err());
        assert!(!output.exists());
        let mut stdout = Vec::new();
        assert!(seal::open_to(&p, &input, &mut stdout, id(&key), &mut &s).is_err());
        assert_eq!(stdout, [] as [u8; 0]);
        assert!(seal::update_file(&key, &input, &output).is_err());
        assert!(!output.exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
    fs::write(&input, sealed).unwrap();
    fs::write(&output, b"existing").unwrap();
    assert!(seal::open_file(&p, &input, &output, id(&key), &mut &s).is_err());
    assert_eq!(fs::read(&output).unwrap(), b"existing");
    #[cfg(unix)]
    {
        fs::remove_file(&output).unwrap();
        std::os::unix::fs::symlink("missing", &output).unwrap();
        // Refuse even a dangling destination before requesting any factor.
        assert!(matches!(
            seal::open_file(&p, &input, &output, id(&key), &mut ()),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
        ));
        assert_eq!(
            fs::read_link(&output).unwrap(),
            std::path::Path::new("missing")
        );
        assert!(!directory.path().join("missing").exists());
    }
}
#[test]
fn method_updates_keep_payload_bytes_and_large_files_use_complete_operations() {
    let (p, s, mut key) = recovery_key();
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("plain");
    let old = directory.path().join("old");
    let new = directory.path().join("new");
    let output = directory.path().join("out");
    let plain = vec![0x89; 3 * 1024 * 1024 + 97];
    fs::write(&input, &plain).unwrap();
    seal::seal_file(&key, &input, &old).unwrap();
    let original_id = id(&key);
    let recovery = secret(2);
    let next = p
        .add_method(
            &mut key,
            &enrollment(Method::RecoverySecret),
            &mut &recovery,
        )
        .unwrap();
    p.remove_method(&mut key, original_id).unwrap();
    let pending = key.envelope().to_bytes();
    fs::write(&new, b"occupied").unwrap();
    assert!(matches!(
        seal::update_file(&key, &old, &new),
        Err(Error::Io(_))
    ));
    assert_eq!(fs::read(&new).unwrap(), b"occupied");
    assert_eq!(key.envelope().to_bytes(), pending);
    fs::remove_file(&new).unwrap();
    seal::update_file(&key, &old, &new).unwrap();
    let a = fs::read(&old).unwrap();
    let b = fs::read(&new).unwrap();
    assert_eq!(&a[payload_offset(&a)..], &b[payload_offset(&b)..]);
    seal::open_file(&p, &new, &output, next, &mut &recovery).unwrap();
    assert_eq!(fs::read(&output).unwrap(), plain);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o077,
            0
        );
    }
    let mut bytes = Vec::new();
    seal::open_to(&p, &old, &mut bytes, original_id, &mut &s).unwrap();
    assert_eq!(bytes, plain);
    let (_, _, unrelated) = recovery_key();
    assert!(matches!(
        seal::update_file(&unrelated, &old, directory.path().join("wrong")),
        Err(Error::UnlockFailed)
    ));
}

#[test]
fn failed_file_saves_keep_enrollment_for_retry_and_never_clobber_a_racing_output() {
    use std::io::{self, Read};
    struct BrokenReader;
    impl Read for BrokenReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("input failed"))
        }
    }
    struct RacingReader<'a> {
        destination: &'a std::path::Path,
        input: &'a [u8],
    }
    impl Read for RacingReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            fs::write(self.destination, b"another writer")?;
            self.input.read(buffer)
        }
    }
    let store = Arc::new(MemoryStore::default());
    let p = protector().with_keystore(Arc::clone(&store));
    let key = p
        .create(
            &enrollment(Method::Keystore(StoreAccess::Standard)),
            &mut (),
        )
        .unwrap();
    let snapshot = key.envelope().to_bytes();
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("sealed");
    let mut failing = io::repeat(0x5a).take(131_072).chain(BrokenReader);
    assert!(matches!(
        seal::seal_reader(&key, &mut failing, &output),
        Err(Error::Io(_))
    ));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    let mut racing = RacingReader {
        destination: &output,
        input: b"secret",
    };
    assert!(matches!(
        seal::seal_reader(&key, &mut racing, &output),
        Err(Error::Io(_))
    ));
    assert_eq!(fs::read(&output).unwrap(), b"another writer");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    assert_eq!(key.envelope().to_bytes(), snapshot);

    let retry = dir.path().join("retry");
    seal::seal_reader(&key, &mut b"secret".as_slice(), &retry).unwrap();
    assert_eq!(seal::inspect_file(&retry).unwrap().to_bytes(), snapshot);
    assert_eq!(
        &*seal::open_bytes(&p, &fs::read(retry).unwrap(), id(&key), &mut ()).unwrap(),
        b"secret"
    );
}

fn vector_fields(text: &str) -> std::collections::HashMap<&str, Vec<u8>> {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let (name, hex) = line.split_once('=').unwrap();
            let bytes = hex
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            (name, bytes)
        })
        .collect()
}
#[test]
fn independent_python_vectors_cover_every_recipe_and_stream_framing() {
    use sha2::{Digest, Sha256};
    let vectors = [
        include_str!("../../../test-vectors/format-2-0.txt"),
        include_str!("../../../test-vectors/format-2-1-0-0.txt"),
        include_str!("../../../test-vectors/format-2-1-1-1.txt"),
        include_str!("../../../test-vectors/format-2-2-0.txt"),
        include_str!("../../../test-vectors/format-2-2-1.txt"),
        include_str!("../../../test-vectors/format-2-2-2.txt"),
        include_str!("../../../test-vectors/format-2-3-0-0.txt"),
        include_str!("../../../test-vectors/format-2-3-1-1.txt"),
        include_str!("../../../test-vectors/format-2-4-0-0-0.txt"),
        include_str!("../../../test-vectors/format-2-4-1-1-1.txt"),
        include_str!("../../../test-vectors/format-2-5.txt"),
    ];
    for text in vectors {
        let v = vector_fields(text);
        let envelope = Envelope::from_bytes(&v["envelope"]).unwrap();
        assert_eq!(envelope.to_bytes(), v["envelope"]);
        let record = &envelope.records[0];
        let context = record.context(&envelope.application, &envelope.id);
        assert_eq!(context.as_slice(), v["context"]);
        assert_eq!(
            crypto::hash(&[b"fkw/v2/prf", &context]).as_slice(),
            v["prf_salt"]
        );
        let root: [u8; 32] = v["root"].as_slice().try_into().unwrap();
        envelope.verify(&root).unwrap();
        let password = record.kdf.as_ref().map(|kdf| {
            let raw = crypto::passphrase(
                &Passphrase::new(v["passphrase"].clone()).unwrap(),
                &kdf.salt,
                kdf.cost,
            )
            .unwrap();
            crypto::factor(raw.as_slice(), &context, b"passphrase")
        });
        let fido = crypto::factor(&v["prf"], &context, b"security-key");
        let store = crypto::factor(&v["store"], &context, b"keystore");
        let recovery = crypto::factor(&v["recovery"], &context, b"recovery");
        let wrapping_key = match record.method {
            Method::Passphrase => password.as_ref().unwrap(),
            Method::SecurityKey(_) | Method::KeyAndPassphrase(_) => &fido,
            Method::Keystore(_) => &store,
            Method::KeyAndKeystore(_, _) => &crypto::combine(&fido, &store, &context),
            Method::RecoverySecret => &recovery,
        };
        let inner = if matches!(record.method, Method::KeyAndPassphrase(_)) {
            crypto::wrap(password.as_ref().unwrap(), &record.nonce, &context, &root).unwrap()
        } else {
            root.to_vec()
        };
        assert_eq!(
            crypto::wrap(wrapping_key, &record.nonce, &context, &inner).unwrap(),
            record.wrapped
        );
        let unwrapped =
            crypto::unwrap(wrapping_key, &record.nonce, &context, &record.wrapped).unwrap();
        assert_eq!(*unwrapped, inner);
        let key = UnlockedKey {
            root: zeroize::Zeroizing::new(root),
            envelope,
        };
        assert_eq!(
            key.derive_key("vector").unwrap().expose(|k| k.to_vec()),
            v["application_key"]
        );
        if key.envelope.records[0].method == Method::RecoverySecret {
            let p = Protector::new(key.envelope.application.clone());
            let recovery =
                RecoverySecret::import(&mut v["recovery"].as_slice().try_into().unwrap());
            let nonce: [u8; 32] = v["stream_nonce"].as_slice().try_into().unwrap();
            for label in ["empty", "short"] {
                let plain = &v[format!("plain_{label}").as_str()];
                let sealed = &v[format!("sealed_{label}").as_str()];
                assert_eq!(seal::deterministic_vector(&key, &nonce, plain), *sealed);
                assert_eq!(
                    *seal::open_bytes(&p, sealed, id(&key), &mut &recovery).unwrap(),
                    *plain
                );
            }
            let long = seal::deterministic_vector(&key, &nonce, &vec![b'z'; 131_073]);
            assert_eq!(Sha256::digest(&long).as_slice(), v["sealed_long_sha256"]);
        }
    }
}

#[test]
fn rejected_pin_is_not_resubmitted_during_enrollment_cleanup() {
    struct RejectAfterCreation {
        device: Arc<Device>,
        pins: usize,
    }
    impl Interaction for RejectAfterCreation {
        fn pin(&mut self, _: Prompt<'_>) -> Result<Pin> {
            self.pins += 1;
            Ok(Pin::new("123456").unwrap())
        }
        fn touch(&mut self, _: Prompt<'_>) -> Result<()> {
            self.device.pin_invalid.store(true, SeqCst);
            Ok(())
        }
    }
    let device = Arc::new(Device::default());
    let p = protector().with_test_device(Arc::clone(&device));
    let mut ui = RejectAfterCreation {
        device: Arc::clone(&device),
        pins: 0,
    };
    let request = enrollment(Method::SecurityKey(
        KeyOptions::new(Verification::UserVerified).managed(),
    ));
    assert!(matches!(
        p.create(&request, &mut ui),
        Err(Error::EnrollmentUncertain { .. })
    ));
    assert_eq!(ui.pins, 1);
    assert_eq!(device.cleanups.load(SeqCst), 0);
    assert_eq!(device.calls.load(SeqCst), 2);
}
#[cfg(not(target_os = "macos"))]
#[test]
fn unsupported_store_access_is_rejected_before_key_interaction() {
    let device = Arc::new(Device::default());
    let p = protector().with_test_device(Arc::clone(&device));
    let request = enrollment(Method::KeyAndKeystore(
        KeyOptions::new(Verification::Presence),
        StoreAccess::UserAuthentication,
    ));
    let mut ui = UI::default();
    assert!(matches!(
        p.create(&request, &mut ui),
        Err(Error::Store(StoreError::Unsupported))
    ));
    assert_eq!(device.calls.load(SeqCst), 0);
    assert_eq!(ui.pins + ui.touches, 0);
}
#[test]
fn rotation_reencrypts_and_verification_checks_the_entire_stream() {
    let (p, s, mut key) = recovery_key();
    let replacement_secret = secret(8);
    let replacement = p
        .create(
            &enrollment(Method::RecoverySecret),
            &mut &replacement_secret,
        )
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("old");
    let rotated = dir.path().join("rotated");
    fs::write(&old, seal::seal_bytes(&key, b"rotate this secret").unwrap()).unwrap();
    assert!(matches!(
        seal::rotate_file(&p, &old, &rotated, id(&key), &mut (), &key),
        Err(Error::InvalidInput(_))
    ));
    // Changing methods does not create a fresh root for rotation.
    p.add_method(
        &mut key,
        &enrollment(Method::RecoverySecret),
        &mut &secret(3),
    )
    .unwrap();
    assert!(matches!(
        seal::rotate_file(&p, &old, &rotated, id(&key), &mut (), &key),
        Err(Error::InvalidInput(_))
    ));
    assert!(!rotated.exists());
    seal::rotate_file(&p, &old, &rotated, id(&key), &mut &s, &replacement).unwrap();
    seal::verify_file(&replacement, &rotated).unwrap();
    assert!(seal::verify_file(&key, &rotated).is_err());
    let bytes = fs::read(&rotated).unwrap();
    assert_eq!(
        &*seal::open_bytes(&p, &bytes, id(&replacement), &mut &replacement_secret).unwrap(),
        b"rotate this secret"
    );
    let mut corrupt = bytes;
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(&rotated, corrupt).unwrap();
    assert!(seal::verify_file(&replacement, &rotated).is_err());
}
