use super::*;
use crate::{ApplicationId, Enrollment, Method, Protector, RecoverySecret};

fn identity() -> (Protector, UnlockedKey, RecoverySecret) {
    let protector = Protector::new(ApplicationId::new("recipient.example").unwrap());
    let mut recovery = RecoverySecret::generate().unwrap();
    let key = protector
        .create(
            &Enrollment::new(Method::RecoverySecret, "primary").unwrap(),
            &mut recovery,
        )
        .unwrap();
    (protector, key, recovery)
}

#[test]
fn identity_survives_method_changes_and_recovery_but_not_rotation() {
    let (protector, mut key, _) = identity();
    let recipient = Recipient::from_key(&key).unwrap();
    let ciphertext = encrypt_bytes(&recipient, b"private message").unwrap();
    let old = key.envelope().methods().next().unwrap().id;
    let mut backup = RecoverySecret::generate().unwrap();
    let added = protector
        .add_method(
            &mut key,
            &Enrollment::new(Method::RecoverySecret, "backup").unwrap(),
            &mut backup,
        )
        .unwrap();
    protector.remove_method(&mut key, old).unwrap();
    let recovered = protector
        .unlock(key.envelope(), added, &mut backup)
        .unwrap();
    assert_eq!(Recipient::from_key(&recovered).unwrap(), recipient);
    assert_eq!(
        decrypt_bytes(&recovered, &ciphertext).unwrap().as_slice(),
        b"private message"
    );
    let (_, fresh, _) = identity();
    assert_ne!(Recipient::from_key(&fresh).unwrap(), recipient);
    assert!(decrypt_bytes(&fresh, &ciphertext).is_err());
}

#[test]
fn complete_bytes_and_adversarial_inputs() {
    let (_, key, _) = identity();
    let recipient = Recipient::from_key(&key).unwrap();
    assert_eq!(
        Recipient::from_bytes(&recipient.to_bytes()).unwrap(),
        recipient
    );
    for size in [0, 1, 65_535, 65_536, 65_537, MAX_PLAINTEXT_BYTES] {
        let plain = vec![0x59; size];
        let sealed = encrypt_bytes(&recipient, &plain).unwrap();
        assert_eq!(*decrypt_bytes(&key, &sealed).unwrap(), plain);
    }
    assert!(encrypt_bytes(&recipient, &vec![0; MAX_PLAINTEXT_BYTES + 1]).is_err());
    let sealed = encrypt_bytes(&recipient, b"message").unwrap();
    assert_ne!(sealed, encrypt_bytes(&recipient, b"message").unwrap());
    for index in 0..sealed.len() {
        let mut changed = sealed.clone();
        changed[index] ^= 1;
        assert!(
            decrypt_bytes(&key, &changed).is_err(),
            "accepted mutation at {index}"
        );
        assert!(
            decrypt_bytes(&key, &sealed[..index]).is_err(),
            "accepted prefix {index}"
        );
    }
    let mut trailing = sealed;
    trailing.push(0);
    assert!(decrypt_bytes(&key, &trailing).is_err());
    let mut invalid = KEY_MAGIC.to_vec();
    invalid.extend_from_slice(&[0; 32]);
    assert!(encrypt_bytes(&Recipient::from_bytes(&invalid).unwrap(), b"message").is_err());
}

#[test]
fn framing_rejects_reordering_and_cross_message_splicing() {
    let (_, key, _) = identity();
    let recipient = Recipient::from_key(&key).unwrap();
    let plain = vec![9; 3 * 65_536];
    let first = encrypt_bytes(&recipient, &plain).unwrap();
    let second = encrypt_bytes(&recipient, &plain).unwrap();
    let frame = 65_536 + 21;
    let mut reordered = first.clone();
    reordered[HEADER_BYTES..HEADER_BYTES + frame]
        .copy_from_slice(&first[HEADER_BYTES + frame..HEADER_BYTES + 2 * frame]);
    reordered[HEADER_BYTES + frame..HEADER_BYTES + 2 * frame]
        .copy_from_slice(&first[HEADER_BYTES..HEADER_BYTES + frame]);
    assert!(decrypt_bytes(&key, &reordered).is_err());
    let mut spliced = first;
    spliced[HEADER_BYTES + frame..].copy_from_slice(&second[HEADER_BYTES + frame..]);
    assert!(decrypt_bytes(&key, &spliced).is_err());
}

#[test]
fn file_failure_never_publishes_plaintext() {
    let (_, key, _) = identity();
    let recipient = Recipient::from_key(&key).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("plain");
    let sealed = dir.path().join("sealed");
    let opened = dir.path().join("opened");
    let data = vec![0x87; 2 * MAX_PLAINTEXT_BYTES];
    std::fs::write(&plain, &data).unwrap();
    encrypt_file(&recipient, &plain, &sealed).unwrap();
    verify_file(&key, &sealed).unwrap();
    decrypt_file(&key, &sealed, &opened).unwrap();
    assert_eq!(std::fs::read(&opened).unwrap(), data);
    assert!(decrypt_file(&key, &sealed, &opened).is_err());
    let mut changed = std::fs::read(&sealed).unwrap();
    *changed.last_mut().unwrap() ^= 1;
    std::fs::write(&sealed, changed).unwrap();
    let bad = dir.path().join("bad");
    assert!(decrypt_file(&key, &sealed, &bad).is_err());
    assert!(!bad.exists());
    let mut writer = Vec::new();
    assert!(decrypt_to(&key, &sealed, &mut writer).is_err());
    assert_eq!(writer, [] as [u8; 0]);
}

#[test]
fn independent_hpke_and_payload_vector() {
    use crate::test_support::vector;
    let protection = include_str!("../../../../test-vectors/format-2-5.txt");
    let vectors = include_str!("../../../../test-vectors/public-key-1.txt");
    let protector = Protector::new(ApplicationId::new("vectors.example").unwrap());
    let envelope = crate::Envelope::from_bytes(&vector(protection, "envelope")).unwrap();
    let mut bytes = vector(protection, "recovery").try_into().unwrap();
    let mut recovery = RecoverySecret::import(&mut bytes);
    let key = protector
        .unlock(
            &envelope,
            envelope.methods().next().unwrap().id,
            &mut recovery,
        )
        .unwrap();
    let recipient = Recipient::from_key(&key).unwrap();
    assert_eq!(recipient.to_bytes(), vector(vectors, "recipient"));
    assert_eq!(
        recipient.fingerprint().as_slice(),
        vector(vectors, "fingerprint")
    );
    assert!(
        decrypt_bytes(&key, &vector(vectors, "recipient_empty"))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        *decrypt_bytes(&key, &vector(vectors, "recipient_message")).unwrap(),
        vector(vectors, "recipient_plaintext")
    );
}
