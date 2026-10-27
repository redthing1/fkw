use super::*;
use p256::ecdsa::{SigningKey, signature::Signer as _};

fn key() -> (SigningKey, VerificationKey) {
    let signing = SigningKey::from_slice(&[7; 32]).unwrap();
    let public_key = signing.verifying_key().to_sec1_point(false).as_bytes()[1..]
        .try_into()
        .unwrap();
    (
        signing,
        VerificationKey {
            application: ApplicationId::new("sign.example").unwrap(),
            public_key,
        },
    )
}

fn signature(signing: &SigningKey, key: &VerificationKey, message: &[u8], flags: u8) -> Signature {
    let hash = key.challenge("release", &mut Cursor::new(message)).unwrap();
    let mut data = Sha256::digest(key.application.as_str().as_bytes()).to_vec();
    data.push(flags);
    data.extend_from_slice(&7u32.to_be_bytes());
    let signed: p256::ecdsa::Signature = signing.sign(&[data.as_slice(), &hash].concat());
    Signature(AssertionProof::from_parts(&data, signed.to_der().as_bytes()).unwrap())
}

#[test]
fn signature_binds_key_application_purpose_and_message() {
    let (signing, key) = key();
    let signature = signature(&signing, &key, b"release manifest", 5);
    key.verify("release", b"release manifest", &signature)
        .unwrap();
    assert!(
        key.verify("deployment", b"release manifest", &signature)
            .is_err()
    );
    assert!(
        key.verify("release", b"another manifest", &signature)
            .is_err()
    );
    let mut other = key.clone();
    other.application = ApplicationId::new("another.example").unwrap();
    assert!(
        other
            .verify("release", b"release manifest", &signature)
            .is_err()
    );
    other.public_key = SigningKey::from_slice(&[8; 32])
        .unwrap()
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()[1..]
        .try_into()
        .unwrap();
    assert!(
        other
            .verify("release", b"release manifest", &signature)
            .is_err()
    );
}

#[test]
fn signed_downgrades_and_backup_flags_are_rejected() {
    let (signing, key) = key();
    for flags in [0, 1, 4, 7, 0x0d, 0x15, 0x1d, 0x25, 0x45, 0x85] {
        let proof = signature(&signing, &key, b"manifest", flags);
        assert!(
            key.verify("release", b"manifest", &proof).is_err(),
            "accepted flags {flags}"
        );
    }
}

#[test]
fn encodings_are_bounded_and_mutations_do_not_verify() {
    let (signing, key) = key();
    assert_eq!(VerificationKey::from_bytes(&key.to_bytes()).unwrap(), key);
    let credential = Credential {
        key: key.clone(),
        id: vec![42; 32],
    };
    assert_eq!(
        Credential::from_bytes(&credential.to_bytes())
            .unwrap()
            .to_bytes(),
        credential.to_bytes()
    );
    let proof = signature(&signing, &key, b"manifest", 5);
    let bytes = proof.to_bytes();
    key.verify(
        "release",
        b"manifest",
        &Signature::from_bytes(&bytes).unwrap(),
    )
    .unwrap();
    for index in 0..bytes.len() {
        let mut altered = bytes.clone();
        altered[index] ^= 1;
        if let Ok(parsed) = Signature::from_bytes(&altered) {
            assert!(key.verify("release", b"manifest", &parsed).is_err());
        }
        assert!(Signature::from_bytes(&bytes[..index]).is_err());
    }
    for length in 0..1400 {
        let bytes = vec![0xff; length];
        assert!(VerificationKey::from_bytes(&bytes).is_err());
        assert!(Credential::from_bytes(&bytes).is_err());
        assert!(Signature::from_bytes(&bytes).is_err());
    }
}

#[test]
fn invalid_purpose_or_wrong_application_fails_before_device_access() {
    let (_, key) = key();
    let credential = Credential {
        key,
        id: vec![1; 32],
    };
    let signer = Signer::new(ApplicationId::new("sign.example").unwrap());
    assert!(matches!(
        signer.sign(&credential, "", b"message", &mut ()),
        Err(Error::InvalidInput(_))
    ));
    let other = Signer::new(ApplicationId::new("other.example").unwrap());
    assert!(matches!(
        other.sign(&credential, "release", b"message", &mut ()),
        Err(Error::WrongApplication)
    ));
}

#[test]
fn independent_signature_vector() {
    use crate::test_support::vector;
    let vectors = include_str!("../../../../test-vectors/public-key-1.txt");
    let key = VerificationKey::from_bytes(&vector(vectors, "verification_key")).unwrap();
    let credential = Credential::from_bytes(&vector(vectors, "credential")).unwrap();
    assert_eq!(credential.verification_key(), &key);
    let message = vector(vectors, "signing_message");
    assert_eq!(
        key.challenge("release", &mut Cursor::new(&message))
            .unwrap()
            .as_slice(),
        vector(vectors, "challenge")
    );
    let signature = Signature::from_bytes(&vector(vectors, "signature")).unwrap();
    key.verify("release", &message, &signature).unwrap();
}
