use super::*;
use p256::ecdsa::{SigningKey, signature::Signer as _};

#[test]
fn offline_verification_checks_extensions_and_exact_uv() {
    let key = SigningKey::from_slice(&[3; 32]).unwrap();
    let public = key.verifying_key().to_sec1_point(false).as_bytes()[1..]
        .try_into()
        .unwrap();
    let challenge = [9; 32];
    for (flags, extension, valid) in [
        (5, vec![], true),
        (0x85, vec![0xa0], true),
        (0x85, vec![0x80], false),
        (0x85, vec![0xa0, 0], false),
        (0x85, vec![0xa1], false),
        (5, vec![0xa0], false),
        (1, vec![], false),
    ] {
        let mut data = Sha256::digest(b"fixture.example").to_vec();
        data.push(flags);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&extension);
        let signature: Signature = key.sign(&[data.as_slice(), &challenge].concat());
        let proof = AssertionProof::from_parts(&data, signature.to_der().as_bytes()).unwrap();
        assert_eq!(
            proof
                .verify(
                    "fixture.example",
                    &challenge,
                    &public,
                    ExactPolicy::UserVerified
                )
                .is_ok(),
            valid
        );
        assert!(
            proof
                .verify(
                    "other.example",
                    &challenge,
                    &public,
                    ExactPolicy::UserVerified
                )
                .is_err()
        );
        assert!(
            proof
                .verify(
                    "fixture.example",
                    &[8; 32],
                    &public,
                    ExactPolicy::UserVerified
                )
                .is_err()
        );
    }
}
