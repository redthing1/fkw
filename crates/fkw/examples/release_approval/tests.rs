use super::*;
use p256::ecdsa::{SigningKey, signature::Signer as _};

// Synthetic CTAP assertions using the public format in doc/public-key-formats.md.
// These private keys are test data; production approval always calls fkw::Signer.
fn key(seed: u8) -> (SigningKey, VerificationKey) {
    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
    let mut public = b"FKVP\x01".to_vec();
    public.extend_from_slice(&u16::try_from(APPLICATION.len()).unwrap().to_be_bytes());
    public.extend_from_slice(APPLICATION.as_bytes());
    public.extend_from_slice(&key.verifying_key().to_sec1_point(false).as_bytes()[1..]);
    (key, VerificationKey::from_bytes(&public).unwrap())
}

fn signature(key: &SigningKey, public: &VerificationKey, purpose: &str, bytes: &[u8]) -> Signature {
    let public = public.to_bytes();
    let digest = Sha256::digest(bytes);
    let parts = [
        b"fkw/sign/v1/message".as_slice(),
        &public,
        purpose.as_bytes(),
        &digest,
    ];
    let mut framed = 4u32.to_be_bytes().to_vec();
    for part in parts {
        framed.extend_from_slice(&u32::try_from(part.len()).unwrap().to_be_bytes());
        framed.extend_from_slice(part);
    }
    let mut data = Sha256::digest(APPLICATION.as_bytes()).to_vec();
    data.push(5);
    data.extend_from_slice(&0u32.to_be_bytes());
    let message = [data.as_slice(), &Sha256::digest(framed)].concat();
    let signed: p256::ecdsa::Signature = key.sign(&message);
    Signature::from_bytes(&[b"FKSG\x01", data.as_slice(), signed.to_der().as_bytes()].concat())
        .unwrap()
}

fn fixture() -> (SigningKey, PendingRelease) {
    let (key, public) = key(7);
    (
        key,
        PendingRelease::prepare(public, [0x42; 32], 100).unwrap(),
    )
}

#[test]
fn valid_approval_claims_the_exact_release_once() {
    let (key, pending) = fixture();
    let bytes = pending.request.encode();
    let proof = signature(&key, &pending.trusted_key, PURPOSE, &bytes);
    let accepted = pending.claim(&bytes, &proof, || Ok(101)).unwrap();
    assert_eq!(accepted, &pending.request);
    assert!(pending.claim(&bytes, &proof, || Ok(102)).is_err());
}

#[test]
fn even_valid_signatures_cannot_change_the_pending_request() {
    let (key, pending) = fixture();
    let original = &pending.request;
    let mut changed = vec![original.clone(); 6];
    changed[0].id[0] ^= 1;
    changed[1].audience = "other.example".into();
    changed[2].environment = "staging".into();
    changed[3].artifact[0] ^= 1;
    changed[4].expires_at += 1;
    changed[5].expires_at -= 1;
    for request in changed {
        let bytes = request.encode();
        let proof = signature(&key, &pending.trusted_key, PURPOSE, &bytes);
        assert!(pending.claim(&bytes, &proof, || Ok(101)).is_err());
    }
    let bytes = original.encode();
    let proof = signature(&key, &pending.trusted_key, PURPOSE, &bytes);
    pending.claim(&bytes, &proof, || Ok(101)).unwrap();
}

#[test]
fn wrong_key_purpose_and_damaged_signatures_do_not_consume_the_request() {
    let (signing, pending) = fixture();
    let bytes = pending.request.encode();
    let (other, other_public) = key(8);
    let untrusted = signature(&other, &other_public, PURPOSE, &bytes);
    assert!(pending.claim(&bytes, &untrusted, || Ok(101)).is_err());
    let wrong_purpose = signature(&signing, &pending.trusted_key, "file", &bytes);
    assert!(pending.claim(&bytes, &wrong_purpose, || Ok(101)).is_err());
    let valid = signature(&signing, &pending.trusted_key, PURPOSE, &bytes);
    let mut damaged = valid.to_bytes();
    *damaged.last_mut().unwrap() ^= 1;
    let damaged = Signature::from_bytes(&damaged).unwrap();
    assert!(pending.claim(&bytes, &damaged, || Ok(101)).is_err());
    pending.claim(&bytes, &valid, || Ok(101)).unwrap();
}

#[test]
fn expiry_is_checked_at_claim_and_clock_errors_fail_closed() {
    for offset in [0, 1] {
        let (key, pending) = fixture();
        let bytes = pending.request.encode();
        let proof = signature(&key, &pending.trusted_key, PURPOSE, &bytes);
        assert!(
            pending
                .claim(&bytes, &proof, || Ok(pending.request.expires_at + offset))
                .is_err()
        );
        assert!(!*pending.claimed.lock().unwrap());
    }
    let (key, pending) = fixture();
    let bytes = pending.request.encode();
    let proof = signature(&key, &pending.trusted_key, PURPOSE, &bytes);
    assert!(
        pending
            .claim(&bytes, &proof, || bail!("clock unavailable"))
            .is_err()
    );
    pending
        .claim(&bytes, &proof, || Ok(pending.request.expires_at - 1))
        .unwrap();
}

#[test]
fn concurrent_submissions_have_one_winner() {
    let (key, pending) = fixture();
    let bytes = pending.request.encode();
    let proof = signature(&key, &pending.trusted_key, PURPOSE, &bytes);
    let barrier = std::sync::Barrier::new(2);
    let attempt = || {
        barrier.wait();
        pending.claim(&bytes, &proof, || Ok(101)).is_ok()
    };
    std::thread::scope(|scope| {
        let first = scope.spawn(attempt);
        let second = scope.spawn(attempt);
        assert_ne!(first.join().unwrap(), second.join().unwrap());
    });
}

#[test]
fn review_requires_bounded_canonical_requests_and_shows_every_field() {
    let (_, pending) = fixture();
    let bytes = pending.request.encode();
    assert_eq!(Request::decode(&bytes).unwrap(), pending.request);
    let mut displayed = Vec::new();
    review(&bytes, &mut displayed, 101).unwrap();
    let text = String::from_utf8(displayed).unwrap();
    for field in [
        AUDIENCE.to_owned(),
        ENVIRONMENT.to_owned(),
        hex(&pending.request.artifact),
        hex(&pending.request.id),
        pending.request.expires_at.to_string(),
    ] {
        assert!(text.contains(&field));
    }
    for len in 0..bytes.len() {
        assert!(Request::decode(&bytes[..len]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    let mut version = bytes.clone();
    version[1] = 2;
    let mut noncanonical = bytes.clone();
    noncanonical.splice(1..2, [0x18, 1]);
    let mut indefinite = bytes.clone();
    indefinite[0] = 0x9f;
    indefinite.push(0xff);
    for invalid in [
        trailing,
        version,
        noncanonical,
        indefinite,
        vec![0; MAX_REQUEST_BYTES + 1],
    ] {
        let mut output = Vec::new();
        assert!(review(&invalid, &mut output, 101).is_err());
        assert_eq!(output, [] as [u8; 0]);
    }
    for audience in [
        String::new(),
        "x".repeat(65),
        "fake\nAudience: trusted".to_owned(),
    ] {
        let mut request = pending.request.clone();
        request.audience = audience;
        assert!(Request::decode(&request.encode()).is_err());
    }
    assert!(review(&bytes, &mut Vec::new(), pending.request.expires_at).is_err());
}

#[test]
fn a_new_request_for_the_same_artifact_needs_a_new_approval() {
    let (key, first) = fixture();
    let second =
        PendingRelease::prepare(first.trusted_key.clone(), first.request.artifact, 100).unwrap();
    assert_ne!(first.request.id, second.request.id);
    let bytes = first.request.encode();
    let proof = signature(&key, &first.trusted_key, PURPOSE, &bytes);
    assert!(second.claim(&bytes, &proof, || Ok(101)).is_err());
    first.claim(&bytes, &proof, || Ok(101)).unwrap();
}

#[test]
fn completed_handles_survive_a_publication_race_without_overwriting() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("approver.key");
    fresh(&destination).unwrap();
    fs::write(&destination, b"another writer").unwrap();
    let error = save(&destination, b"completed credential").unwrap_err();
    assert!(format!("{error:#}").contains("completed output retained"));
    assert_eq!(fs::read(&destination).unwrap(), b"another writer");
    let retained: Vec<_> = fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path != &destination)
        .collect();
    assert_eq!(retained.len(), 1);
    assert_eq!(fs::read(&retained[0]).unwrap(), b"completed credential");
}
