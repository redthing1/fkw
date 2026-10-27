//! Encrypt to a public recipient; decrypt with its unlocked protected identity.
//!
//! The recipient identity is stable across access-method changes. Senders need
//! only the public key. Encryption does not authenticate a sender.
//!
//! ```
//! use fkw::{ApplicationId, Enrollment, Method, Protector, RecoverySecret, recipient};
//! # fn main() -> fkw::Result<()> {
//! let protector = Protector::new(ApplicationId::new("mail.example")?);
//! let mut recovery = RecoverySecret::generate()?;
//! let key = protector.create(&Enrollment::new(Method::RecoverySecret, "backup")?, &mut recovery)?;
//! // Persist the envelope and recovery secret separately before using this identity.
//! let public = recipient::Recipient::from_key(&key)?;
//! let encrypted = recipient::encrypt_bytes(&public, b"a private message")?;
//! assert_eq!(recipient::decrypt_bytes(&key, &encrypted)?.as_slice(), b"a private message");
//! # Ok(())
//! # }
//! ```
use crate::{Error, Result, UnlockedKey, crypto, files, payload, seal::MAX_PLAINTEXT_BYTES};
use chacha20::ChaCha20Rng;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::ExportOnlyAead,
    kdf::HkdfSha256, kem::X25519HkdfSha256, rand_core::SeedableRng,
};
use std::{
    fs::File,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    path::Path,
};
use zeroize::Zeroizing;

type Kem = X25519HkdfSha256;
type PrivateKey = <Kem as KemTrait>::PrivateKey;
type PublicKey = <Kem as KemTrait>::PublicKey;
const MAGIC: &[u8; 5] = b"FKWR\x01";
const KEY_MAGIC: &[u8; 5] = b"FKRP\x01";
const HEADER_BYTES: usize = 69;
const PURPOSE: &str = "fkw/recipient/v1/identity";
const INFO: &[u8] = b"fkw/recipient/v1/hpke";
const EXPORT: &[u8] = b"fkw/recipient/v1/stream";

/// Public encryption identity. Obtain this through an authenticated channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient(PublicKey);

impl Recipient {
    /// Size of an encoded public recipient.
    pub const MAX_BYTES: usize = 37;

    /// Derives the public identity without changing the protection envelope.
    pub fn from_key(key: &UnlockedKey) -> Result<Self> {
        Ok(Self(keypair(key)?.1))
    }

    /// Encodes the public identity with its format version.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        [KEY_MAGIC.as_slice(), self.0.to_bytes().as_slice()].concat()
    }

    /// Parses a public key. Obtain the encoded key through an authenticated channel.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::MAX_BYTES || !bytes.starts_with(KEY_MAGIC) {
            return Err(Error::InvalidRecipient);
        }
        Ok(Self(
            PublicKey::from_bytes(&bytes[5..]).map_err(|_| Error::InvalidRecipient)?,
        ))
    }

    /// Stable digest of the complete public representation.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        crypto::hash(&[b"fkw/recipient/v1/fingerprint", &self.to_bytes()])
    }
}

fn keypair(key: &UnlockedKey) -> Result<(PrivateKey, PublicKey)> {
    Ok(key
        .derive_key(PURPOSE)?
        .expose(|seed| Kem::derive_keypair(seed)))
}

/// Encrypts at most 1 MiB. Use file operations for larger messages.
pub fn encrypt_bytes(recipient: &Recipient, plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut output = Vec::new();
    encrypt(recipient, &mut Cursor::new(plaintext), &mut output)?;
    Ok(output)
}

/// Authenticates the complete message before returning at most 1 MiB of plaintext.
pub fn decrypt_bytes(key: &UnlockedKey, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if ciphertext.len() > MAX_PLAINTEXT_BYTES + HEADER_BYTES + 1024 {
        return Err(Error::ResourceLimit);
    }
    let mut output = Zeroizing::new(Vec::new());
    decrypt(
        key,
        &mut Cursor::new(ciphertext),
        &mut *output,
        Some(MAX_PLAINTEXT_BYTES as u64),
    )?;
    Ok(output)
}

pub fn encrypt_file(
    recipient: &Recipient,
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<()> {
    encrypt_reader(recipient, &mut File::open(input)?, output)
}

/// Authenticates the entire message without writing plaintext.
pub fn verify_file(key: &UnlockedKey, input: impl AsRef<Path>) -> Result<()> {
    decrypt(key, &mut File::open(input)?, &mut io::sink(), None)
}

pub fn encrypt_reader(
    recipient: &Recipient,
    input: &mut impl Read,
    output: impl AsRef<Path>,
) -> Result<()> {
    let output = output.as_ref();
    let mut staged = files::staging_file(output)?;
    encrypt(recipient, input, staged.as_file_mut())?;
    files::publish(staged, output)
}

/// Publishes plaintext only after the entire message authenticates.
pub fn decrypt_file(
    key: &UnlockedKey,
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<()> {
    let output = output.as_ref();
    let mut staged = files::staging_file(output)?;
    decrypt(key, &mut File::open(input)?, staged.as_file_mut(), None)?;
    files::publish(staged, output)
}

/// Fully authenticates into a private spool before copying to the writer.
/// A subsequent writer failure can leave partial output.
pub fn decrypt_to(
    key: &UnlockedKey,
    input: impl AsRef<Path>,
    output: &mut impl Write,
) -> Result<()> {
    let mut spool = tempfile::tempfile()?;
    decrypt(key, &mut File::open(input)?, &mut spool, None)?;
    spool.seek(SeekFrom::Start(0))?;
    io::copy(&mut spool, output)?;
    output.flush()?;
    Ok(())
}

fn encrypt(recipient: &Recipient, input: &mut impl Read, output: &mut impl Write) -> Result<()> {
    let seed = crypto::random()?;
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let (enc, context) = hpke::setup_sender_with_rng::<ExportOnlyAead, HkdfSha256, Kem>(
        &OpModeS::Base,
        &recipient.0,
        INFO,
        &mut rng,
    )
    .map_err(|_| Error::InvalidRecipient)?;
    let mut secret = Zeroizing::new([0; 32]);
    context
        .export(EXPORT, secret.as_mut())
        .map_err(|_| Error::InvalidRecipient)?;
    let header = [
        MAGIC.as_slice(),
        &recipient.fingerprint(),
        enc.to_bytes().as_slice(),
    ]
    .concat();
    let binding = crypto::hash(&[b"fkw/recipient/v1/payload", &header]);
    output.write_all(&header)?;
    payload::encrypt(&secret, &binding, input, output)
}

fn decrypt(
    key: &UnlockedKey,
    input: &mut impl Read,
    output: &mut impl Write,
    limit: Option<u64>,
) -> Result<()> {
    let mut header = [0; HEADER_BYTES];
    files::exact(input, &mut header)?;
    if &header[..5] != MAGIC {
        return Err(Error::InvalidSealedData);
    }
    let (secret_key, public_key) = keypair(key)?;
    if header[5..37] != Recipient(public_key).fingerprint() {
        return Err(Error::UnlockFailed);
    }
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&header[37..])
        .map_err(|_| Error::InvalidSealedData)?;
    let context = hpke::setup_receiver::<ExportOnlyAead, HkdfSha256, Kem>(
        &OpModeR::Base,
        &secret_key,
        &enc,
        INFO,
    )
    .map_err(|_| Error::UnlockFailed)?;
    let mut secret = Zeroizing::new([0; 32]);
    context
        .export(EXPORT, secret.as_mut())
        .map_err(|_| Error::UnlockFailed)?;
    let binding = crypto::hash(&[b"fkw/recipient/v1/payload", &header]);
    payload::decrypt(&secret, &binding, input, output, limit)
}

#[cfg(test)]
mod tests;
