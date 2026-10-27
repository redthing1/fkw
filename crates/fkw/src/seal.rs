//! Complete sealed-data operations. File plaintext is staged privately, fully
//! authenticated, then published without replacing existing destinations.
//! Saving never changes the supplied key. On failure, keep it and retry the save;
//! a `PublicationUncertain` error means the destination was already published.
use crate::{
    Envelope, Error, Interaction, MethodId, Protector, Result, UnlockedKey, crypto,
    envelope::MAX_ENVELOPE_BYTES,
};
use crate::{
    files::{exact, publish, staging_file},
    payload,
};
use std::{
    fs::File,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    path::Path,
};
use zeroize::Zeroizing;

/// Byte helpers are bounded; use file operations for larger data.
pub const MAX_PLAINTEXT_BYTES: usize = 1_048_576;
const MAX_SEALED_BYTES: usize = MAX_PLAINTEXT_BYTES + MAX_ENVELOPE_BYTES + 1024;

pub fn seal_bytes(key: &UnlockedKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut output = Vec::new();
    encrypt(key, &mut Cursor::new(plaintext), &mut output)?;
    Ok(output)
}
pub fn open_bytes(
    protector: &Protector,
    sealed: &[u8],
    method: MethodId,
    interaction: &mut dyn Interaction,
) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() > MAX_SEALED_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut input = Cursor::new(sealed);
    let (envelope, nonce) = read_header(&mut input)?;
    let key = protector.unlock(&envelope, method, interaction)?;
    let mut plaintext = Zeroizing::new(Vec::new());
    decrypt(
        &key,
        &nonce,
        &mut input,
        &mut *plaintext,
        Some(MAX_PLAINTEXT_BYTES as u64),
    )?;
    Ok(plaintext)
}
/// Reads bounded, untrusted public metadata. Does not prompt or load native code.
pub fn inspect_bytes(sealed: &[u8]) -> Result<Envelope> {
    Ok(read_header(&mut Cursor::new(sealed))?.0)
}
pub fn inspect_file(path: impl AsRef<Path>) -> Result<Envelope> {
    Ok(read_header(&mut File::open(path)?)?.0)
}

/// Authenticates the complete file with an already unlocked key, without
/// publishing plaintext or prompting again.
pub fn verify_file(key: &UnlockedKey, input: impl AsRef<Path>) -> Result<()> {
    let mut input = File::open(input)?;
    let (envelope, nonce) = read_header(&mut input)?;
    key.authenticate(&envelope)?;
    decrypt(key, &nonce, &mut input, &mut io::sink(), None)
}

/// Re-encrypts under a fresh key, using private plaintext staging and a new
/// destination. Rejects reuse of the old key, including after method changes.
/// Old copies remain protected by their old key.
pub fn rotate_file(
    protector: &Protector,
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    method: MethodId,
    interaction: &mut dyn Interaction,
    new_key: &UnlockedKey,
) -> Result<()> {
    let mut input = File::open(input)?;
    let (envelope, nonce) = read_header(&mut input)?;
    if envelope.id == new_key.envelope.id {
        return Err(Error::InvalidInput(
            "rotation requires a freshly created key",
        ));
    }
    let output = output.as_ref();
    let mut staged = staging_file(output)?;
    let mut plaintext = tempfile::tempfile()?;
    let old_key = protector.unlock(&envelope, method, interaction)?;
    decrypt(&old_key, &nonce, &mut input, &mut plaintext, None)?;
    plaintext.seek(SeekFrom::Start(0))?;
    encrypt(new_key, &mut plaintext, staged.as_file_mut())?;
    publish(staged, output)
}

pub fn seal_file(
    key: &UnlockedKey,
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<()> {
    seal_reader(key, &mut File::open(input)?, output)
}
/// Accepts a plaintext reader (including stdin) and atomically publishes a file.
pub fn seal_reader(
    key: &UnlockedKey,
    input: &mut impl Read,
    output: impl AsRef<Path>,
) -> Result<()> {
    let output = output.as_ref();
    let mut staged = staging_file(output)?;
    encrypt(key, input, staged.as_file_mut())?;
    publish(staged, output)
}
pub fn open_file(
    protector: &Protector,
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    method: MethodId,
    interaction: &mut dyn Interaction,
) -> Result<()> {
    let mut input = File::open(input)?;
    let output = output.as_ref();
    let mut staged = staging_file(output)?;
    open_into_private(
        protector,
        &mut input,
        staged.as_file_mut(),
        method,
        interaction,
    )?;
    publish(staged, output)
}
/// Fully verifies into a private spool before writing any plaintext to `output`.
/// A later output I/O failure can still leave a partially written destination.
pub fn open_to(
    protector: &Protector,
    input: impl AsRef<Path>,
    output: &mut impl Write,
    method: MethodId,
    interaction: &mut dyn Interaction,
) -> Result<()> {
    let mut input = File::open(input)?;
    let mut spool = tempfile::tempfile()?;
    open_into_private(protector, &mut input, &mut spool, method, interaction)?;
    spool.seek(SeekFrom::Start(0))?;
    io::copy(&mut spool, output)?;
    output.flush()?;
    Ok(())
}
/// Replaces the access header, preserving payload ciphertext. Verifies the
/// complete staged container before publishing it to a new path.
/// Older copies retain their original unlock methods.
pub fn update_file(
    key: &UnlockedKey,
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<()> {
    let mut input = File::open(input)?;
    let (old, nonce) = read_header(&mut input)?;
    key.authenticate(&old)?;
    let output = output.as_ref();
    let mut staged = staging_file(output)?;
    write_header(&key.envelope, &nonce, staged.as_file_mut())?;
    io::copy(&mut input, staged.as_file_mut())?;
    verify_file(key, staged.path())?;
    publish(staged, output)
}
fn open_into_private(
    protector: &Protector,
    input: &mut impl Read,
    output: &mut impl Write,
    method: MethodId,
    interaction: &mut dyn Interaction,
) -> Result<()> {
    let (envelope, nonce) = read_header(input)?;
    let key = protector.unlock(&envelope, method, interaction)?;
    decrypt(&key, &nonce, input, output, None)
}
fn write_header(envelope: &Envelope, nonce: &[u8; 32], output: &mut impl Write) -> Result<()> {
    let bytes = envelope.to_bytes();
    output.write_all(b"FKWS\x02")?;
    output.write_all(
        &u32::try_from(bytes.len())
            .map_err(|_| Error::InvalidEnvelope)?
            .to_be_bytes(),
    )?;
    output.write_all(&bytes)?;
    output.write_all(nonce)?;
    Ok(())
}
fn read_header(input: &mut impl Read) -> Result<(Envelope, [u8; 32])> {
    let mut header = [0; 9];
    exact(input, &mut header)?;
    if &header[..5] != b"FKWS\x02" {
        return Err(Error::InvalidSealedData);
    }
    let len = u32::from_be_bytes(header[5..].try_into().expect("four bytes")) as usize;
    if !(4..=MAX_ENVELOPE_BYTES).contains(&len) {
        return Err(Error::InvalidSealedData);
    }
    let mut bytes = vec![0; len];
    exact(input, &mut bytes)?;
    let envelope = Envelope::from_bytes(&bytes)?;
    let mut nonce = [0; 32];
    exact(input, &mut nonce)?;
    Ok((envelope, nonce))
}
fn stream_key(key: &UnlockedKey, nonce: &[u8; 32]) -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let app = key.envelope.application.as_str().as_bytes();
    let id = &key.envelope.id;
    (
        crypto::derive(key.root.as_slice(), nonce, &[b"fkw/v2/stream", app, id]),
        crypto::hash(&[b"fkw/v2/stream", app, id, nonce]),
    )
}
fn encrypt(key: &UnlockedKey, input: &mut impl Read, output: &mut impl Write) -> Result<()> {
    let nonce = crypto::random()?;
    encrypt_with_nonce(key, &nonce, input, output)
}
fn encrypt_with_nonce(
    key: &UnlockedKey,
    nonce: &[u8; 32],
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<()> {
    write_header(&key.envelope, nonce, output)?;
    let (secret, context) = stream_key(key, nonce);
    payload::encrypt(&secret, &context, input, output)
}
#[cfg(test)]
pub(crate) fn deterministic_vector(
    key: &UnlockedKey,
    nonce: &[u8; 32],
    plaintext: &[u8],
) -> Vec<u8> {
    let mut output = Vec::new();
    encrypt_with_nonce(key, nonce, &mut Cursor::new(plaintext), &mut output).unwrap();
    output
}
fn decrypt(
    key: &UnlockedKey,
    nonce: &[u8; 32],
    input: &mut impl Read,
    output: &mut impl Write,
    limit: Option<u64>,
) -> Result<()> {
    let (secret, context) = stream_key(key, nonce);
    payload::decrypt(&secret, &context, input, output, limit)
}
