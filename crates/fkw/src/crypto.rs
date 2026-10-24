use crate::{Error, KdfCost, Passphrase, Result};
use aes_gcm::{Aes256Gcm, KeyInit, aead::AeadInPlace};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub(crate) fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut bytes = Zeroizing::new([0u8; N]);
    getrandom::fill(bytes.as_mut()).map_err(|_| Error::RandomUnavailable)?;
    Ok(bytes)
}
pub(crate) fn frame(parts: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(
        &u32::try_from(parts.len())
            .expect("bounded part count")
            .to_be_bytes(),
    );
    for part in parts {
        output.extend_from_slice(
            &u32::try_from(part.len())
                .expect("bounded transcript field")
                .to_be_bytes(),
        );
        output.extend_from_slice(part);
    }
    output
}
pub(crate) fn hash(parts: &[&[u8]]) -> [u8; 32] {
    Sha256::digest(frame(parts)).into()
}
pub(crate) fn derive(secret: &[u8], salt: &[u8], info: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(salt), secret)
        .expand(&frame(info), key.as_mut())
        .expect("fixed output length");
    key
}
pub(crate) fn factor(secret: &[u8], context: &[u8; 32], role: &[u8]) -> Zeroizing<[u8; 32]> {
    derive(secret, context, &[b"fkw/v2/factor", role])
}
pub(crate) fn combine(key: &[u8; 32], store: &[u8; 32], context: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut material = Zeroizing::new([0; 64]);
    material[..32].copy_from_slice(key);
    material[32..].copy_from_slice(store);
    derive(material.as_slice(), context, &[b"fkw/v2/combined"])
}
pub(crate) fn passphrase(
    pass: &Passphrase,
    salt: &[u8; 16],
    cost: KdfCost,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(cost.memory, cost.passes, cost.lanes, Some(32))
        .map_err(|_| Error::InvalidEnvelope)?;
    let count = params.block_count();
    let mut memory = Vec::new();
    memory
        .try_reserve_exact(count)
        .map_err(|_| Error::KdfResourceUnavailable)?;
    memory.resize(count, Block::default());
    let mut memory = Zeroizing::new(memory);
    let mut output = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(&pass.0, salt, output.as_mut(), memory.as_mut_slice())
        .map_err(|_| Error::InvalidEnvelope)?;
    Ok(output)
}
pub(crate) fn wrap(
    key: &[u8; 32],
    nonce: &[u8; 12],
    context: &[u8; 32],
    plain: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let mut buffer = Zeroizing::new(plain.to_vec());
    let tag = cipher
        .encrypt_in_place_detached(nonce.into(), context, &mut buffer)
        .map_err(|_| Error::UnlockFailed)?;
    buffer.extend_from_slice(&tag);
    Ok(buffer.to_vec())
}
pub(crate) fn unwrap(
    key: &[u8; 32],
    nonce: &[u8; 12],
    context: &[u8; 32],
    cipher: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let (body, tag) = cipher
        .split_at_checked(cipher.len().checked_sub(16).ok_or(Error::UnlockFailed)?)
        .ok_or(Error::UnlockFailed)?;
    let mut buffer = Zeroizing::new(body.to_vec());
    Aes256Gcm::new(key.into())
        .decrypt_in_place_detached(nonce.into(), context, &mut buffer, tag.into())
        .map_err(|_| Error::UnlockFailed)?;
    Ok(buffer)
}
pub(crate) fn mac(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key).expect("fixed key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}
pub(crate) fn verify_mac(key: &[u8; 32], message: &[u8], expected: &[u8; 32]) -> Result<()> {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key).expect("fixed key length");
    mac.update(message);
    mac.verify_slice(expected).map_err(|_| Error::UnlockFailed)
}
