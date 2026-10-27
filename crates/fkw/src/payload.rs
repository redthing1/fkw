//! Authenticated bounded-memory framing. Callers own the key schedule and context.
use crate::{
    Error, Result,
    files::{exact, fill},
};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::AeadInPlace};
use std::io::{Read, Write};
use zeroize::Zeroizing;
const CHUNK: usize = 65_536;
fn frame_nonce(index: u64, final_flag: u8) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[3..11].copy_from_slice(&index.to_be_bytes());
    nonce[11] = final_flag;
    nonce
}
fn associated_data(context: &[u8; 32], header: [u8; 5]) -> [u8; 37] {
    let mut aad = [0; 37];
    aad[..32].copy_from_slice(context);
    aad[32..].copy_from_slice(&header);
    aad
}
pub(crate) fn encrypt(
    secret: &[u8; 32],
    context: &[u8; 32],
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<()> {
    let cipher = ChaCha20Poly1305::new(secret.into());
    let mut current = Zeroizing::new(vec![0; CHUNK]);
    let mut next = Zeroizing::new(vec![0; CHUNK]);
    let mut len = fill(input, &mut current)?;
    let mut index = 0u64;
    loop {
        let next_len = if len == CHUNK {
            fill(input, &mut next)?
        } else {
            0
        };
        let final_flag = u8::from(next_len == 0);
        let mut header = [0; 5];
        header[..4].copy_from_slice(&u32::try_from(len).expect("bounded chunk").to_be_bytes());
        header[4] = final_flag;
        let tag = cipher
            .encrypt_in_place_detached(
                (&frame_nonce(index, final_flag)).into(),
                &associated_data(context, header),
                &mut current[..len],
            )
            .map_err(|_| Error::InvalidSealedData)?;
        output.write_all(&header)?;
        output.write_all(&current[..len])?;
        output.write_all(&tag)?;
        if final_flag == 1 {
            return Ok(());
        }
        index = index.checked_add(1).ok_or(Error::ResourceLimit)?;
        std::mem::swap(&mut current, &mut next);
        len = next_len;
    }
}
pub(crate) fn decrypt(
    secret: &[u8; 32],
    context: &[u8; 32],
    input: &mut impl Read,
    output: &mut impl Write,
    limit: Option<u64>,
) -> Result<()> {
    let cipher = ChaCha20Poly1305::new(secret.into());
    let mut index = 0u64;
    let mut total = 0u64;
    loop {
        let mut header = [0; 5];
        exact(input, &mut header)?;
        let len = u32::from_be_bytes(header[..4].try_into().expect("four bytes")) as usize;
        let final_flag = header[4];
        if len > CHUNK
            || final_flag > 1
            || (final_flag == 0 && len != CHUNK)
            || (len == 0 && index != 0)
        {
            return Err(Error::InvalidSealedData);
        }
        total = total.checked_add(len as u64).ok_or(Error::ResourceLimit)?;
        if limit.is_some_and(|max| total > max) {
            return Err(Error::ResourceLimit);
        }
        let mut buffer = Zeroizing::new(vec![0; len]);
        let mut tag = [0; 16];
        exact(input, &mut buffer)?;
        exact(input, &mut tag)?;
        cipher
            .decrypt_in_place_detached(
                (&frame_nonce(index, final_flag)).into(),
                &associated_data(context, header),
                &mut buffer,
                (&tag).into(),
            )
            .map_err(|_| Error::UnlockFailed)?;
        output.write_all(&buffer)?;
        if final_flag == 1 {
            if fill(input, &mut [0; 1])? != 0 {
                return Err(Error::InvalidSealedData);
            }
            return Ok(());
        }
        index = index.checked_add(1).ok_or(Error::ResourceLimit)?;
    }
}
