//! Owned assertion data and verification independent of the native runtime.
use crate::{Error, ExactPolicy, Result};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};

/// An untrusted ES256 assertion. Construction checks bounds, not authenticity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionProof {
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
}

impl AssertionProof {
    /// Copies bounded raw authenticator data and a DER-encoded signature.
    ///
    /// # Errors
    /// Returns `VerificationFailed` for invalid sizes or signature encoding.
    pub fn from_parts(authenticator_data: &[u8], signature: &[u8]) -> Result<Self> {
        if !(37..=4096).contains(&authenticator_data.len()) || signature.len() > 72 {
            return Err(Error::VerificationFailed);
        }
        Signature::from_der(signature).map_err(|_| Error::VerificationFailed)?;
        Ok(Self {
            authenticator_data: authenticator_data.to_vec(),
            signature: signature.to_vec(),
        })
    }

    #[must_use]
    pub fn authenticator_data(&self) -> &[u8] {
        &self.authenticator_data
    }
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Verifies the exact trusted RP, challenge, public key and UP/UV policy.
    /// Backup flags, attested credential data and reserved flags are rejected.
    ///
    /// # Errors
    /// Returns `VerificationFailed` on malformed data or any verification failure.
    pub fn verify(
        &self,
        relying_party: &str,
        client_data_hash: &[u8; 32],
        public_key: &[u8; 64],
        policy: ExactPolicy,
    ) -> Result<()> {
        let data = &self.authenticator_data;
        let flags = data[32];
        if data[..32] != Sha256::digest(relying_party.as_bytes())[..]
            || !flags_match(flags, policy)
            || flags & 0x62 != 0
        {
            return Err(Error::VerificationFailed);
        }
        if flags & 0x80 == 0 {
            if data.len() != 37 {
                return Err(Error::VerificationFailed);
            }
        } else {
            let mut decoder = minicbor::Decoder::new(&data[37..]);
            if decoder.datatype().map_err(|_| Error::VerificationFailed)?
                != minicbor::data::Type::Map
            {
                return Err(Error::VerificationFailed);
            }
            decoder.skip().map_err(|_| Error::VerificationFailed)?;
            if decoder.position() != data.len() - 37 {
                return Err(Error::VerificationFailed);
            }
        }
        let key = verifying_key(public_key)?;
        let signature =
            Signature::from_der(&self.signature).map_err(|_| Error::VerificationFailed)?;
        let message = [data.as_slice(), client_data_hash.as_slice()].concat();
        key.verify(&message, &signature)
            .map_err(|_| Error::VerificationFailed)
    }
}

pub(crate) fn verifying_key(bytes: &[u8; 64]) -> Result<VerifyingKey> {
    let mut sec1 = [0; 65];
    sec1[0] = 4;
    sec1[1..].copy_from_slice(bytes);
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| Error::VerificationFailed)
}

pub(crate) fn flags_match(flags: u8, policy: ExactPolicy) -> bool {
    flags & 1 != 0 && (flags & 4 != 0) == (policy == ExactPolicy::UserVerified) && flags & 0x18 == 0
}

#[cfg(test)]
mod tests;
