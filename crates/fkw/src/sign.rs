//! Hardware signatures bound to an application, a trusted public key and a purpose.
//!
//! Signing requires PIN and touch. Verification is offline and does not load
//! native code. Signing credentials are non-discoverable and cannot be recovered
//! through a protection envelope. Keep the credential handle for future signing.
use crate::{
    ApplicationId, Error, FidoConfig, Interaction, Operation, Prompt, Result, Target, crypto,
};
use fkw_libfido2::{self as native, AssertionProof};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Cursor, Read},
    path::Path,
};

const PUBLIC_MAGIC: &[u8; 5] = b"FKVP\x01";
const CREDENTIAL_MAGIC: &[u8; 5] = b"FKSC\x01";
const SIGNATURE_MAGIC: &[u8; 5] = b"FKSG\x01";

/// Public verification identity. Obtain this through an authenticated channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationKey {
    application: ApplicationId,
    public_key: [u8; 64],
}

impl VerificationKey {
    /// Maximum encoded public-key size.
    pub const MAX_BYTES: usize = 324;

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let app = self.application.as_str().as_bytes();
        let mut out = PUBLIC_MAGIC.to_vec();
        out.extend_from_slice(
            &u16::try_from(app.len())
                .expect("bounded application")
                .to_be_bytes(),
        );
        out.extend_from_slice(app);
        out.extend_from_slice(&self.public_key);
        out
    }

    /// Parses a public key without establishing trust in its origin.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if !(74..=Self::MAX_BYTES).contains(&bytes.len()) || !bytes.starts_with(PUBLIC_MAGIC) {
            return Err(Error::InvalidSignature);
        }
        let len = usize::from(u16::from_be_bytes([bytes[5], bytes[6]]));
        if bytes.len() != 7 + len + 64 {
            return Err(Error::InvalidSignature);
        }
        let app = std::str::from_utf8(&bytes[7..7 + len]).map_err(|_| Error::InvalidSignature)?;
        let application = ApplicationId::new(app).map_err(|_| Error::InvalidSignature)?;
        let public_key: [u8; 64] = bytes[7 + len..]
            .try_into()
            .map_err(|_| Error::InvalidSignature)?;
        let mut sec1 = [0; 65];
        sec1[0] = 4;
        sec1[1..].copy_from_slice(&public_key);
        p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| Error::InvalidSignature)?;
        Ok(Self {
            application,
            public_key,
        })
    }

    /// Stable digest of the complete public representation.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        crypto::hash(&[b"fkw/sign/v1/fingerprint", &self.to_bytes()])
    }

    /// Verifies the complete message and expected purpose without accessing a token.
    pub fn verify(&self, purpose: &str, message: &[u8], signature: &Signature) -> Result<()> {
        self.verify_reader(purpose, &mut Cursor::new(message), signature)
    }

    pub fn verify_file(
        &self,
        purpose: &str,
        path: impl AsRef<Path>,
        signature: &Signature,
    ) -> Result<()> {
        self.verify_reader(purpose, &mut File::open(path)?, signature)
    }

    pub fn verify_reader(
        &self,
        purpose: &str,
        message: &mut impl Read,
        signature: &Signature,
    ) -> Result<()> {
        let challenge = self.challenge(purpose, message)?;
        // This signature format has no extensions; all 37 bytes are fixed fields.
        if signature.0.authenticator_data().len() != 37 {
            return Err(Error::VerificationFailed);
        }
        signature
            .0
            .verify(
                self.application.as_str(),
                &challenge,
                &self.public_key,
                native::ExactPolicy::UserVerified,
            )
            .map_err(|_| Error::VerificationFailed)
    }

    fn challenge(&self, purpose: &str, message: &mut impl Read) -> Result<[u8; 32]> {
        if purpose.is_empty() || purpose.len() > 128 || purpose.chars().any(char::is_control) {
            return Err(Error::InvalidInput(
                "purpose must contain 1–128 bytes without control characters",
            ));
        }
        let mut hash = Sha256::new();
        let mut buffer = vec![0; 65_536];
        loop {
            match message.read(&mut buffer) {
                Ok(0) => break,
                Ok(len) => hash.update(&buffer[..len]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(crypto::hash(&[
            b"fkw/sign/v1/message",
            &self.to_bytes(),
            purpose.as_bytes(),
            &hash.finalize(),
        ]))
    }
}

/// Public credential handle required to address the private key on its token.
#[derive(Clone, Debug)]
pub struct Credential {
    key: VerificationKey,
    id: Vec<u8>,
}

impl Credential {
    /// Maximum encoded credential-handle size.
    pub const MAX_BYTES: usize = 7 + VerificationKey::MAX_BYTES + 1024;

    #[must_use]
    pub const fn verification_key(&self) -> &VerificationKey {
        &self.key
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let key = self.key.to_bytes();
        let mut out = CREDENTIAL_MAGIC.to_vec();
        out.extend_from_slice(&u16::try_from(key.len()).expect("bounded key").to_be_bytes());
        out.extend_from_slice(&key);
        out.extend_from_slice(&self.id);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if !(82..=Self::MAX_BYTES).contains(&bytes.len()) || !bytes.starts_with(CREDENTIAL_MAGIC) {
            return Err(Error::InvalidSignature);
        }
        let len = usize::from(u16::from_be_bytes([bytes[5], bytes[6]]));
        let end = 7 + len;
        if end >= bytes.len() || bytes.len() - end > 1024 {
            return Err(Error::InvalidSignature);
        }
        Ok(Self {
            key: VerificationKey::from_bytes(&bytes[7..end])?,
            id: bytes[end..].to_vec(),
        })
    }
}

/// Detached signature. Parsing does not establish authenticity.
#[derive(Clone, Debug)]
pub struct Signature(AssertionProof);

impl Signature {
    /// Maximum encoded detached-signature size.
    pub const MAX_BYTES: usize = 114;

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        [
            SIGNATURE_MAGIC.as_slice(),
            self.0.authenticator_data(),
            self.0.signature(),
        ]
        .concat()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if !(50..=Self::MAX_BYTES).contains(&bytes.len()) || !bytes.starts_with(SIGNATURE_MAGIC) {
            return Err(Error::InvalidSignature);
        }
        Ok(Self(
            AssertionProof::from_parts(&bytes[5..42], &bytes[42..])
                .map_err(|_| Error::InvalidSignature)?,
        ))
    }
}

/// Trusted application identity and bounded native signing operations.
pub struct Signer {
    application: ApplicationId,
    config: FidoConfig,
}

impl Signer {
    #[must_use]
    pub fn new(application: ApplicationId) -> Self {
        Self {
            application,
            config: FidoConfig::default(),
        }
    }

    #[must_use]
    pub const fn with_fido_config(mut self, config: FidoConfig) -> Self {
        self.config = config;
        self
    }

    pub fn inspect_authenticators(&self) -> Result<Vec<crate::diagnostics::DeviceReport>> {
        Ok(
            native::Backend::new(self.config)
                .inspect_authenticators(native::Capability::Signing)?,
        )
    }

    /// Enrolls a dedicated credential. Save the handle before using it;
    /// retry a failed save with this handle instead of enrolling again.
    pub fn create(&self, interaction: &mut dyn Interaction) -> Result<Credential> {
        let prompt = Prompt {
            operation: Operation::Enroll,
            label: "signing key",
            target: Target::SigningKey,
        };
        let mut authenticator = self.select(prompt, interaction)?;
        let pin = interaction.pin(prompt)?;
        interaction.touch(prompt)?;
        let enrollment = authenticator
            .enroll(
                native::EnrollmentRequest {
                    purpose: native::CredentialPurpose::Signing,
                    relying_party_id: self.application.as_str(),
                    relying_party_name: "fkw",
                    policy: native::ExactPolicy::UserVerified,
                    storage: native::CredentialStorage::NonDiscoverable,
                },
                &pin,
            )
            .map_err(|failure| failure.into_parts().0)?;
        let (credential, _) = enrollment.into_parts();
        Ok(Credential {
            key: VerificationKey {
                application: self.application.clone(),
                public_key: credential.es256_public_key,
            },
            id: credential.credential_id,
        })
    }

    /// Signs a message under an explicit purpose (1–128 bytes, no control characters).
    pub fn sign(
        &self,
        credential: &Credential,
        purpose: &str,
        message: &[u8],
        interaction: &mut dyn Interaction,
    ) -> Result<Signature> {
        self.sign_reader(credential, purpose, &mut Cursor::new(message), interaction)
    }

    pub fn sign_file(
        &self,
        credential: &Credential,
        purpose: &str,
        path: impl AsRef<Path>,
        interaction: &mut dyn Interaction,
    ) -> Result<Signature> {
        self.sign_reader(credential, purpose, &mut File::open(path)?, interaction)
    }

    pub fn sign_reader(
        &self,
        credential: &Credential,
        purpose: &str,
        message: &mut impl Read,
        interaction: &mut dyn Interaction,
    ) -> Result<Signature> {
        if credential.key.application != self.application {
            return Err(Error::WrongApplication);
        }
        let challenge = credential.key.challenge(purpose, message)?;
        let prompt = Prompt {
            operation: Operation::Sign,
            label: purpose,
            target: Target::SigningKey,
        };
        let mut authenticator = self.select(prompt, interaction)?;
        let pin = interaction.pin(prompt)?;
        interaction.touch(prompt)?;
        let proof = authenticator.sign(
            native::SignRequest {
                relying_party_id: self.application.as_str(),
                credential_id: &credential.id,
                es256_public_key: &credential.key.public_key,
                client_data_hash: &challenge,
            },
            &pin,
        )?;
        if proof.authenticator_data().len() != 37 {
            return Err(Error::VerificationFailed);
        }
        Ok(Signature(proof))
    }

    fn select(
        &self,
        prompt: Prompt<'_>,
        interaction: &mut dyn Interaction,
    ) -> Result<native::Authenticator> {
        let selection =
            native::Backend::new(self.config).prepare_selection(native::Capability::Signing)?;
        interaction.select(prompt, selection.compatible_authenticators())?;
        Ok(selection.select()?)
    }
}

#[cfg(test)]
mod tests;
