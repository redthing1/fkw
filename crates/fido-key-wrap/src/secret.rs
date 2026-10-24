use crate::{Error, Result};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Opaque passphrase bytes. No implicit text normalization.
pub struct Passphrase(pub(crate) Zeroizing<Vec<u8>>);
impl Passphrase {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes.into());
        if bytes.is_empty() || bytes.len() > 1024 {
            return Err(Error::InvalidInput("passphrase must contain 1–1024 bytes"));
        }
        Ok(Self(bytes))
    }
    pub(crate) fn matches(&self, other: &Self) -> bool {
        let mut a = Zeroizing::new([0u8; 1024]);
        let mut b = Zeroizing::new([0u8; 1024]);
        a[..self.0.len()].copy_from_slice(&self.0);
        b[..other.0.len()].copy_from_slice(&other.0);
        bool::from(a.as_slice().ct_eq(b.as_slice()) & self.0.len().ct_eq(&other.0.len()))
    }
}
impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase([REDACTED])")
    }
}
/// Generated random recovery material. Store it before enrolling its method.
pub struct RecoverySecret(pub(crate) Zeroizing<[u8; 32]>);
impl RecoverySecret {
    pub fn generate() -> Result<Self> {
        Ok(Self(crate::crypto::random()?))
    }
    /// Imports exactly 32 random bytes and erases the source. Never use a password.
    pub fn import(bytes: &mut [u8; 32]) -> Self {
        let value = Self(Zeroizing::new(*bytes));
        bytes.zeroize();
        value
    }
    /// Exposes bytes for explicit backup; the caller must protect any copy.
    pub fn expose<T>(&self, f: impl FnOnce(&[u8; 32]) -> T) -> T {
        f(&self.0)
    }
}
impl fmt::Debug for RecoverySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoverySecret([REDACTED])")
    }
}
/// Purpose-separated application key, erased on drop.
pub struct DerivedKey(pub(crate) Zeroizing<[u8; 32]>);
impl DerivedKey {
    pub fn expose<T>(&self, f: impl FnOnce(&[u8; 32]) -> T) -> T {
        f(&self.0)
    }
}
impl fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DerivedKey([REDACTED])")
    }
}
