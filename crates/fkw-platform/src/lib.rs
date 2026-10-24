//! Native storage of random factors; independent of envelope policy.
#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
mod error;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod macos_user_presence;
#[cfg(feature = "testing")]
pub mod testing;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported;
pub use error::{Result, StoreError};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};
const SECRET_BYTES: usize = 32;

/// Exact native access requirement. Unsupported requirements fail closed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Access {
    /// Linux Secret Service or macOS data-protection keychain.
    Standard,
    /// OS-enforced local user authentication (macOS only).
    UserAuthentication,
    /// Explicit macOS login keychain for unsigned command-line programs.
    MacosLogin,
}
/// Random store factor, erased on drop and redacted in debug output.
pub struct Secret(Zeroizing<[u8; 32]>);
impl Secret {
    /// Copies a factor into zeroizing storage and erases the source.
    pub fn import(bytes: &mut [u8; 32]) -> Self {
        let secret = Self(Zeroizing::new(*bytes));
        bytes.zeroize();
        secret
    }
    /// Temporarily exposes the factor to a trusted adapter.
    pub fn expose<T>(&self, f: impl FnOnce(&[u8; 32]) -> T) -> T {
        f(&self.0)
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}
/// Confirmed result of deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Removal {
    Removed,
    Absent,
}
/// Trusted adapter. Creation never overwrites different material and confirms
/// an exact read-back. Loads reject ambiguity. Removal matches the expected
/// factor and confirms absence. Report uncertain effects as `StateUncertain`.
/// Enforce `access` exactly. Application namespaces are trusted configuration.
pub trait Keystore: Send + Sync {
    /// Rejects unsupported access before an operation prompts for other factors.
    /// Actual store availability can still fail during I/O.
    fn check_access(&self, _access: Access) -> Result<()> {
        Ok(())
    }
    fn create(
        &self,
        application: &str,
        id: &[u8; 32],
        access: Access,
        secret: &Secret,
    ) -> Result<()>;
    fn load(&self, application: &str, id: &[u8; 32], access: Access) -> Result<Secret>;
    fn remove(
        &self,
        application: &str,
        id: &[u8; 32],
        access: Access,
        expected: &Secret,
    ) -> Result<Removal>;
}
impl<T: Keystore + ?Sized> Keystore for std::sync::Arc<T> {
    fn check_access(&self, access: Access) -> Result<()> {
        (**self).check_access(access)
    }
    fn create(&self, app: &str, id: &[u8; 32], access: Access, secret: &Secret) -> Result<()> {
        (**self).create(app, id, access, secret)
    }
    fn load(&self, app: &str, id: &[u8; 32], access: Access) -> Result<Secret> {
        (**self).load(app, id, access)
    }
    fn remove(
        &self,
        app: &str,
        id: &[u8; 32],
        access: Access,
        expected: &Secret,
    ) -> Result<Removal> {
        (**self).remove(app, id, access, expected)
    }
}
/// Stateless native dispatcher; construction performs no native I/O.
#[derive(Debug, Default)]
pub struct NativeStore;
impl Keystore for NativeStore {
    fn check_access(&self, access: Access) -> Result<()> {
        let supported = match access {
            Access::Standard => cfg!(any(target_os = "linux", target_os = "macos")),
            Access::UserAuthentication | Access::MacosLogin => cfg!(target_os = "macos"),
        };
        if supported {
            Ok(())
        } else {
            Err(StoreError::Unsupported)
        }
    }
    fn create(&self, app: &str, id: &[u8; 32], access: Access, secret: &Secret) -> Result<()> {
        if access == Access::UserAuthentication {
            #[cfg(target_os = "macos")]
            return macos_user_presence::create(
                &AuthenticatedStore::new(app),
                EntryId(*id),
                secret,
            );
            #[cfg(not(target_os = "macos"))]
            return Err(StoreError::Unsupported);
        }
        platform_create(&StandardStore::new(app, access)?, EntryId(*id), secret)
    }
    fn load(&self, app: &str, id: &[u8; 32], access: Access) -> Result<Secret> {
        if access == Access::UserAuthentication {
            #[cfg(target_os = "macos")]
            return macos_user_presence::load(&AuthenticatedStore::new(app), EntryId(*id));
            #[cfg(not(target_os = "macos"))]
            return Err(StoreError::Unsupported);
        }
        platform_load(&StandardStore::new(app, access)?, EntryId(*id))
    }
    fn remove(
        &self,
        app: &str,
        id: &[u8; 32],
        access: Access,
        expected: &Secret,
    ) -> Result<Removal> {
        if access == Access::UserAuthentication {
            #[cfg(target_os = "macos")]
            return macos_user_presence::remove(
                &AuthenticatedStore::new(app),
                EntryId(*id),
                expected,
            );
            #[cfg(not(target_os = "macos"))]
            return Err(StoreError::Unsupported);
        }
        let store = StandardStore::new(app, access)?;
        let current = match platform_load(&store, EntryId(*id)) {
            Ok(value) => value,
            Err(StoreError::Missing) => return Ok(Removal::Absent),
            Err(error) => return Err(error),
        };
        if !current.expose(|a| expected.expose(|b| bool::from(a.ct_eq(b)))) {
            return Err(StoreError::AlreadyExists);
        }
        platform_remove(&store, EntryId(*id))
    }
}
// Vocabulary private to retained native adapters.
#[derive(Clone, Copy)]
struct EntryId([u8; 32]);
impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
struct StandardStore {
    application: String,
    #[cfg(target_os = "macos")]
    kind: macos::StoreKind,
}
impl StandardStore {
    fn new(app: &str, access: Access) -> Result<Self> {
        #[cfg(not(target_os = "macos"))]
        if access != Access::Standard {
            return Err(StoreError::Unsupported);
        }
        Ok(Self {
            application: app.to_owned(),
            #[cfg(target_os = "macos")]
            kind: match access {
                Access::Standard => macos::StoreKind::DataProtection,
                Access::MacosLogin => macos::StoreKind::LoginKeychain,
                Access::UserAuthentication => return Err(StoreError::Unsupported),
            },
        })
    }
    fn application_id(&self) -> &str {
        &self.application
    }
}
#[cfg(target_os = "macos")]
struct AuthenticatedStore {
    application: String,
}
#[cfg(target_os = "macos")]
impl AuthenticatedStore {
    fn new(app: &str) -> Self {
        Self {
            application: app.to_owned(),
        }
    }
    fn application_id(&self) -> &str {
        &self.application
    }
}
#[cfg(target_os = "linux")]
use linux::{create as platform_create, load as platform_load, remove as platform_remove};
#[cfg(target_os = "macos")]
use macos::{create as platform_create, load as platform_load, remove as platform_remove};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use unsupported::{create as platform_create, load as platform_load, remove as platform_remove};
#[cfg(target_os = "macos")]
fn service_name(app: &str) -> String {
    // Stable v2 storage namespace.
    format!("fido-key-wrap.v2.factor:{app}")
}
#[cfg(target_os = "macos")]
fn authenticated_service_name(app: &str) -> String {
    // Stable v2 storage namespace.
    format!("fido-key-wrap.v2.authenticated-factor:{app}")
}
fn recipient_name(id: EntryId) -> String {
    id.to_string()
}
fn import_binary(bytes: &[u8]) -> Result<Secret> {
    let mut exact: [u8; 32] = bytes.try_into().map_err(|_| StoreError::Corrupt)?;
    Ok(Secret::import(&mut exact))
}
fn binary_matches(bytes: &[u8], secret: &Secret) -> bool {
    bytes.len() == 32 && secret.expose(|expected| bool::from(expected.as_slice().ct_eq(bytes)))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_binary_and_redaction() {
        let mut source = [0xab; 32];
        let secret = Secret::import(&mut source);
        assert_eq!(source, [0; 32]);
        assert!(binary_matches(&[0xab; 32], &secret));
        assert!(import_binary(&[0; 31]).is_err());
        assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
    }
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn unsupported_access_never_falls_back() {
        assert_eq!(
            NativeStore
                .load("vault.example", &[0; 32], Access::UserAuthentication)
                .unwrap_err(),
            StoreError::Unsupported
        );
        assert_eq!(
            NativeStore
                .load("vault.example", &[0; 32], Access::MacosLogin)
                .unwrap_err(),
            StoreError::Unsupported
        );
    }
}
