//! Small, explicit protection of application keys and sealed data.
//!
//! A [`Protector`] owns trusted policy. An [`Envelope`] contains public metadata.
//! Unlock exactly one [`MethodId`] to obtain an [`UnlockedKey`]. Multiple methods
//! are alternatives; combined methods require both factors. Native FIDO loading
//! happens only when a security-key operation is selected.
//!
//! ```
//! use fkw::{ApplicationId, Enrollment, Method, Protector, RecoverySecret, seal};
//! # fn main() -> fkw::Result<()> {
//! let protector = Protector::new(ApplicationId::new("notes.example")?);
//! let mut recovery = RecoverySecret::generate()?;
//! // In a persistent application, securely save recovery before enrollment.
//! let key = protector.create(&Enrollment::new(Method::RecoverySecret, "backup")?, &mut recovery)?;
//! let method = key.envelope().methods().next().unwrap().id;
//! let sealed = seal::seal_bytes(&key, b"a secret")?;
//! let opened = seal::open_bytes(&protector, &sealed, method, &mut recovery)?;
//! assert_eq!(opened.as_slice(), b"a secret");
//! # Ok(())
//! # }
//! ```
#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
mod crypto;
mod envelope;
mod error;
mod id;
mod interaction;
mod methods;
mod platform;
mod protector;
pub mod seal;
mod secret;

pub use envelope::{Envelope, MethodInfo};
pub use error::{Error, Result};
pub use fkw_libfido2::{Config as FidoConfig, Pin};
pub use fkw_platform::{
    Access as StoreAccess, Keystore, NativeStore, Removal, Secret as StoreSecret, StoreError,
};
pub use id::{ApplicationId, MethodId};
pub use interaction::{Interaction, Operation, PassphrasePurpose, Prompt};
pub use methods::{CredentialStorage, Enrollment, KdfCost, KeyOptions, Method, Verification};
pub use protector::{Protector, UnlockedKey};
pub use secret::{DerivedKey, Passphrase, RecoverySecret};
/// Native errors and read-only device diagnostics.
pub mod diagnostics {
    pub use fkw_libfido2::{
        Capabilities, DeviceReport, DeviceStatus, Error as FidoError, Incompatibility,
        runtime_available,
    };
}
#[cfg(test)]
mod tests;
