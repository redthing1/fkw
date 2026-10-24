//! protocol operations backed by `libfido2`.
//!
//! the api covers capability discovery, authenticator selection,
//! exact es256 credential enrollment, verified `hmac-secret` evaluation, and
//! selective retirement of managed discoverable credentials.

#![deny(unsafe_op_in_unsafe_fn)]

mod error;
mod ffi;
mod native;

pub use error::{Error, Result};

/// reports whether a complete compatible libfido2 runtime is available.
#[must_use]
pub fn runtime_available() -> bool {
    ffi::runtime_available()
}
pub use native::{
    Authenticator, Backend, Capabilities, Config, CredentialProtection, CredentialStorage,
    DeviceReport, DeviceStatus, EnrolledCredential, Enrollment, EnrollmentFailure,
    EnrollmentRequest, ExactPolicy, Incompatibility, ManagedCapability, ManagedCleanup,
    ManagedCredential, PendingManagedCredential, Pin, PreparedSelection, PrfRequest,
};
