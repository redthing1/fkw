//! FIDO2 operations and offline assertion verification.
//!
//! libfido2 supplies device discovery, selection, ES256 enrollment, assertions,
//! and managed credential retirement. Assertions are verified before releasing
//! signatures or `hmac-secret` outputs. Offline verification loads no native runtime.

#![deny(unsafe_op_in_unsafe_fn)]

mod assertion;
mod error;
pub use assertion::AssertionProof;
mod ffi;
mod native;

pub use error::{Error, Result};

/// reports whether a complete compatible libfido2 runtime is available.
#[must_use]
pub fn runtime_available() -> bool {
    ffi::runtime_available()
}
pub use native::{
    Authenticator, Backend, Capabilities, Capability, Config, CredentialProtection,
    CredentialPurpose, CredentialStorage, DeviceReport, DeviceStatus, EnrolledCredential,
    Enrollment, EnrollmentFailure, EnrollmentRequest, ExactPolicy, Incompatibility,
    ManagedCapability, ManagedCleanup, ManagedCredential, PendingManagedCredential, Pin,
    PreparedSelection, PrfRequest, SignRequest,
};
