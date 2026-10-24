use thiserror::Error;

/// a sanitized backend error.
///
/// errors never contain an authenticator path, a pin, credential material, or
/// native library debug output. `Native` exposes only a stable operation name
/// and numeric status code for diagnostics.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("the libfido2 runtime is unavailable")]
    LibraryUnavailable,

    #[error("the libfido2 runtime is incompatible")]
    LibraryIncompatible,

    #[error("invalid backend input: {0}")]
    InvalidInput(&'static str),

    #[error("native allocation failed")]
    AllocationFailed,

    #[error("operating-system randomness is unavailable")]
    RandomUnavailable,

    #[error("no FIDO authenticator was found")]
    NoAuthenticators,

    #[error("no compatible FIDO authenticator was found")]
    NoCompatibleAuthenticators,

    #[error("authenticator selection timed out")]
    SelectionTimedOut,

    #[error("authenticator operation timed out")]
    TimedOut,

    #[error("authenticator is busy")]
    Busy,

    #[error("authenticator transport failed (device may be unavailable or inaccessible)")]
    Transport,

    #[error("the PIN was incorrect{remaining}", remaining = retry_suffix(*retries))]
    PinInvalid { retries: Option<u8> },

    #[error("the PIN is blocked")]
    PinBlocked,

    #[error("PIN authentication is temporarily blocked; unplug and reconnect the authenticator")]
    PinAuthBlocked,

    #[error("a PIN is required")]
    PinRequired,

    #[error("user action was denied or not completed")]
    UserAction,

    #[error("the authenticator does not support the requested operation")]
    Unsupported,

    #[error("the authenticator does not support managed discoverable credentials")]
    CredentialManagementUnsupported,

    #[error("the authenticator credential store is full")]
    CredentialStoreFull,

    #[error("a managed credential may remain on the authenticator")]
    CredentialMayRemain,

    #[error("the authenticator does not contain the requested credential")]
    CredentialNotFound,

    #[error("the managed credential does not match its stored identity")]
    CredentialMismatch,

    #[error("managed credential retirement could not be confirmed")]
    RetirementUncertain,

    #[error("authenticator response verification failed")]
    VerificationFailed,

    #[error("unexpected authenticator response")]
    Protocol,

    #[error("libfido2 operation {operation} failed with status {code}")]
    Native { operation: &'static str, code: i32 },
}

fn retry_suffix(retries: Option<u8>) -> String {
    match retries {
        Some(1) => " (1 retry remains)".into(),
        Some(count) => format!(" ({count} retries remain)"),
        None => String::new(),
    }
}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_retry_text_is_grammatical() {
        assert_eq!(
            Error::PinInvalid { retries: Some(1) }.to_string(),
            "the PIN was incorrect (1 retry remains)"
        );
        assert_eq!(
            Error::PinInvalid { retries: Some(2) }.to_string(),
            "the PIN was incorrect (2 retries remain)"
        );
    }
}
