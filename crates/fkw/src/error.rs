use crate::MethodId;
/// Library result.
pub type Result<T> = std::result::Result<T, Error>;
/// Bounded errors. Secret values and native device paths are never included.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid application identity")]
    InvalidApplicationId,
    #[error("invalid method identifier")]
    InvalidMethodId,
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("invalid or unsupported envelope")]
    InvalidEnvelope,
    #[error("invalid or incomplete sealed data")]
    InvalidSealedData,
    #[error("envelope belongs to a different application")]
    WrongApplication,
    #[error("method is not permitted by application policy")]
    MethodNotAllowed,
    #[error("selected method exceeds application resource limits")]
    ResourceLimit,
    #[error("KDF memory could not be allocated")]
    KdfResourceUnavailable,
    #[error("method not found")]
    MethodNotFound,
    #[error("cannot remove the last method")]
    LastMethod,
    #[error("method limit reached")]
    TooManyMethods,
    #[error("unlock or authentication failed")]
    UnlockFailed,
    #[error("passphrase confirmation did not match")]
    ConfirmationMismatch,
    #[error("interaction cancelled")]
    Cancelled,
    #[error("requested interaction is not supported")]
    InteractionUnsupported,
    #[error("interaction failed")]
    InteractionFailed,
    #[error("secure randomness unavailable")]
    RandomUnavailable,
    #[error("security key: {0}")]
    Fido(#[from] fkw_libfido2::Error),
    #[error("keystore: {0}")]
    Store(#[from] crate::StoreError),
    #[error("enrollment failed; an external factor may remain for method {method}: {cause}")]
    EnrollmentUncertain {
        method: MethodId,
        #[source]
        cause: Box<Error>,
    },
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("output was published, but directory durability could not be confirmed: {0}")]
    PublicationUncertain(#[source] std::io::Error),
}
