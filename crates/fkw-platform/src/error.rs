/// result returned by a native factor store.
pub type Result<T> = std::result::Result<T, StoreError>;

/// bounded failure from native factor storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// this target has no native backend.
    #[error("platform factor storage is unsupported")]
    Unsupported,
    /// the native store or its user session is unavailable.
    #[error("platform factor storage is unavailable")]
    Unavailable,
    /// the native store is locked.
    #[error("platform factor storage is locked")]
    Locked,
    /// the process is not permitted to access the entry.
    #[error("platform factor storage denied access")]
    AccessDenied,
    /// the user cancelled a native storage prompt.
    #[error("platform factor storage was cancelled")]
    Cancelled,
    /// the exact entry already contains different secret material.
    #[error("the factor entry already exists")]
    AlreadyExists,
    /// the exact entry does not exist.
    #[error("the factor entry is missing")]
    Missing,
    /// more than one entry matched the exact public identity.
    #[error("the factor entry is ambiguous")]
    Ambiguous,
    /// the stored value is not one canonical factor.
    #[error("the factor entry is corrupt")]
    Corrupt,
    /// a native mutation may have changed the exact entry.
    #[error("the factor entry state is uncertain")]
    StateUncertain,
    /// the native operation failed without a safer useful category.
    #[error("platform factor storage failed")]
    OperationFailed,
}
