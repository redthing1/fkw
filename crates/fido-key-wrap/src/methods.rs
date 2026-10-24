use crate::{Error, Result, StoreAccess};
/// Exact signed FIDO assertion policy; there is no automatic downgrade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verification {
    Presence,
    UserVerified,
}
/// Credential lifecycle. Only managed credentials can be explicitly retired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialStorage {
    NonDiscoverable,
    Managed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyOptions {
    pub verification: Verification,
    pub storage: CredentialStorage,
}
impl KeyOptions {
    #[must_use]
    pub const fn new(verification: Verification) -> Self {
        Self {
            verification,
            storage: CredentialStorage::NonDiscoverable,
        }
    }
    #[must_use]
    pub const fn managed(mut self) -> Self {
        self.storage = CredentialStorage::Managed;
        self
    }
}
/// A finite unlock recipe. Alternatives are separate methods in an envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Passphrase,
    SecurityKey(KeyOptions),
    Keystore(StoreAccess),
    KeyAndPassphrase(KeyOptions),
    KeyAndKeystore(KeyOptions, StoreAccess),
    RecoverySecret,
}
impl Method {
    #[must_use]
    pub const fn key_options(self) -> Option<KeyOptions> {
        match self {
            Self::SecurityKey(k) | Self::KeyAndPassphrase(k) | Self::KeyAndKeystore(k, _) => {
                Some(k)
            }
            _ => None,
        }
    }
    #[must_use]
    pub const fn store_access(self) -> Option<StoreAccess> {
        match self {
            Self::Keystore(a) | Self::KeyAndKeystore(_, a) => Some(a),
            _ => None,
        }
    }
    #[must_use]
    pub const fn needs_passphrase(self) -> bool {
        matches!(self, Self::Passphrase | Self::KeyAndPassphrase(_))
    }
}
/// Bounded Argon2id work factor; also used for local operation ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfCost {
    pub(crate) memory: u32,
    pub(crate) passes: u32,
    pub(crate) lanes: u32,
}
impl KdfCost {
    pub const INTERACTIVE: Self = Self {
        memory: 65_536,
        passes: 3,
        lanes: 1,
    };
    pub const DEFAULT: Self = Self {
        memory: 262_144,
        passes: 3,
        lanes: 4,
    };
    pub const MAX: Self = Self {
        memory: 262_144,
        passes: 6,
        lanes: 4,
    };
    pub fn new(memory_kib: u32, passes: u32, lanes: u32) -> Result<Self> {
        if !(65_536..=262_144).contains(&memory_kib)
            || !(3..=6).contains(&passes)
            || !(1..=4).contains(&lanes)
            || memory_kib % (4 * lanes) != 0
        {
            return Err(Error::InvalidInput("invalid Argon2id cost"));
        }
        Ok(Self {
            memory: memory_kib,
            passes,
            lanes,
        })
    }
    #[must_use]
    pub const fn memory_kib(self) -> u32 {
        self.memory
    }
    #[must_use]
    pub const fn passes(self) -> u32 {
        self.passes
    }
    #[must_use]
    pub const fn lanes(self) -> u32 {
        self.lanes
    }
    pub(crate) const fn fits(self, ceiling: Self) -> bool {
        self.memory <= ceiling.memory
            && self.passes <= ceiling.passes
            && self.lanes <= ceiling.lanes
    }
}
impl Default for KdfCost {
    fn default() -> Self {
        Self::DEFAULT
    }
}
/// Creation parameters, distinct from secret input supplied by Interaction.
#[derive(Clone, Debug)]
pub struct Enrollment {
    pub(crate) method: Method,
    pub(crate) label: String,
    pub(crate) cost: KdfCost,
}
impl Enrollment {
    pub fn new(method: Method, label: impl Into<String>) -> Result<Self> {
        let label = label.into();
        validate_label(&label)?;
        Ok(Self {
            method,
            label,
            cost: KdfCost::DEFAULT,
        })
    }
    pub fn with_kdf_cost(mut self, cost: KdfCost) -> Result<Self> {
        if !self.method.needs_passphrase() {
            return Err(Error::InvalidInput("this method has no passphrase"));
        }
        self.cost = cost;
        Ok(self)
    }
    #[must_use]
    pub const fn method(&self) -> Method {
        self.method
    }
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}
pub(crate) fn validate_label(label: &str) -> Result<()> {
    if label.len() > 128 || label.chars().any(char::is_control) {
        return Err(Error::InvalidInput("invalid method label"));
    }
    Ok(())
}
