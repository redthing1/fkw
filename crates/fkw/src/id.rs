use std::{fmt, str::FromStr};

use crate::{Error, Result};

const MIN_APPLICATION_ID_BYTES: usize = 3;
const MAX_APPLICATION_ID_BYTES: usize = 253;

/// trusted lowercase dns-shaped application and fido relying-party identity.
///
/// applications construct this value from trusted configuration and never
/// adopt the identity carried by an unverified envelope.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ApplicationId(String);

impl ApplicationId {
    /// validates and constructs an application identity.
    ///
    /// # errors
    ///
    /// returns [`Error::InvalidApplicationId`] unless the value contains at
    /// least two lowercase dns-shaped labels and is at most 253 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if !(MIN_APPLICATION_ID_BYTES..=MAX_APPLICATION_ID_BYTES).contains(&value.len())
            || !value.is_ascii()
        {
            return Err(Error::InvalidApplicationId);
        }

        let mut count = 0usize;
        for label in value.split('.') {
            count += 1;
            let bytes = label.as_bytes();
            if bytes.is_empty()
                || bytes.len() > 63
                || !bytes[0].is_ascii_alphanumeric()
                || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
                || !bytes
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
            {
                return Err(Error::InvalidApplicationId);
            }
        }
        if count < 2 {
            return Err(Error::InvalidApplicationId);
        }
        Ok(Self(value))
    }

    /// returns the canonical application identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ApplicationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// stable public identity of one root-recovery route.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MethodId(pub(crate) [u8; 32]);

impl MethodId {
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for MethodId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for MethodId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "MethodId({self})")
    }
}

impl FromStr for MethodId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::InvalidMethodId);
        }
        let mut bytes = [0u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (decode_hex(pair[0]) << 4) | decode_hex(pair[1]);
        }
        Ok(Self(bytes))
    }
}

const fn decode_hex(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_id_is_strict_and_canonical() {
        assert!(ApplicationId::new("org.example.vault").is_ok());
        assert!(ApplicationId::new("org.example.research-vault").is_ok());
        assert!(ApplicationId::new("localhost").is_err());
        assert!(ApplicationId::new("Org.example.vault").is_err());
        assert!(ApplicationId::new("org..vault").is_err());
        assert!(ApplicationId::new("org.example._vault").is_err());
    }

    #[test]
    fn recipient_id_uses_exact_lowercase_hex() {
        let id = MethodId([0xabu8; 32]);
        let text = id.to_string();
        assert_eq!(text.len(), 64);
        assert_eq!(text.parse::<MethodId>().unwrap(), id);
        assert!(text.to_uppercase().parse::<MethodId>().is_err());
        assert!(text[..63].parse::<MethodId>().is_err());
    }
}
