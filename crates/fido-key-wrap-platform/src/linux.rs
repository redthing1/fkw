use std::collections::HashMap;

use crate::{EntryId, Secret};
use secret_service::{EncryptionType, blocking::SecretService};
use zeroize::Zeroizing;

use crate::{
    Removal, Result, StandardStore, StoreError, binary_matches, import_binary, recipient_name,
};

const LABEL: &str = "fido key wrap local secret";
const SCHEMA: &str = "org.fido-key-wrap.v2.factor";

struct EntryKey<'a> {
    application: &'a str,
    recipient: String,
}

impl EntryKey<'_> {
    fn attributes(&self) -> HashMap<&str, &str> {
        HashMap::from([
            ("xdg:schema", SCHEMA),
            ("fido-key-wrap.application", self.application),
            ("fido-key-wrap.recipient", self.recipient.as_str()),
        ])
    }
}

pub(crate) fn create(store: &StandardStore, recipient: EntryId, secret: &Secret) -> Result<()> {
    let service = connect()?;
    let collection = default_collection(&service)?;
    unlock_collection(&collection)?;
    let key = entry_key(store, recipient);
    let existing = collection
        .search_items(key.attributes())
        .map_err(map_error)?;
    match existing.as_slice() {
        [] => {}
        [item] => {
            let bytes = Zeroizing::new(item.get_secret().map_err(map_error)?);
            return if binary_matches(&bytes, secret) {
                Ok(())
            } else if bytes.len() == crate::SECRET_BYTES {
                Err(StoreError::AlreadyExists)
            } else {
                Err(StoreError::Corrupt)
            };
        }
        _ => return Err(StoreError::Ambiguous),
    }

    let created = match secret.expose(|bytes| {
        collection.create_item(
            LABEL,
            key.attributes(),
            bytes,
            false,
            "application/octet-stream",
        )
    }) {
        Ok(item) => item,
        Err(error) => return reconcile_after_create_error(&collection, &key, secret, error),
    };

    let read_back = match created.get_secret() {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(error) => {
            return cleanup_after_failed_create(&collection, &key, &created, map_error(error));
        }
    };
    if !binary_matches(&read_back, secret) {
        return cleanup_after_failed_create(&collection, &key, &created, StoreError::Corrupt);
    }

    let inventory = match collection.search_items(key.attributes()) {
        Ok(items) => items,
        Err(error) => {
            return cleanup_after_failed_create(&collection, &key, &created, map_error(error));
        }
    };
    if inventory.len() == 1 && inventory[0] == created {
        return Ok(());
    }

    cleanup_after_failed_create(&collection, &key, &created, StoreError::Ambiguous)
}

pub(crate) fn load(store: &StandardStore, recipient: EntryId) -> Result<Secret> {
    let service = connect()?;
    let collection = default_collection(&service)?;
    unlock_collection(&collection)?;
    let key = entry_key(store, recipient);
    let items = collection
        .search_items(key.attributes())
        .map_err(map_error)?;
    match items.as_slice() {
        [] => Err(StoreError::Missing),
        [item] => {
            let bytes = Zeroizing::new(item.get_secret().map_err(map_error)?);
            import_binary(&bytes)
        }
        _ => Err(StoreError::Ambiguous),
    }
}

pub(crate) fn remove(store: &StandardStore, recipient: EntryId) -> Result<Removal> {
    let service = connect()?;
    let collection = default_collection(&service)?;
    unlock_collection(&collection)?;
    let key = entry_key(store, recipient);
    let items = collection
        .search_items(key.attributes())
        .map_err(map_error)?;
    let item = match items.as_slice() {
        [] => return Ok(Removal::Absent),
        [item] => item,
        _ => return Err(StoreError::Ambiguous),
    };
    if let Err(error) = item.delete() {
        let remaining = collection
            .search_items(key.attributes())
            .map_err(|_| StoreError::StateUncertain)?;
        return match remaining.as_slice() {
            [] => Ok(Removal::Removed),
            [candidate] if candidate == item => Err(map_error(error)),
            _ => Err(StoreError::StateUncertain),
        };
    }

    let remaining = collection
        .search_items(key.attributes())
        .map_err(|_| StoreError::StateUncertain)?;
    if remaining.is_empty() {
        Ok(Removal::Removed)
    } else {
        Err(StoreError::StateUncertain)
    }
}

fn reconcile_after_create_error(
    collection: &secret_service::blocking::Collection<'_>,
    key: &EntryKey<'_>,
    secret: &Secret,
    native_error: secret_service::Error,
) -> Result<()> {
    let items = collection
        .search_items(key.attributes())
        .map_err(|_| StoreError::StateUncertain)?;
    match items.as_slice() {
        [] => Err(map_error(native_error)),
        [item] => {
            let bytes = Zeroizing::new(item.get_secret().map_err(|_| StoreError::StateUncertain)?);
            if binary_matches(&bytes, secret) {
                Ok(())
            } else if bytes.len() == crate::SECRET_BYTES {
                Err(StoreError::AlreadyExists)
            } else {
                Err(StoreError::Corrupt)
            }
        }
        _ => Err(StoreError::Ambiguous),
    }
}

fn connect() -> Result<SecretService<'static>> {
    SecretService::connect(EncryptionType::Dh).map_err(map_error)
}

fn default_collection<'a>(
    service: &'a SecretService<'a>,
) -> Result<secret_service::blocking::Collection<'a>> {
    service.get_default_collection().map_err(map_error)
}

fn unlock_collection(collection: &secret_service::blocking::Collection<'_>) -> Result<()> {
    if collection.is_locked().map_err(map_error)? {
        collection.unlock().map_err(map_error)?;
    }
    collection.ensure_unlocked().map_err(map_error)
}

fn entry_key(store: &StandardStore, recipient: EntryId) -> EntryKey<'_> {
    EntryKey {
        application: store.application_id(),
        recipient: recipient_name(recipient),
    }
}

fn cleanup_after_failed_create(
    collection: &secret_service::blocking::Collection<'_>,
    key: &EntryKey<'_>,
    item: &secret_service::blocking::Item<'_>,
    error: StoreError,
) -> Result<()> {
    let _ = item.delete();
    let remaining = collection
        .search_items(key.attributes())
        .map_err(|_| StoreError::StateUncertain)?;
    if remaining.iter().any(|candidate| candidate == item) {
        Err(StoreError::StateUncertain)
    } else {
        Err(error)
    }
}

fn map_error(error: secret_service::Error) -> StoreError {
    match error {
        secret_service::Error::Locked => StoreError::Locked,
        secret_service::Error::Prompt => StoreError::Cancelled,
        secret_service::Error::Unavailable | secret_service::Error::NoResult => {
            StoreError::Unavailable
        }
        secret_service::Error::Zbus(error) => map_zbus_error(error),
        secret_service::Error::ZbusFdo(error) => map_fdo_error(&error),
        secret_service::Error::Crypto(_) | secret_service::Error::Zvariant(_) => {
            StoreError::OperationFailed
        }
        _ => StoreError::OperationFailed,
    }
}

fn map_zbus_error(error: zbus::Error) -> StoreError {
    match error {
        zbus::Error::Unsupported | zbus::Error::InterfaceNotFound => StoreError::Unsupported,
        zbus::Error::Address(_) | zbus::Error::Handshake(_) | zbus::Error::InputOutput(_) => {
            StoreError::Unavailable
        }
        zbus::Error::FDO(error) => map_fdo_error(&error),
        _ => StoreError::OperationFailed,
    }
}

fn map_fdo_error(error: &zbus::fdo::Error) -> StoreError {
    use zbus::fdo::Error as FdoError;

    match error {
        FdoError::AccessDenied(_)
        | FdoError::AuthFailed(_)
        | FdoError::InteractiveAuthorizationRequired(_) => StoreError::AccessDenied,
        FdoError::NotSupported(_) | FdoError::UnknownInterface(_) | FdoError::UnknownMethod(_) => {
            StoreError::Unsupported
        }
        FdoError::BadAddress(_)
        | FdoError::Disconnected(_)
        | FdoError::IOError(_)
        | FdoError::NameHasNoOwner(_)
        | FdoError::NoNetwork(_)
        | FdoError::NoReply(_)
        | FdoError::NoServer(_)
        | FdoError::ServiceUnknown(_)
        | FdoError::TimedOut(_)
        | FdoError::Timeout(_) => StoreError::Unavailable,
        _ => StoreError::OperationFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_identity_contains_only_the_fixed_public_namespace() {
        let key = EntryKey {
            application: "vault.example",
            recipient: "12".repeat(32),
        };
        assert_eq!(
            key.attributes(),
            HashMap::from([
                ("xdg:schema", SCHEMA),
                ("fido-key-wrap.application", "vault.example"),
                ("fido-key-wrap.recipient", key.recipient.as_str()),
            ])
        );
    }

    #[test]
    fn native_errors_are_sanitized() {
        for (error, expected) in [
            (secret_service::Error::Locked, StoreError::Locked),
            (secret_service::Error::Prompt, StoreError::Cancelled),
            (secret_service::Error::Unavailable, StoreError::Unavailable),
            (secret_service::Error::NoResult, StoreError::Unavailable),
        ] {
            assert_eq!(map_error(error), expected);
        }

        assert_eq!(
            map_fdo_error(&zbus::fdo::Error::AccessDenied(String::new())),
            StoreError::AccessDenied
        );
        assert_eq!(
            map_fdo_error(&zbus::fdo::Error::NotSupported(String::new())),
            StoreError::Unsupported
        );
        assert_eq!(
            map_fdo_error(&zbus::fdo::Error::ServiceUnknown(String::new())),
            StoreError::Unavailable
        );
    }
}
