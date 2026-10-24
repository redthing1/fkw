use crate::{EntryId, Secret};
use core_foundation::{base::ToVoid, data::CFData, dictionary::CFMutableDictionary};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    base::Error as NativeError,
    item::{
        CloudSync, ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Limit, Location,
        SearchResult,
    },
    passwords::{AccessControlOptions, PasswordOptions},
};
use security_framework_sys::base::{
    errSecAuthFailed as ERR_SEC_AUTH_FAILED, errSecDuplicateItem as ERR_SEC_DUPLICATE_ITEM,
    errSecIO as ERR_SEC_IO, errSecItemNotFound as ERR_SEC_ITEM_NOT_FOUND,
    errSecUnimplemented as ERR_SEC_UNIMPLEMENTED,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    AuthenticatedStore, Removal, Result, StoreError, authenticated_service_name, binary_matches,
    import_binary, recipient_name,
};

// Part of the persistent deletion identity, not just a display label.
const LABEL_PREFIX: &str = "fido key wrap authenticated factor ";
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_NOT_AVAILABLE: i32 = -25_291;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25_308;
const ERR_SEC_INTERACTION_REQUIRED: i32 = -25_315;
const ERR_SEC_DATA_NOT_AVAILABLE: i32 = -25_316;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34_018;
const ERR_SEC_SERVICE_NOT_AVAILABLE: i32 = -67_585;

pub(crate) fn create(
    store: &AuthenticatedStore,
    recipient: EntryId,
    secret: &Secret,
) -> Result<()> {
    match add(store, recipient, secret) {
        Ok(()) => verify_created(store, recipient, secret)
            .or_else(|error| cleanup_after_failed_create(store, recipient, secret, error)),
        Err(error) if error.code() == ERR_SEC_DUPLICATE_ITEM => {
            compare_existing(store, recipient, secret)
        }
        Err(error) if is_definite_add_failure(error) => Err(map_error(error)),
        Err(error) => reconcile_after_add_error(store, recipient, secret, error),
    }
}

pub(crate) fn load(store: &AuthenticatedStore, recipient: EntryId) -> Result<Secret> {
    load_exact(store, recipient)
}

fn load_exact(store: &AuthenticatedStore, recipient: EntryId) -> Result<Secret> {
    match inventory_count(store, recipient)? {
        0 => return Err(StoreError::Missing),
        1 => {}
        _ => return Err(StoreError::Ambiguous),
    }

    let mut values = find_values(store, recipient)?;
    let secret = match values.len() {
        0 => return Err(StoreError::Missing),
        1 => import_binary(&values.pop().expect("one exact value"))?,
        _ => return Err(StoreError::Ambiguous),
    };
    match fingerprint_count(store, recipient, &secret)? {
        1 => Ok(secret),
        0 => Err(StoreError::Corrupt),
        _ => Err(StoreError::Ambiguous),
    }
}

pub(crate) fn remove(
    store: &AuthenticatedStore,
    recipient: EntryId,
    expected: &Secret,
) -> Result<Removal> {
    match inventory_count(store, recipient)? {
        0 => return Ok(Removal::Absent),
        1 => {}
        _ => return Err(StoreError::Ambiguous),
    }

    // The caller obtains `expected` through the user-presence protected load
    // before retiring its envelope route. Binding deletion to its public
    // fingerprint avoids a second prompt and cannot select different material.
    match deletion_query(store, recipient, expected).delete() {
        Ok(()) => confirm_removed(store, recipient),
        Err(error) => reconcile_after_delete_error(store, recipient, error),
    }
}

fn add(
    store: &AuthenticatedStore,
    recipient: EntryId,
    secret: &Secret,
) -> security_framework::base::Result<()> {
    let service = authenticated_service_name(store.application_id());
    let account = recipient_name(recipient);
    let label = item_label(secret);
    let access_control = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        AccessControlOptions::USER_PRESENCE.bits(),
    )?;

    secret.expose(|bytes| {
        let value = ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data: CFData::from_buffer(bytes),
        };
        let mut options = ItemAddOptions::new(value);
        options
            .set_service(&service)
            .set_account_name(&account)
            .set_label(label)
            .set_location(Location::DataProtectionKeychain);

        #[allow(deprecated)]
        let dictionary = options.to_dictionary();
        let mut dictionary = CFMutableDictionary::from(&dictionary);
        let mut access_options = PasswordOptions::new_generic_password(&service, &account);
        access_options.use_protected_keychain();
        access_options.set_access_synchronized(Some(false));
        access_options.set_access_control(access_control);
        #[allow(deprecated)]
        for (key, value) in access_options.query {
            dictionary.set(key.to_void(), value.to_void());
        }
        #[allow(deprecated)]
        security_framework::item::add_item(dictionary.to_immutable())
    })
}

fn verify_created(store: &AuthenticatedStore, recipient: EntryId, secret: &Secret) -> Result<()> {
    let stored = load_exact(store, recipient)?;
    if secrets_match(&stored, secret) {
        Ok(())
    } else {
        Err(StoreError::Corrupt)
    }
}

fn compare_existing(store: &AuthenticatedStore, recipient: EntryId, secret: &Secret) -> Result<()> {
    let stored = load_exact(store, recipient)?;
    if secrets_match(&stored, secret) {
        Ok(())
    } else {
        Err(StoreError::AlreadyExists)
    }
}

fn reconcile_after_add_error(
    store: &AuthenticatedStore,
    recipient: EntryId,
    secret: &Secret,
    native_error: NativeError,
) -> Result<()> {
    match inventory_count(store, recipient) {
        Ok(0) => Err(map_error(native_error)),
        Ok(1) => {
            let stored = load_exact(store, recipient).map_err(|_| StoreError::StateUncertain)?;
            if secrets_match(&stored, secret) {
                Ok(())
            } else {
                Err(StoreError::AlreadyExists)
            }
        }
        Ok(_) => Err(StoreError::Ambiguous),
        Err(_) => Err(StoreError::StateUncertain),
    }
}

fn cleanup_after_failed_create(
    store: &AuthenticatedStore,
    recipient: EntryId,
    secret: &Secret,
    original_error: StoreError,
) -> Result<()> {
    let _ = deletion_query(store, recipient, secret).delete();
    match inventory_count(store, recipient) {
        Ok(0) => Err(original_error),
        Ok(_) | Err(_) => Err(StoreError::StateUncertain),
    }
}

fn reconcile_after_delete_error(
    store: &AuthenticatedStore,
    recipient: EntryId,
    native_error: NativeError,
) -> Result<Removal> {
    match inventory_count(store, recipient) {
        Ok(0) => Ok(Removal::Removed),
        Ok(1) if native_error.code() == ERR_SEC_ITEM_NOT_FOUND => Err(StoreError::AlreadyExists),
        Ok(1) => Err(map_error(native_error)),
        Ok(_) | Err(_) => Err(StoreError::StateUncertain),
    }
}

fn confirm_removed(store: &AuthenticatedStore, recipient: EntryId) -> Result<Removal> {
    match inventory_count(store, recipient) {
        Ok(0) => Ok(Removal::Removed),
        Ok(_) | Err(_) => Err(StoreError::StateUncertain),
    }
}

fn find_values(store: &AuthenticatedStore, recipient: EntryId) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    let mut query = exact_query(store, recipient);
    query.load_data(true);
    let results = match query.search() {
        Ok(results) => results,
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(Vec::new()),
        Err(error) => return Err(map_error(error)),
    };
    results
        .into_iter()
        .map(|result| match result {
            SearchResult::Data(bytes) => Ok(Zeroizing::new(bytes)),
            _ => Err(StoreError::Corrupt),
        })
        .collect()
}

fn inventory_count(store: &AuthenticatedStore, recipient: EntryId) -> Result<usize> {
    let mut query = exact_query(store, recipient);
    query.load_attributes(true);
    match query.search() {
        Ok(results)
            if results
                .iter()
                .all(|result| matches!(result, SearchResult::Dict(_))) =>
        {
            Ok(results.len())
        }
        Ok(_) => Err(StoreError::Corrupt),
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(0),
        Err(error) => Err(map_error(error)),
    }
}

fn fingerprint_count(
    store: &AuthenticatedStore,
    recipient: EntryId,
    secret: &Secret,
) -> Result<usize> {
    let mut query = deletion_query(store, recipient, secret);
    query.limit(Limit::All).load_attributes(true);
    match query.search() {
        Ok(results)
            if results
                .iter()
                .all(|result| matches!(result, SearchResult::Dict(_))) =>
        {
            Ok(results.len())
        }
        Ok(_) => Err(StoreError::Corrupt),
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(0),
        Err(error) => Err(map_error(error)),
    }
}

fn exact_query(store: &AuthenticatedStore, recipient: EntryId) -> ItemSearchOptions {
    let mut query = base_query(store, recipient);
    query.limit(Limit::All);
    query
}

fn base_query(store: &AuthenticatedStore, recipient: EntryId) -> ItemSearchOptions {
    let mut query = ItemSearchOptions::new();
    query
        .class(ItemClass::generic_password())
        .service(&authenticated_service_name(store.application_id()))
        .account(&recipient_name(recipient))
        .cloud_sync(CloudSync::MatchSyncNo)
        .ignore_legacy_keychains();
    query
}

fn deletion_query(
    store: &AuthenticatedStore,
    recipient: EntryId,
    expected: &Secret,
) -> ItemSearchOptions {
    let mut query = base_query(store, recipient);
    query.label(&item_label(expected));
    query
}

// Secret is uniformly random with 256 bits of entropy. Its digest is
// public item identity, not a verifier for passwords or other guessable input.
fn item_label(secret: &Secret) -> String {
    secret.expose(|bytes| {
        use std::fmt::Write;

        let mut label = String::with_capacity(LABEL_PREFIX.len() + 64);
        label.push_str(LABEL_PREFIX);
        for byte in Sha256::digest(bytes) {
            write!(label, "{byte:02x}").expect("writing to a string cannot fail");
        }
        label
    })
}

fn secrets_match(actual: &Secret, expected: &Secret) -> bool {
    actual.expose(|bytes| binary_matches(bytes, expected))
}

fn is_definite_add_failure(error: NativeError) -> bool {
    matches!(
        error.code(),
        ERR_SEC_MISSING_ENTITLEMENT | ERR_SEC_UNIMPLEMENTED
    )
}

fn map_error(error: NativeError) -> StoreError {
    match error.code() {
        ERR_SEC_DUPLICATE_ITEM => StoreError::AlreadyExists,
        ERR_SEC_ITEM_NOT_FOUND => StoreError::Missing,
        ERR_SEC_USER_CANCELED => StoreError::Cancelled,
        ERR_SEC_AUTH_FAILED | ERR_SEC_MISSING_ENTITLEMENT => StoreError::AccessDenied,
        ERR_SEC_NOT_AVAILABLE
        | ERR_SEC_IO
        | ERR_SEC_INTERACTION_NOT_ALLOWED
        | ERR_SEC_INTERACTION_REQUIRED
        | ERR_SEC_DATA_NOT_AVAILABLE
        | ERR_SEC_SERVICE_NOT_AVAILABLE => StoreError::Unavailable,
        ERR_SEC_UNIMPLEMENTED => StoreError::Unsupported,
        _ => StoreError::OperationFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_errors_are_sanitized() {
        for (code, expected) in [
            (ERR_SEC_DUPLICATE_ITEM, StoreError::AlreadyExists),
            (ERR_SEC_ITEM_NOT_FOUND, StoreError::Missing),
            (ERR_SEC_USER_CANCELED, StoreError::Cancelled),
            (ERR_SEC_AUTH_FAILED, StoreError::AccessDenied),
            (ERR_SEC_MISSING_ENTITLEMENT, StoreError::AccessDenied),
            (ERR_SEC_NOT_AVAILABLE, StoreError::Unavailable),
            (ERR_SEC_IO, StoreError::Unavailable),
            (ERR_SEC_INTERACTION_NOT_ALLOWED, StoreError::Unavailable),
            (ERR_SEC_INTERACTION_REQUIRED, StoreError::Unavailable),
            (ERR_SEC_DATA_NOT_AVAILABLE, StoreError::Unavailable),
            (ERR_SEC_SERVICE_NOT_AVAILABLE, StoreError::Unavailable),
            (ERR_SEC_UNIMPLEMENTED, StoreError::Unsupported),
        ] {
            assert_eq!(map_error(NativeError::from_code(code)), expected);
        }
        assert_eq!(
            map_error(NativeError::from_code(-1)),
            StoreError::OperationFailed
        );
        assert!(is_definite_add_failure(NativeError::from_code(
            ERR_SEC_MISSING_ENTITLEMENT
        )));
        assert!(is_definite_add_failure(NativeError::from_code(
            ERR_SEC_UNIMPLEMENTED
        )));
        assert!(!is_definite_add_failure(NativeError::from_code(ERR_SEC_IO)));
    }

    #[test]
    fn item_identity_contains_only_a_public_secret_fingerprint() {
        let mut bytes = [7u8; 32];
        let secret = Secret::import(&mut bytes);
        assert_eq!(
            item_label(&secret),
            "fido key wrap authenticated factor \
             4bb06f8e4e3a7715d201d573d0aa423762e55dabd61a2c02278fa56cc6d294e0"
        );
    }
}
