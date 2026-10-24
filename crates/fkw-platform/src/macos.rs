use crate::{EntryId, Secret};
use core_foundation::{base::ToVoid, data::CFData, dictionary::CFMutableDictionary};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    base::Error as NativeError,
    item::{
        CloudSync, ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Limit, Location,
        Reference, SearchResult,
    },
    os::macos::{keychain::SecKeychain, keychain_item::SecKeychainItem},
    passwords::PasswordOptions,
};
use security_framework_sys::base::{
    errSecAuthFailed as ERR_SEC_AUTH_FAILED, errSecDuplicateItem as ERR_SEC_DUPLICATE_ITEM,
    errSecIO as ERR_SEC_IO, errSecItemNotFound as ERR_SEC_ITEM_NOT_FOUND,
    errSecUnimplemented as ERR_SEC_UNIMPLEMENTED,
};
use zeroize::Zeroizing;

use crate::{
    Removal, Result, StandardStore, StoreError, binary_matches, import_binary, recipient_name,
    service_name,
};

const LABEL: &str = "fkw local secret";
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_NOT_AVAILABLE: i32 = -25_291;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25_308;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34_018;

#[derive(Clone, Copy, Debug)]
pub(crate) enum StoreKind {
    DataProtection,
    LoginKeychain,
}

pub(crate) fn create(store: &StandardStore, recipient: EntryId, secret: &Secret) -> Result<()> {
    let result = match store.kind {
        StoreKind::DataProtection => add_data_protection(store, recipient, secret),
        StoreKind::LoginKeychain => add_login_keychain(store, recipient, secret),
    };
    match result {
        Ok(()) => match verify_created(store, recipient, secret) {
            Ok(()) => Ok(()),
            Err(_) => Err(StoreError::StateUncertain),
        },
        Err(error) if error.code() == ERR_SEC_DUPLICATE_ITEM => {
            let values = find_values(store, recipient)?;
            match values.as_slice() {
                [bytes] if binary_matches(bytes, secret) => Ok(()),
                [bytes] if bytes.len() == crate::SECRET_BYTES => Err(StoreError::AlreadyExists),
                [_] => Err(StoreError::Corrupt),
                [] => Err(StoreError::OperationFailed),
                _ => Err(StoreError::Ambiguous),
            }
        }
        Err(error) => reconcile_after_add_error(store, recipient, secret, error),
    }
}

pub(crate) fn load(store: &StandardStore, recipient: EntryId) -> Result<Secret> {
    let mut values = find_values(store, recipient)?;
    match values.len() {
        0 => Err(StoreError::Missing),
        1 => import_binary(&values.pop().expect("one exact value")),
        _ => Err(StoreError::Ambiguous),
    }
}

pub(crate) fn remove(store: &StandardStore, recipient: EntryId) -> Result<Removal> {
    let mut items = find_items(store, recipient)?;
    match items.len() {
        0 => Ok(Removal::Absent),
        1 => {
            items.pop().expect("one exact item").delete();
            if find_items(store, recipient)
                .map_err(|_| StoreError::StateUncertain)?
                .is_empty()
            {
                Ok(Removal::Removed)
            } else {
                Err(StoreError::StateUncertain)
            }
        }
        _ => Err(StoreError::Ambiguous),
    }
}

fn reconcile_after_add_error(
    store: &StandardStore,
    recipient: EntryId,
    secret: &Secret,
    native_error: NativeError,
) -> Result<()> {
    let values = find_values(store, recipient).map_err(|_| StoreError::StateUncertain)?;
    match values.as_slice() {
        [] => Err(map_error(native_error)),
        [bytes] if binary_matches(bytes, secret) => Ok(()),
        [bytes] if bytes.len() == crate::SECRET_BYTES => Err(StoreError::AlreadyExists),
        [_] => Err(StoreError::Corrupt),
        _ => Err(StoreError::Ambiguous),
    }
}

fn verify_created(store: &StandardStore, recipient: EntryId, secret: &Secret) -> Result<()> {
    let values = find_values(store, recipient)?;
    match values.as_slice() {
        [bytes] if binary_matches(bytes, secret) => Ok(()),
        [_] => Err(StoreError::Corrupt),
        [] => Err(StoreError::OperationFailed),
        _ => Err(StoreError::Ambiguous),
    }
}

fn add_login_keychain(
    store: &StandardStore,
    recipient: EntryId,
    secret: &Secret,
) -> security_framework::base::Result<()> {
    let keychain = SecKeychain::default()?;
    secret.expose(|bytes| {
        let value = ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data: CFData::from_buffer(bytes),
        };
        let mut options = ItemAddOptions::new(value);
        options
            .set_service(service_name(store.application_id()))
            .set_account_name(recipient_name(recipient))
            .set_label(LABEL)
            .set_location(Location::FileKeychain(keychain));
        options.add()
    })
}

fn add_data_protection(
    store: &StandardStore,
    recipient: EntryId,
    secret: &Secret,
) -> security_framework::base::Result<()> {
    secret.expose(|bytes| {
        let value = ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data: CFData::from_buffer(bytes),
        };
        let mut options = ItemAddOptions::new(value);
        options
            .set_service(service_name(store.application_id()))
            .set_account_name(recipient_name(recipient))
            .set_label(LABEL)
            .set_location(Location::DataProtectionKeychain);

        #[allow(deprecated)]
        let dictionary = options.to_dictionary();
        let mut dictionary = CFMutableDictionary::from(&dictionary);
        let access_control = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            0,
        )?;
        let mut access_options = PasswordOptions::new_generic_password(
            &service_name(store.application_id()),
            &recipient_name(recipient),
        );
        access_options.use_protected_keychain();
        access_options.set_access_control(access_control);
        #[allow(deprecated)]
        for (key, value) in access_options.query {
            dictionary.set(key.to_void(), value.to_void());
        }
        #[allow(deprecated)]
        security_framework::item::add_item(dictionary.to_immutable())
    })
}

fn find_values(store: &StandardStore, recipient: EntryId) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    let results = match query(store, recipient, true)?.search() {
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

fn find_items(store: &StandardStore, recipient: EntryId) -> Result<Vec<SecKeychainItem>> {
    let mut query = query(store, recipient, false)?;
    query.load_refs(true);
    let results = match query.search() {
        Ok(results) => results,
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(Vec::new()),
        Err(error) => return Err(map_error(error)),
    };
    results
        .into_iter()
        .map(|result| match result {
            SearchResult::Ref(Reference::KeychainItem(item)) => Ok(item),
            _ => Err(StoreError::Corrupt),
        })
        .collect()
}

fn query(store: &StandardStore, recipient: EntryId, load_data: bool) -> Result<ItemSearchOptions> {
    let mut query = ItemSearchOptions::new();
    query
        .class(ItemClass::generic_password())
        .service(&service_name(store.application_id()))
        .account(&recipient_name(recipient))
        .load_data(load_data);
    match store.kind {
        StoreKind::DataProtection => {
            query
                .cloud_sync(CloudSync::MatchSyncNo)
                .limit(Limit::All)
                .ignore_legacy_keychains();
        }
        StoreKind::LoginKeychain => {
            let keychain = SecKeychain::default().map_err(map_error)?;
            // One file keychain enforces generic-password uniqueness by class,
            // service, and account. Its modern query path rejects Limit::All.
            query.keychains(&[keychain]).limit(1);
        }
    }
    Ok(query)
}

fn map_error(error: NativeError) -> StoreError {
    match error.code() {
        ERR_SEC_DUPLICATE_ITEM => StoreError::AlreadyExists,
        ERR_SEC_ITEM_NOT_FOUND => StoreError::Missing,
        ERR_SEC_USER_CANCELED => StoreError::Cancelled,
        ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED | ERR_SEC_MISSING_ENTITLEMENT => {
            StoreError::AccessDenied
        }
        ERR_SEC_NOT_AVAILABLE | ERR_SEC_IO => StoreError::Unavailable,
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
            (ERR_SEC_INTERACTION_NOT_ALLOWED, StoreError::AccessDenied),
            (ERR_SEC_MISSING_ENTITLEMENT, StoreError::AccessDenied),
            (ERR_SEC_NOT_AVAILABLE, StoreError::Unavailable),
            (ERR_SEC_IO, StoreError::Unavailable),
            (ERR_SEC_UNIMPLEMENTED, StoreError::Unsupported),
        ] {
            assert_eq!(map_error(NativeError::from_code(code)), expected);
        }
        assert_eq!(
            map_error(NativeError::from_code(-1)),
            StoreError::OperationFailed
        );
    }
}
