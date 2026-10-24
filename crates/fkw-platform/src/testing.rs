//! Explicit in-memory adapter for tests. Never select this in production.
use crate::{Access, Keystore, Removal, Result, Secret, StoreError};
use std::{collections::HashMap, sync::Mutex};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
type Entry = (String, [u8; 32], Access);
#[derive(Default)]
pub struct MemoryStore(Mutex<HashMap<Entry, Zeroizing<[u8; 32]>>>);
impl Keystore for MemoryStore {
    fn create(&self, app: &str, id: &[u8; 32], access: Access, secret: &Secret) -> Result<()> {
        let mut entries = self.0.lock().map_err(|_| StoreError::OperationFailed)?;
        let key = (app.to_owned(), *id, access);
        if let Some(current) = entries.get(&key) {
            return if secret.expose(|s| bool::from(current.as_slice().ct_eq(s))) {
                Ok(())
            } else {
                Err(StoreError::AlreadyExists)
            };
        }
        entries.insert(key, secret.expose(|s| Zeroizing::new(*s)));
        Ok(())
    }
    fn load(&self, app: &str, id: &[u8; 32], access: Access) -> Result<Secret> {
        let entries = self.0.lock().map_err(|_| StoreError::OperationFailed)?;
        let current = entries
            .get(&(app.to_owned(), *id, access))
            .ok_or(StoreError::Missing)?;
        let mut bytes = current.clone();
        Ok(Secret::import(&mut bytes))
    }
    fn remove(
        &self,
        app: &str,
        id: &[u8; 32],
        access: Access,
        expected: &Secret,
    ) -> Result<Removal> {
        let mut entries = self.0.lock().map_err(|_| StoreError::OperationFailed)?;
        let key = (app.to_owned(), *id, access);
        let Some(current) = entries.get(&key) else {
            return Ok(Removal::Absent);
        };
        if !expected.expose(|s| bool::from(current.as_slice().ct_eq(s))) {
            return Err(StoreError::AlreadyExists);
        }
        entries.remove(&key);
        Ok(Removal::Removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn writes_are_create_only_and_namespaces_and_access_are_distinct() {
        let store = MemoryStore::default();
        let secret = Secret::import(&mut [1; 32]);
        let other = Secret::import(&mut [2; 32]);
        store
            .create("vault.example", &[7; 32], Access::Standard, &secret)
            .unwrap();
        store
            .create("vault.example", &[7; 32], Access::Standard, &secret)
            .unwrap();
        assert_eq!(
            store.create("vault.example", &[7; 32], Access::Standard, &other),
            Err(StoreError::AlreadyExists)
        );
        assert_eq!(
            store
                .load("other.example", &[7; 32], Access::Standard)
                .unwrap_err(),
            StoreError::Missing
        );
        assert_eq!(
            store
                .load("vault.example", &[7; 32], Access::UserAuthentication)
                .unwrap_err(),
            StoreError::Missing
        );
        assert_eq!(
            store
                .load("vault.example", &[7; 32], Access::Standard)
                .unwrap()
                .expose(|s| *s),
            [1; 32]
        );
    }
    #[test]
    fn deletion_requires_expected_factor_and_confirms_absence() {
        let store = MemoryStore::default();
        let secret = Secret::import(&mut [1; 32]);
        let other = Secret::import(&mut [2; 32]);
        store
            .create("vault.example", &[7; 32], Access::Standard, &secret)
            .unwrap();
        assert_eq!(
            store.remove("vault.example", &[7; 32], Access::Standard, &other),
            Err(StoreError::AlreadyExists)
        );
        assert_eq!(
            store.remove("vault.example", &[7; 32], Access::Standard, &secret),
            Ok(Removal::Removed)
        );
        assert_eq!(
            store.remove("vault.example", &[7; 32], Access::Standard, &secret),
            Ok(Removal::Absent)
        );
    }
}
