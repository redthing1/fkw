use crate::{EntryId, Secret};

use crate::{Removal, Result, StandardStore, StoreError};

pub(crate) fn create(_store: &StandardStore, _recipient: EntryId, _secret: &Secret) -> Result<()> {
    Err(StoreError::Unsupported)
}

pub(crate) fn load(_store: &StandardStore, _recipient: EntryId) -> Result<Secret> {
    Err(StoreError::Unsupported)
}

pub(crate) fn remove(_store: &StandardStore, _recipient: EntryId) -> Result<Removal> {
    Err(StoreError::Unsupported)
}
