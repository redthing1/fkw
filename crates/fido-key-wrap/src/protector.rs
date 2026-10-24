use crate::{
    ApplicationId, DerivedKey, Enrollment, Envelope, Error, FidoConfig, Interaction, KdfCost,
    Keystore, Method, MethodId, NativeStore, Operation, PassphrasePurpose, Removal, Result,
    StoreError, StoreSecret, crypto,
    envelope::{Kdf, MAX_METHODS, Record},
    platform::{Keys, prompt},
};
use std::fmt;
use zeroize::Zeroizing;

/// Trusted application policy and operational dependencies. Construction is inert.
pub struct Protector {
    application: ApplicationId,
    allowed: Option<Vec<Method>>,
    max_cost: KdfCost,
    keys: Keys,
    store: Box<dyn Keystore>,
}
/// An authenticated envelope and a zeroizing root. Contains no platform handles.
pub struct UnlockedKey {
    pub(crate) root: Zeroizing<[u8; 32]>,
    pub(crate) envelope: Envelope,
}
impl fmt::Debug for UnlockedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedKey")
            .field("envelope", &self.envelope)
            .field("root", &"[REDACTED]")
            .finish()
    }
}
impl UnlockedKey {
    #[must_use]
    pub const fn envelope(&self) -> &Envelope {
        &self.envelope
    }
    /// Authenticates another snapshot of the same protected key.
    pub(crate) fn authenticate(&self, envelope: &Envelope) -> Result<()> {
        if envelope.application != self.envelope.application || envelope.id != self.envelope.id {
            return Err(Error::UnlockFailed);
        }
        envelope.verify(&self.root)
    }
    /// Derives a separate 32-byte application key for a stable, explicit purpose.
    pub fn derive_key(&self, purpose: &str) -> Result<DerivedKey> {
        if purpose.is_empty() || purpose.len() > 128 {
            return Err(Error::InvalidInput("purpose must contain 1–128 bytes"));
        }
        Ok(DerivedKey(crypto::derive(
            self.root.as_slice(),
            &self.envelope.id,
            &[
                b"fkw/v2/application",
                self.envelope.application.as_str().as_bytes(),
                purpose.as_bytes(),
            ],
        )))
    }
}
impl Protector {
    #[must_use]
    pub fn new(application: ApplicationId) -> Self {
        Self {
            application,
            allowed: None,
            max_cost: KdfCost::MAX,
            keys: Keys::new(FidoConfig::default()),
            store: Box::new(NativeStore),
        }
    }
    /// Restricts every method in an envelope, including unselected alternatives.
    pub fn allow_only(mut self, methods: impl IntoIterator<Item = Method>) -> Result<Self> {
        let methods: Vec<_> = methods.into_iter().collect();
        if methods.is_empty() {
            return Err(Error::InvalidInput("empty method allow-list"));
        }
        self.allowed = Some(methods);
        Ok(self)
    }
    #[must_use]
    pub const fn with_max_kdf_cost(mut self, cost: KdfCost) -> Self {
        self.max_cost = cost;
        self
    }
    #[must_use]
    pub const fn with_fido_config(mut self, config: FidoConfig) -> Self {
        self.keys.config = config;
        self
    }
    #[must_use]
    pub fn with_keystore(mut self, store: impl Keystore + 'static) -> Self {
        self.store = Box::new(store);
        self
    }
    #[must_use]
    pub const fn application_id(&self) -> &ApplicationId {
        &self.application
    }
    #[cfg(test)]
    pub(crate) fn with_test_device(
        mut self,
        device: std::sync::Arc<crate::platform::fake::Device>,
    ) -> Self {
        self.keys.fake = Some(device);
        self
    }
    pub fn inspect_authenticators(&self) -> Result<Vec<crate::diagnostics::DeviceReport>> {
        Ok(fido_key_wrap_libfido2::Backend::new(self.keys.config).inspect_authenticators()?)
    }
    /// Generates a root and enrolls its first method. Persist the returned envelope.
    /// If saving fails, retain this handle and retry the save, not enrollment.
    pub fn create(
        &self,
        enrollment: &Enrollment,
        interaction: &mut dyn Interaction,
    ) -> Result<UnlockedKey> {
        self.check_enrollment(enrollment)?;
        let root = crypto::random()?;
        let base = Envelope {
            application: self.application.clone(),
            id: *crypto::random()?,
            records: Vec::new(),
            mac: [0; 32],
        };
        let envelope = self.enroll(&base, &root, enrollment, None, interaction)?;
        Ok(UnlockedKey { root, envelope })
    }
    /// Unlocks exactly the selected method; never tries another route.
    pub fn unlock(
        &self,
        envelope: &Envelope,
        method: MethodId,
        interaction: &mut dyn Interaction,
    ) -> Result<UnlockedKey> {
        self.check_envelope(envelope)?;
        let record = envelope.record(method)?;
        self.check_selected(record)?;
        let root = self.unwrap(envelope, record, interaction)?;
        envelope.verify(&root)?;
        Ok(UnlockedKey {
            root,
            envelope: envelope.clone(),
        })
    }
    /// Adds an alternative. The handle changes only after successful enrollment.
    pub fn add_method(
        &self,
        key: &mut UnlockedKey,
        enrollment: &Enrollment,
        interaction: &mut dyn Interaction,
    ) -> Result<MethodId> {
        self.check_key(key)?;
        if key.envelope.records.len() == MAX_METHODS {
            return Err(Error::TooManyMethods);
        }
        let next = self.enroll(&key.envelope, &key.root, enrollment, None, interaction)?;
        let id = next.records.last().expect("new method").id;
        key.envelope = next;
        Ok(id)
    }
    /// Enrolls a replacement before removing the old route. External factors remain.
    pub fn replace_method(
        &self,
        key: &mut UnlockedKey,
        old: MethodId,
        enrollment: &Enrollment,
        interaction: &mut dyn Interaction,
    ) -> Result<MethodId> {
        self.check_key(key)?;
        key.envelope.record(old)?;
        let next = self.enroll(&key.envelope, &key.root, enrollment, Some(old), interaction)?;
        let id = next.records.last().expect("new method").id;
        key.envelope = next;
        Ok(id)
    }
    /// Removes an alternative, without deleting any external factor.
    pub fn remove_method(&self, key: &mut UnlockedKey, method: MethodId) -> Result<()> {
        self.check_key(key)?;
        key.envelope.record(method)?;
        if key.envelope.records.len() == 1 {
            return Err(Error::LastMethod);
        }
        let mut next = key.envelope.clone();
        next.records.retain(|r| r.id != method);
        next.sign(&key.root);
        key.envelope = next;
        Ok(())
    }
    /// Retires a managed credential from an old authenticated envelope. Requires
    /// a surviving envelope with that method removed and the same root. Publish
    /// and independently unlock the survivor before calling this operation.
    pub fn retire_credential(
        &self,
        old: &Envelope,
        method: MethodId,
        survivor: &UnlockedKey,
        interaction: &mut dyn Interaction,
    ) -> Result<()> {
        self.check_survivor(old, method, survivor)?;
        self.keys
            .retire(&self.application, old.record(method)?, interaction)
    }
    /// Deletes the stored factor named by the authenticated old envelope.
    /// First publish and independently unlock a survivor with this method removed.
    /// No old security key is needed; an already absent factor returns `Absent`.
    /// Old copies depending on the factor also lose access.
    pub fn remove_store_factor(
        &self,
        envelope: &Envelope,
        method: MethodId,
        survivor: &UnlockedKey,
    ) -> Result<Removal> {
        self.check_survivor(envelope, method, survivor)?;
        let record = envelope.record(method)?;
        let access = record
            .method
            .store_access()
            .ok_or(Error::InvalidInput("method has no keystore factor"))?;
        self.store.check_access(access)?;
        // The survivor authenticates the complete reference. Requiring the old
        // route to unlock would prevent cleanup after its key is lost or retired.
        let secret = match self
            .store
            .load(self.application.as_str(), method.as_bytes(), access)
        {
            Ok(secret) => secret,
            Err(StoreError::Missing) => return Ok(Removal::Absent),
            Err(error) => return Err(error.into()),
        };
        Ok(self.store.remove(
            self.application.as_str(),
            method.as_bytes(),
            access,
            &secret,
        )?)
    }
    fn check_survivor(
        &self,
        old: &Envelope,
        removed: MethodId,
        survivor: &UnlockedKey,
    ) -> Result<()> {
        self.check_key(survivor)?;
        self.check_envelope(old)?;
        old.record(removed)?;
        survivor.authenticate(old)?;
        if survivor.envelope.records.iter().any(|r| r.id == removed) {
            return Err(Error::InvalidInput(
                "remove the method from the surviving envelope first",
            ));
        }
        Ok(())
    }
    pub(crate) fn check_envelope(&self, envelope: &Envelope) -> Result<()> {
        if envelope.application != self.application {
            return Err(Error::WrongApplication);
        }
        for record in &envelope.records {
            self.check_method(record.method)?;
        }
        Ok(())
    }
    fn check_key(&self, key: &UnlockedKey) -> Result<()> {
        self.check_envelope(&key.envelope)?;
        key.envelope.verify(&key.root)
    }
    fn check_method(&self, method: Method) -> Result<()> {
        if self.allowed.as_ref().is_some_and(|a| !a.contains(&method)) {
            return Err(Error::MethodNotAllowed);
        }
        Ok(())
    }
    fn check_selected(&self, record: &Record) -> Result<()> {
        if record
            .kdf
            .as_ref()
            .is_some_and(|k| !k.cost.fits(self.max_cost))
        {
            return Err(Error::ResourceLimit);
        }
        if let Some(access) = record.method.store_access() {
            self.store.check_access(access)?;
        }
        Ok(())
    }
    fn check_enrollment(&self, request: &Enrollment) -> Result<()> {
        self.check_method(request.method)?;
        if request.method.needs_passphrase() && !request.cost.fits(self.max_cost) {
            return Err(Error::ResourceLimit);
        }
        if let Some(access) = request.method.store_access() {
            self.store.check_access(access)?;
        }
        Ok(())
    }
    fn enroll(
        &self,
        base: &Envelope,
        root: &[u8; 32],
        request: &Enrollment,
        replace: Option<MethodId>,
        interaction: &mut dyn Interaction,
    ) -> Result<Envelope> {
        self.check_enrollment(request)?;
        let mut record = new_record(request)?;
        let mut session = None;
        let mut store_uncertain = false;
        let result = (|| {
            if request.method.key_options().is_some() {
                session = Some(
                    self.keys
                        .enroll(&self.application, &mut record, interaction)?,
                );
            }
            let context = record.context(&self.application, &base.id);
            let key_factor = session
                .as_mut()
                .map(|s| s.evaluate(&self.application, &record, &context, interaction))
                .transpose()?;
            let password = if request.method.needs_passphrase() {
                Some(password_key(
                    &record,
                    &context,
                    Operation::Enroll,
                    interaction,
                )?)
            } else {
                None
            };
            let store_secret = if request.method.store_access().is_some() {
                Some(StoreSecret::import(&mut *crypto::random()?))
            } else {
                None
            };
            let store_key = store_secret
                .as_ref()
                .map(|s| s.expose(|b| crypto::factor(b, &context, b"keystore")));
            let recovery = if request.method == Method::RecoverySecret {
                let secret = interaction.recovery_secret(prompt(&record, Operation::Enroll))?;
                Some(crypto::factor(secret.0.as_slice(), &context, b"recovery"))
            } else {
                None
            };
            let wrap_key = match request.method {
                Method::Passphrase => password.as_ref().expect("password"),
                Method::SecurityKey(_) | Method::KeyAndPassphrase(_) => {
                    key_factor.as_ref().expect("key")
                }
                Method::Keystore(_) => store_key.as_ref().expect("store"),
                Method::RecoverySecret => recovery.as_ref().expect("recovery"),
                Method::KeyAndKeystore(_, _) => &crypto::combine(
                    key_factor.as_ref().expect("key"),
                    store_key.as_ref().expect("store"),
                    &context,
                ),
            };
            let inner = if let Some(password) = password
                .as_ref()
                .filter(|_| matches!(request.method, Method::KeyAndPassphrase(_)))
            {
                crypto::wrap(password, &record.nonce, &context, root)?
            } else {
                root.to_vec()
            };
            let inner = Zeroizing::new(inner);
            record.wrapped = crypto::wrap(wrap_key, &record.nonce, &context, &inner)?;
            // Build and validate the complete result before the final store write.
            let mut next = base.clone();
            next.records.retain(|r| Some(r.id) != replace);
            next.records.push(record.clone());
            next.sign(root);
            Envelope::from_bytes(&next.to_bytes())?.verify(root)?;
            if let (Some(access), Some(secret)) = (request.method.store_access(), store_secret) {
                if let Err(error) = self.store.create(
                    self.application.as_str(),
                    record.id.as_bytes(),
                    access,
                    &secret,
                ) {
                    store_uncertain = error == StoreError::StateUncertain;
                    return Err(error.into());
                }
            }
            Ok(next)
        })();
        match result {
            Ok(next) => Ok(next),
            Err(error) => {
                let cleanup_failed = session.as_mut().is_some_and(|s| {
                    s.cleanup(&error, prompt(&record, Operation::Enroll), interaction)
                        .is_err()
                });
                if store_uncertain || cleanup_failed {
                    Err(Error::EnrollmentUncertain {
                        method: record.id,
                        cause: Box::new(error),
                    })
                } else {
                    Err(error)
                }
            }
        }
    }
    fn unwrap(
        &self,
        envelope: &Envelope,
        record: &Record,
        interaction: &mut dyn Interaction,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let context = record.context(&self.application, &envelope.id);
        let key_factor = if record.method.key_options().is_some() {
            Some(
                self.keys
                    .evaluate(&self.application, record, &context, interaction)?,
            )
        } else {
            None
        };
        // Authenticate the outer key layer before asking for a combined password.
        let inner = if matches!(record.method, Method::KeyAndPassphrase(_)) {
            Some(crypto::unwrap(
                key_factor.as_ref().expect("key"),
                &record.nonce,
                &context,
                &record.wrapped,
            )?)
        } else {
            None
        };
        let password = if record.method.needs_passphrase() {
            Some(password_key(
                record,
                &context,
                Operation::Unlock,
                interaction,
            )?)
        } else {
            None
        };
        let store_secret = record
            .method
            .store_access()
            .map(|a| {
                self.store
                    .load(self.application.as_str(), record.id.as_bytes(), a)
            })
            .transpose()?;
        let store_key = store_secret
            .as_ref()
            .map(|s| s.expose(|b| crypto::factor(b, &context, b"keystore")));
        let recovery = if record.method == Method::RecoverySecret {
            let secret = interaction.recovery_secret(prompt(record, Operation::Unlock))?;
            Some(crypto::factor(secret.0.as_slice(), &context, b"recovery"))
        } else {
            None
        };
        let wrapping_key = match record.method {
            Method::Passphrase | Method::KeyAndPassphrase(_) => {
                password.as_ref().expect("password")
            }
            Method::SecurityKey(_) => key_factor.as_ref().expect("key"),
            Method::Keystore(_) => store_key.as_ref().expect("store"),
            Method::RecoverySecret => recovery.as_ref().expect("recovery"),
            Method::KeyAndKeystore(_, _) => &crypto::combine(
                key_factor.as_ref().expect("key"),
                store_key.as_ref().expect("store"),
                &context,
            ),
        };
        let plain = crypto::unwrap(
            wrapping_key,
            &record.nonce,
            &context,
            inner
                .as_deref()
                .map_or(record.wrapped.as_slice(), Vec::as_slice),
        )?;
        let mut root = Zeroizing::new([0; 32]);
        if plain.len() != root.len() {
            return Err(Error::UnlockFailed);
        }
        root.copy_from_slice(&plain);
        Ok(root)
    }
}
fn password_key(
    record: &Record,
    context: &[u8; 32],
    operation: Operation,
    interaction: &mut dyn Interaction,
) -> Result<Zeroizing<[u8; 32]>> {
    let prompt = prompt(record, operation);
    let purpose = if operation == Operation::Enroll {
        PassphrasePurpose::New
    } else {
        PassphrasePurpose::Unlock
    };
    let password = interaction.passphrase(prompt, purpose)?;
    if operation == Operation::Enroll
        && !password.matches(&interaction.passphrase(prompt, PassphrasePurpose::Confirm)?)
    {
        return Err(Error::ConfirmationMismatch);
    }
    let kdf = record.kdf.as_ref().expect("password recipe");
    let value = crypto::passphrase(&password, &kdf.salt, kdf.cost)?;
    Ok(crypto::factor(value.as_slice(), context, b"passphrase"))
}

fn new_record(request: &Enrollment) -> Result<Record> {
    Ok(Record {
        id: MethodId::from_bytes(*crypto::random()?),
        label: request.label.clone(),
        method: request.method,
        kdf: if request.method.needs_passphrase() {
            Some(Kdf {
                cost: request.cost,
                salt: *crypto::random()?,
            })
        } else {
            None
        },
        credential: None,
        nonce: *crypto::random()?,
        wrapped: Vec::new(),
    })
}
