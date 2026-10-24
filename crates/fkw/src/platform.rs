//! FIDO orchestration. Native verification and unsafe code stay in the adapter.
use crate::{
    ApplicationId, CredentialStorage, Error, FidoConfig, Interaction, KeyOptions, Operation, Pin,
    Prompt, Result, Verification, crypto,
    envelope::{Credential, Record},
};
use fkw_libfido2 as native;
use zeroize::Zeroizing;

pub(crate) struct Keys {
    pub config: FidoConfig,
    #[cfg(test)]
    pub fake: Option<std::sync::Arc<fake::Device>>,
}
impl Keys {
    pub fn new(config: FidoConfig) -> Self {
        Self {
            config,
            #[cfg(test)]
            fake: None,
        }
    }
    pub fn select(
        &self,
        prompt: Prompt<'_>,
        options: KeyOptions,
        interaction: &mut dyn Interaction,
    ) -> Result<native::Authenticator> {
        let backend = native::Backend::new(self.config);
        let selection = match (prompt.operation, options.storage) {
            (Operation::Enroll, CredentialStorage::Managed) => backend.prepare_managed_selection(
                native::ManagedCapability::Enrollment(policy(options.verification)),
            )?,
            (Operation::Retire, _) => {
                backend.prepare_managed_selection(native::ManagedCapability::Management)?
            }
            _ => backend.prepare_selection(policy(options.verification))?,
        };
        interaction.select(prompt, selection.compatible_authenticators())?;
        Ok(selection.select()?)
    }
    pub fn enroll(
        &self,
        app: &ApplicationId,
        record: &mut Record,
        interaction: &mut dyn Interaction,
    ) -> Result<Session> {
        #[cfg(test)]
        if let Some(fake) = &self.fake {
            return fake.enroll(record, interaction);
        }
        let options = record.method.key_options().expect("key recipe");
        let prompt = prompt(record, Operation::Enroll);
        let mut authenticator = self.select(prompt, options, interaction)?;
        let pin = interaction.pin(prompt)?;
        interaction.touch(prompt)?;
        let result = authenticator.enroll(
            native::EnrollmentRequest {
                relying_party_id: app.as_str(),
                relying_party_name: "fkw",
                policy: policy(options.verification),
                storage: match options.storage {
                    CredentialStorage::NonDiscoverable => {
                        native::CredentialStorage::NonDiscoverable
                    }
                    CredentialStorage::Managed => native::CredentialStorage::ManagedDiscoverable {
                        user_id: record.id.as_bytes(),
                    },
                },
            },
            &pin,
        );
        let (credential, pending) = match result {
            Ok(enrolled) => enrolled.into_parts(),
            Err(failure) => {
                let (error, pending) = failure.into_parts();
                let uncertain = matches!(error, native::Error::CredentialMayRemain);
                let mut session = NativeSession {
                    authenticator,
                    pin,
                    pending,
                };
                // Never submit a rejected PIN again during rollback.
                let cleanup_failed = session.pending.is_some()
                    && (pin_rejected(&error) || session.cleanup(prompt, interaction).is_err());
                return Err(if uncertain || cleanup_failed {
                    Error::EnrollmentUncertain {
                        method: record.id,
                        cause: Box::new(error.into()),
                    }
                } else {
                    error.into()
                });
            }
        };
        record.credential = Some(Credential {
            id: credential.credential_id,
            public_key: credential.es256_public_key,
        });
        Ok(Session::Native(NativeSession {
            authenticator,
            pin,
            pending,
        }))
    }
    pub fn evaluate(
        &self,
        app: &ApplicationId,
        record: &Record,
        context: &[u8; 32],
        interaction: &mut dyn Interaction,
    ) -> Result<Zeroizing<[u8; 32]>> {
        #[cfg(test)]
        if let Some(fake) = &self.fake {
            return fake.evaluate(record, context, Operation::Unlock, interaction);
        }
        let options = record.method.key_options().expect("key recipe");
        let prompt = prompt(record, Operation::Unlock);
        let mut authenticator = self.select(prompt, options, interaction)?;
        let pin = if options.verification == Verification::UserVerified {
            Some(interaction.pin(prompt)?)
        } else {
            None
        };
        interaction.touch(prompt)?;
        let salt = crypto::hash(&[b"fkw/v2/prf", context]);
        let secret = authenticator.evaluate(request(app, record, &salt), pin.as_ref())?;
        Ok(crypto::factor(secret.as_slice(), context, b"security-key"))
    }
    pub fn retire(
        &self,
        app: &ApplicationId,
        record: &Record,
        interaction: &mut dyn Interaction,
    ) -> Result<()> {
        let options = record
            .method
            .key_options()
            .ok_or(Error::InvalidInput("not a security-key method"))?;
        if options.storage != CredentialStorage::Managed {
            return Err(Error::InvalidInput("credential is not managed"));
        }
        let prompt = prompt(record, Operation::Retire);
        let mut authenticator = self.select(prompt, options, interaction)?;
        let pin = interaction.pin(prompt)?;
        interaction.touch(prompt)?;
        Ok(authenticator.retire_managed(managed(app, record), &pin)?)
    }
}
pub(crate) enum Session {
    Native(NativeSession),
    #[cfg(test)]
    Fake(std::sync::Arc<fake::Device>),
}
impl Session {
    pub fn evaluate(
        &mut self,
        app: &ApplicationId,
        record: &Record,
        context: &[u8; 32],
        interaction: &mut dyn Interaction,
    ) -> Result<Zeroizing<[u8; 32]>> {
        match self {
            Self::Native(session) => session.evaluate(app, record, context, interaction),
            #[cfg(test)]
            Self::Fake(device) => device.evaluate(record, context, Operation::Enroll, interaction),
        }
    }
    pub fn cleanup(
        &mut self,
        cause: &Error,
        prompt: Prompt<'_>,
        interaction: &mut dyn Interaction,
    ) -> Result<()> {
        if !prompt
            .method
            .key_options()
            .is_some_and(|options| options.storage == CredentialStorage::Managed)
        {
            return Ok(());
        }
        if matches!(cause, Error::Fido(error) if pin_rejected(error)) {
            return Err(native::Error::CredentialMayRemain.into());
        }
        match self {
            Self::Native(session) => session.cleanup(prompt, interaction),
            #[cfg(test)]
            Self::Fake(device) => device.cleanup(),
        }
    }
}
pub(crate) struct NativeSession {
    authenticator: native::Authenticator,
    pin: Pin,
    pending: Option<Box<native::PendingManagedCredential>>,
}
impl NativeSession {
    pub fn evaluate(
        &mut self,
        app: &ApplicationId,
        record: &Record,
        context: &[u8; 32],
        interaction: &mut dyn Interaction,
    ) -> Result<Zeroizing<[u8; 32]>> {
        interaction.touch(prompt(record, Operation::Enroll))?;
        let salt = crypto::hash(&[b"fkw/v2/prf", context]);
        let request = request(app, record, &salt);
        let secret = if self.pending.is_some() {
            self.authenticator.evaluate_managed_enrollment(
                request,
                managed(app, record),
                &self.pin,
            )?
        } else {
            let pin = if request.policy == native::ExactPolicy::UserVerified {
                Some(&self.pin)
            } else {
                None
            };
            self.authenticator.evaluate(request, pin)?
        };
        Ok(crypto::factor(secret.as_slice(), context, b"security-key"))
    }
    pub fn cleanup(&mut self, prompt: Prompt<'_>, interaction: &mut dyn Interaction) -> Result<()> {
        if let Some(pending) = &self.pending {
            if let Some(cleanup) = self
                .authenticator
                .prepare_managed_cleanup(pending, &self.pin)?
            {
                interaction.touch(Prompt {
                    operation: Operation::Retire,
                    ..prompt
                })?;
                cleanup.finish()?;
            }
        }
        Ok(())
    }
}
pub(crate) fn prompt(record: &Record, operation: Operation) -> Prompt<'_> {
    Prompt {
        operation,
        id: record.id,
        label: &record.label,
        method: record.method,
    }
}
fn pin_rejected(error: &native::Error) -> bool {
    matches!(
        error,
        native::Error::PinInvalid { .. }
            | native::Error::PinBlocked
            | native::Error::PinAuthBlocked
            | native::Error::PinRequired
    )
}
fn policy(verification: Verification) -> native::ExactPolicy {
    match verification {
        Verification::Presence => native::ExactPolicy::Presence,
        Verification::UserVerified => native::ExactPolicy::UserVerified,
    }
}
fn request<'a>(
    app: &'a ApplicationId,
    record: &'a Record,
    salt: &'a [u8; 32],
) -> native::PrfRequest<'a> {
    let credential = record.credential.as_ref().expect("key credential");
    native::PrfRequest {
        relying_party_id: app.as_str(),
        credential_id: &credential.id,
        es256_public_key: &credential.public_key,
        salt,
        policy: policy(
            record
                .method
                .key_options()
                .expect("key recipe")
                .verification,
        ),
    }
}
fn managed<'a>(app: &'a ApplicationId, record: &'a Record) -> native::ManagedCredential<'a> {
    let credential = record.credential.as_ref().expect("key credential");
    native::ManagedCredential {
        relying_party_id: app.as_str(),
        user_id: record.id.as_bytes(),
        credential_id: &credential.id,
        es256_public_key: &credential.public_key,
        protection: match record
            .method
            .key_options()
            .expect("key recipe")
            .verification
        {
            Verification::Presence => native::CredentialProtection::OptionalWithCredentialId,
            Verification::UserVerified => native::CredentialProtection::UserVerificationRequired,
        },
    }
}

// A test-only device verifies orchestration; native signature/flag verification
// remains covered by the adapter's own tests. This is never a production backend.
#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    };
    #[derive(Default)]
    pub struct Device {
        pub calls: AtomicUsize,
        pub wrong_secret: AtomicBool,
        pub pin_invalid: AtomicBool,
        pub cleanup_fails: AtomicBool,
        pub cleanups: AtomicUsize,
    }
    impl Device {
        pub fn enroll(
            self: &Arc<Self>,
            record: &mut Record,
            ui: &mut dyn Interaction,
        ) -> Result<Session> {
            self.calls.fetch_add(1, SeqCst);
            ui.pin(prompt(record, Operation::Enroll))?;
            if self.pin_invalid.load(SeqCst) {
                return Err(native::Error::PinInvalid { retries: Some(7) }.into());
            }
            ui.touch(prompt(record, Operation::Enroll))?;
            let public = p256::SecretKey::from_slice(&[7; 32])
                .unwrap()
                .public_key()
                .to_sec1_bytes();
            record.credential = Some(Credential {
                id: record.id.as_bytes().to_vec(),
                public_key: public[1..].try_into().unwrap(),
            });
            Ok(Session::Fake(Arc::clone(self)))
        }
        pub fn evaluate(
            &self,
            record: &Record,
            context: &[u8; 32],
            operation: Operation,
            ui: &mut dyn Interaction,
        ) -> Result<Zeroizing<[u8; 32]>> {
            self.calls.fetch_add(1, SeqCst);
            if operation == Operation::Unlock
                && record.method.key_options().unwrap().verification == Verification::UserVerified
            {
                ui.pin(prompt(record, operation))?;
            }
            if self.pin_invalid.load(SeqCst) {
                return Err(native::Error::PinInvalid { retries: Some(7) }.into());
            }
            ui.touch(prompt(record, operation))?;
            let seed = if self.wrong_secret.load(SeqCst) {
                b"wrong".as_slice()
            } else {
                b"fake".as_slice()
            };
            let secret = crypto::hash(&[seed, &record.credential.as_ref().unwrap().id, context]);
            Ok(crypto::factor(&secret, context, b"security-key"))
        }
        pub fn cleanup(&self) -> Result<()> {
            self.cleanups.fetch_add(1, SeqCst);
            if self.cleanup_fails.load(SeqCst) {
                Err(native::Error::RetirementUncertain.into())
            } else {
                Ok(())
            }
        }
    }
}
