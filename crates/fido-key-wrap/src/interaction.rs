use crate::{Error, Method, MethodId, Passphrase, Pin, RecoverySecret, Result};
/// The operation requesting input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Enroll,
    Unlock,
    Retire,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassphrasePurpose {
    New,
    Confirm,
    Unlock,
}
/// Public context. Labels and methods from a locked envelope are untrusted.
#[derive(Clone, Copy, Debug)]
pub struct Prompt<'a> {
    pub operation: Operation,
    pub id: MethodId,
    pub label: &'a str,
    pub method: Method,
}
/// Synchronous interaction boundary. No native handles or cryptographic policy.
///
/// Return Cancelled to stop the requested operation. A failed enrollment may
/// request separate interaction to clean up its newly created credential.
/// Native calls are bounded by `FidoConfig`, not by an async runtime. PINs are
/// requested once per operation and never retried automatically.
pub trait Interaction {
    fn passphrase(
        &mut self,
        _prompt: Prompt<'_>,
        _purpose: PassphrasePurpose,
    ) -> Result<Passphrase> {
        Err(Error::InteractionUnsupported)
    }
    fn recovery_secret(&mut self, _prompt: Prompt<'_>) -> Result<RecoverySecret> {
        Err(Error::InteractionUnsupported)
    }
    fn pin(&mut self, _prompt: Prompt<'_>) -> Result<Pin> {
        Err(Error::InteractionUnsupported)
    }
    fn touch(&mut self, _prompt: Prompt<'_>) -> Result<()> {
        Ok(())
    }
    fn select(&mut self, _prompt: Prompt<'_>, _compatible_devices: usize) -> Result<()> {
        Ok(())
    }
}
impl Interaction for () {}
impl Interaction for RecoverySecret {
    fn recovery_secret(&mut self, _prompt: Prompt<'_>) -> Result<RecoverySecret> {
        Ok(RecoverySecret(self.0.clone()))
    }
}
impl Interaction for Passphrase {
    fn passphrase(
        &mut self,
        _prompt: Prompt<'_>,
        _purpose: PassphrasePurpose,
    ) -> Result<Passphrase> {
        Ok(Passphrase(self.0.clone()))
    }
}
/// A previously generated recovery secret is a complete noninteractive input.
impl Interaction for &RecoverySecret {
    fn recovery_secret(&mut self, _prompt: Prompt<'_>) -> Result<RecoverySecret> {
        Ok(RecoverySecret(self.0.clone()))
    }
}
impl Interaction for &Passphrase {
    fn passphrase(
        &mut self,
        _prompt: Prompt<'_>,
        _purpose: PassphrasePurpose,
    ) -> Result<Passphrase> {
        Ok(Passphrase(self.0.clone()))
    }
}
