use anyhow::{Context, Result, bail};
use fido_key_wrap::{
    CredentialStorage, Envelope, Error, Interaction, Method, MethodId, Passphrase,
    PassphrasePurpose, Pin, Prompt, RecoverySecret, StoreAccess, Verification,
};
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Write},
    path::PathBuf,
};
use zeroize::Zeroizing;

pub struct Terminal {
    pub no_input: bool,
    pub recovery: Option<PathBuf>,
}
impl Terminal {
    pub fn choose(&self, title: &str, options: &[String], hint: &str) -> Result<usize> {
        if self.no_input {
            bail!("{hint}");
        }
        #[cfg(windows)]
        let console = "CONIN$";
        #[cfg(not(windows))]
        let console = "/dev/tty";
        let input = File::open(console).with_context(|| hint.to_owned())?;
        eprintln!("{title}");
        for (index, choice) in options.iter().enumerate() {
            eprintln!("  {}. {choice}", index + 1);
        }
        eprint!("Choice: ");
        io::stderr().flush()?;
        let mut line = String::new();
        BufReader::new(input).take(64).read_line(&mut line)?;
        let index = line
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .filter(|&n| n < options.len());
        index.ok_or_else(|| Error::Cancelled.into())
    }

    pub fn method(
        &self,
        envelope: &Envelope,
        requested: Option<&str>,
        title: &str,
    ) -> Result<MethodId> {
        let methods: Vec<_> = envelope.methods().collect();
        if let Some(selector) = requested {
            let matches: Vec<_> = methods
                .iter()
                .filter(|m| {
                    m.label == selector
                        || (selector.len() >= 4 && m.id.to_string().starts_with(selector))
                })
                .collect();
            return match matches.as_slice() {
                [one] => Ok(one.id),
                [] => bail!("method {selector:?} not found; use info to list labels and IDs"),
                _ => bail!("method selector is ambiguous; use a longer ID prefix"),
            };
        }
        if methods.len() == 1 {
            return Ok(methods[0].id);
        }
        let choices = methods
            .iter()
            .map(|m| {
                format!(
                    "{:?} — {} ({})",
                    m.label,
                    describe(m.method),
                    &m.id.to_string()[..8]
                )
            })
            .collect::<Vec<_>>();
        let selected = self.choose(
            title,
            &choices,
            "select a method explicitly; use info for labels and IDs, or --help for usage",
        )?;
        Ok(methods[selected].id)
    }

    pub fn hidden(&self, prompt: &str) -> fido_key_wrap::Result<Zeroizing<String>> {
        if self.no_input {
            return Err(Error::InteractionUnsupported);
        }
        rpassword::prompt_password(prompt)
            .map(Zeroizing::new)
            .map_err(|error| {
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::UnexpectedEof
                ) {
                    Error::Cancelled
                } else {
                    Error::InteractionUnsupported
                }
            })
    }
}
impl Interaction for Terminal {
    fn passphrase(
        &mut self,
        prompt: Prompt<'_>,
        purpose: PassphrasePurpose,
    ) -> fido_key_wrap::Result<Passphrase> {
        let action = match purpose {
            PassphrasePurpose::New => "New passphrase",
            PassphrasePurpose::Confirm => "Confirm passphrase",
            PassphrasePurpose::Unlock => "Passphrase",
        };
        let value = self.hidden(&format!("{action} for {:?}: ", prompt.label))?;
        Passphrase::new(value.as_bytes().to_vec())
    }
    fn pin(&mut self, _: Prompt<'_>) -> fido_key_wrap::Result<Pin> {
        Ok(Pin::new(&self.hidden("Security-key PIN: ")?)?)
    }
    fn recovery_secret(&mut self, _: Prompt<'_>) -> fido_key_wrap::Result<RecoverySecret> {
        let path = self
            .recovery
            .as_ref()
            .ok_or(Error::InvalidInput("supply --recovery-file"))?;
        let file = File::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if file.metadata()?.permissions().mode() & 0o077 != 0 {
                return Err(Error::InvalidInput(
                    "recovery file requires private permissions (chmod 600)",
                ));
            }
        }
        let mut bytes = Zeroizing::new([0; 33]);
        let mut input = file.take(33);
        let mut count = 0;
        loop {
            let n = input.read(&mut bytes[count..])?;
            if n == 0 {
                break;
            }
            count += n;
        }
        if count != 32 {
            return Err(Error::InvalidInput(
                "recovery file must contain exactly 32 bytes",
            ));
        }
        let mut exact = Zeroizing::new([0; 32]);
        exact.copy_from_slice(&bytes[..32]);
        Ok(RecoverySecret::import(&mut exact))
    }
    fn select(&mut self, _: Prompt<'_>, count: usize) -> fido_key_wrap::Result<()> {
        if count > 1 {
            eprintln!("Touch the security key you want to use.");
        }
        Ok(())
    }
    fn touch(&mut self, _: Prompt<'_>) -> fido_key_wrap::Result<()> {
        eprintln!("Touch your security key.");
        Ok(())
    }
}

pub fn describe(method: Method) -> String {
    let mut text = match method {
        Method::Passphrase => "passphrase",
        Method::SecurityKey(_) => "key",
        Method::Keystore(_) => "keystore",
        Method::KeyAndPassphrase(_) => "key+passphrase",
        Method::KeyAndKeystore(_, _) => "key+keystore",
        Method::RecoverySecret => "recovery",
    }
    .to_owned();
    if let Some(key) = method.key_options() {
        text.push_str(match key.verification {
            Verification::Presence => " · touch",
            Verification::UserVerified => " · user verification",
        });
        if key.storage == CredentialStorage::Managed {
            text.push_str(" · managed");
        }
    }
    if let Some(access) = method.store_access() {
        text.push_str(match access {
            StoreAccess::Standard => " · standard access",
            StoreAccess::UserAuthentication => " · OS authentication",
            StoreAccess::MacosLogin => " · macOS login keychain",
        });
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use fido_key_wrap::{ApplicationId, Enrollment, Protector};

    #[test]
    fn a_label_cannot_silently_override_another_methods_id_prefix() {
        let protector = Protector::new(ApplicationId::new("test.example").unwrap());
        let mut secret = RecoverySecret::generate().unwrap();
        let mut key = protector
            .create(
                &Enrollment::new(Method::RecoverySecret, "original").unwrap(),
                &mut secret,
            )
            .unwrap();
        let first = key.envelope().methods().next().unwrap().id;
        let id = first.to_string();
        protector
            .add_method(
                &mut key,
                &Enrollment::new(Method::RecoverySecret, &id[..8]).unwrap(),
                &mut secret,
            )
            .unwrap();
        let terminal = Terminal {
            no_input: true,
            recovery: None,
        };
        assert!(terminal.method(key.envelope(), Some(&id[..8]), "").is_err());
        assert_eq!(
            terminal.method(key.envelope(), Some(&id), "").unwrap(),
            first
        );
        assert_eq!(
            terminal
                .method(key.envelope(), Some("original"), "")
                .unwrap(),
            first
        );
        assert!(terminal.method(key.envelope(), None, "").is_err());
    }
}
