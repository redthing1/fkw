//! Thin command-line client of the public library.
use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use fido_key_wrap::{
    ApplicationId, Enrollment, Envelope, Error, Interaction, KdfCost, KeyOptions, Method, MethodId,
    Passphrase, PassphrasePurpose, Pin, Prompt, Protector, RecoverySecret, StoreAccess,
    Verification, seal,
};
use std::{
    fs::File,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "Seal text and files with explicit unlock methods")]
struct Cli {
    /// Trusted application namespace, required again when opening.
    #[arg(long, global = true, default_value = "io.fido-key-wrap.cli")]
    application: String,
    /// Existing 32-byte recovery file; never pass secrets as command arguments.
    #[arg(long, global = true)]
    recovery_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Seal a file, piped stdin, or a hidden short-text prompt.
    Seal {
        input: Option<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, conflicts_with = "input")]
        text: bool,
        #[command(flatten)]
        enroll: EnrollArgs,
    },
    /// Authenticate the entire file before publishing plaintext.
    Open {
        input: PathBuf,
        /// New destination; default is stdout after complete verification.
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        method_id: Option<MethodId>,
    },
    /// Display unverified public method metadata without prompting.
    Inspect { input: PathBuf },
    /// Edit access methods while keeping encrypted payload bytes unchanged.
    Methods {
        #[command(subcommand)]
        command: Methods,
    },
    /// Generate a private recovery file before enrolling its method.
    Recovery { output: PathBuf },
    /// Inspect security-key capabilities (loads libfido2).
    Devices,
}
#[derive(Args)]
struct EnrollArgs {
    #[arg(long, value_enum, default_value = "passphrase")]
    method: Recipe,
    #[arg(long, default_value = "")]
    label: String,
    /// Require exact FIDO user verification instead of presence.
    #[arg(long)]
    uv: bool,
    /// Enroll a credential that can later be retired individually.
    #[arg(long)]
    managed: bool,
    #[arg(long, value_enum)]
    store_access: Option<Access>,
    /// Argon2 memory in KiB (65536–262144); three passes, four lanes.
    #[arg(long)]
    kdf_memory: Option<u32>,
    /// Separate existing recovery file for the newly enrolled method.
    #[arg(long)]
    new_recovery_file: Option<PathBuf>,
}
#[derive(Clone, Copy, ValueEnum)]
enum Recipe {
    Passphrase,
    Key,
    Keystore,
    KeyPassphrase,
    KeyKeystore,
    Recovery,
}
#[derive(Clone, Copy, ValueEnum)]
enum Access {
    Standard,
    UserAuthentication,
    MacosLogin,
}
impl EnrollArgs {
    fn enrollment(&self) -> Result<Enrollment> {
        let options = KeyOptions::new(if self.uv {
            Verification::UserVerified
        } else {
            Verification::Presence
        });
        let options = if self.managed {
            options.managed()
        } else {
            options
        };
        let access = match self.store_access.unwrap_or(Access::Standard) {
            Access::Standard => StoreAccess::Standard,
            Access::UserAuthentication => StoreAccess::UserAuthentication,
            Access::MacosLogin => StoreAccess::MacosLogin,
        };
        let method = match self.method {
            Recipe::Passphrase => Method::Passphrase,
            Recipe::Key => Method::SecurityKey(options),
            Recipe::Keystore => Method::Keystore(access),
            Recipe::KeyPassphrase => Method::KeyAndPassphrase(options),
            Recipe::KeyKeystore => Method::KeyAndKeystore(options, access),
            Recipe::Recovery => Method::RecoverySecret,
        };
        if (self.uv || self.managed) && method.key_options().is_none() {
            bail!("--uv and --managed require a key method");
        }
        if self.store_access.is_some() && method.store_access().is_none() {
            bail!("--store-access requires a keystore method");
        }
        if self.new_recovery_file.is_some() && method != Method::RecoverySecret {
            bail!("--new-recovery-file requires a recovery method");
        }
        let request = Enrollment::new(method, &self.label)?;
        Ok(if let Some(memory) = self.kdf_memory {
            request.with_kdf_cost(KdfCost::new(memory, 3, 4)?)?
        } else {
            request
        })
    }
}
#[derive(Subcommand)]
enum Methods {
    Add {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        unlock: Option<MethodId>,
        #[command(flatten)]
        enroll: EnrollArgs,
    },
    Replace {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        unlock: Option<MethodId>,
        #[arg(long)]
        remove: MethodId,
        #[command(flatten)]
        enroll: EnrollArgs,
    },
    Remove {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        unlock: Option<MethodId>,
        #[arg(long)]
        remove: MethodId,
    },
    /// Delete one external factor, after verifying a separately saved survivor.
    Retire {
        /// Old container still referencing the method to retire.
        input: PathBuf,
        #[arg(long)]
        method_id: MethodId,
        /// Published updated container, with that method removed.
        #[arg(long)]
        survivor: PathBuf,
        #[arg(long)]
        verify_with: Option<MethodId>,
        #[arg(long, value_enum)]
        factor: RetireFactor,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum RetireFactor {
    Credential,
    Keystore,
}

struct Terminal {
    recovery: Option<PathBuf>,
}
impl Interaction for Terminal {
    fn passphrase(
        &mut self,
        prompt: Prompt<'_>,
        purpose: PassphrasePurpose,
    ) -> fido_key_wrap::Result<Passphrase> {
        let prefix = match purpose {
            PassphrasePurpose::New => "New passphrase",
            PassphrasePurpose::Confirm => "Confirm passphrase",
            PassphrasePurpose::Unlock => "Passphrase",
        };
        let value = hidden(&format!("{prefix} for {:?}: ", prompt.label))?;
        Passphrase::new(value.as_bytes().to_vec())
    }
    fn pin(&mut self, _prompt: Prompt<'_>) -> fido_key_wrap::Result<Pin> {
        let value = hidden("Security-key PIN: ")?;
        Ok(Pin::new(&value)?)
    }
    fn recovery_secret(&mut self, _prompt: Prompt<'_>) -> fido_key_wrap::Result<RecoverySecret> {
        let path = self.recovery.as_ref().ok_or(Error::InvalidInput(
            "supply --recovery-file or --new-recovery-file",
        ))?;
        read_recovery(path)
    }
    fn select(&mut self, _prompt: Prompt<'_>, count: usize) -> fido_key_wrap::Result<()> {
        if count > 1 {
            eprintln!("Touch the security key to select it.");
        }
        Ok(())
    }
    fn touch(&mut self, prompt: Prompt<'_>) -> fido_key_wrap::Result<()> {
        eprintln!("Touch your security key ({:?}).", prompt.operation);
        Ok(())
    }
}
fn hidden(prompt: &str) -> fido_key_wrap::Result<Zeroizing<String>> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::Interrupted {
                Error::Cancelled
            } else {
                Error::InteractionFailed
            }
        })
}
fn read_recovery(path: &Path) -> fido_key_wrap::Result<RecoverySecret> {
    let file = File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(Error::InvalidInput(
                "recovery file must not be accessible to group or others",
            ));
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(33).read_to_end(&mut bytes)?;
    if bytes.len() != 32 {
        return Err(Error::InvalidInput(
            "recovery file must contain exactly 32 bytes",
        ));
    }
    let mut exact = Zeroizing::new([0; 32]);
    exact.copy_from_slice(&bytes);
    Ok(RecoverySecret::import(&mut exact))
}
fn generate_recovery(path: &Path) -> Result<()> {
    fresh_destination(path)?;
    let secret = RecoverySecret::generate()?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    secret.expose(|bytes| file.write_all(bytes))?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    File::open(parent)?
        .sync_all()
        .context("recovery file was published, but directory durability is uncertain")?;
    Ok(())
}
fn fresh_destination(path: &Path) -> Result<()> {
    if path.try_exists()? {
        bail!("destination already exists: {}", path.display());
    }
    Ok(())
}
fn selected(envelope: &Envelope, requested: Option<MethodId>) -> Result<MethodId> {
    if let Some(id) = requested {
        if !envelope.methods().any(|m| m.id == id) {
            bail!("method not found");
        }
        return Ok(id);
    }
    if envelope.methods().len() == 1 {
        return Ok(envelope.methods().next().expect("one method").id);
    }
    bail!("select a method explicitly with --method-id or --unlock; use inspect to list IDs")
}
fn main() -> Result<()> {
    let cli = Cli::parse();
    let protector = Protector::new(ApplicationId::new(cli.application)?);
    let mut terminal = Terminal {
        recovery: cli.recovery_file,
    };
    match cli.command {
        Command::Recovery { output } => generate_recovery(&output)?,
        Command::Devices => {
            for device in protector.inspect_authenticators()? {
                println!("{device:?}");
            }
        }
        Command::Inspect { input } => {
            let envelope = seal::inspect_file(input)?;
            println!(
                "Unverified metadata; application: {}",
                envelope.application_id()
            );
            for info in envelope.methods() {
                println!("{}  {:?}  {:?}", info.id, info.method, info.label);
            }
        }
        Command::Seal {
            input,
            output,
            text,
            enroll,
        } => {
            fresh_destination(&output)?;
            let request = enroll.enrollment()?;
            if let Some(path) = enroll.new_recovery_file {
                terminal.recovery = Some(path);
            }
            if !text
                && input.as_deref().is_none_or(|p| p == Path::new("-"))
                && io::stdin().is_terminal()
            {
                bail!("use --text for a hidden prompt, supply a file, or pipe stdin");
            }
            let mut file = input
                .filter(|p| p != Path::new("-"))
                .map(File::open)
                .transpose()?;
            let text = if text {
                Some(hidden("Text to seal: ")?)
            } else {
                None
            };
            let key = protector.create(&request, &mut terminal)?;
            let result = if let Some(text) = text {
                seal::seal_reader(&key, &mut text.as_bytes(), &output)
            } else if let Some(file) = &mut file {
                seal::seal_reader(&key, file, &output)
            } else {
                seal::seal_reader(&key, &mut io::stdin().lock(), &output)
            };
            result.context(
                "container publication failed after enrollment; external factors may remain",
            )?;
        }
        Command::Open {
            input,
            output,
            method_id,
        } => {
            let envelope = seal::inspect_file(&input)?;
            let id = selected(&envelope, method_id)?;
            if let Some(output) = output {
                seal::open_file(&protector, input, output, id, &mut terminal)?;
            } else {
                seal::open_to(
                    &protector,
                    input,
                    &mut io::stdout().lock(),
                    id,
                    &mut terminal,
                )?;
            }
        }
        Command::Methods { command } => methods(&protector, &mut terminal, command)?,
    }
    Ok(())
}
fn methods(protector: &Protector, terminal: &mut Terminal, command: Methods) -> Result<()> {
    match command {
        Methods::Add {
            input,
            output,
            unlock,
            enroll,
        } => edit(
            protector,
            terminal,
            input,
            output,
            unlock,
            None,
            Some(enroll),
        ),
        Methods::Replace {
            input,
            output,
            unlock,
            enroll,
            remove,
        } => edit(
            protector,
            terminal,
            input,
            output,
            unlock,
            Some(remove),
            Some(enroll),
        ),
        Methods::Remove {
            input,
            output,
            unlock,
            remove,
        } => edit(
            protector,
            terminal,
            input,
            output,
            unlock,
            Some(remove),
            None,
        ),
        Methods::Retire {
            input,
            method_id,
            survivor,
            verify_with,
            factor,
        } => {
            let next = seal::inspect_file(&survivor)?;
            if next.methods().any(|m| m.id == method_id) {
                bail!("survivor still contains the method being retired");
            }
            let verified = protector.unlock(&next, selected(&next, verify_with)?, terminal)?;
            seal::verify_file(&verified, survivor)?;
            let old = seal::inspect_file(input)?;
            match factor {
                RetireFactor::Credential => {
                    protector.retire_credential(&old, method_id, &verified, terminal)?;
                }
                RetireFactor::Keystore => {
                    protector.remove_store_factor(&old, method_id, &verified)?;
                }
            }
            Ok(())
        }
    }
}
fn edit(
    protector: &Protector,
    terminal: &mut Terminal,
    input: PathBuf,
    output: PathBuf,
    unlock: Option<MethodId>,
    remove: Option<MethodId>,
    enroll: Option<EnrollArgs>,
) -> Result<()> {
    fresh_destination(&output)?;
    let enrollment = enroll.as_ref().map(EnrollArgs::enrollment).transpose()?;
    let envelope = seal::inspect_file(&input)?;
    let mut key = protector.unlock(&envelope, selected(&envelope, unlock)?, terminal)?;
    if let Some(path) = enroll.and_then(|e| e.new_recovery_file) {
        terminal.recovery = Some(path);
    }
    match (remove, enrollment) {
        (Some(id), Some(request)) => {
            protector.replace_method(&mut key, id, &request, terminal)?;
        }
        (None, Some(request)) => {
            protector.add_method(&mut key, &request, terminal)?;
        }
        (Some(id), None) => protector.remove_method(&mut key, id)?,
        (None, None) => unreachable!(),
    }
    seal::update_file(&key, input, output).context(
        "updated container publication failed; any newly enrolled external factors may remain",
    )?;
    Ok(())
}
