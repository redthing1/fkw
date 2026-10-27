//! A terminal client of the public fkw API.
#![allow(clippy::unnecessary_debug_formatting)] // Escape control characters in paths and labels.
mod args;
mod files;
mod public_key;
mod terminal;

use anyhow::{Context, Result, bail};
use args::{Access, Cli, Command, Enroll, Recipe};
use clap::{Parser, ValueEnum};
use fkw::{
    ApplicationId, Enrollment, Envelope, Error, KeyOptions, Method, MethodId, Protector,
    StoreAccess, UnlockedKey, Verification, seal,
};
use std::{
    fs::File,
    io::{self, Cursor, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};
use terminal::Terminal;
use zeroize::Zeroizing;

// Persistent identity shared by sealed files, credentials, and keystore entries.
const APPLICATION: &str = "io.fido-key-wrap.cli";

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fkw: {error:#}");
            if error.chain().any(|cause| {
                matches!(
                    cause.downcast_ref::<Error>(),
                    Some(Error::InteractionUnsupported)
                )
            }) {
                eprintln!("Terminal input is required; use a terminal without --no-input.");
            } else if error.chain().any(|cause| {
                matches!(
                    cause.downcast_ref::<Error>(),
                    Some(Error::Fido(fkw::diagnostics::FidoError::CredentialNotFound))
                )
            }) {
                eprintln!("Use the security key used during enrollment.");
            }
            ExitCode::from(
                if error
                    .chain()
                    .any(|cause| matches!(cause.downcast_ref::<Error>(), Some(Error::Cancelled)))
                {
                    130
                } else {
                    1
                },
            )
        }
    }
}
fn run(cli: Cli) -> Result<()> {
    let protector = Protector::new(ApplicationId::new(APPLICATION)?);
    let mut terminal = Terminal {
        no_input: cli.no_input,
        recovery: cli.recovery_file,
    };
    match cli.command {
        Command::Seal(args) => seal_command(&protector, &mut terminal, args),
        Command::Open {
            input,
            output,
            unlock: choice,
            identity,
        } => open_command(
            &protector,
            &mut terminal,
            &input,
            output,
            choice.using.as_deref(),
            identity.as_deref(),
        ),
        Command::Info { input } => {
            let input = files::Input::read(&input)?;
            let envelope = seal::inspect_file(input.path)?;
            let mut output = io::stdout().lock();
            writeln!(output, "Unverified unlock methods:")?;
            for method in envelope.methods() {
                writeln!(
                    output,
                    "  {:?} — {}\n    {}",
                    method.label,
                    terminal::describe(method.method),
                    method.id
                )?;
            }
            Ok(())
        }
        Command::Verify {
            input,
            unlock: choice,
            identity,
            signature,
            key,
            purpose,
        } => {
            if let Some(signature) = signature {
                return public_key::verify(
                    &input,
                    key.as_deref().expect("clap requires a public key"),
                    &purpose,
                    &signature,
                );
            }
            let input = files::Input::read(&input)?;
            if let Some(identity) = identity {
                let key = public_key::identity(
                    &protector,
                    &mut terminal,
                    &identity,
                    choice.using.as_deref(),
                )?;
                fkw::recipient::verify_file(&key, &input.path)?;
                eprintln!("Verified.");
                return Ok(());
            }
            let envelope = seal::inspect_file(&input.path)?;
            let key = unlock(
                &protector,
                &envelope,
                choice.using.as_deref(),
                &mut terminal,
            )?;
            seal::verify_file(&key, input.path)?;
            eprintln!("Verified.");
            Ok(())
        }
        Command::Access { command } => access(&protector, &mut terminal, &command),
        Command::Recovery { output } => files::recovery(&output),
        Command::Recipient { command } => public_key::recipient(&protector, &mut terminal, command),
        Command::Signer { command } => public_key::signer(&mut terminal, command),
        Command::Sign(args) => public_key::sign(&mut terminal, args),
    }
}

fn open_command(
    protector: &Protector,
    terminal: &mut Terminal,
    input: &Path,
    output: args::Output,
    using: Option<&str>,
    identity: Option<&Path>,
) -> Result<()> {
    let output = destination(output, None, false)?;
    if let Some(path) = &output {
        files::fresh_destination(path)?;
    }
    let input = files::Input::read(input)?;
    if let Some(identity) = identity {
        let key = public_key::identity(protector, terminal, identity, using)?;
        if let Some(output) = &output {
            fkw::recipient::decrypt_file(&key, &input.path, output)?;
        } else {
            fkw::recipient::decrypt_to(&key, &input.path, &mut io::stdout().lock())?;
        }
    } else {
        let envelope = seal::inspect_file(&input.path)?;
        let method = select_method(&envelope, using, terminal)?;
        if let Some(output) = &output {
            seal::open_file(protector, &input.path, output, method, terminal)?;
        } else {
            seal::open_to(
                protector,
                &input.path,
                &mut io::stdout().lock(),
                method,
                terminal,
            )?;
        }
    }
    if let Some(output) = output {
        eprintln!("Saved {output:?}");
    }
    Ok(())
}

fn select_method(
    envelope: &Envelope,
    using: Option<&str>,
    terminal: &Terminal,
) -> Result<MethodId> {
    if envelope.application_id().as_str() != APPLICATION {
        return Err(Error::WrongApplication.into());
    }
    terminal.method(
        envelope,
        using,
        "Choose an unlock method (unverified labels):",
    )
}
fn unlock(
    protector: &Protector,
    envelope: &Envelope,
    using: Option<&str>,
    terminal: &mut Terminal,
) -> Result<UnlockedKey> {
    let method = select_method(envelope, using, terminal)?;
    Ok(protector.unlock(envelope, method, terminal)?)
}
fn destination(
    output: args::Output,
    default: Option<PathBuf>,
    armor: bool,
) -> Result<Option<PathBuf>> {
    if output.stdout || output.output.as_deref() == Some(Path::new("-")) {
        return Ok(None);
    }
    if let Some(path) = output.output.or(default) {
        return Ok(Some(path));
    }
    if armor {
        return Ok(None);
    }
    bail!("choose an output with -o FILE or -c / --stdout")
}
fn seal_command(protector: &Protector, terminal: &mut Terminal, args: args::Seal) -> Result<()> {
    let default = args
        .input
        .as_ref()
        .filter(|p| p.as_os_str() != "-")
        .map(|path| {
            let mut output = path.as_os_str().to_owned();
            output.push(".fkw");
            PathBuf::from(output)
        });
    let output = destination(args.output, default, args.armor)?;
    if output.is_none() && io::stdout().is_terminal() && !args.armor {
        bail!("use --armor to print encrypted data to a terminal, or -o FILE");
    }
    let work = files::Work::new(output)?;
    let mut input: Box<dyn Read> = if args.text {
        let text = terminal.hidden("Text to seal: ")?;
        Box::new(Cursor::new(Zeroizing::new(text.as_bytes().to_vec())))
    } else if let Some(path) = args.input.filter(|p| p.as_os_str() != "-") {
        Box::new(File::open(&path).with_context(|| format!("cannot read {path:?}"))?)
    } else {
        if io::stdin().is_terminal() {
            bail!("supply a file, pipe stdin, or use --text");
        }
        Box::new(io::stdin())
    };
    if let Some(path) = args.to {
        let recipient = public_key::read_recipient(&path)?;
        return work.save(None, args.armor, |path| {
            Ok(fkw::recipient::encrypt_reader(
                &recipient, &mut input, path,
            )?)
        });
    }
    let key = if let Some(path) = args.resume {
        unlock(
            protector,
            &files::read_envelope(&path)?,
            args.using.as_deref(),
            terminal,
        )?
    } else {
        let request = enrollment(&args.enroll, None, None, terminal)?;
        protector.create(&request, terminal)?
    };
    work.save(Some(key.envelope()), args.armor, |path| {
        Ok(seal::seal_reader(&key, &mut input, path)?)
    })
}

fn enrollment(
    args: &Enroll,
    envelope: Option<&Envelope>,
    replace: Option<MethodId>,
    terminal: &Terminal,
) -> Result<Enrollment> {
    let recipe = if let Some(recipe) = args.with {
        recipe
    } else {
        let choices = Recipe::value_variants()
            .iter()
            .map(|r| r.to_possible_value().expect("recipe").get_name().to_owned())
            .collect::<Vec<_>>();
        let index = terminal.choose(
            "How should this unlock?",
            &choices,
            "choose protection with --with",
        )?;
        Recipe::value_variants()[index]
    };
    let mut key = KeyOptions::new(if args.uv {
        Verification::UserVerified
    } else {
        Verification::Presence
    });
    if args.managed {
        key = key.managed();
    }
    let access = match args.store_access.unwrap_or(args::StoreAccess::Standard) {
        args::StoreAccess::Standard => StoreAccess::Standard,
        args::StoreAccess::UserAuthentication => StoreAccess::UserAuthentication,
        args::StoreAccess::MacosLogin => StoreAccess::MacosLogin,
    };
    let method = match recipe {
        Recipe::Key => Method::SecurityKey(key),
        Recipe::Passphrase => Method::Passphrase,
        Recipe::KeyPassphrase => Method::KeyAndPassphrase(key),
        Recipe::Keystore => Method::Keystore(access),
        Recipe::KeyKeystore => Method::KeyAndKeystore(key, access),
        Recipe::Recovery => Method::RecoverySecret,
    };
    if (args.uv || args.managed) && method.key_options().is_none() {
        bail!("--uv and --managed require a key method");
    }
    if args.store_access.is_some() && method.store_access().is_none() {
        bail!("--store-access requires a keystore method");
    }
    let old_label = envelope
        .and_then(|e| e.methods().find(|m| Some(m.id) == replace))
        .map(|m| m.label);
    let label_exists = |name: &str| {
        envelope.is_some_and(|e| {
            e.methods()
                .any(|m| Some(m.id) != replace && m.label == name)
        })
    };
    let mut name = args
        .name
        .clone()
        .or_else(|| old_label.map(str::to_owned))
        .unwrap_or_else(|| {
            recipe
                .to_possible_value()
                .expect("recipe")
                .get_name()
                .to_owned()
        });
    if args.name.is_none() && old_label.is_none() {
        let base = name.clone();
        let mut suffix = 2;
        while label_exists(&name) {
            name = format!("{base}-{suffix}");
            suffix += 1;
        }
    }
    if name.is_empty() {
        bail!("method name cannot be empty");
    }
    if label_exists(&name) {
        bail!("method name already exists; choose another with --name");
    }
    Ok(Enrollment::new(method, name)?)
}

fn access(protector: &Protector, terminal: &mut Terminal, command: &Access) -> Result<()> {
    let edit = match command {
        Access::Add { edit, .. }
        | Access::Replace { edit, .. }
        | Access::Remove { edit, .. }
        | Access::Restore { edit, .. } => edit,
    };
    let work = files::Work::edit(&edit.input, edit.output.as_deref())?;
    let input = files::Input::read(&edit.input)?;
    let envelope = match command {
        Access::Restore { envelope, .. } => files::read_envelope(envelope)?,
        _ => seal::inspect_file(&input.path)?,
    };
    let unlocking = select_method(&envelope, edit.unlock.using.as_deref(), terminal)?;
    let mut key = protector.unlock(&envelope, unlocking, terminal)?;
    // Check the input before creating any new external factor.
    seal::verify_file(&key, &input.path)?;
    match command {
        Access::Add { new, .. } => {
            enroll_method(protector, &mut key, terminal, new, None)?;
        }
        Access::Replace { method, new, .. } => {
            let target = terminal.method(
                key.envelope(),
                method.as_deref(),
                "Choose the method to replace:",
            )?;
            enroll_method(protector, &mut key, terminal, new, Some(target))?;
        }
        Access::Remove { method, .. } => {
            let target = terminal.method(
                key.envelope(),
                method.as_deref(),
                "Choose the method to remove:",
            )?;
            if edit.output.is_none() && target == unlocking && key.envelope().methods().len() > 1 {
                bail!(
                    "unlock with a method you are keeping (--using), or write a separate copy with -o"
                );
            }
            protector.remove_method(&mut key, target)?;
        }
        Access::Restore { .. } => {}
    }
    work.save(Some(key.envelope()), input.armored, |path| {
        Ok(seal::update_file(&key, &input.path, path)?)
    })?;
    if matches!(command, Access::Replace { .. } | Access::Remove { .. }) {
        eprintln!("Older copies and external factors are unchanged.");
    }
    Ok(())
}

fn enroll_method(
    protector: &Protector,
    key: &mut UnlockedKey,
    terminal: &mut Terminal,
    new: &args::NewMethod,
    replace: Option<MethodId>,
) -> Result<()> {
    let request = enrollment(&new.enroll, Some(key.envelope()), replace, terminal)?;
    if let Some(path) = &new.new_recovery_file {
        if request.method() != Method::RecoverySecret {
            bail!("--new-recovery-file requires a recovery method");
        }
        terminal.recovery = Some(path.clone());
    }
    if request.method().key_options().is_some() {
        terminal.connect_key(request.label())?;
    }
    match replace {
        Some(target) => protector.replace_method(key, target, &request, terminal)?,
        None => protector.add_method(key, &request, terminal)?,
    };
    Ok(())
}
