//! A terminal client of the public fkw API.
#![allow(clippy::unnecessary_debug_formatting)] // Escape control characters in paths and labels.
mod args;
mod files;
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
                eprintln!(
                    "Terminal input is unavailable. Use a terminal without --no-input, or select a recovery method with --recovery-file."
                );
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
        } => {
            let output = destination(output, None, false)?;
            if let Some(path) = &output {
                files::fresh_destination(path)?;
            }
            let input = files::Input::read(&input)?;
            let envelope = seal::inspect_file(&input.path)?;
            let method = select_method(&envelope, choice.using.as_deref(), &terminal)?;
            if let Some(output) = output {
                seal::open_file(&protector, &input.path, &output, method, &mut terminal)?;
                eprintln!("Saved {output:?}");
            } else {
                seal::open_to(
                    &protector,
                    &input.path,
                    &mut io::stdout().lock(),
                    method,
                    &mut terminal,
                )?;
            }
            Ok(())
        }
        Command::Info { input } => {
            let input = files::Input::read(&input)?;
            let envelope = seal::inspect_file(input.path)?;
            let mut output = io::stdout().lock();
            writeln!(
                output,
                "Unverified metadata · {}",
                envelope.application_id()
            )?;
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
        } => {
            let input = files::Input::read(&input)?;
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
    }
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
    work.save(key.envelope(), args.armor, |path| {
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
    let name = args
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
    if name.is_empty() {
        bail!("method name cannot be empty");
    }
    if envelope.is_some_and(|e| {
        e.methods()
            .any(|m| Some(m.id) != replace && m.label == name)
    }) {
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
    if edit.output == Path::new("-") {
        bail!("access changes require an output file");
    }
    let work = files::Work::new(Some(edit.output.clone()))?;
    let input = files::Input::read(&edit.input)?;
    let envelope = match command {
        Access::Restore { envelope, .. } => files::read_envelope(envelope)?,
        _ => seal::inspect_file(&input.path)?,
    };
    let mut key = unlock(protector, &envelope, edit.unlock.using.as_deref(), terminal)?;
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
            protector.remove_method(&mut key, target)?;
        }
        Access::Restore { .. } => {}
    }
    work.save(key.envelope(), false, |path| {
        Ok(seal::update_file(&key, &input.path, path)?)
    })?;
    if matches!(command, Access::Replace { .. } | Access::Remove { .. }) {
        eprintln!("Older copies retain their access. External factors are still present.");
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
    match replace {
        Some(target) => protector.replace_method(key, target, &request, terminal)?,
        None => protector.add_method(key, &request, terminal)?,
    };
    Ok(())
}
