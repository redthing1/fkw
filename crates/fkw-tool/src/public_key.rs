//! Public-key command orchestration; constructions belong to the library.
use crate::{
    APPLICATION,
    args::{RecipientCommand, Sign, SignerCommand},
    files,
    terminal::Terminal,
};
use anyhow::{Result, bail};
use fkw::{
    ApplicationId, Protector, UnlockedKey,
    recipient::Recipient,
    seal,
    sign::{Credential, Signature, Signer, VerificationKey},
};
use std::{
    fs::File,
    io::{self, IsTerminal, Read},
    path::{Path, PathBuf},
};

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        bail!("key or signature file exceeds its size limit");
    }
    Ok(bytes)
}

pub fn read_recipient(path: &Path) -> Result<Recipient> {
    Ok(Recipient::from_bytes(&read(path, Recipient::MAX_BYTES)?)?)
}

pub fn identity(
    protector: &Protector,
    terminal: &mut Terminal,
    path: &Path,
    using: Option<&str>,
) -> Result<UnlockedKey> {
    let input = files::Input::read(path)?;
    let envelope = seal::inspect_file(&input.path)?;
    let key = crate::unlock(protector, &envelope, using, terminal)?;
    seal::verify_file(&key, &input.path)?;
    Ok(key)
}

fn public_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".pub");
    name.into()
}

pub fn recipient(
    protector: &Protector,
    terminal: &mut Terminal,
    command: RecipientCommand,
) -> Result<()> {
    match command {
        RecipientCommand::Create { output, enroll } => {
            let public = public_path(&output);
            files::fresh_destination(&public)?;
            let work = files::Work::new(Some(output))?;
            let request = crate::enrollment(&enroll, None, None, terminal)?;
            let key = protector.create(&request, terminal)?;
            let recipient = Recipient::from_key(&key)?;
            work.save(Some(key.envelope()), false, |path| {
                Ok(seal::seal_reader(&key, &mut io::empty(), path)?)
            })?;
            files::save_artifact(&public, &recipient.to_bytes())
        }
        RecipientCommand::Public {
            identity: path,
            output,
            unlock,
        } => {
            files::fresh_destination(&output)?;
            let key = identity(protector, terminal, &path, unlock.using.as_deref())?;
            files::save_artifact(&output, &Recipient::from_key(&key)?.to_bytes())
        }
    }
}

pub fn signer(terminal: &mut Terminal, command: SignerCommand) -> Result<()> {
    let signer = Signer::new(ApplicationId::new(APPLICATION)?);
    match command {
        SignerCommand::Create { output } => {
            let public = public_path(&output);
            files::fresh_destination(&output)?;
            files::fresh_destination(&public)?;
            let credential = signer.create(terminal)?;
            files::save_artifact(&output, &credential.to_bytes())?;
            files::save_artifact(&public, &credential.verification_key().to_bytes())
        }
        SignerCommand::Public { key, output } => {
            files::fresh_destination(&output)?;
            let credential = Credential::from_bytes(&read(&key, Credential::MAX_BYTES)?)?;
            files::save_artifact(&output, &credential.verification_key().to_bytes())
        }
    }
}

fn message(path: &Path) -> Result<Box<dyn Read>> {
    if path == Path::new("-") {
        if io::stdin().is_terminal() {
            bail!("supply a file or pipe stdin");
        }
        Ok(Box::new(io::stdin()))
    } else {
        Ok(Box::new(File::open(path)?))
    }
}

pub fn sign(terminal: &mut Terminal, args: Sign) -> Result<()> {
    let output = match args.output {
        Some(path) => path,
        None if args.input != Path::new("-") => {
            let mut name = args.input.as_os_str().to_owned();
            name.push(".sig");
            PathBuf::from(name)
        }
        None => bail!("signing stdin requires -o FILE"),
    };
    if output == Path::new("-") {
        bail!("signatures require an output file");
    }
    files::fresh_destination(&output)?;
    let credential = Credential::from_bytes(&read(&args.key, Credential::MAX_BYTES)?)?;
    let signer = Signer::new(ApplicationId::new(APPLICATION)?);
    let signature = signer.sign_reader(
        &credential,
        &args.purpose,
        &mut message(&args.input)?,
        terminal,
    )?;
    files::save_artifact(&output, &signature.to_bytes())
}

pub fn verify(input: &Path, key: &Path, purpose: &str, signature: &Path) -> Result<()> {
    let key = VerificationKey::from_bytes(&read(key, VerificationKey::MAX_BYTES)?)?;
    let signature = Signature::from_bytes(&read(signature, Signature::MAX_BYTES)?)?;
    key.verify_reader(purpose, &mut message(input)?, &signature)?;
    eprintln!("Verified.");
    Ok(())
}
