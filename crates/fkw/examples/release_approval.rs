//! Review and authorize one release using the public fkw API.
//!
//! The client and verifier run in one process. Pending state is in memory;
//! a deployment service needs durable claims and execution by approved digest.
#![allow(clippy::unnecessary_debug_formatting)] // Escape control characters in paths.
use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use fkw::{
    ApplicationId, Interaction, Pin, Prompt,
    sign::{Credential, Signature, Signer, VerificationKey},
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const APPLICATION: &str = "release.example";
const PURPOSE: &str = "release-approval/v1";
const AUDIENCE: &str = "deploy.example";
const ENVIRONMENT: &str = "production";
const LIFETIME_SECONDS: u64 = 300;
const MAX_REQUEST_BYTES: usize = 256;

#[derive(Parser)]
#[command(
    about = "Review and authorize a release digest (example; no deployment)",
    disable_help_subcommand = true,
    max_term_width = 100
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Enroll a signing credential and save KEY and KEY.pub.
    Enroll {
        /// New signing credential file.
        key: PathBuf,
    },
    /// Prepare, review, sign, and claim one release request.
    Approve {
        /// Release artifact to hash and request approval for.
        artifact: PathBuf,
        /// Signing credential created by enroll.
        #[arg(long)]
        key: PathBuf,
        /// Verifier's trusted public key, configured independently of the request.
        #[arg(long, value_name = "PUBLIC_KEY")]
        trust: PathBuf,
    },
}

// Application protocol: [version, id, audience, environment, digest, expiry].
#[derive(Clone, Debug, PartialEq, Eq)]
struct Request {
    id: [u8; 32],
    audience: String,
    environment: String,
    artifact: [u8; 32],
    expires_at: u64,
}

impl Request {
    fn encode(&self) -> Vec<u8> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(6)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.id)
            .unwrap()
            .str(&self.audience)
            .unwrap()
            .str(&self.environment)
            .unwrap()
            .bytes(&self.artifact)
            .unwrap()
            .u64(self.expires_at)
            .unwrap();
        encoder.into_writer()
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_REQUEST_BYTES, "request is too large");
        let mut decoder = minicbor::Decoder::new(bytes);
        ensure!(
            decoder.array()? == Some(6) && decoder.u8()? == 1,
            "unsupported request"
        );
        let request = Self {
            id: decoder.bytes()?.try_into()?,
            audience: decoder.str()?.to_owned(),
            environment: decoder.str()?.to_owned(),
            artifact: decoder.bytes()?.try_into()?,
            expires_at: decoder.u64()?,
        };
        for name in [&request.audience, &request.environment] {
            ensure!(
                (1..=64).contains(&name.len())
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)),
                "invalid audience or environment"
            );
        }
        ensure!(
            request.encode() == bytes,
            "noncanonical request or trailing data"
        );
        Ok(request)
    }
}

// Trusted verifier state. Neither this key nor this request comes from an approval.
struct PendingRelease {
    trusted_key: VerificationKey,
    request: Request,
    claimed: Mutex<bool>,
}

impl PendingRelease {
    fn prepare(trusted_key: VerificationKey, artifact: [u8; 32], now: u64) -> Result<Self> {
        let mut id = [0; 32];
        getrandom::fill(&mut id)?;
        Ok(Self {
            trusted_key,
            request: Request {
                id,
                audience: AUDIENCE.into(),
                environment: ENVIRONMENT.into(),
                artifact,
                expires_at: now
                    .checked_add(LIFETIME_SECONDS)
                    .context("clock overflow")?,
            },
            claimed: Mutex::new(false),
        })
    }

    fn claim(
        &self,
        bytes: &[u8],
        signature: &Signature,
        clock: impl FnOnce() -> Result<u64>,
    ) -> Result<&Request> {
        ensure!(
            bytes == self.request.encode(),
            "approval does not match the pending release"
        );
        self.trusted_key.verify(PURPOSE, bytes, signature)?;
        let mut claimed = self
            .claimed
            .lock()
            .map_err(|_| anyhow::anyhow!("claim state unavailable"))?;
        ensure!(clock()? < self.request.expires_at, "approval expired");
        ensure!(!*claimed, "release already claimed");
        *claimed = true;
        Ok(&self.request)
    }
}

fn signer() -> Result<Signer> {
    Ok(Signer::new(ApplicationId::new(APPLICATION)?))
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn digest(path: &Path) -> Result<[u8; 32]> {
    let mut input = File::open(path).with_context(|| format!("cannot read {path:?}"))?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        match input.read(&mut buffer) {
            Ok(0) => break,
            Ok(len) => hash.update(&buffer[..len]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(hash.finalize().into())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02x}").unwrap();
    }
    result
}

fn review(bytes: &[u8], output: &mut impl Write, now: u64) -> Result<()> {
    let request = Request::decode(bytes)?;
    ensure!(request.expires_at > now, "request expired before review");
    writeln!(
        output,
        "Release approval\n  Audience: {}\n  Environment: {}\n  Artifact SHA-256: {}\n  Request: {}\n  Expires: {} (Unix seconds; {} seconds remaining)",
        request.audience,
        request.environment,
        hex(&request.artifact),
        hex(&request.id),
        request.expires_at,
        request.expires_at - now
    )?;
    Ok(())
}

fn approve(credential: &Credential, bytes: &[u8]) -> Result<Signature> {
    require_terminal()?;
    review(bytes, &mut io::stderr().lock(), now()?)?;
    eprint!("Approve this release? [y/N] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    ensure!(
        answer.trim().eq_ignore_ascii_case("y"),
        "approval cancelled"
    );
    // The exact immutable bytes shown above are passed to fkw.
    Ok(signer()?.sign(credential, PURPOSE, bytes, &mut Terminal)?)
}

fn require_terminal() -> Result<()> {
    ensure!(
        io::stdin().is_terminal() && io::stderr().is_terminal(),
        "run from an interactive terminal"
    );
    Ok(())
}

struct Terminal;
impl Interaction for Terminal {
    fn pin(&mut self, _: Prompt<'_>) -> fkw::Result<Pin> {
        let pin = Zeroizing::new(rpassword::prompt_password("Security-key PIN: ")?);
        Ok(Pin::new(&pin)?)
    }

    fn select(&mut self, _: Prompt<'_>, count: usize) -> fkw::Result<()> {
        if count > 1 {
            eprintln!("Touch the key you want to use.");
        }
        Ok(())
    }

    fn touch(&mut self, _: Prompt<'_>) -> fkw::Result<()> {
        eprintln!("Touch the security key.");
        Ok(())
    }
}

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("cannot read {path:?}"))?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= maximum, "key file exceeds its size limit");
    Ok(bytes)
}

fn fresh(path: &Path) -> Result<()> {
    ensure!(path != Path::new("-"), "choose an output file");
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => bail!("destination already exists: {path:?}"),
    }
}

fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    if let Err(error) = staged.persist_noclobber(path) {
        let (_, retained) = error.file.keep()?;
        return Err(error.error)
            .with_context(|| format!("completed output retained at {retained:?}"));
    }
    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(fkw::Error::PublicationUncertain)?;
    eprintln!("Saved {path:?}");
    Ok(())
}

fn enroll(key: &Path) -> Result<()> {
    let mut public = key.as_os_str().to_owned();
    public.push(".pub");
    let public = PathBuf::from(public);
    fresh(key)?;
    fresh(&public)?;
    require_terminal()?;
    let credential = signer()?.create(&mut Terminal)?;
    save(key, &credential.to_bytes())?;
    save(&public, &credential.verification_key().to_bytes())
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::Enroll { key } => enroll(&key),
        Command::Approve {
            artifact,
            key,
            trust,
        } => {
            let credential = Credential::from_bytes(&read(&key, Credential::MAX_BYTES)?)?;
            // This path is verifier configuration, never a key supplied in the approval.
            let trusted_key =
                VerificationKey::from_bytes(&read(&trust, VerificationKey::MAX_BYTES)?)?;
            let pending = PendingRelease::prepare(trusted_key, digest(&artifact)?, now()?)?;
            let bytes = pending.request.encode();
            let signature = approve(&credential, &bytes)?;
            let accepted = pending.claim(&bytes, &signature, now)?;
            println!(
                "Accepted release {}: SHA-256 {}",
                hex(&accepted.id),
                hex(&accepted.artifact)
            );
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "release_approval/tests.rs"]
mod tests;
