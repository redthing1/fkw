//! CLI transport and publication. Encrypted containers are produced by the library.
use anyhow::{Context, Result, bail};
use base64::{engine::general_purpose::STANDARD, read::DecoderReader, write::EncoderWriter};
use fkw::{Envelope, Error, RecoverySecret};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, IsTerminal, Read, Write},
    path::{Path, PathBuf},
};
use tempfile::{NamedTempFile, TempDir};

pub struct Input {
    pub path: PathBuf,
    _temporary: Option<NamedTempFile>,
}
impl Input {
    /// Decode printable transport or spool stdin; ordinary binary files stay in place.
    pub fn read(path: &Path) -> Result<Self> {
        let stdin = path == Path::new("-");
        if stdin && io::stdin().is_terminal() {
            bail!("supply a sealed file or pipe stdin");
        }
        let reader: Box<dyn Read> = if stdin {
            Box::new(io::stdin())
        } else {
            Box::new(File::open(path).with_context(|| format!("cannot read {path:?}"))?)
        };
        let mut reader = BufReader::new(reader);
        let mut prefix = [0; 4];
        reader
            .read_exact(&mut prefix)
            .context("input is not a complete sealed file")?;
        if prefix != *b"fkw:" && !stdin {
            return Ok(Self {
                path: path.to_owned(),
                _temporary: None,
            });
        }
        let mut temporary = NamedTempFile::new()?;
        if prefix == *b"fkw:" {
            let mut decoded = DecoderReader::new(Whitespace(reader), &STANDARD);
            io::copy(&mut decoded, &mut temporary).context("invalid armored data")?;
        } else {
            temporary.write_all(&prefix)?;
            io::copy(&mut reader, &mut temporary)?;
        }
        temporary.flush()?;
        Ok(Self {
            path: temporary.path().to_owned(),
            _temporary: Some(temporary),
        })
    }
}

// Permit line wrapping and surrounding whitespace inside the printable encoding.
struct Whitespace<R>(R);
impl<R: Read> Read for Whitespace<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let n = self.0.read(buffer)?;
            if n == 0 {
                return Ok(0);
            }
            let mut kept = 0;
            for i in 0..n {
                if !buffer[i].is_ascii_whitespace() {
                    buffer[kept] = buffer[i];
                    kept += 1;
                }
            }
            if kept != 0 {
                return Ok(kept);
            }
        }
    }
}

pub fn read_envelope(path: &Path) -> Result<Envelope> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(Envelope::MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(Envelope::from_bytes(&bytes)?)
}

pub fn fresh_destination(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("destination already exists: {path:?}"),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}
fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
fn private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = private_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    sync_directory(parent(path))?;
    Ok(())
}
fn publish(source: &Path, destination: &Path) -> Result<()> {
    // Work is staged on the destination filesystem. Linking is create-only,
    // including when another writer wins after the initial destination check.
    fs::hard_link(source, destination)?;
    sync_directory(parent(destination)).map_err(Error::PublicationUncertain)?;
    Ok(())
}
fn armor(input: &mut impl Read, output: &mut impl Write) -> Result<()> {
    output.write_all(b"fkw:")?;
    let mut encoder = EncoderWriter::new(output, &STANDARD);
    io::copy(input, &mut encoder)?;
    let output = encoder.finish()?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

/// One private directory for encrypted work. Only failed saves retain it.
/// Plaintext never belongs here: retaining work must not retain plaintext.
pub struct Work {
    directory: TempDir,
    destination: Option<PathBuf>,
}
impl Work {
    pub fn new(destination: Option<PathBuf>) -> Result<Self> {
        let directory = if let Some(path) = &destination {
            fresh_destination(path)?;
            tempfile::Builder::new()
                .prefix(".fkw-")
                .tempdir_in(parent(path))?
        } else {
            tempfile::Builder::new().prefix("fkw-").tempdir()?
        };
        Ok(Self {
            directory,
            destination,
        })
    }
    pub fn save(
        self,
        envelope: &Envelope,
        armored: bool,
        build: impl FnOnce(&Path) -> Result<()>,
    ) -> Result<()> {
        let sealed = self.directory.path().join("sealed.fkw");
        let snapshot = self.directory.path().join("envelope");
        let result: Result<()> = (|| {
            write_private(&snapshot, &envelope.to_bytes())?;
            sync_directory(parent(self.directory.path()))?;
            build(&sealed)?;
            if let Some(destination) = &self.destination {
                let source = if armored {
                    let path = self.directory.path().join("armored.fkw");
                    let mut file = private_file(&path)?;
                    armor(&mut File::open(&sealed)?, &mut file)?;
                    file.sync_all()?;
                    path
                } else {
                    sealed.clone()
                };
                publish(&source, destination)?;
                eprintln!("Saved {destination:?}");
            } else {
                let mut output = io::stdout().lock();
                let mut input = File::open(&sealed)?;
                if armored {
                    armor(&mut input, &mut output)?;
                } else {
                    io::copy(&mut input, &mut output)?;
                    output.flush()?;
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                let retained = self.directory.keep();
                let next = if sealed.is_file() {
                    "the complete encrypted file is sealed.fkw"
                } else if read_envelope(&snapshot).is_ok() {
                    "retry with the envelope snapshot using seal --resume or access restore"
                } else {
                    "the enrollment snapshot could not be saved; a new external factor may remain"
                };
                Err(error)
                    .with_context(|| format!("save failed; work retained at {retained:?}; {next}"))
            }
        }
    }
}

pub fn recovery(path: &Path) -> Result<()> {
    fresh_destination(path)?;
    let temporary = tempfile::Builder::new()
        .prefix(".fkw-")
        .tempdir_in(parent(path))?;
    let source = temporary.path().join("recovery");
    RecoverySecret::generate()?.expose(|bytes| write_private(&source, bytes))?;
    publish(&source, path)?;
    eprintln!("Saved {path:?}; keep it separate from sealed data.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fkw::{ApplicationId, Enrollment, Method, Protector, seal};

    #[test]
    fn publication_race_retains_enrollment_and_complete_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("output");
        let protector = Protector::new(ApplicationId::new("test.example").unwrap());
        let mut secret = RecoverySecret::generate().unwrap();
        let key = protector
            .create(
                &Enrollment::new(Method::RecoverySecret, "backup").unwrap(),
                &mut secret,
            )
            .unwrap();
        let work = Work::new(Some(destination.clone())).unwrap();
        let retained = work.directory.path().to_owned();
        let result = work.save(key.envelope(), false, |path| {
            seal::seal_reader(&key, &mut b"private text".as_slice(), path)?;
            fs::write(&destination, b"another writer")?;
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"another writer");
        assert_eq!(
            read_envelope(&retained.join("envelope"))
                .unwrap()
                .to_bytes(),
            key.envelope().to_bytes()
        );
        seal::verify_file(&key, retained.join("sealed.fkw")).unwrap();
        assert!(format!("{:#}", result.unwrap_err()).contains("complete encrypted file"));
        fs::remove_dir_all(retained).unwrap();
    }

    #[test]
    fn failed_encryption_retains_only_public_enrollment() {
        struct BrokenInput;
        impl Read for BrokenInput {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("input failed"))
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let protector = Protector::new(ApplicationId::new("test.example").unwrap());
        let mut secret = RecoverySecret::generate().unwrap();
        let key = protector
            .create(
                &Enrollment::new(Method::RecoverySecret, "backup").unwrap(),
                &mut secret,
            )
            .unwrap();
        let work = Work::new(Some(dir.path().join("output"))).unwrap();
        let retained = work.directory.path().to_owned();
        let error = work
            .save(key.envelope(), false, |path| {
                Ok(seal::seal_reader(&key, &mut BrokenInput, path)?)
            })
            .unwrap_err();
        assert!(format!("{error:#}").contains("retry with the envelope snapshot"));
        assert_eq!(fs::read_dir(&retained).unwrap().count(), 1);
        assert_eq!(
            read_envelope(&retained.join("envelope"))
                .unwrap()
                .to_bytes(),
            key.envelope().to_bytes()
        );
        assert!(!dir.path().join("output").exists());
        fs::remove_dir_all(retained).unwrap();
    }

    #[test]
    fn snapshot_failure_does_not_offer_an_unusable_retry() {
        let dir = tempfile::tempdir().unwrap();
        let protector = Protector::new(ApplicationId::new("test.example").unwrap());
        let mut secret = RecoverySecret::generate().unwrap();
        let key = protector
            .create(
                &Enrollment::new(Method::RecoverySecret, "backup").unwrap(),
                &mut secret,
            )
            .unwrap();
        let work = Work::new(Some(dir.path().join("output"))).unwrap();
        let retained = work.directory.path().to_owned();
        fs::create_dir(retained.join("envelope")).unwrap();
        let error = work
            .save(key.envelope(), false, |_| {
                panic!("snapshot must be saved first")
            })
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("snapshot could not be saved"));
        assert!(!message.contains("retry"));
        assert!(!dir.path().join("output").exists());
        fs::remove_dir_all(retained).unwrap();
    }
}
