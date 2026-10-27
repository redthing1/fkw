//! Private staging and bounded I/O shared by complete data operations.
use crate::{Error, Result};
use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
};
use tempfile::NamedTempFile;
pub(crate) fn staging_file(output: &Path) -> Result<NamedTempFile> {
    match fs::symlink_metadata(output) {
        Ok(_) => {
            return Err(
                io::Error::new(io::ErrorKind::AlreadyExists, "destination already exists").into(),
            );
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(NamedTempFile::new_in(parent(output))?)
}
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}
pub(crate) fn publish(staged: NamedTempFile, output: &Path) -> Result<()> {
    staged.as_file().sync_all()?;
    staged
        .persist_noclobber(output)
        .map_err(|error| error.error)?;
    #[cfg(unix)]
    File::open(parent(output))
        .and_then(|directory| directory.sync_all())
        .map_err(Error::PublicationUncertain)?;
    Ok(())
}
pub(crate) fn exact(input: &mut impl Read, buffer: &mut [u8]) -> Result<()> {
    input.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Error::InvalidSealedData
        } else {
            error.into()
        }
    })
}
pub(crate) fn fill(input: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut count = 0;
    while count < buffer.len() {
        match input.read(&mut buffer[count..]) {
            Ok(0) => break,
            Ok(n) => count += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(count)
}
