//! The file rgb-lib validates. It reads a consignment only from a path, so the
//! request bytes go through a new scratch file that is always removed.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{EnclaveError, Result};

/// Runs `read` on `bytes`, written to a scratch file no other request uses.
pub(super) fn with_scratch_file<T>(
    bytes: &[u8],
    read: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
    with_file_at(&scratch_path(), bytes, read)
}

/// [`with_scratch_file`] through a new file at `path`. An existing file is
/// refused, not overwritten or removed.
pub(super) fn with_file_at<T>(
    path: &Path,
    bytes: &[u8],
    read: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
    let file = File::create_new(path).map_err(|e| scratch_error("create", path, e))?;
    let _on_panic = RemoveOnUnwind(path);
    let result = write_all(file, path, bytes).and_then(|()| read(path));
    match (result, std::fs::remove_file(path)) {
        (result, Ok(())) => result,
        (Ok(_), Err(e)) => Err(scratch_error("remove", path, e)),
        (Err(err), Err(e)) => {
            tracing::warn!(path = %path.display(), "could not remove the consignment scratch file: {e}");
            Err(err)
        }
    }
}

/// Removes the file if `read` panics: a debug build unwinds, a release build aborts.
struct RemoveOnUnwind<'a>(&'a Path);

impl Drop for RemoveOnUnwind<'_> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        if let Err(e) = std::fs::remove_file(self.0) {
            tracing::warn!(path = %self.0.display(), "could not remove the consignment scratch file: {e}");
        }
    }
}

/// Writes and closes the file, so the reader sees every byte.
fn write_all(mut file: File, path: &Path, bytes: &[u8]) -> Result<()> {
    file.write_all(bytes)
        .map_err(|e| scratch_error("write", path, e))
}

/// An enclave fault, not one of the consignment.
fn scratch_error(action: &str, path: &Path, e: std::io::Error) -> EnclaveError {
    EnclaveError::Internal(format!(
        "could not {action} the consignment scratch file {}: {e}",
        path.display()
    ))
}

/// A file name no other request of this or another enclave process uses.
fn scratch_path() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "utexo-enclave-consignment-{}-{n}.rgb",
        std::process::id()
    ))
}
