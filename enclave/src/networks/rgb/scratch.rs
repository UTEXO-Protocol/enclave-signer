//! The file rgb-lib reads. It takes a consignment and a fascia only from a
//! path, so the request bytes go through a new scratch file that is always
//! removed. `what` names what the file holds, in its name and in an error.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{EnclaveError, Result};

/// Runs `read` on `bytes`, written to a scratch file no other request uses.
pub(super) fn with_scratch_file<T>(
    what: &str,
    bytes: &[u8],
    read: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
    with_file_at(what, &scratch_path(what), bytes, read)
}

/// [`with_scratch_file`] through a new file at `path`. An existing file is
/// refused, not overwritten or removed.
pub(super) fn with_file_at<T>(
    what: &str,
    path: &Path,
    bytes: &[u8],
    read: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
    let file = File::create_new(path).map_err(|e| scratch_error(what, "create", path, e))?;
    let _on_panic = RemoveOnUnwind(path);
    let result = write_all(what, file, path, bytes).and_then(|()| read(path));
    match (result, std::fs::remove_file(path)) {
        (result, Ok(())) => result,
        (Ok(_), Err(e)) => Err(scratch_error(what, "remove", path, e)),
        (Err(err), Err(e)) => {
            tracing::warn!(path = %path.display(), "could not remove the {what} scratch file: {e}");
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
            tracing::warn!(path = %self.0.display(), "could not remove the scratch file: {e}");
        }
    }
}

/// Writes and closes the file, so the reader sees every byte.
fn write_all(what: &str, mut file: File, path: &Path, bytes: &[u8]) -> Result<()> {
    file.write_all(bytes)
        .map_err(|e| scratch_error(what, "write", path, e))
}

/// An enclave fault, not one of the request bytes.
fn scratch_error(what: &str, action: &str, path: &Path, e: std::io::Error) -> EnclaveError {
    EnclaveError::Internal(format!(
        "could not {action} the {what} scratch file {}: {e}",
        path.display()
    ))
}

/// A file name no other request of this or another enclave process uses.
fn scratch_path(what: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "utexo-enclave-{what}-{}-{n}.rgb",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch path of its own for each test.
    fn path_of(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "utexo-enclave-test-{name}-{}.rgb",
            std::process::id()
        ))
    }

    /// The file rgb-lib read is gone after a pass, and after a refusal.
    #[test]
    fn the_scratch_file_is_removed_after_rgb_lib_reads_it() {
        for (name, pass) in [("removed-ok", true), ("removed-err", false)] {
            let path = path_of(name);
            let result = with_file_at("consignment", &path, b"bytes", |at| {
                assert_eq!(std::fs::read(at).unwrap(), b"bytes");
                if pass {
                    Ok(())
                } else {
                    Err(EnclaveError::CrossCheck("refused".into()))
                }
            });
            assert_eq!(result.is_ok(), pass, "{name}");
            assert!(!path.exists(), "{name}");
        }
    }

    /// A file already at the scratch path is refused and left in place.
    #[test]
    fn the_scratch_file_never_reuses_an_existing_file() {
        let path = path_of("existing");
        std::fs::write(&path, b"someone else's").unwrap();
        let err = with_file_at("fascia", &path, b"bytes", |_| Ok(())).unwrap_err();
        let kept = std::fs::read(&path);
        std::fs::remove_file(&path).unwrap();
        assert!(
            matches!(err, EnclaveError::Internal(_)),
            "an enclave fault: {err}"
        );
        // The label names the field the bytes came from.
        assert!(
            err.to_string()
                .contains("could not create the fascia scratch file"),
            "{err}"
        );
        assert_eq!(kept.unwrap(), b"someone else's");
    }

    /// A debug build unwinds a panic in the reader: the file is removed then too.
    #[test]
    fn the_scratch_file_is_removed_when_the_reader_panics() {
        let path = path_of("panicked");
        let panicked = std::panic::catch_unwind(|| {
            with_file_at("consignment", &path, b"bytes", |_| -> Result<()> {
                panic!("rgb-lib panicked")
            })
        });
        assert!(panicked.is_err());
        assert!(!path.exists());
    }

    /// Each request gets a file of its own, named after the field it holds.
    #[test]
    fn each_scratch_path_is_new_and_names_its_field() {
        let first = scratch_path("fascia");
        let second = scratch_path("fascia");
        assert_ne!(first, second);
        let name = first.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with("utexo-enclave-fascia-"), "{name}");
    }
}
