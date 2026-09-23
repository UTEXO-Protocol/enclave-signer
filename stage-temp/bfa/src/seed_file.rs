//! File-only input for retained stage seeds. Errors never contain file contents.
use std::{
    fs::OpenOptions,
    io::{self, Read},
    path::Path,
};
use zeroize::Zeroizing;

fn read_protected(path: &Path) -> io::Result<Zeroizing<String>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.mode() & 0o077 != 0 || meta.len() > 4096 {
            return Err(io::Error::other(
                "expected a private regular file of at most 4096 bytes",
            ));
        }
        let mut text = Zeroizing::new(String::new());
        file.take(4097).read_to_string(&mut text)?;
        if text.len() > 4096 {
            return Err(io::Error::other("secret file too large"));
        }
        Ok(text)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(io::Error::other(
            "stage import requires Unix file permissions",
        ))
    }
}

pub fn read_seed(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    let text = read_protected(path)?;
    if text.trim().len() != 128 {
        return Err(io::Error::other("expected a 64-byte hex seed"));
    }
    let seed = hex::decode(text.trim()).map_err(|_| io::Error::other("invalid seed encoding"))?;
    Ok(Zeroizing::new(seed))
}

pub fn read_secret(path: &Path) -> io::Result<Zeroizing<String>> {
    let text = read_protected(path)?;
    if text.trim().is_empty() {
        return Err(io::Error::other("empty cloning secret"));
    }
    Ok(Zeroizing::new(text.trim().to_owned()))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn private_valid_seed_only() {
        let dir = std::env::temp_dir().join(format!("stage-seed-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("seed");
        std::fs::write(&file, "ab".repeat(64)).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(&*read_seed(&file).unwrap(), &vec![0xab; 64]);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_seed(&file).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link");
        symlink(&file, &link).unwrap();
        assert!(read_seed(&link).is_err());
        std::fs::write(&file, "bad secret value").unwrap();
        assert!(!read_seed(&file)
            .unwrap_err()
            .to_string()
            .contains("bad secret value"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
