//! Bounded, regular-file-only input handling for the standalone edge relay.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::Path,
};

/// Read an existing regular file without following a symlink or reparse point.
///
/// The path is checked before and after opening. Unix uses `O_NOFOLLOW` and
/// `O_NONBLOCK`; Windows opens the final component with
/// `FILE_FLAG_OPEN_REPARSE_POINT` and checks the resulting metadata. The
/// opened handle is then read through a `max_bytes + 1` limit so a file that
/// grows after the initial metadata check is still rejected.
pub fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let read_limit = max_bytes.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "bounded file limit is too large",
        )
    })?;

    reject_reparse_components(path)?;
    let file = open_readonly_no_reparse(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(invalid_input("path must reference a regular file"));
    }
    if metadata.len() > max_bytes {
        return Err(size_limit_error());
    }

    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut contents = Vec::with_capacity(capacity);
    file.take(read_limit).read_to_end(&mut contents)?;
    if contents.len() as u64 > max_bytes {
        return Err(size_limit_error());
    }
    Ok(contents)
}

fn open_readonly_no_reparse(path: &Path) -> io::Result<File> {
    reject_reparse_components(path)?;

    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;

        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?
    };

    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?
    };

    #[cfg(not(any(unix, windows)))]
    let file = File::open(path)?;

    ensure_open_handle_not_reparse(&file)?;
    reject_reparse_components(path)?;
    Ok(file)
}

fn reject_reparse_components(path: &Path) -> io::Result<()> {
    let mut current = Some(path);
    while let Some(component) = current {
        if component.as_os_str().is_empty() {
            break;
        }
        match fs::symlink_metadata(component) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(invalid_input(format!(
                    "refusing to traverse symlink component '{}'",
                    component.display()
                )));
            }
            Ok(_metadata) =>
            {
                #[cfg(windows)]
                if metadata_is_reparse_point(&_metadata) {
                    return Err(invalid_input(format!(
                        "refusing to traverse Windows reparse-point component '{}'",
                        component.display()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        current = component.parent();
    }
    Ok(())
}

fn ensure_open_handle_not_reparse(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(invalid_input("path must reference a regular file"));
    }

    #[cfg(windows)]
    if metadata_is_reparse_point(&metadata) {
        return Err(invalid_input(
            "refusing to access a Windows reparse-point file handle",
        ));
    }

    Ok(())
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn size_limit_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "file exceeds the configured size limit",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env, fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock is after Unix epoch")
                .as_nanos();
            let suffix = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "shph-edge-file-{}-{nonce}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn accepts_contents_at_the_limit() {
        let temp = TempDir::new();
        let path = temp.path("input");
        fs::write(&path, b"1234").expect("write input");

        assert_eq!(
            read_bounded_regular_file(&path, 4).expect("read at limit"),
            b"1234"
        );
    }

    #[test]
    fn rejects_contents_over_the_limit() {
        let temp = TempDir::new();
        let path = temp.path("input");
        fs::write(&path, b"12345").expect("write input");

        let error = read_bounded_regular_file(&path, 4).expect_err("oversized input");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "file exceeds the configured size limit");
    }

    #[test]
    fn rejects_an_overflowing_limit_before_opening() {
        let path = PathBuf::from("does-not-need-to-exist");
        let error = read_bounded_regular_file(&path, u64::MAX)
            .expect_err("overflowing file limit must reject");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "bounded file limit is too large");
    }

    #[test]
    fn rejects_directories() {
        let temp = TempDir::new();
        let error = read_bounded_regular_file(&temp.0, 4).expect_err("directory input");
        #[cfg(windows)]
        assert!(matches!(
            error.kind(),
            io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied
        ));
        #[cfg(not(windows))]
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        #[cfg(not(windows))]
        assert_eq!(error.to_string(), "path must reference a regular file");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_file_and_directory_components() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new();
        let target = temp.path("target");
        fs::write(&target, b"secret").expect("write target");
        let file_link = temp.path("file-link");
        symlink(&target, &file_link).expect("create file symlink");

        let error =
            read_bounded_regular_file(&file_link, 64).expect_err("symlinked file must reject");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let directory = temp.path("directory");
        fs::create_dir(&directory).expect("create directory");
        fs::write(directory.join("nested"), b"secret").expect("write nested target");
        let directory_link = temp.path("directory-link");
        symlink(&directory, &directory_link).expect("create directory symlink");

        let error = read_bounded_regular_file(&directory_link.join("nested"), 64)
            .expect_err("symlinked directory component must reject");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(windows)]
    #[test]
    fn rejects_symlinked_file_when_supported() {
        use std::os::windows::fs::symlink_file;

        let temp = TempDir::new();
        let target = temp.path("target");
        fs::write(&target, b"secret").expect("write target");
        let link = temp.path("file-link");
        if let Err(error) = symlink_file(&target, &link) {
            if matches!(
                error.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
            ) || error.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("create file symlink: {error}");
        }

        let error = read_bounded_regular_file(&link, 64).expect_err("symlink must reject");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
