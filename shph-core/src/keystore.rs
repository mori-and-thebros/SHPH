//! Keystore for identity and contact management.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::crypto::IdentityKeyPair;
use crate::error::{Result, ShphError};

/// Maximum accepted keystore file size on load. A keystore is a small JSON
/// document (identity keys + contacts); anything larger is almost certainly
/// malicious or corrupt, and capping it prevents an attacker from forcing a
/// huge allocation by pointing the loader at a giant file.
const MAX_KEYSTORE_BYTES: u64 = 1 << 20; // 1 MiB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub alias: String,
    pub endpoint: crate::net::Endpoint,
    pub pubkey_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeyStoreConfig {
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredKeyStore {
    identity_private_b64: String,
    identity_public_b64: String,
    /// Ed25519 signing seed. Absent in pre-v0.3 keystores; on load it falls
    /// back to the X25519 DH seed, so an upgraded old identity can still verify
    /// peers but should be re-`init`ed to obtain a distinct signing key.
    #[serde(default)]
    sign_seed_b64: Option<String>,
    contacts: HashMap<String, Contact>,
    config: KeyStoreConfig,
}

#[derive(Clone)]
pub struct KeyStore {
    pub identity: IdentityKeyPair,
    pub contacts: HashMap<String, Contact>,
    pub config: KeyStoreConfig,
}

impl KeyStore {
    pub fn new(config: KeyStoreConfig) -> Result<Self> {
        Ok(Self {
            identity: IdentityKeyPair::generate()?,
            contacts: HashMap::new(),
            config,
        })
    }

    pub fn fingerprint_hex(&self) -> String {
        self.identity.fingerprint_hex()
    }

    pub fn public_key_b64(&self) -> String {
        self.identity.public_key_b64()
    }

    pub fn add_contact(&mut self, contact: Contact) {
        self.contacts.insert(contact.alias.clone(), contact);
    }

    /// Persist the keystore (including the private identity key) to `path`.
    ///
    /// The write is **atomic** (temp file in the same directory, fsync, then
    /// rename) so a crash mid-write cannot leave a truncated/corrupt key file,
    /// and the file is created with restrictive permissions (0600 on Unix) so
    /// the private key is not world/group-readable.
    pub fn save(&self, path: &Path) -> Result<()> {
        let stored = StoredKeyStore {
            identity_private_b64: self.identity.private_key_b64(),
            identity_public_b64: self.identity.public_key_b64(),
            sign_seed_b64: Some(self.identity.signing_seed_b64()),
            contacts: self.contacts.clone(),
            config: self.config.clone(),
        };
        let data = serde_json::to_string_pretty(&stored)?;
        atomic_secret_write(path, data.as_bytes())
    }

    pub fn load(path: &Path, password: Option<&str>) -> Result<Self> {
        // Refuse to load a keystore whose permissions are too permissive on
        // Unix: a private key readable by group/other is a secret-hygiene
        // failure. We still load it but only after the operator fixes perms;
        // failing closed here is safer than silently using a leaky key file.
        assert_secret_file_perms(path)?;

        // Bound the read: a keystore is tiny; reject anything oversized to
        // avoid a hostile/giant file forcing a large allocation.
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        if len > MAX_KEYSTORE_BYTES {
            return Err(ShphError::InvalidArgument(format!(
                "keystore file too large ({len} bytes > {}); refusing to load",
                MAX_KEYSTORE_BYTES
            )));
        }
        // Also seek-check against a stream that lies about metadata.
        let mut limited = file.take(MAX_KEYSTORE_BYTES);
        let mut buf = Vec::new();
        limited.read_to_end(&mut buf)?;
        let contents = String::from_utf8(buf)
            .map_err(|_| ShphError::InvalidArgument("keystore is not valid UTF-8".into()))?;
        let stored: StoredKeyStore = serde_json::from_str(&contents)?;

        let mut config = stored.config;
        if config.password.is_none() {
            config.password = password.map(ToOwned::to_owned);
        }
        let identity = match &stored.sign_seed_b64 {
            Some(seed_b64) => {
                let dh_seed = base64_decode_32(&stored.identity_private_b64, "identity private")?;
                let sign_seed = base64_decode_32(seed_b64, "signing seed")?;
                let id = IdentityKeyPair::from_seeds(dh_seed, sign_seed);
                // Verify the stored X25519 public key matches.
                let stored_pub = base64_decode_32(&stored.identity_public_b64, "identity public")?;
                if id.public_key_bytes() != stored_pub {
                    return Err(ShphError::Crypto(
                        "public key does not match private key".into(),
                    ));
                }
                id
            }
            None => IdentityKeyPair::from_base64(
                &stored.identity_private_b64,
                Some(&stored.identity_public_b64),
            )?,
        };
        Ok(Self {
            identity,
            contacts: stored.contacts,
            config,
        })
    }
}

/// Atomically write secret bytes to `path` with restrictive permissions.
///
/// Writes to a temp file beside `path`, fsyncs, sets 0600 perms on Unix, then
/// renames over the target. This avoids a partial/corrupt key file on crash
/// and keeps the private key from being world/group-readable.
fn atomic_secret_write(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir)?;

    let (mut tmp, tmp_path) = create_temp_file(&dir, path)?;
    restrict_secret_perms(&tmp_path)?;
    tmp.write_all(data)?;
    tmp.sync_all()?;
    drop(tmp);

    persist_over(path, &tmp_path)
}

/// Create an exclusively-named temp file beside the target and return both the
/// handle and its path (so the rename step uses the exact same path).
fn create_temp_file(dir: &Path, target: &Path) -> Result<(File, PathBuf)> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let base = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("keystore");
    let tmp_path = dir.join(format!(".{base}.tmp.{pid}.{nanos}"));
    let file = File::create(&tmp_path)
        .map_err(|e| ShphError::Io(io::Error::other(format!("temp create failed: {e}"))))?;
    Ok((file, tmp_path))
}

/// Cross-platform persist: rename on Unix, copy+remove on Windows (rename over
/// an existing file is not atomic on all Windows filesystems).
fn persist_over(target: &Path, tmp: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::fs::rename(tmp, target)?;
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::remove_file(target);
        std::fs::copy(tmp, target)?;
        let _ = std::fs::remove_file(tmp);
    }
    Ok(())
}

/// On Unix, set the file mode to 0600 (owner read/write only). No-op on
/// non-Unix targets (file ACLs are the operator's responsibility there).
fn restrict_secret_perms(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// On Unix, fail if the keystore file is readable or writable by group/other.
/// This is a defensive check: a private key sitting in a 0644 file is a leak.
fn assert_secret_file_perms(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(ShphError::InvalidArgument(format!(
                "keystore file is group/other accessible (mode {mode:o}); refusing to load a leaky key file"
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Decode a base64 string into exactly 32 bytes.
fn base64_decode_32(b64: &str, label: &str) -> Result<[u8; 32]> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|_| ShphError::Crypto(format!("invalid {label} base64")))?;
    raw.try_into()
        .map_err(|_| ShphError::Crypto(format!("{label} must be 32 bytes")))
}

pub fn compute_fingerprint_hex(public_key_raw: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"shph-fingerprint-v1");
    hasher.update(public_key_raw);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_then_load_roundtrips() {
        let dir = std::env::temp_dir().join(format!(
            "shph-ks-rt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keystore.json");
        let ks = KeyStore::new(KeyStoreConfig::default()).unwrap();
        ks.save(&path).unwrap();
        let loaded = KeyStore::load(&path, None).unwrap();
        assert_eq!(
            ks.identity.public_key_b64(),
            loaded.identity.public_key_b64()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn save_creates_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "shph-ks-perm-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keystore.json");
        let ks = KeyStore::new(KeyStoreConfig::default()).unwrap();
        ks.save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "keystore must be owner-only (0600), got {mode:o}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_world_readable_key_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "shph-ks-leak-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keystore.json");
        let ks = KeyStore::new(KeyStoreConfig::default()).unwrap();
        ks.save(&path).unwrap();
        // Deliberately loosen perms to world-readable; load must refuse.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let res = KeyStore::load(&path, None);
        assert!(
            res.is_err(),
            "load must reject a group/other-readable keystore"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_rejects_oversized_file() {
        let dir = std::env::temp_dir().join(format!(
            "shph-ks-big-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keystore.json");
        // Write a file larger than MAX_KEYSTORE_BYTES.
        let junk = vec![b' '; (MAX_KEYSTORE_BYTES + 1) as usize];
        std::fs::write(&path, &junk).unwrap();
        let res = KeyStore::load(&path, None);
        assert!(
            res.is_err(),
            "load must reject a keystore larger than the cap"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_does_not_leave_temp_file_behind() {
        let dir = std::env::temp_dir().join(format!(
            "shph-ks-tmp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keystore.json");
        let ks = KeyStore::new(KeyStoreConfig::default()).unwrap();
        ks.save(&path).unwrap();
        // After a successful atomic save, no .tmp sibling should remain.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".tmp."))
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
