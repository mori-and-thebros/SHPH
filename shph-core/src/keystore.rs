//! Keystore for identity and contact management.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::crypto::IdentityKeyPair;
use crate::error::{Result, ShphError};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

/// Maximum accepted keystore file size on load. A keystore is a small JSON
/// document (identity keys + contacts); anything larger is almost certainly
/// malicious or corrupt, and capping it prevents an attacker from forcing a
/// huge allocation by pointing the loader at a giant file.
const MAX_KEYSTORE_BYTES: u64 = 1 << 20; // 1 MiB
const KEYSTORE_FORMAT_VERSION: u8 = 1;
const KEYSTORE_PBKDF2_ITERATIONS: u32 = 600_000;
const KEYSTORE_MIN_PBKDF2_ITERATIONS: u32 = 100_000;
const KEYSTORE_MAX_PBKDF2_ITERATIONS: u32 = 1_000_000;
const KEYSTORE_SALT_BYTES: usize = 16;
const KEYSTORE_NONCE_BYTES: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub alias: String,
    pub endpoint: crate::net::Endpoint,
    pub pubkey_b64: String,
    /// Ed25519 signing public key pinned for handshake authentication.
    ///
    /// This is optional only at the serialization boundary so older
    /// keystores can be read and then rejected by the peer-policy gate until
    /// their contacts are upgraded.
    #[serde(default)]
    pub sign_pubkey_b64: Option<String>,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, Default, zeroize::Zeroize, zeroize::ZeroizeOnDrop,
)]
pub struct KeyStoreConfig {
    /// Reserved for a future encrypted keystore format. It is intentionally
    /// not serialized because the current format does not encrypt secrets.
    #[serde(skip)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct StoredKeyStore {
    identity_private_b64: String,
    identity_public_b64: String,
    /// Ed25519 signing seed. Absent in pre-v0.3 keystores; on load it falls
    /// back to the X25519 DH seed, so an upgraded old identity can still verify
    /// peers but should be re-`init`ed to obtain a distinct signing key.
    #[serde(default)]
    sign_seed_b64: Option<String>,
    #[zeroize(skip)]
    contacts: HashMap<String, Contact>,
    config: KeyStoreConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct StoredEncryptedKeyStore {
    format: String,
    version: u8,
    kdf: String,
    iterations: u32,
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

#[derive(Clone)]
pub struct KeyStore {
    pub identity: IdentityKeyPair,
    pub contacts: HashMap<String, Contact>,
    pub config: KeyStoreConfig,
}

impl KeyStore {
    pub fn new(config: KeyStoreConfig) -> Result<Self> {
        let mut config = config;
        if config.password.is_none() {
            config.password = std::env::var("SHPH_KEYSTORE_PASSWORD").ok();
        }
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
        let data = if let Some(password) = self.config.password.as_deref() {
            if password.is_empty() {
                return Err(ShphError::KeyStore(
                    "keystore password cannot be empty".into(),
                ));
            }
            Zeroizing::new(serde_json::to_vec_pretty(&encrypt_keystore(
                &stored, password,
            )?)?)
        } else {
            Zeroizing::new(serde_json::to_vec_pretty(&stored)?)
        };
        atomic_secret_write(path, &data)
    }

    pub fn load(path: &Path, password: Option<&str>) -> Result<Self> {
        // Refuse to load a keystore whose permissions are too permissive on
        // Unix: a private key readable by group/other is a secret-hygiene
        // failure. We still load it but only after the operator fixes perms;
        // failing closed here is safer than silently using a leaky key file.
        assert_secret_file_perms(path)?;

        // Bound the read: a keystore is tiny; reject anything oversized to
        // avoid a hostile/giant file forcing a large allocation.
        let file = open_keystore_readonly(path)?;
        let len = file.metadata()?.len();
        if len > MAX_KEYSTORE_BYTES {
            return Err(ShphError::InvalidArgument(format!(
                "keystore file too large ({len} bytes > {}); refusing to load",
                MAX_KEYSTORE_BYTES
            )));
        }
        // Also seek-check against a stream that lies about metadata.
        let mut limited = file.take(MAX_KEYSTORE_BYTES);
        let mut buf = Zeroizing::new(Vec::new());
        limited.read_to_end(&mut buf)?;
        let contents = Zeroizing::new(
            String::from_utf8(std::mem::take(&mut *buf))
                .map_err(|_| ShphError::InvalidArgument("keystore is not valid UTF-8".into()))?,
        );
        let value: serde_json::Value = serde_json::from_str(&contents)?;
        let stored: StoredKeyStore = if value.get("format").and_then(serde_json::Value::as_str)
            == Some("shph-encrypted-keystore")
        {
            let encrypted: StoredEncryptedKeyStore = serde_json::from_value(value)?;
            let env_password = std::env::var("SHPH_KEYSTORE_PASSWORD").ok();
            let password = password.or(env_password.as_deref()).ok_or_else(|| {
                ShphError::KeyStore(
                    "encrypted keystore requires SHPH_KEYSTORE_PASSWORD or an explicit password"
                        .into(),
                )
            })?;
            decrypt_keystore(&encrypted, password)?
        } else {
            serde_json::from_value(value)?
        };

        let mut stored = stored;
        let mut config = std::mem::take(&mut stored.config);
        let stored_password = config.password.take();
        config.password = password
            .map(ToOwned::to_owned)
            .or_else(|| std::env::var("SHPH_KEYSTORE_PASSWORD").ok())
            .or(stored_password);
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
        let contacts = std::mem::take(&mut stored.contacts);
        Ok(Self {
            identity,
            contacts,
            config,
        })
    }
}

fn encrypt_keystore(stored: &StoredKeyStore, password: &str) -> Result<StoredEncryptedKeyStore> {
    let plaintext = Zeroizing::new(serde_json::to_vec(stored)?);
    let mut salt = [0u8; KEYSTORE_SALT_BYTES];
    let mut nonce = [0u8; KEYSTORE_NONCE_BYTES];
    let rng = ring::rand::SystemRandom::new();
    ring::rand::SecureRandom::fill(&rng, &mut salt)?;
    ring::rand::SecureRandom::fill(&rng, &mut nonce)?;
    let key = derive_keystore_key(password, &salt, KEYSTORE_PBKDF2_ITERATIONS);
    let cipher =
        ChaCha20Poly1305::new_from_slice(&*key).map_err(|e| ShphError::Crypto(e.to_string()))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: b"shph-encrypted-keystore-v1",
            },
        )
        .map_err(|_| ShphError::KeyStore("keystore encryption failed".into()))?;
    Ok(StoredEncryptedKeyStore {
        format: "shph-encrypted-keystore".into(),
        version: KEYSTORE_FORMAT_VERSION,
        kdf: "pbkdf2-hmac-sha256".into(),
        iterations: KEYSTORE_PBKDF2_ITERATIONS,
        salt_b64: base64::engine::general_purpose::STANDARD.encode(salt),
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce),
        ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(ciphertext),
    })
}

fn decrypt_keystore(encrypted: &StoredEncryptedKeyStore, password: &str) -> Result<StoredKeyStore> {
    if encrypted.version != KEYSTORE_FORMAT_VERSION
        || encrypted.format != "shph-encrypted-keystore"
        || encrypted.kdf != "pbkdf2-hmac-sha256"
        || encrypted.iterations < KEYSTORE_MIN_PBKDF2_ITERATIONS
        || encrypted.iterations > KEYSTORE_MAX_PBKDF2_ITERATIONS
    {
        return Err(ShphError::KeyStore(
            "unsupported encrypted keystore format".into(),
        ));
    }
    let salt = decode_exact(&encrypted.salt_b64, KEYSTORE_SALT_BYTES, "keystore salt")?;
    let nonce = decode_exact(&encrypted.nonce_b64, KEYSTORE_NONCE_BYTES, "keystore nonce")?;
    let ciphertext = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(encrypted.ciphertext_b64.as_bytes())
            .map_err(|_| ShphError::KeyStore("invalid keystore ciphertext".into()))?,
    );
    let key = derive_keystore_key(password, &salt, encrypted.iterations);
    let cipher =
        ChaCha20Poly1305::new_from_slice(&*key).map_err(|e| ShphError::Crypto(e.to_string()))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: b"shph-encrypted-keystore-v1",
                },
            )
            .map_err(|_| ShphError::KeyStore("invalid keystore password or ciphertext".into()))?,
    );
    serde_json::from_slice(&plaintext).map_err(ShphError::Serialization)
}

fn derive_keystore_key(password: &str, salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(iterations.max(1)).unwrap_or(NonZeroU32::MIN),
        salt,
        password.as_bytes(),
        &mut *key,
    );
    key
}

fn decode_exact(value: &str, expected: usize, label: &str) -> Result<Zeroizing<Vec<u8>>> {
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(value.as_bytes())
            .map_err(|_| ShphError::KeyStore(format!("invalid {label} base64")))?,
    );
    if decoded.len() != expected {
        return Err(ShphError::KeyStore(format!(
            "{label} must be {expected} bytes"
        )));
    }
    Ok(decoded)
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

    if let Err(err) = persist_over(path, &tmp_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }
    Ok(())
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
    for attempt in 0..32 {
        let tmp_path = dir.join(format!(".{base}.tmp.{pid}.{nanos}.{attempt}"));
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)
        {
            Ok(file) => return Ok((file, tmp_path)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(ShphError::Io(err)),
        }
    }
    Err(ShphError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "unable to allocate a unique keystore temp file",
    )))
}

fn open_keystore_readonly(path: &Path) -> Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(ShphError::Io)
    }
    #[cfg(not(unix))]
    {
        ensure_not_reparse_point(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(ShphError::InvalidArgument(
                "refusing to load a symlinked keystore".into(),
            ));
        }
        File::open(path).map_err(ShphError::Io)
    }
}

pub fn ensure_not_reparse_point(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
        };
        let path = wide_path(path)?;
        let attributes = unsafe { GetFileAttributesW(path.as_ptr()) };
        if attributes == INVALID_FILE_ATTRIBUTES {
            return Err(windows_error("GetFileAttributesW"));
        }
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ShphError::InvalidArgument(
                "refusing to access a Windows reparse point".into(),
            ));
        }
    }
    #[cfg(not(windows))]
    {
        let _ = path;
    }
    Ok(())
}

/// Cross-platform persist with crash-safe replacement semantics.
fn persist_over(target: &Path, tmp: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::fs::rename(tmp, target)?;
    }
    #[cfg(not(unix))]
    {
        persist_over_windows(target, tmp)?;
    }
    Ok(())
}

/// Set owner-only permissions on the target platform, failing closed if the
/// platform-specific operation fails.
fn restrict_secret_perms(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        restrict_secret_perms_windows(path)?;
    }
    Ok(())
}

pub fn enforce_owner_only_file_permissions(path: &Path) -> Result<()> {
    restrict_secret_perms(path)
}

/// Reject secret files whose platform permissions are not enforceable.
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
        assert_secret_file_perms_windows(path)?;
    }
    Ok(())
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(ShphError::InvalidArgument(
            "keystore path contains an embedded NUL".into(),
        ));
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(windows)]
fn windows_error(operation: &str) -> ShphError {
    use windows_sys::Win32::Foundation::GetLastError;
    ShphError::Io(io::Error::other(format!(
        "{operation} failed with Win32 error {}",
        unsafe { GetLastError() }
    )))
}

#[cfg(windows)]
fn restrict_secret_perms_windows(path: &Path) -> Result<()> {
    use windows_sys::core::BOOL;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    let path = wide_path(path)?;
    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)\0".encode_utf16().collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut descriptor_size = 0u32;
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            &mut descriptor_size,
        )
    };
    if ok == 0 {
        return Err(windows_error(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        ));
    }
    let mut dacl_present: BOOL = 0;
    let mut dacl_defaulted: BOOL = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let extracted = unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    };
    if extracted == 0 || dacl_present == 0 || dacl.is_null() {
        unsafe {
            LocalFree(descriptor as _);
        }
        return Err(windows_error("GetSecurityDescriptorDacl"));
    }
    let result = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    unsafe {
        LocalFree(descriptor as _);
    }
    if result != ERROR_SUCCESS {
        return Err(ShphError::Io(io::Error::from_raw_os_error(result as i32)));
    }
    Ok(())
}

#[cfg(windows)]
fn assert_secret_file_perms_windows(path: &Path) -> Result<()> {
    // Reassert the exact owner-only DACL on every load. This avoids trusting
    // inherited or operator-modified permissions and fails closed if Windows
    // cannot apply the protection.
    restrict_secret_perms_windows(path)
}

#[cfg(windows)]
fn persist_over_windows(target: &Path, tmp: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        REPLACEFILE_WRITE_THROUGH,
    };

    let target_w = wide_path(target)?;
    let tmp_w = wide_path(tmp)?;
    let result = if target.exists() {
        unsafe {
            ReplaceFileW(
                target_w.as_ptr(),
                tmp_w.as_ptr(),
                std::ptr::null(),
                REPLACEFILE_WRITE_THROUGH,
                std::ptr::null(),
                std::ptr::null(),
            )
        }
    } else {
        unsafe {
            MoveFileExW(
                tmp_w.as_ptr(),
                target_w.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
    };
    if result == 0 {
        return Err(windows_error("atomic keystore replacement"));
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

    #[cfg(windows)]
    #[test]
    fn windows_acl_protected_keystore_roundtrips() {
        let dir =
            std::env::temp_dir().join(format!("shph-keystore-windows-acl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keystore.json");
        let keystore = KeyStore::new(KeyStoreConfig::default()).unwrap();
        keystore.save(&path).unwrap();
        let loaded = KeyStore::load(&path, None).unwrap();
        assert_eq!(
            keystore.identity.public_key_b64(),
            loaded.identity.public_key_b64()
        );
        std::fs::remove_dir_all(dir).unwrap();
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

    #[test]
    fn encrypted_keystore_requires_correct_password() {
        let dir = std::env::temp_dir().join(format!(
            "shph-ks-encrypted-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keystore.json");
        let ks = KeyStore::new(KeyStoreConfig {
            password: Some("correct horse battery staple".into()),
        })
        .unwrap();
        ks.save(&path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("shph-encrypted-keystore"));
        assert!(KeyStore::load(&path, Some("wrong")).is_err());
        let loaded = KeyStore::load(&path, Some("correct horse battery staple")).unwrap();
        assert_eq!(loaded.public_key_b64(), ks.public_key_b64());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_final_component_symlink() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!(
            "shph-ks-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real.json");
        let link = dir.join("keystore.json");
        let ks = KeyStore::new(KeyStoreConfig::default()).unwrap();
        ks.save(&target).unwrap();
        symlink(&target, &link).unwrap();

        assert!(KeyStore::load(&link, None).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn encrypted_keystore_rejects_unsafe_iteration_count() {
        let dir = std::env::temp_dir().join(format!(
            "shph-ks-iterations-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keystore.json");
        let ks = KeyStore::new(KeyStoreConfig {
            password: Some("correct horse battery staple".into()),
        })
        .unwrap();
        ks.save(&path).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        value["iterations"] = serde_json::Value::from(KEYSTORE_MAX_PBKDF2_ITERATIONS + 1);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();

        assert!(KeyStore::load(&path, Some("correct horse battery staple")).is_err());
        std::fs::remove_dir_all(dir).ok();
    }
}
