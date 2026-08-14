use sha2::{Digest, Sha256};
use shph_core::{Result, ShphError};
use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::slice;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    CloseHandle, FreeLibrary, GetLastError, FARPROC, HANDLE, HMODULE,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
    LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, WaitForSingleObject,
};

const WINTUN_DLL: &str = "wintun.dll";
const WINTUN_SHA256_ENV: &str = "SHPH_WINTUN_SHA256";
const WINTUN_TUNNEL_TYPE: &str = "SHPH";
const MAX_WINTUN_DLL_BYTES: u64 = 64 * 1024 * 1024;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const WAIT_FAILED: u32 = u32::MAX;

pub type WintunAdapterHandle = *mut c_void;
pub type WintunSessionHandle = *mut c_void;

pub type WintunCreateAdapter =
    unsafe extern "system" fn(*const u16, *const u16, *const GUID) -> WintunAdapterHandle;
pub type WintunCloseAdapter = unsafe extern "system" fn(WintunAdapterHandle);
pub type WintunStartSession =
    unsafe extern "system" fn(WintunAdapterHandle, u32) -> WintunSessionHandle;
pub type WintunEndSession = unsafe extern "system" fn(WintunSessionHandle);
pub type WintunGetReadWaitEvent = unsafe extern "system" fn(WintunSessionHandle) -> HANDLE;
pub type WintunReceivePacket = unsafe extern "system" fn(WintunSessionHandle, *mut u32) -> *mut u8;
pub type WintunReleaseReceivePacket = unsafe extern "system" fn(WintunSessionHandle, *const u8);
pub type WintunAllocateSendPacket = unsafe extern "system" fn(WintunSessionHandle, u32) -> *mut u8;
pub type WintunSendPacket = unsafe extern "system" fn(WintunSessionHandle, *const u8);

const WINTUN_MIN_RING_CAPACITY: u32 = 128 * 1024;
const WINTUN_MAX_RING_CAPACITY: u32 = 64 * 1024 * 1024;
const WINTUN_DEFAULT_RING_CAPACITY: u32 = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct WintunApi {
    module: HMODULE,
    path: PathBuf,
    pub create_adapter: WintunCreateAdapter,
    pub close_adapter: WintunCloseAdapter,
    pub start_session: WintunStartSession,
    pub end_session: WintunEndSession,
    pub get_read_wait_event: WintunGetReadWaitEvent,
    pub receive_packet: WintunReceivePacket,
    pub release_receive_packet: WintunReleaseReceivePacket,
    pub allocate_send_packet: WintunAllocateSendPacket,
    pub send_packet: WintunSendPacket,
}

impl WintunApi {
    pub fn load_default() -> Result<Self> {
        Self::load(Path::new(WINTUN_DLL))
    }

    pub fn load(path: &Path) -> Result<Self> {
        validate_runtime_path(path)?;
        let application_path = application_local_runtime_path(path)?;
        verify_runtime_hash(&application_path)?;
        if !is_process_elevated()? {
            return Err(ShphError::PermissionDenied(
                "Administrator elevation is required before loading Wintun".into(),
            ));
        }

        let wide_path = wide_null(application_path.as_os_str().to_string_lossy().as_ref())?;
        let flags = LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32;
        // SAFETY: `wide_path` is a NUL-terminated UTF-16 string owned for
        // the duration of this call. The flags restrict DLL resolution to the
        // application and system directories.
        let module = unsafe { LoadLibraryExW(wide_path.as_ptr(), null_mut(), flags) };
        if module.is_null() {
            return Err(ShphError::Unsupported(format!(
                "unable to load Wintun runtime '{}': Win32 error {}",
                application_path.display(),
                // SAFETY: GetLastError is read immediately after the failed
                // LoadLibraryExW call.
                unsafe { GetLastError() }
            )));
        }

        // SAFETY: `module` is a live library handle returned by
        // LoadLibraryExW. `from_module` either takes ownership or returns an
        // error, in which case this function frees the handle below.
        let result = unsafe { Self::from_module(module, application_path) };
        if result.is_err() {
            // SAFETY: `module` was returned by LoadLibraryExW and remains
            // owned by this error path.
            unsafe {
                FreeLibrary(module);
            }
        }
        result
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    unsafe fn from_module(module: HMODULE, path: PathBuf) -> Result<Self> {
        // SAFETY: The caller guarantees that `module` is a live library
        // handle. Each requested export is converted to its exact Wintun ABI
        // function-pointer type by `load_symbol`.
        Ok(Self {
            module,
            path,
            create_adapter: load_symbol(module, b"WintunCreateAdapter\0")?,
            close_adapter: load_symbol(module, b"WintunCloseAdapter\0")?,
            start_session: load_symbol(module, b"WintunStartSession\0")?,
            end_session: load_symbol(module, b"WintunEndSession\0")?,
            get_read_wait_event: load_symbol(module, b"WintunGetReadWaitEvent\0")?,
            receive_packet: load_symbol(module, b"WintunReceivePacket\0")?,
            release_receive_packet: load_symbol(module, b"WintunReleaseReceivePacket\0")?,
            allocate_send_packet: load_symbol(module, b"WintunAllocateSendPacket\0")?,
            send_packet: load_symbol(module, b"WintunSendPacket\0")?,
        })
    }
}

impl Drop for WintunApi {
    fn drop(&mut self) {
        if !self.module.is_null() {
            // SAFETY: `module` is a live library handle owned by this object
            // and Drop runs at most once.
            unsafe {
                FreeLibrary(self.module);
            }
        }
    }
}

#[derive(Debug)]
pub struct WintunRuntime {
    api: WintunApi,
    adapter: WintunAdapterHandle,
    session: WintunSessionHandle,
    read_wait_event: HANDLE,
    ring_capacity: u32,
}

// Wintun handles are opaque OS resources that may move between worker threads.
// TunDevice serializes shared access with a Mutex; concurrent access is not
// assumed at this FFI boundary.
unsafe impl Send for WintunRuntime {}

impl WintunRuntime {
    pub fn open(name: &str) -> Result<Self> {
        Self::open_with_capacity(name, WINTUN_DEFAULT_RING_CAPACITY)
    }

    pub fn open_with_capacity(name: &str, ring_capacity: u32) -> Result<Self> {
        validate_adapter_name(name)?;
        validate_ring_capacity(ring_capacity)?;
        let api = WintunApi::load_default()?;
        let adapter_name = wide_null(name)?;
        let tunnel_type = wide_null(WINTUN_TUNNEL_TYPE)?;
        // SAFETY: Both UTF-16 strings are NUL-terminated and remain alive for
        // the duration of the call. A null GUID requests a generated GUID.
        let adapter =
            unsafe { (api.create_adapter)(adapter_name.as_ptr(), tunnel_type.as_ptr(), null()) };
        if adapter.is_null() {
            return Err(ShphError::PermissionDenied(format!(
                "WintunCreateAdapter failed for '{name}': Win32 error {}",
                // SAFETY: GetLastError is read immediately after the failed
                // WintunCreateAdapter call.
                unsafe { GetLastError() }
            )));
        }

        // SAFETY: `adapter` is the non-null handle returned above and
        // `ring_capacity` has been checked against the configured bounds.
        let session = unsafe { (api.start_session)(adapter, ring_capacity) };
        if session.is_null() {
            // SAFETY: `adapter` is owned by this failure path and has not been
            // closed elsewhere.
            unsafe {
                (api.close_adapter)(adapter);
            }
            return Err(ShphError::Tun(format!(
                "WintunStartSession failed for '{name}': Win32 error {}",
                // SAFETY: GetLastError is read immediately after the failed
                // WintunStartSession call.
                unsafe { GetLastError() }
            )));
        }

        // SAFETY: `session` is the non-null handle returned by
        // WintunStartSession and remains owned by the returned runtime.
        let read_wait_event = unsafe { (api.get_read_wait_event)(session) };
        if read_wait_event.is_null() {
            // SAFETY: Both handles are owned by this failure path; Wintun
            // requires ending the session before closing its adapter.
            unsafe {
                (api.end_session)(session);
                (api.close_adapter)(adapter);
            }
            return Err(ShphError::Tun(
                "WintunGetReadWaitEvent returned a null event handle".into(),
            ));
        }

        Ok(Self {
            api,
            adapter,
            session,
            read_wait_event,
            ring_capacity,
        })
    }

    pub fn read_wait_event(&self) -> HANDLE {
        self.read_wait_event
    }

    pub fn ring_capacity(&self) -> u32 {
        self.ring_capacity
    }

    pub fn ring_capacity_bounds() -> (u32, u32) {
        (WINTUN_MIN_RING_CAPACITY, WINTUN_MAX_RING_CAPACITY)
    }

    pub fn session_handle(&self) -> WintunSessionHandle {
        self.session
    }

    pub fn wait_for_packet(&self) -> Result<()> {
        // SAFETY: `read_wait_event` is the live event handle returned by
        // WintunGetReadWaitEvent for this runtime.
        let status = unsafe { WaitForSingleObject(self.read_wait_event, 100) };
        let last_error = if status == WAIT_FAILED {
            // SAFETY: GetLastError is read immediately after the failed
            // WaitForSingleObject call.
            unsafe { GetLastError() }
        } else {
            0
        };
        classify_wait_status(status, last_error)
    }

    pub fn try_receive_packet(&self) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
        let mut packet_size = 0u32;
        // SAFETY: `self.session` is a live Wintun session and
        // `packet_size` points to writable storage for the returned length.
        let packet = unsafe { (self.api.receive_packet)(self.session, &mut packet_size) };
        if packet.is_null() {
            // SAFETY: GetLastError is read immediately after the failed
            // WintunReceivePacket call.
            let error = unsafe { GetLastError() };
            if error == ERROR_NO_MORE_ITEMS {
                return Ok(None);
            }
            return Err(ShphError::Tun(format!(
                "WintunReceivePacket failed: Win32 error {error}"
            )));
        }

        let result = if packet_size == 0 {
            Err(ShphError::Tun(
                "WintunReceivePacket returned an empty packet".into(),
            ))
        } else if packet_size as usize > crate::MAX_TUN_PACKET_BYTES {
            Err(ShphError::Tun(format!(
                "Wintun packet exceeds the {}-byte safety limit",
                crate::MAX_TUN_PACKET_BYTES
            )))
        } else {
            // SAFETY: Wintun guarantees that the returned pointer references
            // `packet_size` readable bytes until ReleaseReceivePacket is
            // called. The copy completes before that release.
            let bytes = zeroize::Zeroizing::new(unsafe {
                slice::from_raw_parts(packet, packet_size as usize).to_vec()
            });
            match crate::validate_ip_packet(&bytes) {
                Ok(()) => Ok(Some(bytes)),
                Err(error) => Err(error),
            }
        };

        // SAFETY: `packet` is the exact pointer returned by
        // WintunReceivePacket for this live session and has not been released.
        unsafe {
            (self.api.release_receive_packet)(self.session, packet);
        }
        result
    }

    pub fn send_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() {
            return Err(ShphError::Tun("Wintun packet cannot be empty".into()));
        }
        if packet.len() > crate::MAX_TUN_PACKET_BYTES {
            return Err(ShphError::Tun(format!(
                "Wintun packet exceeds the {}-byte safety limit",
                crate::MAX_TUN_PACKET_BYTES
            )));
        }
        crate::validate_ip_packet(packet)?;

        // SAFETY: `self.session` is live and the requested allocation length
        // is bounded by the platform packet limit.
        let destination =
            unsafe { (self.api.allocate_send_packet)(self.session, packet.len() as u32) };
        if destination.is_null() {
            // SAFETY: GetLastError is read immediately after the failed
            // WintunAllocateSendPacket call.
            let error = unsafe { GetLastError() };
            if error == ERROR_BUFFER_OVERFLOW {
                return Err(ShphError::ResourceExhausted(
                    "Wintun send ring is full".into(),
                ));
            }
            return Err(ShphError::Tun(format!(
                "WintunAllocateSendPacket failed: Win32 error {error}"
            )));
        }

        // SAFETY: `destination` points to an allocation of at least
        // `packet.len()` writable bytes owned by this Wintun session, and the
        // source slice is valid for exactly that length.
        unsafe {
            std::ptr::copy_nonoverlapping(packet.as_ptr(), destination, packet.len());
        }
        // SAFETY: `destination` is the allocation returned above and is
        // committed exactly once to the same live session.
        unsafe {
            (self.api.send_packet)(self.session, destination as *const u8);
        }
        Ok(())
    }
}

impl Drop for WintunRuntime {
    fn drop(&mut self) {
        // SAFETY: The session and adapter are live handles owned by this
        // runtime; Wintun requires ending the session before closing adapter.
        unsafe {
            (self.api.end_session)(self.session);
            (self.api.close_adapter)(self.adapter);
        }
    }
}

fn validate_adapter_name(name: &str) -> Result<()> {
    let utf16_len = name.encode_utf16().count();
    if name.is_empty()
        || utf16_len > 255
        || name.trim() != name
        || name.contains('\0')
        || name.chars().any(char::is_control)
    {
        return Err(ShphError::InvalidArgument(
            "Wintun adapter name must be 1..=255 UTF-16 code units with no surrounding whitespace, null bytes, or control characters"
                .into(),
        ));
    }
    Ok(())
}

fn validate_runtime_path(path: &Path) -> Result<()> {
    let file_name = path.file_name().and_then(|value| value.to_str());
    if path.components().count() != 1
        || !file_name.is_some_and(|value| value.eq_ignore_ascii_case(WINTUN_DLL))
    {
        return Err(ShphError::InvalidArgument(
            "Wintun runtime path must be the application-local filename 'wintun.dll'".into(),
        ));
    }
    Ok(())
}

fn application_local_runtime_path(path: &Path) -> Result<PathBuf> {
    let executable = std::env::current_exe().map_err(|error| {
        ShphError::Unsupported(format!(
            "unable to resolve the application directory for Wintun: {error}"
        ))
    })?;
    let application_dir = executable.parent().ok_or_else(|| {
        ShphError::Unsupported("current executable has no application directory".into())
    })?;
    let runtime = application_dir.join(path);
    shph_core::ensure_not_reparse_point(application_dir)?;
    shph_core::ensure_not_reparse_point(&runtime)?;
    Ok(runtime)
}

fn verify_runtime_hash(path: &Path) -> Result<()> {
    let expected_text = std::env::var(WINTUN_SHA256_ENV).map_err(|_| {
        ShphError::Config(format!(
            "{WINTUN_SHA256_ENV} must be set to the expected SHA-256 of the application-local {WINTUN_DLL}"
        ))
    })?;
    let expected = parse_sha256_hex(&expected_text)?;

    let file = File::open(path).map_err(ShphError::Io)?;
    let metadata = file.metadata().map_err(ShphError::Io)?;
    if !metadata.file_type().is_file() {
        return Err(ShphError::Unsupported(
            "application-local Wintun runtime is not a regular file".into(),
        ));
    }
    if metadata.len() > MAX_WINTUN_DLL_BYTES {
        return Err(ShphError::ResourceExhausted(format!(
            "Wintun runtime exceeds the {}-byte hash safety limit",
            MAX_WINTUN_DLL_BYTES
        )));
    }

    let mut reader = file.take(MAX_WINTUN_DLL_BYTES.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buffer).map_err(ShphError::Io)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > MAX_WINTUN_DLL_BYTES {
            return Err(ShphError::ResourceExhausted(format!(
                "Wintun runtime exceeds the {}-byte hash safety limit",
                MAX_WINTUN_DLL_BYTES
            )));
        }
        hasher.update(&buffer[..read]);
    }

    let actual = hasher.finalize();
    if actual.as_slice() != expected {
        return Err(ShphError::PermissionDenied(format!(
            "application-local Wintun SHA-256 does not match {WINTUN_SHA256_ENV}"
        )));
    }
    Ok(())
}

fn parse_sha256_hex(value: &str) -> Result<[u8; 32]> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ShphError::InvalidArgument(format!(
            "{WINTUN_SHA256_ENV} must be exactly 64 hexadecimal characters"
        )));
    }

    let mut decoded = [0u8; 32];
    for (index, slot) in decoded.iter_mut().enumerate() {
        let start = index * 2;
        *slot = u8::from_str_radix(&value[start..start + 2], 16).map_err(|_| {
            ShphError::InvalidArgument(format!(
                "{WINTUN_SHA256_ENV} contains invalid hexadecimal data"
            ))
        })?;
    }
    Ok(decoded)
}

fn validate_ring_capacity(capacity: u32) -> Result<()> {
    if !(WINTUN_MIN_RING_CAPACITY..=WINTUN_MAX_RING_CAPACITY).contains(&capacity) {
        return Err(ShphError::InvalidArgument(format!(
            "Wintun ring capacity must be between {WINTUN_MIN_RING_CAPACITY} and {WINTUN_MAX_RING_CAPACITY} bytes"
        )));
    }
    Ok(())
}

fn classify_wait_status(status: u32, last_error: u32) -> Result<()> {
    match status {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(ShphError::Timeout),
        WAIT_FAILED => Err(ShphError::Tun(format!(
            "Wintun read wait failed: Win32 error {last_error}"
        ))),
        other => Err(ShphError::Tun(format!(
            "Wintun read wait returned unexpected status {other}"
        ))),
    }
}

fn wide_null(value: &str) -> Result<Vec<u16>> {
    if value.contains('\0') {
        return Err(ShphError::InvalidArgument(
            "Wintun path/name cannot contain null bytes".into(),
        ));
    }
    Ok(value.encode_utf16().chain(std::iter::once(0)).collect())
}

fn is_process_elevated() -> Result<bool> {
    let mut token: HANDLE = null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle valid for this
    // process, and `token` is writable HANDLE storage.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 {
        return Err(ShphError::PermissionDenied(format!(
            "OpenProcessToken failed: Win32 error {}",
            // SAFETY: GetLastError is read immediately after the failed
            // OpenProcessToken call.
            unsafe { GetLastError() }
        )));
    }

    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    // SAFETY: `elevation` and `returned` are valid writable buffers with the
    // exact size supplied to GetTokenInformation; `token` has TOKEN_QUERY.
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut TOKEN_ELEVATION as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    // SAFETY: `token` was returned by OpenProcessToken and is closed exactly
    // once on this path.
    let close_result = unsafe { CloseHandle(token) };
    if close_result == 0 {
        return Err(ShphError::Internal(format!(
            "CloseHandle failed after token query: Win32 error {}",
            // SAFETY: GetLastError is read immediately after the failed
            // CloseHandle call.
            unsafe { GetLastError() }
        )));
    }
    if result == 0 {
        return Err(ShphError::PermissionDenied(format!(
            "GetTokenInformation failed: Win32 error {}",
            // SAFETY: GetLastError is read immediately after the failed
            // GetTokenInformation call.
            unsafe { GetLastError() }
        )));
    }
    Ok(elevation.TokenIsElevated != 0)
}

unsafe fn load_symbol<T>(module: HMODULE, name: &[u8]) -> Result<T> {
    // SAFETY: The caller supplies a live module handle and NUL-terminated
    // export name. Each call site requests the exact documented Wintun ABI
    // and calling convention.
    let symbol: FARPROC = GetProcAddress(module, name.as_ptr());
    let symbol = symbol.ok_or_else(|| {
        ShphError::Unsupported(format!(
            "Wintun runtime is missing required symbol '{}'",
            String::from_utf8_lossy(name).trim_end_matches('\0')
        ))
    })?;
    // SAFETY: T is one of the declared Wintun function-pointer types, all of
    // which have the same ABI-sized representation as FARPROC on Windows.
    Ok(std::mem::transmute_copy(&symbol))
}

#[cfg(test)]
mod tests {
    use shph_core::ShphError;
    use std::path::Path;

    use super::{
        classify_wait_status, parse_sha256_hex, validate_adapter_name, validate_ring_capacity,
        validate_runtime_path, wide_null, WAIT_FAILED, WAIT_TIMEOUT,
    };

    #[test]
    fn ring_capacity_is_bounded() {
        let (min, max) = super::WintunRuntime::ring_capacity_bounds();
        assert!(min <= super::WINTUN_DEFAULT_RING_CAPACITY);
        assert!(super::WINTUN_DEFAULT_RING_CAPACITY <= max);
        assert!(validate_ring_capacity(min).is_ok());
        assert!(validate_ring_capacity(max).is_ok());
        assert!(validate_ring_capacity(min - 1).is_err());
        assert!(validate_ring_capacity(max.saturating_add(1)).is_err());
    }

    #[test]
    fn adapter_names_are_bounded() {
        assert!(validate_adapter_name("SHPH").is_ok());
        assert!(validate_adapter_name("").is_err());
        assert!(validate_adapter_name(&"x".repeat(256)).is_err());
        assert!(validate_adapter_name(" bad").is_err());
        assert!(validate_adapter_name("bad\0name").is_err());
        assert!(validate_adapter_name("bad\nname").is_err());
        assert!(validate_adapter_name(&"😀".repeat(128)).is_err());
    }

    #[test]
    fn wide_strings_are_null_terminated() {
        assert_eq!(wide_null("wintun.dll").unwrap().last(), Some(&0));
        assert!(wide_null("bad\0name").is_err());
    }

    #[test]
    fn runtime_path_is_application_local_and_named_wintun() {
        assert!(validate_runtime_path(Path::new("wintun.dll")).is_ok());
        assert!(validate_runtime_path(Path::new("WINTUN.DLL")).is_ok());
        assert!(validate_runtime_path(Path::new("subdir/wintun.dll")).is_err());
        assert!(validate_runtime_path(Path::new("other.dll")).is_err());
    }

    #[test]
    fn wintun_hash_requires_exact_hex_sha256() {
        assert_eq!(parse_sha256_hex(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert_eq!(parse_sha256_hex(&"AB".repeat(32)).unwrap(), [0xab; 32]);
        assert!(parse_sha256_hex("").is_err());
        assert!(parse_sha256_hex(&"g".repeat(64)).is_err());
        assert!(parse_sha256_hex(&"a".repeat(63)).is_err());
    }

    #[test]
    fn wait_status_classification_is_explicit() {
        assert!(classify_wait_status(0, 0).is_ok());
        assert!(matches!(
            classify_wait_status(WAIT_TIMEOUT, 0),
            Err(ShphError::Timeout)
        ));
        assert!(matches!(
            classify_wait_status(WAIT_FAILED, 5),
            Err(ShphError::Tun(message)) if message.contains("error 5")
        ));
        assert!(matches!(
            classify_wait_status(0x80, 0),
            Err(ShphError::Tun(message)) if message.contains("unexpected status")
        ));
    }
}
