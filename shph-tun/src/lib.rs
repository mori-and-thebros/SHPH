//! TUN device abstraction for SHPH.
//!
//! Default behavior remains a safe stub for cross-platform developer flow.
//! On Linux, real TUN I/O can be enabled by setting `SHPH_TUN_NATIVE=1`.

use shph_core::{Result, ShphError};
#[cfg(target_os = "linux")]
use std::io::{ErrorKind, Read, Write};

#[derive(Debug)]
enum TunBackend {
    Stub,
    #[cfg(target_os = "linux")]
    Linux(std::fs::File),
}

#[derive(Debug)]
pub struct TunDevice {
    name: String,
    backend: TunBackend,
}

impl TunDevice {
    pub fn open(name: &str) -> Result<Self> {
        validate_tun_name(name)?;

        #[cfg(target_os = "linux")]
        {
            if std::env::var("SHPH_TUN_NATIVE").ok().as_deref() == Some("1") {
                return open_linux_tun(name);
            }
        }

        Ok(Self {
            name: name.to_string(),
            backend: TunBackend::Stub,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_native(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            matches!(self.backend, TunBackend::Linux(..))
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    pub fn try_clone(&self) -> Result<Self> {
        match &self.backend {
            TunBackend::Stub => Ok(Self {
                name: self.name.clone(),
                backend: TunBackend::Stub,
            }),
            #[cfg(target_os = "linux")]
            TunBackend::Linux(file) => Ok(Self {
                name: self.name.clone(),
                backend: TunBackend::Linux(file.try_clone().map_err(ShphError::Io)?),
            }),
        }
    }

    pub fn recv_packet(&mut self, packet: &mut [u8]) -> Result<usize> {
        if packet.is_empty() {
            return Err(ShphError::Tun("packet buffer cannot be empty".into()));
        }
        match &mut self.backend {
            TunBackend::Stub => Err(ShphError::Unsupported(
                "TUN packet read not enabled (set SHPH_TUN_NATIVE=1 on Linux)".into(),
            )),
            #[cfg(target_os = "linux")]
            TunBackend::Linux(file) => match file.read(packet) {
                Ok(n) => Ok(n),
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    Err(ShphError::Timeout)
                }
                Err(err) => Err(ShphError::Io(err)),
            },
        }
    }

    pub fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() {
            return Ok(());
        }
        match &mut self.backend {
            TunBackend::Stub => Err(ShphError::Unsupported(
                "TUN packet write not enabled (set SHPH_TUN_NATIVE=1 on Linux)".into(),
            )),
            #[cfg(target_os = "linux")]
            TunBackend::Linux(file) => match file.write_all(packet) {
                Ok(()) => Ok(()),
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    Err(ShphError::Timeout)
                }
                Err(err) => Err(ShphError::Io(err)),
            },
        }
    }
}

#[cfg(target_os = "linux")]
const TUN_DEVICE_PATH: &str = "/dev/net/tun";
#[cfg(target_os = "linux")]
const IFNAMSIZ: usize = 16;
#[cfg(target_os = "linux")]
const IFF_TUN: libc::c_short = 0x0001;
#[cfg(target_os = "linux")]
const IFF_NO_PI: libc::c_short = 0x1000;
#[cfg(target_os = "linux")]
const TUNSETIFF: libc::c_ulong = 0x400454ca;
#[cfg(target_os = "linux")]
const TUN_NAME_MAX_BYTES: usize = IFNAMSIZ - 1;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct IfReq {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_flags: libc::c_short,
}

#[cfg(target_os = "linux")]
fn open_linux_tun(name: &str) -> Result<TunDevice> {
    assert_tun_control_available()?;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(TUN_DEVICE_PATH)
        .map_err(classify_tun_open_error)?;

    let fd = file.as_raw_fd();
    let mut ifr = IfReq {
        ifr_name: [0; IFNAMSIZ],
        ifr_flags: IFF_TUN | IFF_NO_PI,
    };
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name.as_bytes().iter().copied()) {
        *dst = src as libc::c_char;
    }

    // SAFETY: ioctl argument points to a valid IfReq for TUNSETIFF.
    let res = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
    if res < 0 {
        return Err(classify_tun_ioctl_error(
            name,
            std::io::Error::last_os_error(),
        ));
    }

    Ok(TunDevice {
        name: name.to_string(),
        backend: TunBackend::Linux(file),
    })
}

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileTypeExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(target_os = "linux")]
fn validate_tun_name(name: &str) -> Result<()> {
    let name = name.trim();
    if name.is_empty() {
        return Err(ShphError::InvalidArgument(
            "TUN interface name cannot be empty".into(),
        ));
    }

    if name.len() > TUN_NAME_MAX_BYTES {
        return Err(ShphError::InvalidArgument(format!(
            "TUN interface name too long: max {TUN_NAME_MAX_BYTES} bytes, got {}",
            name.len()
        )));
    }

    if !name.is_ascii() {
        return Err(ShphError::InvalidArgument(
            "TUN interface name must be ASCII".into(),
        ));
    }

    if name.contains('\0') {
        return Err(ShphError::InvalidArgument(
            "TUN interface name cannot contain null bytes".into(),
        ));
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ':')
    {
        return Err(ShphError::InvalidArgument(
            "TUN interface name contains unsupported characters".into(),
        ));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn classify_tun_open_error(err: std::io::Error) -> ShphError {
    if is_permission_error(&err) {
        ShphError::PermissionDenied(format!(
            "permission denied opening {} (need CAP_NET_ADMIN/root for real TUN): {}",
            TUN_DEVICE_PATH, err
        ))
    } else {
        ShphError::Tun(format!("failed to open {}: {}", TUN_DEVICE_PATH, err))
    }
}

#[cfg(target_os = "linux")]
fn classify_tun_ioctl_error(interface_name: &str, err: std::io::Error) -> ShphError {
    if is_permission_error(&err) {
        ShphError::PermissionDenied(format!(
            "permission denied configuring TUN interface '{interface_name}' via TUNSETIFF (need CAP_NET_ADMIN/root)",
        ))
    } else {
        ShphError::Tun(format!(
            "ioctl(TUNSETIFF) failed for interface '{}': {}",
            interface_name, err
        ))
    }
}

#[cfg(target_os = "linux")]
fn is_permission_error(err: &std::io::Error) -> bool {
    err.kind() == ErrorKind::PermissionDenied
        || err.raw_os_error() == Some(libc::EACCES)
        || err.raw_os_error() == Some(libc::EPERM)
}

#[cfg(target_os = "linux")]
fn assert_tun_control_available() -> Result<()> {
    let metadata = std::fs::metadata(TUN_DEVICE_PATH).map_err(classify_tun_open_error)?;
    if !metadata.file_type().is_char_device() {
        return Err(ShphError::Tun(format!(
            "{} must be a character device for TUN support",
            TUN_DEVICE_PATH
        )));
    }
    Ok(())
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::validate_tun_name;

    #[test]
    fn validate_tun_name_accepts_valid() {
        assert!(validate_tun_name("shph0").is_ok());
        assert!(validate_tun_name("vpn-bridge_0").is_ok());
    }

    #[test]
    fn validate_tun_name_rejects_bad_names() {
        assert!(validate_tun_name("").is_err());
        assert!(validate_tun_name("this-name-is-way-too-long").is_err());
        assert!(validate_tun_name("name with space").is_err());
        assert!(validate_tun_name("bad\x00name").is_err());
        assert!(validate_tun_name("ünicode").is_err());
    }
}
