//! TUN device abstraction for SHPH.
//!
//! Default behavior remains a safe stub for cross-platform developer flow.
//! On Linux, real TUN I/O can be enabled by setting `SHPH_TUN_NATIVE=1`.

use shph_core::{Result, ShphError};
#[cfg(target_os = "linux")]
use std::io::{ErrorKind, Read, Write};

/// Largest IPv4/IPv6 packet representable by the layer-3 TUN interface.
pub const MAX_TUN_PACKET_BYTES: usize = u16::MAX as usize;
/// Read one byte beyond the maximum packet size so an oversized frame cannot
/// be mistaken for a valid maximum-sized packet.
pub const TUN_READ_BUFFER_BYTES: usize = MAX_TUN_PACKET_BYTES + 1;

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

        #[cfg(target_os = "windows")]
        {
            if std::env::var("SHPH_TUN_NATIVE").ok().as_deref() == Some("1") {
                return Err(ShphError::Unsupported(
                    "native Windows TUN requires a provisioned Wintun adapter and runtime integration; refusing to fall back to the stub".into(),
                ));
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
        if packet.len() > TUN_READ_BUFFER_BYTES {
            return Err(ShphError::Tun(format!(
                "packet buffer exceeds TUN safety limit of {TUN_READ_BUFFER_BYTES} bytes"
            )));
        }
        match &mut self.backend {
            TunBackend::Stub => Err(ShphError::Unsupported(
                "TUN packet read not enabled (set SHPH_TUN_NATIVE=1 on Linux)".into(),
            )),
            #[cfg(target_os = "linux")]
            TunBackend::Linux(file) => match file.read(packet) {
                Ok(n) if n > MAX_TUN_PACKET_BYTES => Err(ShphError::Tun(
                    "received TUN packet exceeds the 65535-byte safety limit".into(),
                )),
                Ok(n) => {
                    validate_ip_packet(&packet[..n])?;
                    Ok(n)
                }
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
        if packet.len() > MAX_TUN_PACKET_BYTES {
            return Err(ShphError::Tun(format!(
                "packet exceeds TUN safety limit of {MAX_TUN_PACKET_BYTES} bytes"
            )));
        }
        validate_ip_packet(packet)?;
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

/// Validate a layer-3 packet before it crosses the TUN boundary.
///
/// TUN is an IP-only interface. Rejecting malformed headers and length fields
/// here prevents truncated or trailing bytes from entering the transport and
/// avoids injecting non-IP data into the host network stack.
pub fn validate_ip_packet(packet: &[u8]) -> Result<()> {
    if packet.is_empty() {
        return Err(ShphError::Tun("IP packet cannot be empty".into()));
    }
    if packet.len() > MAX_TUN_PACKET_BYTES {
        return Err(ShphError::Tun(format!(
            "IP packet exceeds TUN safety limit of {MAX_TUN_PACKET_BYTES} bytes"
        )));
    }

    match packet[0] >> 4 {
        4 => validate_ipv4_packet(packet),
        6 => validate_ipv6_packet(packet),
        version => Err(ShphError::Tun(format!(
            "unsupported IP version in TUN packet: {version}"
        ))),
    }
}

fn validate_ipv4_packet(packet: &[u8]) -> Result<()> {
    if packet.len() < 20 {
        return Err(ShphError::Tun(
            "IPv4 packet is shorter than its header".into(),
        ));
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if header_len < 20 {
        return Err(ShphError::Tun("IPv4 header length is invalid".into()));
    }
    if header_len > packet.len() {
        return Err(ShphError::Tun("IPv4 header exceeds packet length".into()));
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < header_len || total_len != packet.len() {
        return Err(ShphError::Tun(
            "IPv4 total length does not match the packet".into(),
        ));
    }
    Ok(())
}

fn validate_ipv6_packet(packet: &[u8]) -> Result<()> {
    if packet.len() < 40 {
        return Err(ShphError::Tun(
            "IPv6 packet is shorter than its header".into(),
        ));
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if payload_len == 0 {
        return Err(ShphError::Tun(
            "IPv6 zero payload length/jumbo packets are unsupported".into(),
        ));
    }
    let total_len = 40usize.saturating_add(payload_len);
    if total_len != packet.len() {
        return Err(ShphError::Tun(
            "IPv6 payload length does not match the packet".into(),
        ));
    }
    Ok(())
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
const TUN_NAME_MAX_BYTES: usize = 15;

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
mod tests {
    use super::{validate_ip_packet, TunDevice};

    #[test]
    fn stub_device_clone_and_lifecycle_are_safe() {
        std::env::remove_var("SHPH_TUN_NATIVE");
        let device = TunDevice::open("shph-test").expect("stub open");
        assert_eq!(device.name(), "shph-test");
        assert!(!device.is_native());
        let mut clone = device.try_clone().expect("stub clone");
        assert!(clone.recv_packet(&mut [0u8; 64]).is_err());
        assert!(clone.send_packet(b"packet").is_err());
        assert!(clone.send_packet(&[]).is_ok());
    }

    #[test]
    fn validates_ipv4_packet_lengths() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(20u16).to_be_bytes());
        assert!(validate_ip_packet(&packet).is_ok());

        packet[2..4].copy_from_slice(&(21u16).to_be_bytes());
        assert!(validate_ip_packet(&packet).is_err());
    }

    #[test]
    fn validates_ipv6_packet_lengths() {
        let mut packet = vec![0u8; 40 + 4];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(4u16).to_be_bytes());
        assert!(validate_ip_packet(&packet).is_ok());

        packet[4..6].copy_from_slice(&(3u16).to_be_bytes());
        assert!(validate_ip_packet(&packet).is_err());
    }

    #[test]
    fn rejects_non_ip_and_oversized_packets() {
        assert!(validate_ip_packet(b"not-an-ip").is_err());
        assert!(validate_ip_packet(&vec![0u8; super::MAX_TUN_PACKET_BYTES + 1]).is_err());
    }

    #[test]
    fn validate_tun_name_accepts_valid() {
        assert!(super::validate_tun_name("shph0").is_ok());
        assert!(super::validate_tun_name("vpn-bridge_0").is_ok());
    }

    #[test]
    fn validate_tun_name_rejects_bad_names() {
        assert!(super::validate_tun_name("").is_err());
        assert!(super::validate_tun_name("this-name-is-way-too-long").is_err());
        assert!(super::validate_tun_name("name with space").is_err());
        assert!(super::validate_tun_name("bad\x00name").is_err());
        assert!(super::validate_tun_name("ünicode").is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_native_mode_refuses_stub_fallback() {
        std::env::set_var("SHPH_TUN_NATIVE", "1");
        let result = TunDevice::open("shph-test");
        std::env::remove_var("SHPH_TUN_NATIVE");
        assert!(matches!(
            result,
            Err(shph_core::ShphError::Unsupported(message))
                if message.contains("Wintun")
        ));
    }
}
