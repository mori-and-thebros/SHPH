//! TUN device abstraction for SHPH.
//!
//! Default behavior remains a safe stub for cross-platform developer flow.
//! On Linux, real TUN I/O can be enabled by setting `SHPH_TUN_NATIVE=1`.

use shph_core::{Result, ShphError};
#[cfg(target_os = "linux")]
use std::io::{ErrorKind, Read, Write};
use zeroize::Zeroize;
pub mod firewall;
#[cfg(target_os = "windows")]
mod windows_firewall;
#[cfg(target_os = "windows")]
pub use windows_firewall::{FirewallTransport as WindowsFirewallTransport, WindowsKillswitchGuard};
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "windows")]
pub use windows::{WintunApi, WintunRuntime};

/// Largest IPv4/IPv6 packet representable by the layer-3 TUN interface.
pub const MAX_TUN_PACKET_BYTES: usize = u16::MAX as usize;
/// Conservative default virtual-interface MTU for the encrypted transport.
pub const DEFAULT_TUN_MTU_BYTES: usize = 1_360;
/// Smallest generally useful IPv4 MTU for the native interface configuration.
pub const MIN_TUN_MTU_BYTES: usize = 576;
/// Read one byte beyond the maximum packet size so an oversized frame cannot
/// be mistaken for a valid maximum-sized packet.
pub const TUN_READ_BUFFER_BYTES: usize = MAX_TUN_PACKET_BYTES + 1;

pub fn validate_tun_mtu(mtu: usize) -> Result<()> {
    if !(MIN_TUN_MTU_BYTES..=MAX_TUN_PACKET_BYTES).contains(&mtu) {
        return Err(ShphError::Config(format!(
            "TUN MTU must be between {MIN_TUN_MTU_BYTES} and {MAX_TUN_PACKET_BYTES} bytes"
        )));
    }
    Ok(())
}

#[derive(Debug)]
enum TunBackend {
    Stub,
    #[cfg(target_os = "linux")]
    Linux(std::fs::File),
    #[cfg(target_os = "windows")]
    Windows(Arc<Mutex<WintunRuntime>>),
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
                return Self::open_native(name);
            }
        }

        #[cfg(target_os = "windows")]
        {
            if std::env::var("SHPH_TUN_NATIVE").ok().as_deref() == Some("1") {
                return Self::open_native(name);
            }
        }

        Ok(Self {
            name: name.to_string(),
            backend: TunBackend::Stub,
        })
    }

    /// Open a real platform TUN device without consulting environment flags.
    ///
    /// The explicit method keeps capability checks and platform failures
    /// testable while `open` preserves the developer-friendly stub default.
    pub fn open_native(name: &str) -> Result<Self> {
        validate_tun_name(name)?;

        #[cfg(target_os = "linux")]
        {
            open_linux_tun(name)
        }

        #[cfg(target_os = "windows")]
        {
            Ok(Self {
                name: name.to_string(),
                backend: TunBackend::Windows(Arc::new(Mutex::new(WintunRuntime::open(name)?))),
            })
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Err(ShphError::Unsupported(
                "native TUN is not implemented on this platform".into(),
            ))
        }
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
            #[cfg(target_os = "windows")]
            {
                matches!(self.backend, TunBackend::Windows(..))
            }
            #[cfg(not(target_os = "windows"))]
            {
                false
            }
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
            #[cfg(target_os = "windows")]
            TunBackend::Windows(runtime) => Ok(Self {
                name: self.name.clone(),
                backend: TunBackend::Windows(Arc::clone(runtime)),
            }),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn into_async(self) -> Result<AsyncTunDevice> {
        match self.backend {
            TunBackend::Stub => Err(ShphError::Unsupported(
                "cannot convert the stub TUN backend to an async device".into(),
            )),
            TunBackend::Linux(file) => AsyncTunDevice::from_file(self.name, file),
        }
    }

    pub fn recv_packet(&mut self, packet: &mut [u8]) -> Result<usize> {
        packet.zeroize();
        validate_packet_buffer(packet)?;
        match &mut self.backend {
            TunBackend::Stub => Err(ShphError::Unsupported(
                "TUN packet read not enabled (set SHPH_TUN_NATIVE=1 for native mode)".into(),
            )),
            #[cfg(target_os = "linux")]
            TunBackend::Linux(file) => loop {
                packet.zeroize();
                match file.read(packet) {
                    Ok(n) if n > MAX_TUN_PACKET_BYTES => {
                        packet.zeroize();
                        break Err(ShphError::Tun(
                            "received TUN packet exceeds the 65535-byte safety limit".into(),
                        ));
                    }
                    Ok(0) => break Err(ShphError::ConnectionClosed),
                    Ok(n) => match validate_ip_packet(&packet[..n]) {
                        Ok(()) => break Ok(n),
                        Err(error) => {
                            packet[..n].zeroize();
                            break Err(error);
                        }
                    },
                    Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                    Err(err)
                        if matches!(
                            err.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        break Err(ShphError::Timeout);
                    }
                    Err(err) => break Err(ShphError::Io(err)),
                }
            },
            #[cfg(target_os = "windows")]
            TunBackend::Windows(runtime) => loop {
                packet.zeroize();
                let received = match runtime
                    .lock()
                    .map_err(|_| ShphError::Internal("Wintun runtime mutex poisoned".into()))?
                    .try_receive_packet()
                {
                    Ok(received) => received,
                    Err(error) => {
                        packet.zeroize();
                        return Err(error);
                    }
                };
                match received {
                    Some(received) => {
                        if received.len() > packet.len() {
                            packet.zeroize();
                            return Err(ShphError::Tun(format!(
                                "received Wintun packet requires {} bytes, buffer has {}",
                                received.len(),
                                packet.len()
                            )));
                        }
                        packet[..received.len()].copy_from_slice(&received);
                        break Ok(received.len());
                    }
                    None => {
                        runtime
                            .lock()
                            .map_err(|_| {
                                ShphError::Internal("Wintun runtime mutex poisoned".into())
                            })?
                            .wait_for_packet()?;
                    }
                }
            },
        }
    }

    pub fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() {
            return Err(ShphError::Tun("TUN packet cannot be empty".into()));
        }
        if packet.len() > MAX_TUN_PACKET_BYTES {
            return Err(ShphError::Tun(format!(
                "packet exceeds TUN safety limit of {MAX_TUN_PACKET_BYTES} bytes"
            )));
        }
        validate_ip_packet(packet)?;
        match &mut self.backend {
            TunBackend::Stub => Err(ShphError::Unsupported(
                "TUN packet write not enabled (set SHPH_TUN_NATIVE=1 for native mode)".into(),
            )),
            #[cfg(target_os = "linux")]
            TunBackend::Linux(file) => loop {
                match file.write(packet) {
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    result => break classify_tun_write_result(result, packet.len()),
                }
            },
            #[cfg(target_os = "windows")]
            TunBackend::Windows(runtime) => runtime
                .lock()
                .map_err(|_| ShphError::Internal("Wintun runtime mutex poisoned".into()))?
                .send_packet(packet),
        }
    }
}

fn validate_packet_buffer(packet: &[u8]) -> Result<()> {
    if packet.is_empty() {
        return Err(ShphError::Tun("packet buffer cannot be empty".into()));
    }
    if packet.len() > TUN_READ_BUFFER_BYTES {
        return Err(ShphError::Tun(format!(
            "packet buffer exceeds TUN safety limit of {TUN_READ_BUFFER_BYTES} bytes"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct AsyncTunDevice {
    name: String,
    io: tokio::io::unix::AsyncFd<std::fs::File>,
}

#[cfg(target_os = "linux")]
impl AsyncTunDevice {
    /// Open a native Linux TUN device inside an active Tokio runtime.
    ///
    /// The descriptor is nonblocking and registered with Tokio's readiness
    /// reactor. This API is additive; the synchronous `TunDevice` API remains
    /// available for existing CLI paths.
    pub async fn open_native(name: &str) -> Result<Self> {
        validate_tun_name(name)?;
        let file = open_linux_tun_file(name)?;
        Self::from_file(name.to_string(), file)
    }

    fn from_file(name: String, file: std::fs::File) -> Result<Self> {
        let io = tokio::io::unix::AsyncFd::new(file).map_err(ShphError::Io)?;
        Ok(Self { name, io })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_native(&self) -> bool {
        true
    }

    pub fn try_clone(&self) -> Result<Self> {
        let file = self.io.get_ref().try_clone().map_err(ShphError::Io)?;
        let io = tokio::io::unix::AsyncFd::new(file).map_err(ShphError::Io)?;
        Ok(Self {
            name: self.name.clone(),
            io,
        })
    }

    pub async fn recv_packet(&mut self, packet: &mut [u8]) -> Result<usize> {
        packet.zeroize();
        validate_packet_buffer(packet)?;
        loop {
            packet.zeroize();
            let mut readiness = self.io.readable_mut().await.map_err(ShphError::Io)?;
            match readiness.try_io(|io| io.get_mut().read(packet)) {
                Err(_) => continue,
                Ok(Ok(n)) if n > MAX_TUN_PACKET_BYTES => {
                    packet.zeroize();
                    return Err(ShphError::Tun(
                        "received TUN packet exceeds the 65535-byte safety limit".into(),
                    ));
                }
                Ok(Ok(0)) => {
                    packet.zeroize();
                    return Err(ShphError::ConnectionClosed);
                }
                Ok(Err(err)) if err.kind() == ErrorKind::Interrupted => continue,
                Ok(Ok(n)) => match validate_ip_packet(&packet[..n]) {
                    Ok(()) => return Ok(n),
                    Err(error) => {
                        packet.zeroize();
                        return Err(error);
                    }
                },
                Ok(Err(err)) => {
                    packet.zeroize();
                    return Err(ShphError::Io(err));
                }
            }
        }
    }

    pub async fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() {
            return Err(ShphError::Tun("TUN packet cannot be empty".into()));
        }
        if packet.len() > MAX_TUN_PACKET_BYTES {
            return Err(ShphError::Tun(format!(
                "packet exceeds TUN safety limit of {MAX_TUN_PACKET_BYTES} bytes"
            )));
        }
        validate_ip_packet(packet)?;
        loop {
            let mut readiness = self.io.writable_mut().await.map_err(ShphError::Io)?;
            match readiness.try_io(|io| io.get_mut().write(packet)) {
                Err(_) => continue,
                Ok(Err(err)) if err.kind() == ErrorKind::Interrupted => continue,
                Ok(result) => return classify_tun_write_result(result, packet.len()),
            }
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
const IFF_TUN_EXCL: libc::c_short = 0x8000u16 as libc::c_short;
#[cfg(target_os = "linux")]
const TUN_INTERFACE_FLAGS: libc::c_short = IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL;
#[cfg(target_os = "linux")]
const TUNSETIFF: libc::c_ulong = 0x400454ca;
#[cfg(target_os = "linux")]
const TUN_OPEN_FLAGS: libc::c_int = libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW;
const TUN_NAME_MAX_BYTES: usize = 15;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct IfReq {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_flags: libc::c_short,
    ifr_padding: [u8; 22],
}

#[cfg(target_os = "linux")]
fn open_linux_tun(name: &str) -> Result<TunDevice> {
    let file = open_linux_tun_file(name)?;
    Ok(TunDevice {
        name: name.to_string(),
        backend: TunBackend::Linux(file),
    })
}

#[cfg(target_os = "linux")]
fn open_linux_tun_file(name: &str) -> Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(TUN_OPEN_FLAGS)
        .open(TUN_DEVICE_PATH)
        .map_err(classify_tun_open_error)?;

    let metadata = file.metadata().map_err(classify_tun_open_error)?;
    if !metadata.file_type().is_char_device() {
        return Err(ShphError::Tun(format!(
            "{} must be a character device for TUN support",
            TUN_DEVICE_PATH
        )));
    }

    let fd = file.as_raw_fd();
    let mut ifr = IfReq {
        ifr_name: [0; IFNAMSIZ],
        ifr_flags: TUN_INTERFACE_FLAGS,
        ifr_padding: [0; 22],
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

    Ok(file)
}

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileTypeExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

fn validate_tun_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(ShphError::InvalidArgument(
            "TUN interface name cannot be empty".into(),
        ));
    }
    if name.trim() != name {
        return Err(ShphError::InvalidArgument(
            "TUN interface name cannot have leading or trailing whitespace".into(),
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
fn classify_tun_write_result(result: std::io::Result<usize>, expected: usize) -> Result<()> {
    match result {
        Ok(written) if written == expected => Ok(()),
        Ok(written) => Err(ShphError::Tun(format!(
            "short TUN packet write: expected {expected} bytes, wrote {written}"
        ))),
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Err(ShphError::Timeout)
        }
        Err(err) => Err(ShphError::Io(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_ip_packet, validate_tun_mtu, TunDevice, DEFAULT_TUN_MTU_BYTES};

    #[test]
    fn stub_device_clone_and_lifecycle_are_safe() {
        std::env::remove_var("SHPH_TUN_NATIVE");
        let device = TunDevice::open("shph-test").expect("stub open");
        assert_eq!(device.name(), "shph-test");
        assert!(!device.is_native());
        let mut clone = device.try_clone().expect("stub clone");
        assert!(clone.recv_packet(&mut [0u8; 64]).is_err());
        assert!(clone.send_packet(b"packet").is_err());
        assert!(clone.send_packet(&[]).is_err());
    }

    #[test]
    fn receive_buffer_is_wiped_when_validation_rejects_it() {
        let device = TunDevice::open("shph-buf-test").expect("stub open");
        let mut device = device;
        let mut buffer = vec![0xa5u8; super::TUN_READ_BUFFER_BYTES + 1];
        assert!(device.recv_packet(&mut buffer).is_err());
        assert!(buffer.iter().all(|byte| *byte == 0));
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
    fn validates_conservative_native_tun_mtu() {
        assert_eq!(DEFAULT_TUN_MTU_BYTES, 1_360);
        assert!(validate_tun_mtu(DEFAULT_TUN_MTU_BYTES).is_ok());
        assert!(validate_tun_mtu(575).is_err());
        assert!(validate_tun_mtu(super::MAX_TUN_PACKET_BYTES + 1).is_err());
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
        assert!(super::validate_tun_name(" shph0").is_err());
        assert!(super::validate_tun_name("shph0 ").is_err());
        assert!(super::validate_tun_name("name with space").is_err());
        assert!(super::validate_tun_name("bad\x00name").is_err());
        assert!(super::validate_tun_name("ünicode").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_ifreq_matches_kernel_abi_size() {
        assert_eq!(std::mem::size_of::<super::IfReq>(), 40);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_native_tun_uses_exclusive_close_on_exec_flags() {
        assert_ne!(
            (super::TUN_INTERFACE_FLAGS as u16) & (super::IFF_TUN as u16),
            0
        );
        assert_ne!(
            (super::TUN_INTERFACE_FLAGS as u16) & (super::IFF_NO_PI as u16),
            0
        );
        assert_ne!(
            (super::TUN_INTERFACE_FLAGS as u16) & (super::IFF_TUN_EXCL as u16),
            0
        );
        assert_ne!(super::TUN_OPEN_FLAGS & libc::O_NONBLOCK, 0);
        assert_ne!(super::TUN_OPEN_FLAGS & libc::O_CLOEXEC, 0);
        assert_ne!(super::TUN_OPEN_FLAGS & libc::O_NOFOLLOW, 0);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_native_mode_fails_closed_without_runtime() {
        let result = TunDevice::open_native("shph-test");
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_native_open_is_capability_gated_and_fail_closed() {
        match TunDevice::open_native("shph-native") {
            Ok(device) => assert!(device.is_native()),
            Err(shph_core::ShphError::PermissionDenied(_)) | Err(shph_core::ShphError::Tun(_)) => {}
            Err(error) => panic!("unexpected native TUN result: {error}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_packet_write_requires_one_complete_write() {
        assert!(super::classify_tun_write_result(Ok(20), 20).is_ok());
        assert!(matches!(
            super::classify_tun_write_result(Ok(19), 20),
            Err(shph_core::ShphError::Tun(message))
                if message.contains("short TUN packet write")
        ));
        assert!(matches!(
            super::classify_tun_write_result(
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
                20,
            ),
            Err(shph_core::ShphError::Timeout)
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn linux_async_native_open_is_capability_gated_and_fail_closed() {
        match super::AsyncTunDevice::open_native("shph-async-test").await {
            Ok(device) => {
                assert!(device.is_native());
                assert_eq!(device.name(), "shph-async-test");
                assert!(device.try_clone().is_ok());
            }
            Err(shph_core::ShphError::PermissionDenied(_)) | Err(shph_core::ShphError::Tun(_)) => {}
            Err(error) => panic!("unexpected async native TUN result: {error}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn linux_async_device_reads_valid_packets_and_reports_eof() {
        use std::fs::File;
        use std::io::Write;
        use std::os::fd::{FromRawFd, RawFd};

        let mut fds = [0 as RawFd; 2];
        let result = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(result, 0);

        let read_fd = fds[0];
        let write_fd = fds[1];
        let flags = unsafe { libc::fcntl(read_fd, libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );

        let read_file = unsafe { File::from_raw_fd(read_fd) };
        let mut write_file = unsafe { File::from_raw_fd(write_fd) };
        let mut device =
            super::AsyncTunDevice::from_file("pipe-test".into(), read_file).expect("AsyncFd");

        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(20u16).to_be_bytes());
        write_file.write_all(&packet).expect("write test packet");

        let mut buffer = vec![0xa5u8; super::TUN_READ_BUFFER_BYTES];
        let length = device.recv_packet(&mut buffer).await.expect("read packet");
        assert_eq!(length, packet.len());
        assert_eq!(&buffer[..length], packet.as_slice());
        assert!(buffer[length..].iter().all(|byte| *byte == 0));

        write_file.flush().expect("flush test pipe");
        drop(write_file);
        buffer.fill(0x5a);
        let error = device.recv_packet(&mut buffer).await.expect_err("EOF");
        assert!(matches!(error, shph_core::ShphError::ConnectionClosed));
        assert!(buffer.iter().all(|byte| *byte == 0));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn linux_async_device_rejects_malformed_packets_without_closing() {
        use std::fs::File;
        use std::io::Write;
        use std::os::fd::{FromRawFd, RawFd};

        let mut fds = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read_fd = fds[0];
        let flags = unsafe { libc::fcntl(read_fd, libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );

        let read_file = unsafe { File::from_raw_fd(read_fd) };
        let mut write_file = unsafe { File::from_raw_fd(fds[1]) };
        let mut device =
            super::AsyncTunDevice::from_file("pipe-malformed".into(), read_file).expect("AsyncFd");
        write_file
            .write_all(b"not-an-ip")
            .expect("write malformed packet");

        let mut buffer = vec![0xa5u8; super::TUN_READ_BUFFER_BYTES];
        let error = device
            .recv_packet(&mut buffer)
            .await
            .expect_err("malformed");
        assert!(matches!(error, shph_core::ShphError::Tun(_)));
        assert!(buffer.iter().all(|byte| *byte == 0));

        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(20u16).to_be_bytes());
        write_file.write_all(&packet).expect("write valid packet");
        let length = device
            .recv_packet(&mut buffer)
            .await
            .expect("read valid packet");
        assert_eq!(length, packet.len());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stub_cannot_be_promoted_to_async_native_backend() {
        let device = TunDevice::open("shph-async-stub").expect("stub open");
        assert!(matches!(
            device.into_async(),
            Err(shph_core::ShphError::Unsupported(message))
                if message.contains("stub")
        ));
    }
}
