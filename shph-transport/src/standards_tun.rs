//! Linux native-TUN bridge for the standards QUIC data plane.
//!
//! The bridge deliberately uses QUIC application datagrams for layer-3
//! packets. Datagrams are bounded and lossy: an oversized or locally queued
//! packet is dropped, while connection capability failures terminate the
//! bridge. Every received datagram is validated before it reaches the TUN
//! device.

use crate::standards_quic::StandardsQuicConnection;
use quinn::Connection;
use shph_core::{Result, ShphError};
use shph_tun::{AsyncTunDevice, TUN_READ_BUFFER_BYTES};
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_MAX_INVALID_DATAGRAMS: usize = 64;
const MAX_INVALID_DATAGRAMS: usize = 4096;
const BRIDGE_CLOSE_REASON: &[u8] = b"SHPH native TUN bridge closed";

/// Runtime limits for the standards-QUIC native-TUN bridge.
#[derive(Debug, Clone, Copy)]
pub struct StandardsTunBridgeConfig {
    /// Maximum number of malformed authenticated datagrams tolerated before
    /// the connection is closed.
    pub max_invalid_datagrams: usize,
}

impl Default for StandardsTunBridgeConfig {
    fn default() -> Self {
        Self {
            max_invalid_datagrams: DEFAULT_MAX_INVALID_DATAGRAMS,
        }
    }
}

impl StandardsTunBridgeConfig {
    fn validate(self) -> Result<Self> {
        if self.max_invalid_datagrams == 0 || self.max_invalid_datagrams > MAX_INVALID_DATAGRAMS {
            return Err(ShphError::Config(
                format!(
                    "standards TUN bridge invalid-datagram limit must be between 1 and {MAX_INVALID_DATAGRAMS}"
                ),
            ));
        }
        Ok(self)
    }
}

/// Counters emitted by one standards-QUIC native-TUN bridge run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StandardsTunBridgeStats {
    pub tun_to_quic_packets: u64,
    pub tun_to_quic_bytes: u64,
    pub quic_to_tun_packets: u64,
    pub quic_to_tun_bytes: u64,
    pub dropped_oversized_packets: u64,
    pub dropped_invalid_datagrams: u64,
}

impl StandardsTunBridgeStats {
    fn combine(self, other: Self) -> Self {
        Self {
            tun_to_quic_packets: self
                .tun_to_quic_packets
                .saturating_add(other.tun_to_quic_packets),
            tun_to_quic_bytes: self
                .tun_to_quic_bytes
                .saturating_add(other.tun_to_quic_bytes),
            quic_to_tun_packets: self
                .quic_to_tun_packets
                .saturating_add(other.quic_to_tun_packets),
            quic_to_tun_bytes: self
                .quic_to_tun_bytes
                .saturating_add(other.quic_to_tun_bytes),
            dropped_oversized_packets: self
                .dropped_oversized_packets
                .saturating_add(other.dropped_oversized_packets),
            dropped_invalid_datagrams: self
                .dropped_invalid_datagrams
                .saturating_add(other.dropped_invalid_datagrams),
        }
    }
}

/// Run both directions of the standards-QUIC native-TUN bridge.
///
/// `tun_to_quic` and `quic_to_tun` must refer to independent clones of the
/// same native TUN descriptor. The bridge returns when the connection closes,
/// either direction encounters a fatal error, or the TUN descriptor closes.
/// A peer connection close is returned as [`ShphError::ConnectionClosed`] so
/// callers never mistake an interrupted tunnel for a clean completion.
pub async fn run(
    connection: StandardsQuicConnection,
    tun_to_quic: AsyncTunDevice,
    quic_to_tun: AsyncTunDevice,
    config: StandardsTunBridgeConfig,
) -> Result<StandardsTunBridgeStats> {
    let config = config.validate()?;
    let connection = connection.connection;
    let sender_connection = connection.clone();
    let receiver_connection = connection.clone();

    let (sender, receiver) = tokio::try_join!(
        tun_to_quic_loop(sender_connection, tun_to_quic),
        quic_to_tun_loop(receiver_connection, quic_to_tun, config),
    )?;

    Ok(sender.combine(receiver))
}

async fn tun_to_quic_loop(
    connection: Connection,
    mut tun: AsyncTunDevice,
) -> Result<StandardsTunBridgeStats> {
    let mut stats = StandardsTunBridgeStats::default();
    let mut packet = Zeroizing::new(vec![0u8; TUN_READ_BUFFER_BYTES]);

    loop {
        tokio::select! {
            _ = connection.closed() => return Err(ShphError::ConnectionClosed),
            result = tun.recv_packet(&mut packet) => {
                match result {
                    Ok(length) => {
                        if length == 0 {
                            close_connection(&connection);
                            return Ok(stats);
                        }
                        match crate::standards_quic::send_datagram_lossy(
                            &connection,
                            &packet[..length],
                        ) {
                            Ok(()) => {
                                stats.tun_to_quic_packets =
                                    stats.tun_to_quic_packets.saturating_add(1);
                                stats.tun_to_quic_bytes =
                                    stats.tun_to_quic_bytes.saturating_add(length as u64);
                            }
                            Err(quinn::SendDatagramError::TooLarge) => {
                                stats.dropped_oversized_packets =
                                    stats.dropped_oversized_packets.saturating_add(1);
                            }
                            Err(quinn::SendDatagramError::UnsupportedByPeer) => {
                                close_connection(&connection);
                                return Err(ShphError::Unsupported(
                                    "peer does not support QUIC DATAGRAM frames".into(),
                                ));
                            }
                            Err(quinn::SendDatagramError::Disabled) => {
                                close_connection(&connection);
                                return Err(ShphError::Unsupported(
                                    "QUIC DATAGRAM frames are disabled".into(),
                                ));
                            }
                            Err(quinn::SendDatagramError::ConnectionLost(error)) => {
                                close_connection(&connection);
                                return Err(ShphError::Transport(error.to_string()));
                            }
                        }
                        packet[..length].zeroize();
                    }
                    Err(ShphError::ConnectionClosed) => {
                        close_connection(&connection);
                        return Err(ShphError::ConnectionClosed);
                    }
                    Err(error) => {
                        close_connection(&connection);
                        return Err(error);
                    }
                }
            }
        }
    }
}

async fn quic_to_tun_loop(
    connection: Connection,
    mut tun: AsyncTunDevice,
    config: StandardsTunBridgeConfig,
) -> Result<StandardsTunBridgeStats> {
    let mut stats = StandardsTunBridgeStats::default();
    let mut invalid_datagrams = 0usize;

    loop {
        tokio::select! {
            _ = connection.closed() => return Err(ShphError::ConnectionClosed),
            result = connection.read_datagram() => {
                let datagram = match result {
                    Ok(datagram) => datagram,
                    Err(error) => {
                        close_connection(&connection);
                        return Err(ShphError::Transport(error.to_string()));
                    }
                };

                if is_oversized_tun_datagram(&datagram) {
                    invalid_datagrams = invalid_datagrams.saturating_add(1);
                    stats.dropped_oversized_packets =
                        stats.dropped_oversized_packets.saturating_add(1);
                } else if is_invalid_tun_datagram(&datagram) {
                    invalid_datagrams = invalid_datagrams.saturating_add(1);
                    stats.dropped_invalid_datagrams =
                        stats.dropped_invalid_datagrams.saturating_add(1);
                } else {
                    let datagram = Zeroizing::new(datagram.to_vec());
                    let length = datagram.len();
                    match tun.send_packet(&datagram).await {
                        Ok(()) => {
                            stats.quic_to_tun_packets =
                                stats.quic_to_tun_packets.saturating_add(1);
                            stats.quic_to_tun_bytes =
                                stats.quic_to_tun_bytes.saturating_add(length as u64);
                        }
                        Err(error) => {
                            close_connection(&connection);
                            return Err(error);
                        }
                    }
                }

                if invalid_datagrams >= config.max_invalid_datagrams {
                    close_connection(&connection);
                    return Err(ShphError::Protocol(format!(
                        "received {} malformed QUIC datagrams",
                        invalid_datagrams
                    )));
                }
            }
        }
    }
}

fn close_connection(connection: &Connection) {
    connection.close(0u32.into(), BRIDGE_CLOSE_REASON);
}

fn is_invalid_tun_datagram(datagram: &[u8]) -> bool {
    datagram.is_empty() || shph_tun::validate_ip_packet(datagram).is_err()
}

fn is_oversized_tun_datagram(datagram: &[u8]) -> bool {
    datagram.len() > shph_tun::MAX_TUN_PACKET_BYTES
}

#[cfg(test)]
mod tests {
    use super::{
        is_invalid_tun_datagram, is_oversized_tun_datagram, StandardsTunBridgeConfig,
        StandardsTunBridgeStats,
    };

    #[test]
    fn bridge_config_rejects_unbounded_invalid_datagram_policy() {
        assert!(StandardsTunBridgeConfig {
            max_invalid_datagrams: 0,
        }
        .validate()
        .is_err());
        assert!(StandardsTunBridgeConfig {
            max_invalid_datagrams: 4097,
        }
        .validate()
        .is_err());
        assert!(StandardsTunBridgeConfig::default().validate().is_ok());
    }

    #[test]
    fn bridge_stats_combine_saturates() {
        let left = StandardsTunBridgeStats {
            tun_to_quic_packets: u64::MAX,
            ..Default::default()
        };
        let right = StandardsTunBridgeStats {
            tun_to_quic_packets: 1,
            quic_to_tun_packets: 2,
            ..Default::default()
        };
        let combined = left.combine(right);
        assert_eq!(combined.tun_to_quic_packets, u64::MAX);
        assert_eq!(combined.quic_to_tun_packets, 2);
    }

    #[test]
    fn bridge_rejects_non_ip_and_accepts_valid_ipv4() {
        assert!(is_invalid_tun_datagram(b"not an IP packet"));

        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(20u16).to_be_bytes());
        assert!(!is_invalid_tun_datagram(&packet));
    }

    #[test]
    fn bridge_accepts_valid_ipv6_and_rejects_oversized_datagrams() {
        let mut packet = vec![0u8; 40 + 4];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(4u16).to_be_bytes());
        assert!(!is_invalid_tun_datagram(&packet));
        assert!(is_invalid_tun_datagram(&vec![
            0u8;
            shph_tun::MAX_TUN_PACKET_BYTES
                + 1
        ]));
        assert!(is_oversized_tun_datagram(&vec![
            0u8;
            shph_tun::MAX_TUN_PACKET_BYTES
                + 1
        ]));
    }
}
