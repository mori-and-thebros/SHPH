//! Network types and transport abstractions.

use serde::{Deserialize, Serialize};

use std::net::ToSocketAddrs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn parse(addr: &str) -> Result<Self, String> {
        let (host, port_text) = if let Some(stripped) = addr.strip_prefix('[') {
            let (host, port) = stripped
                .split_once("]:")
                .ok_or_else(|| format!("invalid endpoint: {}", addr))?;
            (host, port)
        } else {
            addr.rsplit_once(':')
                .ok_or_else(|| format!("invalid endpoint: {}", addr))?
        };
        let port = port_text.parse::<u16>().map_err(|e| e.to_string())?;
        if host.trim().is_empty() || port == 0 {
            return Err(format!("invalid endpoint: {}", addr));
        }
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }

    /// Validate this endpoint as a socket address without panicking.
    ///
    /// Returns an error for malformed hosts (e.g. bad IPv6 literals, invalid
    /// characters) rather than panicking via `.unwrap()`.
    pub fn to_socket_addr_result(&self) -> std::result::Result<std::net::SocketAddr, String> {
        let candidate = if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };
        candidate
            .to_socket_addrs()
            .map_err(|e| format!("invalid endpoint {candidate}: {e}"))?
            .next()
            .ok_or_else(|| format!("endpoint resolved to no address: {candidate}"))
    }
}

/// Panics-free note: callers should prefer [`Endpoint::to_socket_addr_result`].
/// This infallible conversion exists for ergonomic APIs and only succeeds for
/// already-valid endpoints; it constructs an IPv4 unspecified address only as a
/// last-resort to avoid a panic, which the caller will detect as a connection
/// failure rather than a process crash.
impl From<Endpoint> for std::net::SocketAddr {
    fn from(ep: Endpoint) -> Self {
        match ep.to_socket_addr_result() {
            Ok(addr) => addr,
            // Fail safe instead of unwrapping: an invalid endpoint becomes an
            // unspecified address that connection attempts will reject, rather
            // than crashing the process on untrusted input.
            Err(_) => std::net::SocketAddr::from(([0u8, 0, 0, 0], 0)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportType {
    DirectTcp,
    BridgeTls,
    BridgeWs,
    ShroudTcp,
    Quic,
    UdpOverTcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub name: String,
    pub local_addr: String,
    pub remote_endpoint: Endpoint,
    pub transport: TransportType,
    pub psk: Option<String>,
    pub tls_ca: Option<String>,
    pub tls_pin: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::Endpoint;
    use std::net::SocketAddr;

    #[test]
    fn endpoint_parse_rejects_malformed() {
        assert!(Endpoint::parse("no_port").is_err());
        assert!(Endpoint::parse("host:notaport").is_err());
        let ep = Endpoint::parse("127.0.0.1:7000").expect("valid");
        assert_eq!(ep.port, 7000);
        let ipv6 = Endpoint::parse("[::1]:7000").expect("valid IPv6 endpoint");
        assert_eq!(ipv6.host, "::1");
    }

    #[test]
    fn endpoint_to_socket_addr_result_accepts_loopback() {
        let ep = Endpoint {
            host: "127.0.0.1".to_string(),
            port: 7000,
        };
        assert!(ep.to_socket_addr_result().is_ok());
    }

    #[test]
    fn endpoint_to_socket_addr_result_rejects_bad_host() {
        let ep = Endpoint {
            host: "not a valid host !!!".to_string(),
            port: 7000,
        };
        // Must fail closed without panicking.
        assert!(ep.to_socket_addr_result().is_err());
    }

    #[test]
    fn endpoint_from_does_not_panic_on_bad_input() {
        let ep = Endpoint {
            host: "not a valid host !!!".to_string(),
            port: 7000,
        };
        // The From impl must never panic; it degrades to an unspecified addr.
        let addr: SocketAddr = ep.into();
        assert_eq!(addr.port(), 0);
    }
}
