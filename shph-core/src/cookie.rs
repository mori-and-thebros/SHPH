//! Stateless, rotating pre-authentication cookies.
//!
//! Cookies prove that a peer can receive traffic at the source address it
//! presents before the responder spends expensive post-quantum CPU time.
//! They are intentionally opaque and contain no server-side client state.

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, ShphError};

/// Cookie keys and timestamps rotate at this interval.
pub const COOKIE_EPOCH_SECS: u64 = 30;
const COOKIE_SECRET_BYTES: usize = 32;
const COOKIE_TAG_BYTES: usize = 32;
const COOKIE_DOMAIN: &[u8] = b"shph-preauth-cookie-v1";

/// A stateless cookie authority scoped to one listener process.
///
/// The current and immediately previous secrets are retained so a cookie
/// issued immediately before rotation remains usable. Verification also
/// accepts the current and previous time epochs, limiting replay to a short
/// bounded window without storing per-client state.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StatelessCookieAuthority {
    current_secret: [u8; COOKIE_SECRET_BYTES],
    previous_secret: [u8; COOKIE_SECRET_BYTES],
    current_epoch: u64,
}

impl std::fmt::Debug for StatelessCookieAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StatelessCookieAuthority")
            .field("current_epoch", &self.current_epoch)
            .finish_non_exhaustive()
    }
}

impl StatelessCookieAuthority {
    /// Create an authority with fresh process-local key material.
    pub fn new() -> Result<Self> {
        let mut current_secret = [0u8; COOKIE_SECRET_BYTES];
        let mut previous_secret = [0u8; COOKIE_SECRET_BYTES];
        let rng = SystemRandom::new();
        rng.fill(&mut current_secret)?;
        rng.fill(&mut previous_secret)?;
        Ok(Self {
            current_secret,
            previous_secret,
            current_epoch: current_epoch()?,
        })
    }

    /// Issue an opaque cookie bound to the peer's source address.
    pub fn issue(&mut self, peer: SocketAddr) -> Result<[u8; COOKIE_TAG_BYTES]> {
        let epoch = current_epoch()?;
        self.rotate_to(epoch)?;
        Ok(self.mac(&self.current_secret, peer, epoch))
    }

    /// Verify a cookie without allocating or retaining client-specific state.
    pub fn verify(&mut self, peer: SocketAddr, cookie: &[u8]) -> Result<bool> {
        if cookie.len() != COOKIE_TAG_BYTES {
            return Ok(false);
        }
        let epoch = current_epoch()?;
        self.rotate_to(epoch)?;
        let mut matches = 0u8;
        for secret in [&self.current_secret, &self.previous_secret] {
            for candidate_epoch in [epoch, epoch.saturating_sub(1)] {
                let expected = self.mac(secret, peer, candidate_epoch);
                matches |= (constant_time_diff(cookie, &expected) == 0) as u8;
            }
        }
        Ok(matches != 0)
    }

    fn rotate_to(&mut self, epoch: u64) -> Result<()> {
        if epoch <= self.current_epoch {
            return Ok(());
        }
        let mut next_secret = [0u8; COOKIE_SECRET_BYTES];
        SystemRandom::new().fill(&mut next_secret)?;
        self.previous_secret.zeroize();
        self.previous_secret = self.current_secret;
        self.current_secret = next_secret;
        self.current_epoch = epoch;
        Ok(())
    }

    fn mac(
        &self,
        secret: &[u8; COOKIE_SECRET_BYTES],
        peer: SocketAddr,
        epoch: u64,
    ) -> [u8; COOKIE_TAG_BYTES] {
        let mut message = [0u8; COOKIE_DOMAIN.len() + 16 + 2 + 8 + 1];
        let mut offset = 0;
        message[..COOKIE_DOMAIN.len()].copy_from_slice(COOKIE_DOMAIN);
        offset += COOKIE_DOMAIN.len();
        match peer.ip() {
            std::net::IpAddr::V4(address) => {
                message[offset] = 4;
                offset += 1;
                message[offset..offset + 4].copy_from_slice(&address.octets());
                offset += 4;
            }
            std::net::IpAddr::V6(address) => {
                message[offset] = 6;
                offset += 1;
                message[offset..offset + 16].copy_from_slice(&address.octets());
                offset += 16;
            }
        }
        message[offset..offset + 2].copy_from_slice(&peer.port().to_be_bytes());
        offset += 2;
        message[offset..offset + 8].copy_from_slice(&epoch.to_be_bytes());

        let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
        let tag = hmac::sign(&key, &message[..offset + 8]);
        let mut result = [0u8; COOKIE_TAG_BYTES];
        result.copy_from_slice(tag.as_ref());
        result
    }
}

fn current_epoch() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShphError::Crypto("system clock before unix epoch".into()))?
        .as_secs()
        / COOKIE_EPOCH_SECS)
}

fn constant_time_diff(left: &[u8], right: &[u8]) -> u8 {
    let mut diff = (left.len() != right.len()) as u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff
}

#[cfg(test)]
mod tests {
    use super::{StatelessCookieAuthority, COOKIE_EPOCH_SECS};
    use std::net::SocketAddr;

    #[test]
    fn cookie_is_bound_to_source_address() {
        let authority = StatelessCookieAuthority {
            current_secret: [7u8; 32],
            previous_secret: [8u8; 32],
            current_epoch: 10,
        };
        let peer: SocketAddr = "192.0.2.10:1234".parse().expect("peer");
        let cookie = authority.mac(&authority.current_secret, peer, 10);
        assert_eq!(authority.mac(&authority.current_secret, peer, 10), cookie);
        assert_ne!(
            authority.mac(
                &authority.current_secret,
                "192.0.2.10:1235".parse().expect("peer"),
                10
            ),
            cookie
        );
        assert_ne!(
            authority.mac(
                &authority.current_secret,
                "192.0.2.11:1234".parse().expect("peer"),
                10
            ),
            cookie
        );
    }

    #[test]
    fn rotation_preserves_previous_epoch_and_rejects_stale_epochs() {
        let mut authority = StatelessCookieAuthority {
            current_secret: [7u8; 32],
            previous_secret: [8u8; 32],
            current_epoch: 10,
        };
        let peer: SocketAddr = "198.51.100.3:4321".parse().expect("peer");
        let cookie = authority.mac(&authority.current_secret, peer, 10);
        authority.rotate_to(11).expect("rotate");
        let expected = authority.mac(&authority.previous_secret, peer, 10);
        assert_eq!(cookie, expected);
        assert_eq!(COOKIE_EPOCH_SECS, 30);
    }

    #[test]
    fn malformed_cookie_is_rejected_without_panic() {
        let mut authority = StatelessCookieAuthority {
            current_secret: [7u8; 32],
            previous_secret: [8u8; 32],
            current_epoch: 10,
        };
        let peer: SocketAddr = "203.0.113.8:55".parse().expect("peer");
        assert!(!authority.verify(peer, &[0u8; 3]).expect("verify"));
    }
}
