use crate::capability::{CapabilityError, CapabilityVerifier, ReplayCache};
use crate::config::{validate_relay_path, EdgeConfigError, DEFAULT_RELAY_PATH};
use http::{header, HeaderMap, Method, StatusCode, Uri};
use std::time::SystemTime;

pub const CAPABILITY_HEADER: &str = "x-phantom-one-capability";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontDoorDecision {
    Relay,
    Fallback(FrontDoorResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontDoorResponse {
    pub status: StatusCode,
    pub content_type: &'static str,
    pub body: &'static [u8],
}

impl FrontDoorResponse {
    pub const fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            content_type: "text/plain; charset=utf-8",
            body: b"not found\n",
        }
    }

    pub const fn method_not_allowed() -> Self {
        Self {
            status: StatusCode::METHOD_NOT_ALLOWED,
            content_type: "text/plain; charset=utf-8",
            body: b"method not allowed\n",
        }
    }

    pub const fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            content_type: "text/plain; charset=utf-8",
            body: b"unauthorized\n",
        }
    }
}

#[derive(Debug)]
pub struct FrontDoor {
    verifier: CapabilityVerifier,
    max_token_bytes: usize,
    relay_path: String,
}

impl FrontDoor {
    pub fn new(verifier: CapabilityVerifier, max_token_bytes: usize) -> Self {
        Self::with_path(verifier, max_token_bytes, DEFAULT_RELAY_PATH)
            .expect("default relay path is valid")
    }

    pub fn with_path(
        verifier: CapabilityVerifier,
        max_token_bytes: usize,
        relay_path: impl Into<String>,
    ) -> Result<Self, EdgeConfigError> {
        let relay_path = relay_path.into();
        validate_relay_path(&relay_path)?;
        Ok(Self {
            verifier,
            max_token_bytes,
            relay_path,
        })
    }

    pub fn decide(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        replay: &mut ReplayCache,
    ) -> FrontDoorDecision {
        if uri.path() != self.relay_path || uri.query().is_some() {
            return FrontDoorDecision::Fallback(FrontDoorResponse::not_found());
        }
        if method != Method::POST {
            return FrontDoorDecision::Fallback(FrontDoorResponse::method_not_allowed());
        }
        let mut capability_values = headers.get_all(CAPABILITY_HEADER).iter();
        let Some(capability) = capability_values.next() else {
            return FrontDoorDecision::Fallback(FrontDoorResponse::unauthorized());
        };
        if capability_values.next().is_some() {
            return FrontDoorDecision::Fallback(FrontDoorResponse::unauthorized());
        }
        let Some(raw) = capability.to_str().ok() else {
            return FrontDoorDecision::Fallback(FrontDoorResponse::unauthorized());
        };
        if raw.len() > self.max_token_bytes {
            return FrontDoorDecision::Fallback(FrontDoorResponse::unauthorized());
        }
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        match self.verifier.verify(raw, now, replay) {
            Ok(_) => FrontDoorDecision::Relay,
            Err(
                CapabilityError::AudienceMismatch
                | CapabilityError::InvalidSignature
                | CapabilityError::Replay
                | CapabilityError::Expired
                | CapabilityError::NotYetValid
                | CapabilityError::Malformed
                | CapabilityError::LifetimeTooLong
                | CapabilityError::InvalidAudience
                | CapabilityError::InvalidLifetime
                | CapabilityError::InvalidSigningKey,
            ) => FrontDoorDecision::Fallback(FrontDoorResponse::unauthorized()),
        }
    }
}

pub fn is_octet_stream(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value
        .split(';')
        .next()
        .is_some_and(|part| part.trim().eq_ignore_ascii_case("application/octet-stream"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilityClaims, CapabilityIssuer};
    use std::time::Duration;

    #[test]
    fn front_door_falls_back_without_leaking_relay_details() {
        let (issuer, _) = CapabilityIssuer::generate(Duration::from_secs(60)).expect("key");
        let verifier = CapabilityVerifier::new(
            issuer.public_key(),
            "edge-a",
            Duration::from_secs(60),
            Duration::from_secs(86_400),
        )
        .expect("verifier");
        let front_door = FrontDoor::new(verifier, 4096);
        let mut replay = ReplayCache::new(4).expect("cache");
        assert_eq!(
            front_door.decide(
                &Method::GET,
                &"/".parse().expect("URI"),
                &HeaderMap::new(),
                &mut replay,
            ),
            FrontDoorDecision::Fallback(FrontDoorResponse::not_found())
        );
        assert_eq!(
            front_door.decide(
                &Method::POST,
                &crate::carrier::H2_PATH.parse().expect("URI"),
                &HeaderMap::new(),
                &mut replay
            ),
            FrontDoorDecision::Fallback(FrontDoorResponse::unauthorized())
        );
    }

    #[test]
    fn valid_capability_enters_relay_path() {
        let (issuer, _) = CapabilityIssuer::generate(Duration::from_secs(60)).expect("key");
        let verifier = CapabilityVerifier::new(
            issuer.public_key(),
            "edge-a",
            Duration::from_secs(60),
            Duration::from_secs(86_400),
        )
        .expect("verifier");
        let front_door = FrontDoor::new(verifier, 4096);
        let now = crate::capability::unix_now().expect("clock");
        let claims = CapabilityClaims::new("edge-a", now, now + 60, [7; 16]);
        let token = issuer.issue(&claims).expect("token");
        let mut headers = HeaderMap::new();
        headers.insert(CAPABILITY_HEADER, token.parse().expect("header"));
        let mut replay = ReplayCache::new(4).expect("cache");
        assert_eq!(
            front_door.decide(
                &Method::POST,
                &crate::carrier::H2_PATH.parse().expect("URI"),
                &headers,
                &mut replay
            ),
            FrontDoorDecision::Relay
        );
    }

    #[test]
    fn front_door_rejects_query_on_relay_endpoint() {
        let (issuer, _) = CapabilityIssuer::generate(Duration::from_secs(60)).expect("key");
        let verifier = CapabilityVerifier::new(
            issuer.public_key(),
            "edge-a",
            Duration::from_secs(60),
            Duration::from_secs(86_400),
        )
        .expect("verifier");
        let front_door = FrontDoor::new(verifier, 4096);
        let mut replay = ReplayCache::new(4).expect("cache");
        let uri: Uri = "/phantom-one/v1?probe=1".parse().expect("URI");
        assert_eq!(
            front_door.decide(&Method::POST, &uri, &HeaderMap::new(), &mut replay),
            FrontDoorDecision::Fallback(FrontDoorResponse::not_found())
        );
    }

    #[test]
    fn front_door_rejects_duplicate_capability_headers() {
        let (issuer, _) = CapabilityIssuer::generate(Duration::from_secs(60)).expect("key");
        let verifier = CapabilityVerifier::new(
            issuer.public_key(),
            "edge-a",
            Duration::from_secs(60),
            Duration::ZERO,
        )
        .expect("verifier");
        let front_door = FrontDoor::new(verifier, 4096);
        let now = crate::capability::unix_now().expect("clock");
        let token = issuer
            .issue(&CapabilityClaims::new("edge-a", now, now + 60, [8; 16]))
            .expect("token");
        let mut headers = HeaderMap::new();
        headers.append(CAPABILITY_HEADER, token.parse().expect("header"));
        headers.append(CAPABILITY_HEADER, "duplicate".parse().expect("header"));
        let mut replay = ReplayCache::new(4).expect("cache");

        assert_eq!(
            front_door.decide(
                &Method::POST,
                &crate::carrier::H2_PATH.parse().expect("URI"),
                &headers,
                &mut replay
            ),
            FrontDoorDecision::Fallback(FrontDoorResponse::unauthorized())
        );
        assert!(replay.is_empty());
    }
}
