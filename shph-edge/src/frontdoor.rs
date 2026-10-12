use crate::capability::{CapabilityError, CapabilityVerifier, ReplayCache, VerifiedCapability};
use crate::config::{
    validate_relay_path, EdgeConfigError, DEFAULT_RELAY_PATH, DEFAULT_REPLAY_CAPACITY,
};
use http::{header, HeaderMap, Method, StatusCode, Uri};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    sync::Arc,
    time::{Instant, SystemTime},
};

pub const CAPABILITY_HEADER: &str = "x-phantom-one-capability";
const DEFAULT_MAX_VERIFICATIONS_PER_SECOND: u64 = 256;
const MAX_VERIFICATION_RATE: u64 = 100_000;
const RATE_COUNT_BITS: u32 = 20;
const RATE_COUNT_MASK: u64 = (1 << RATE_COUNT_BITS) - 1;

#[derive(Debug)]
struct VerificationRateLimiter {
    limit: u64,
    started: Instant,
    state: AtomicU64,
}

impl VerificationRateLimiter {
    fn new(limit: u64) -> Option<Self> {
        (1..=MAX_VERIFICATION_RATE).contains(&limit).then(|| Self {
            limit,
            started: Instant::now(),
            state: AtomicU64::new(0),
        })
    }

    fn try_acquire(&self) -> bool {
        self.try_acquire_in_window(self.started.elapsed().as_secs())
    }

    fn try_acquire_in_window(&self, window: u64) -> bool {
        let mut observed = self.state.load(Ordering::Relaxed);
        loop {
            let previous_window = observed >> RATE_COUNT_BITS;
            let previous_count = observed & RATE_COUNT_MASK;
            let next = if window > previous_window {
                (window << RATE_COUNT_BITS) | 1
            } else if window < previous_window || previous_count >= self.limit {
                return false;
            } else {
                observed + 1
            };
            match self.state.compare_exchange_weak(
                observed,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => observed = actual,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontDoorDecision {
    Relay,
    Fallback(FrontDoorResponse),
}

#[derive(Debug)]
pub(crate) enum FrontDoorPreparation {
    Verified(VerifiedCapability),
    Fallback(FrontDoorDecision),
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

    pub const fn service_unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            content_type: "text/plain; charset=utf-8",
            body: b"temporarily unavailable\n",
        }
    }
}

#[derive(Debug)]
pub struct FrontDoor {
    verifier: CapabilityVerifier,
    max_token_bytes: usize,
    relay_path: String,
    uniform_fallback: bool,
    verification_rate_limiter: VerificationRateLimiter,
    replay_capacity: usize,
    replay_cache: Arc<tokio::sync::Mutex<ReplayCache>>,
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
        let replay_cache = ReplayCache::new(DEFAULT_REPLAY_CAPACITY)
            .map_err(|_| EdgeConfigError::InvalidLimits)?;
        Ok(Self {
            verifier,
            max_token_bytes,
            relay_path,
            uniform_fallback: false,
            verification_rate_limiter: VerificationRateLimiter::new(
                DEFAULT_MAX_VERIFICATIONS_PER_SECOND,
            )
            .expect("default verification rate is bounded"),
            replay_capacity: DEFAULT_REPLAY_CAPACITY,
            replay_cache: Arc::new(tokio::sync::Mutex::new(replay_cache)),
        })
    }

    pub fn with_replay_capacity(mut self, capacity: usize) -> Result<Self, EdgeConfigError> {
        if (capacity as u64)
            < self
                .verification_rate_limiter
                .limit
                .saturating_mul(self.verifier.replay_retention_secs())
        {
            return Err(EdgeConfigError::InvalidLimits);
        }
        let replay_cache =
            ReplayCache::new(capacity).map_err(|_| EdgeConfigError::InvalidLimits)?;
        self.replay_capacity = capacity;
        self.replay_cache = Arc::new(tokio::sync::Mutex::new(replay_cache));
        Ok(self)
    }

    pub(crate) fn replay_capacity(&self) -> usize {
        self.replay_capacity
    }

    pub(crate) fn replay_cache(&self) -> Arc<tokio::sync::Mutex<ReplayCache>> {
        self.replay_cache.clone()
    }

    pub fn with_max_verifications_per_second(
        mut self,
        max_verifications_per_second: u64,
    ) -> Result<Self, EdgeConfigError> {
        if (self.replay_capacity as u64)
            < max_verifications_per_second.saturating_mul(self.verifier.replay_retention_secs())
        {
            return Err(EdgeConfigError::InvalidLimits);
        }
        self.verification_rate_limiter = VerificationRateLimiter::new(max_verifications_per_second)
            .ok_or(EdgeConfigError::InvalidLimits)?;
        Ok(self)
    }

    /// Experimental response normalization. It does not equalize timing or
    /// claim indistinguishability from an unrelated web service.
    pub fn with_uniform_fallback(mut self, enabled: bool) -> Self {
        self.uniform_fallback = enabled;
        self
    }

    pub fn decide(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        replay: &mut ReplayCache,
    ) -> FrontDoorDecision {
        match self.prepare(method, uri, headers) {
            FrontDoorPreparation::Verified(verified) => self.commit_verified(verified, replay),
            FrontDoorPreparation::Fallback(decision) => decision,
        }
    }

    pub(crate) fn prepare(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> FrontDoorPreparation {
        if uri.path() != self.relay_path || uri.query().is_some() {
            return self.fallback(FrontDoorResponse::not_found());
        }
        if method != Method::POST {
            return self.fallback(FrontDoorResponse::method_not_allowed());
        }
        let mut capability_values = headers.get_all(CAPABILITY_HEADER).iter();
        let Some(capability) = capability_values.next() else {
            return self.fallback(FrontDoorResponse::unauthorized());
        };
        if capability_values.next().is_some() {
            return self.fallback(FrontDoorResponse::unauthorized());
        }
        let Some(raw) = capability.to_str().ok() else {
            return self.fallback(FrontDoorResponse::unauthorized());
        };
        if raw.len() > self.max_token_bytes {
            return self.fallback(FrontDoorResponse::unauthorized());
        }
        if !self.verification_rate_limiter.try_acquire() {
            return self.fallback(FrontDoorResponse {
                status: StatusCode::TOO_MANY_REQUESTS,
                content_type: "text/plain; charset=utf-8",
                body: b"too many requests\n",
            });
        }
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        match self.verifier.verify_for_replay(raw, now) {
            Ok(verified) => FrontDoorPreparation::Verified(verified),
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
            ) => self.fallback(FrontDoorResponse::unauthorized()),
        }
    }

    pub(crate) fn commit_verified(
        &self,
        verified: VerifiedCapability,
        replay: &mut ReplayCache,
    ) -> FrontDoorDecision {
        let accepted = match crate::capability::unix_now() {
            Ok(now) => replay.consume(verified, now).is_ok(),
            Err(_) => false,
        };
        let decision = if accepted {
            FrontDoorDecision::Relay
        } else {
            FrontDoorDecision::Fallback(FrontDoorResponse::unauthorized())
        };
        self.normalize(decision)
    }

    fn fallback(&self, response: FrontDoorResponse) -> FrontDoorPreparation {
        FrontDoorPreparation::Fallback(self.normalize(FrontDoorDecision::Fallback(response)))
    }

    fn normalize(&self, decision: FrontDoorDecision) -> FrontDoorDecision {
        if self.uniform_fallback && matches!(decision, FrontDoorDecision::Fallback(_)) {
            FrontDoorDecision::Fallback(FrontDoorResponse::not_found())
        } else {
            decision
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
    fn verification_rate_limiter_bounds_concurrent_admission_and_resets() {
        let limiter = std::sync::Arc::new(VerificationRateLimiter::new(2).expect("limit"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let attempts = (0..16)
            .map(|_| {
                let limiter = limiter.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    limiter.try_acquire_in_window(0)
                })
            })
            .collect::<Vec<_>>();
        let admitted = attempts
            .into_iter()
            .map(|attempt| attempt.join().expect("thread"))
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, 2);
        assert!(limiter.try_acquire_in_window(1));
    }

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

    #[test]
    fn replay_capacity_must_cover_the_verification_rate_and_retention_window() {
        let make_front_door = || {
            let (issuer, _) = CapabilityIssuer::generate(Duration::from_secs(300)).expect("issuer");
            let verifier = CapabilityVerifier::new(
                issuer.public_key(),
                "edge-a",
                Duration::from_secs(300),
                Duration::from_secs(5),
            )
            .expect("verifier");
            FrontDoor::new(verifier, 4096)
        };

        assert!(make_front_door().with_replay_capacity(16 * 1024).is_err());
        assert!(make_front_door()
            .with_max_verifications_per_second(100_000)
            .is_err());
    }
}
