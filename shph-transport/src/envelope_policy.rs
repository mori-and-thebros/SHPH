//! Explicit, versioned policy agreement inside an authenticated session.
//! Legacy callers keep their existing wire path. Both peers must opt into this
//! exchange before application I/O; there is no automatic protocol sniffing.
use crate::phantom_one::{
    PhantomOneConfig, PhantomOneDecoder, PhantomOneEncoder, PhantomOneFrameType, SizeSelection,
};
use sha2::{Digest, Sha256};
use shph_core::{Result, ShphError};
use shph_obfuscation::ProfileTier;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const MAGIC: &[u8; 9] = b"SHPH-POL\x02";
pub const OFFER_BYTES: usize = 127;
const MAX_EXCHANGE_BYTES: usize = 512;
const PROFILE_MASK: u8 = 0b0011_1111;
const MAX_FRAME_BUDGET: u64 = 1 << 48;
const MAX_PAYLOAD_BUDGET: u64 = 1 << 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameBudget {
    pub max_frames: u64,
    pub max_payload_bytes: u64,
}

impl FrameBudget {
    fn validate(self) -> Result<()> {
        if self.max_frames == 0
            || self.max_frames > MAX_FRAME_BUDGET
            || self.max_payload_bytes == 0
            || self.max_payload_bytes > MAX_PAYLOAD_BUDGET
        {
            return Err(protocol("invalid directional frame budget"));
        }
        Ok(())
    }

    fn intersect(self, peer: Self) -> Self {
        Self {
            max_frames: self.max_frames.min(peer.max_frames),
            max_payload_bytes: self.max_payload_bytes.min(peer.max_payload_bytes),
        }
    }
}

impl Default for FrameBudget {
    fn default() -> Self {
        Self {
            max_frames: 1 << 32,
            max_payload_bytes: 1 << 40,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedPolicy {
    pub config: PhantomOneConfig,
    pub outbound_frame_limit: usize,
    pub inbound_frame_limit: usize,
    pub outbound_budget: FrameBudget,
    pub inbound_budget: FrameBudget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeOffer {
    binding: [u8; 32],
    supported_profiles: u8,
    pub config: PhantomOneConfig,
    pub outbound_frame_limit: u16,
    pub inbound_frame_limit: u16,
    pub outbound_budget: FrameBudget,
    pub inbound_budget: FrameBudget,
    pub cover: Option<crate::cover::CoverPolicy>,
}

impl EnvelopeOffer {
    pub fn new(transcript_hex: &str, config: PhantomOneConfig, frame_limit: usize) -> Result<Self> {
        if transcript_hex.len() != 64 || !transcript_hex.is_ascii() {
            return Err(protocol("policy requires a 32-byte transcript hash"));
        }
        let binding = parse_binding(transcript_hex)?;
        crate::phantom_one::validate_path_mtu(frame_limit)?;
        // Construction validates weights and all padding bounds.
        PhantomOneEncoder::from_seed_with_config(0, 0, config)?;
        Ok(Self {
            binding,
            supported_profiles: 1 << config.profile().id(),
            config,
            outbound_frame_limit: frame_limit as u16,
            inbound_frame_limit: frame_limit as u16,
            outbound_budget: FrameBudget::default(),
            inbound_budget: FrameBudget::default(),
            cover: None,
        })
    }

    pub fn with_supported_profiles(mut self, profiles: &[ProfileTier]) -> Result<Self> {
        if profiles.is_empty() || profiles.len() > 6 {
            return Err(protocol("policy must advertise 1..6 supported profiles"));
        }
        let mut mask = 0u8;
        for profile in profiles {
            let bit = 1 << profile.id();
            if mask & bit != 0 {
                return Err(protocol("duplicate supported policy profile"));
            }
            profile_config(self.config, *profile)?;
            mask |= bit;
        }
        if mask & (1 << self.config.profile().id()) == 0 {
            return Err(protocol("supported profiles omit the preferred profile"));
        }
        if !self.config.is_profile_bound() && mask != 1 << self.config.profile().id() {
            return Err(protocol(
                "multiple profiles require a profile-bound envelope configuration",
            ));
        }
        self.supported_profiles = mask;
        Ok(self)
    }

    pub fn with_directional_limits(mut self, outbound: usize, inbound: usize) -> Result<Self> {
        crate::phantom_one::validate_path_mtu(outbound)?;
        crate::phantom_one::validate_path_mtu(inbound)?;
        self.outbound_frame_limit =
            u16::try_from(outbound).map_err(|_| protocol("outbound frame limit is too large"))?;
        self.inbound_frame_limit =
            u16::try_from(inbound).map_err(|_| protocol("inbound frame limit is too large"))?;
        Ok(self)
    }

    pub fn with_directional_budgets(
        mut self,
        outbound: FrameBudget,
        inbound: FrameBudget,
    ) -> Result<Self> {
        outbound.validate()?;
        inbound.validate()?;
        self.outbound_budget = outbound;
        self.inbound_budget = inbound;
        Ok(self)
    }

    pub fn with_cover(mut self, cover: Option<crate::cover::CoverPolicy>) -> Result<Self> {
        if let Some(policy) = cover {
            policy.validate()?;
        }
        self.cover = cover;
        Ok(self)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(OFFER_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.binding);
        bytes.push(self.config.profile().id());
        bytes.push(self.supported_profiles);
        bytes.push(u8::from(self.config.is_profile_bound()));
        bytes.extend_from_slice(&(self.config.min_padding() as u16).to_be_bytes());
        bytes.extend_from_slice(&(self.config.max_padding() as u16).to_be_bytes());
        let (tag, weights) = match self.config.selection() {
            SizeSelection::FirstFit => (0, [0; 7]),
            SizeSelection::Weighted(weights) => (1, weights),
        };
        bytes.push(tag);
        for weight in weights {
            bytes.extend_from_slice(&weight.to_be_bytes());
        }
        bytes.push(u8::from(self.config.padding_budget().is_some()));
        bytes.extend_from_slice(&self.config.padding_budget().unwrap_or(0).to_be_bytes());
        bytes.extend_from_slice(&self.outbound_frame_limit.to_be_bytes());
        bytes.extend_from_slice(&self.inbound_frame_limit.to_be_bytes());
        bytes.extend_from_slice(&self.outbound_budget.max_frames.to_be_bytes());
        bytes.extend_from_slice(&self.outbound_budget.max_payload_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.inbound_budget.max_frames.to_be_bytes());
        bytes.extend_from_slice(&self.inbound_budget.max_payload_bytes.to_be_bytes());
        if let Some(cover) = self.cover {
            bytes.push(1);
            bytes.extend_from_slice(&cover.interval_ms.to_be_bytes());
            bytes.extend_from_slice(&cover.idle_timeout_ms.to_be_bytes());
            bytes.extend_from_slice(&cover.maximum_bytes.to_be_bytes());
            bytes.extend_from_slice(&cover.overhead_percent.to_be_bytes());
        } else {
            bytes.extend_from_slice(&[0; 19]);
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != OFFER_BYTES || &bytes[..9] != MAGIC {
            return Err(protocol("unsupported or malformed envelope policy"));
        }
        let profile =
            ProfileTier::from_id(bytes[41]).ok_or_else(|| protocol("unknown policy profile"))?;
        let supported_profiles = bytes[42];
        if supported_profiles == 0
            || supported_profiles & !PROFILE_MASK != 0
            || supported_profiles & (1 << profile.id()) == 0
        {
            return Err(protocol("invalid supported-profile set"));
        }
        let mut config = PhantomOneConfig::new(
            u16::from_be_bytes([bytes[44], bytes[45]]) as usize,
            u16::from_be_bytes([bytes[46], bytes[47]]) as usize,
        )?;
        match bytes[43] {
            0 if profile == ProfileTier::Medium => {}
            1 => config = config.with_profile(profile),
            _ => return Err(protocol("noncanonical profile binding")),
        }
        let mut weights = [0; 7];
        for (i, weight) in weights.iter_mut().enumerate() {
            *weight = u16::from_be_bytes([bytes[49 + i * 2], bytes[50 + i * 2]]);
        }
        config = config.with_selection(match bytes[48] {
            0 if weights == [0; 7] => SizeSelection::FirstFit,
            1 => SizeSelection::Weighted(weights),
            _ => return Err(protocol("invalid policy selection")),
        })?;
        let padding_budget = u64::from_be_bytes(bytes[64..72].try_into().unwrap());
        match bytes[63] {
            0 if padding_budget == 0 => {}
            1 => config = config.with_padding_budget(padding_budget),
            _ => return Err(protocol("invalid padding budget encoding")),
        }
        let outbound_frame_limit = u16::from_be_bytes([bytes[72], bytes[73]]);
        let inbound_frame_limit = u16::from_be_bytes([bytes[74], bytes[75]]);
        crate::phantom_one::validate_path_mtu(outbound_frame_limit as usize)?;
        crate::phantom_one::validate_path_mtu(inbound_frame_limit as usize)?;
        let outbound_budget = FrameBudget {
            max_frames: u64::from_be_bytes(bytes[76..84].try_into().unwrap()),
            max_payload_bytes: u64::from_be_bytes(bytes[84..92].try_into().unwrap()),
        };
        let inbound_budget = FrameBudget {
            max_frames: u64::from_be_bytes(bytes[92..100].try_into().unwrap()),
            max_payload_bytes: u64::from_be_bytes(bytes[100..108].try_into().unwrap()),
        };
        outbound_budget.validate()?;
        inbound_budget.validate()?;
        for id in 0..6 {
            if supported_profiles & (1 << id) != 0 {
                let supported =
                    ProfileTier::from_id(id).ok_or_else(|| protocol("unknown policy profile"))?;
                profile_config(config, supported)?;
            }
        }
        let cover = match bytes[108] {
            0 if bytes[109..].iter().all(|byte| *byte == 0) => None,
            1 => {
                let policy = crate::cover::CoverPolicy {
                    interval_ms: u32::from_be_bytes(bytes[109..113].try_into().unwrap()),
                    idle_timeout_ms: u32::from_be_bytes(bytes[113..117].try_into().unwrap()),
                    maximum_bytes: u64::from_be_bytes(bytes[117..125].try_into().unwrap()),
                    overhead_percent: u16::from_be_bytes(bytes[125..127].try_into().unwrap()),
                };
                policy.validate()?;
                Some(policy)
            }
            _ => return Err(protocol("invalid cover policy encoding")),
        };
        Ok(Self {
            binding: bytes[9..41].try_into().unwrap(),
            supported_profiles,
            config,
            outbound_frame_limit,
            inbound_frame_limit,
            outbound_budget,
            inbound_budget,
            cover,
        })
    }

    pub fn agree(&self, peer: &Self) -> Result<usize> {
        let agreement = self.negotiate(peer)?;
        Ok(agreement
            .outbound_frame_limit
            .min(agreement.inbound_frame_limit))
    }

    pub fn negotiate(&self, peer: &Self) -> Result<NegotiatedPolicy> {
        if self.binding != peer.binding
            || !same_policy_settings(self.config, peer.config)
            || self.cover != peer.cover
        {
            return Err(protocol(
                "envelope policies or authenticated sessions do not match",
            ));
        }
        let common = self.supported_profiles & peer.supported_profiles;
        let profile = (0..6)
            .filter(|id| common & (1 << id) != 0)
            .filter_map(ProfileTier::from_id)
            .min_by_key(|profile| {
                (
                    usize::from(*profile != self.config.profile())
                        + usize::from(*profile != peer.config.profile()),
                    profile.id(),
                )
            })
            .ok_or_else(|| protocol("peers have no common envelope profile"))?;
        let config = profile_config(self.config, profile)?;
        profile_config(peer.config, profile)?;
        Ok(NegotiatedPolicy {
            config,
            outbound_frame_limit: usize::from(
                self.outbound_frame_limit.min(peer.inbound_frame_limit),
            ),
            inbound_frame_limit: usize::from(
                self.inbound_frame_limit.min(peer.outbound_frame_limit),
            ),
            outbound_budget: self.outbound_budget.intersect(peer.inbound_budget),
            inbound_budget: self.inbound_budget.intersect(peer.outbound_budget),
        })
    }

    pub fn acknowledgement(&self, peer: &Self) -> Result<[u8; 32]> {
        let agreement = self.negotiate(peer)?;
        let local = self.encode();
        let remote = peer.encode();
        let local_first = local <= remote;
        let mut offers = [local, remote];
        offers.sort();
        let mut hash = Sha256::new();
        hash.update(b"SHPH-policy-ack-v2\0");
        for offer in offers {
            hash.update(offer);
        }
        hash.update([agreement.config.profile().id()]);
        let (first_frame_limit, second_frame_limit, first_budget, second_budget) = if local_first {
            (
                agreement.outbound_frame_limit,
                agreement.inbound_frame_limit,
                agreement.outbound_budget,
                agreement.inbound_budget,
            )
        } else {
            (
                agreement.inbound_frame_limit,
                agreement.outbound_frame_limit,
                agreement.inbound_budget,
                agreement.outbound_budget,
            )
        };
        hash.update((first_frame_limit as u16).to_be_bytes());
        hash.update((second_frame_limit as u16).to_be_bytes());
        for budget in [first_budget, second_budget] {
            hash.update(budget.max_frames.to_be_bytes());
            hash.update(budget.max_payload_bytes.to_be_bytes());
        }
        Ok(hash.finalize().into())
    }
}

fn same_policy_settings(left: PhantomOneConfig, right: PhantomOneConfig) -> bool {
    left.min_padding() == right.min_padding()
        && left.max_padding() == right.max_padding()
        && left.selection() == right.selection()
        && left.padding_budget() == right.padding_budget()
        && left.is_profile_bound() == right.is_profile_bound()
}

fn profile_config(config: PhantomOneConfig, profile: ProfileTier) -> Result<PhantomOneConfig> {
    let candidate = if config.is_profile_bound() {
        config.with_profile(profile)
    } else if config.profile() == profile {
        config
    } else {
        return Err(protocol(
            "unbound envelope policy supports only its configured profile",
        ));
    };
    PhantomOneEncoder::from_seed_with_config(0, 0, candidate)?;
    Ok(candidate)
}

fn protocol(message: &str) -> ShphError {
    ShphError::Protocol(message.into())
}

fn parse_binding(transcript_hex: &str) -> Result<[u8; 32]> {
    if transcript_hex.len() != 64 || !transcript_hex.is_ascii() {
        return Err(protocol("policy requires a 32-byte transcript hash"));
    }
    let mut binding = [0; 32];
    for (index, value) in binding.iter_mut().enumerate() {
        *value = u8::from_str_radix(&transcript_hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| protocol("invalid transcript hash"))?;
    }
    Ok(binding)
}

/// Owns the connection so failed negotiation cannot yield an application path.
pub struct NegotiatedTcp {
    session: crate::SecureSession,
    encoder: PhantomOneEncoder,
    decoder: PhantomOneDecoder,
    outbound_frame_limit: usize,
    inbound_frame_limit: usize,
    outbound_budget: FrameBudget,
    inbound_budget: FrameBudget,
    sent_usage: FrameUsage,
    received_usage: FrameUsage,
    cover: crate::cover::CoverScheduler,
    cover_policy: Option<crate::cover::CoverPolicy>,
    received_cover_bytes: u64,
    origin: Instant,
}

#[derive(Default)]
struct FrameUsage {
    frames: u64,
    payload_bytes: u64,
}

impl FrameUsage {
    fn reserve(&mut self, budget: FrameBudget, payload_bytes: usize) -> Result<()> {
        let frames = self
            .frames
            .checked_add(1)
            .ok_or_else(|| ShphError::ResourceExhausted("frame budget exhausted".into()))?;
        let payload_bytes = self
            .payload_bytes
            .checked_add(payload_bytes as u64)
            .ok_or_else(|| ShphError::ResourceExhausted("payload budget exhausted".into()))?;
        if frames > budget.max_frames || payload_bytes > budget.max_payload_bytes {
            return Err(ShphError::ResourceExhausted(
                "negotiated directional frame budget exhausted".into(),
            ));
        }
        self.frames = frames;
        self.payload_bytes = payload_bytes;
        Ok(())
    }
}

#[derive(Default)]
struct ReceivedCoverUsage {
    bytes: u64,
}

impl ReceivedCoverUsage {
    fn reserve(&mut self, policy: crate::cover::CoverPolicy, bytes: usize) -> Result<()> {
        let next = self
            .bytes
            .checked_add(bytes as u64)
            .ok_or_else(|| protocol("cover traffic byte counter overflow"))?;
        if next > policy.maximum_bytes {
            return Err(protocol("cover traffic exceeds absolute policy budget"));
        }
        self.bytes = next;
        Ok(())
    }

    fn validate_payload(
        &self,
        policy: crate::cover::CoverPolicy,
        payload_bytes: u64,
    ) -> Result<()> {
        if cover_budget_allows(policy, payload_bytes, self.bytes) {
            Ok(())
        } else {
            Err(protocol("cover traffic exceeds relative policy budget"))
        }
    }
}

fn cover_budget_allows(
    policy: crate::cover::CoverPolicy,
    payload_bytes: u64,
    cover_bytes: u64,
) -> bool {
    let relative_allowance = u128::from(payload_bytes) * u128::from(policy.overhead_percent) / 100;
    u128::from(cover_bytes) <= relative_allowance.min(u128::from(policy.maximum_bytes))
}

impl NegotiatedTcp {
    pub fn establish(
        session: crate::SecureSession,
        transcript: &str,
        config: PhantomOneConfig,
        frame_limit: usize,
        timeout: Duration,
    ) -> Result<Self> {
        Self::establish_with_cover(session, transcript, config, frame_limit, timeout, None)
    }

    pub fn establish_with_cover(
        session: crate::SecureSession,
        transcript: &str,
        config: PhantomOneConfig,
        frame_limit: usize,
        timeout: Duration,
        cover_policy: Option<crate::cover::CoverPolicy>,
    ) -> Result<Self> {
        let offer = EnvelopeOffer::new(
            transcript,
            config,
            frame_limit.min(crate::MAX_TCP_PAYLOAD_BYTES),
        )?
        .with_cover(cover_policy)?;
        Self::establish_with_offer(session, transcript, offer, timeout)
    }

    pub fn establish_with_offer(
        mut session: crate::SecureSession,
        transcript: &str,
        offer: EnvelopeOffer,
        timeout: Duration,
    ) -> Result<Self> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(protocol("policy timeout must be 1ns..60s"));
        }
        let authenticated_binding = parse_binding(&session.transcript_hash_hex)?;
        if offer.binding != authenticated_binding || offer.binding != parse_binding(transcript)? {
            return Err(protocol(
                "policy offer is not bound to this authenticated session",
            ));
        }
        let cover_policy = offer.cover;
        let crate::SecureSessionInner::Tcp(tcp) = &mut session.inner else {
            return Err(protocol("TCP policy exchange requires TCP"));
        };
        let read_timeout = tcp.stream.read_timeout().map_err(crate::map_io_error)?;
        let write_timeout = tcp.stream.write_timeout().map_err(crate::map_io_error)?;
        let deadline = Instant::now() + timeout;
        fn send(tcp: &mut crate::SecureTcpSession, bytes: &[u8], deadline: Instant) -> Result<()> {
            let encrypted = tcp.send_cipher.encrypt(bytes)?;
            crate::write_tcp_all_or_closed_with_deadline(
                &mut tcp.stream,
                &(encrypted.len() as u32).to_be_bytes(),
                deadline,
            )?;
            crate::write_tcp_all_or_closed_with_deadline(&mut tcp.stream, &encrypted, deadline)
        }
        fn recv(tcp: &mut crate::SecureTcpSession, deadline: Instant) -> Result<Vec<u8>> {
            let mut length = [0; 4];
            crate::read_exact_or_closed_with_deadline(&mut tcp.stream, &mut length, deadline)?;
            let length = u32::from_be_bytes(length) as usize;
            if !(28..=MAX_EXCHANGE_BYTES).contains(&length) {
                return Err(protocol("oversized policy exchange"));
            }
            let mut bytes = vec![0; length];
            crate::read_exact_or_closed_with_deadline(&mut tcp.stream, &mut bytes, deadline)?;
            tcp.recv_cipher.decrypt(&bytes)
        }
        send(tcp, &offer.encode(), deadline)?;
        let peer = EnvelopeOffer::decode(&recv(tcp, deadline)?)?;
        let agreement = offer.negotiate(&peer)?;
        let ack = offer.acknowledgement(&peer)?;
        send(tcp, &ack, deadline)?;
        if recv(tcp, deadline)?.as_slice() != ack {
            return Err(protocol("policy acknowledgement mismatch"));
        }
        tcp.stream
            .set_read_timeout(read_timeout)
            .map_err(crate::map_io_error)?;
        tcp.stream
            .set_write_timeout(write_timeout)
            .map_err(crate::map_io_error)?;
        tcp.padding_profile = None;
        tcp.padding_padder = None;
        tcp.phantom_one_encoder = None;
        tcp.phantom_one_decoder = None;
        let generation =
            crate::phantom_one_generation_from_transcript(&session.transcript_hash_hex)?;
        Ok(Self {
            session,
            encoder: PhantomOneEncoder::with_config(generation, agreement.config)?,
            decoder: PhantomOneDecoder::with_config(generation, agreement.config)?,
            outbound_frame_limit: agreement.outbound_frame_limit,
            inbound_frame_limit: agreement.inbound_frame_limit,
            outbound_budget: agreement.outbound_budget,
            inbound_budget: agreement.inbound_budget,
            sent_usage: FrameUsage::default(),
            received_usage: FrameUsage::default(),
            cover: crate::cover::CoverScheduler::new(cover_policy)?,
            cover_policy,
            received_cover_bytes: 0,
            origin: Instant::now(),
        })
    }

    pub fn send(&mut self, payload: &[u8]) -> Result<()> {
        if self.sent_usage.frames >= self.outbound_budget.max_frames
            || self
                .sent_usage
                .payload_bytes
                .checked_add(payload.len() as u64)
                .is_none_or(|bytes| bytes > self.outbound_budget.max_payload_bytes)
        {
            return Err(ShphError::ResourceExhausted(
                "negotiated outbound frame budget exhausted".into(),
            ));
        }
        let envelope = Zeroizing::new(self.encoder.encode(
            PhantomOneFrameType::Data,
            payload,
            self.outbound_frame_limit,
        )?);
        self.sent_usage
            .reserve(self.outbound_budget, payload.len())?;
        self.session.send_frame(&envelope)?;
        self.cover
            .record_payload(self.origin.elapsed(), payload.len())
    }

    pub fn send_cover_if_due(
        &mut self,
        payload_pending: bool,
        congested: bool,
        cancelled: bool,
    ) -> Result<bool> {
        if self.sent_usage.frames >= self.outbound_budget.max_frames {
            return Err(ShphError::ResourceExhausted(
                "negotiated outbound frame budget exhausted".into(),
            ));
        }
        let target = self.encoder.target_size(1, self.outbound_frame_limit)?;
        if !self.cover.reserve(
            self.origin.elapsed(),
            target + 32,
            payload_pending,
            congested,
            cancelled,
        )? {
            return Ok(false);
        }
        self.sent_usage.reserve(self.outbound_budget, 0)?;
        let envelope = Zeroizing::new(self.encoder.encode_with_target(
            PhantomOneFrameType::Keepalive,
            &[0],
            target,
            self.outbound_frame_limit,
        )?);
        self.session.send_frame(&envelope)?;
        Ok(true)
    }

    pub fn recv(&mut self) -> Result<Vec<u8>> {
        for _ in 0..32 {
            let envelope = Zeroizing::new(self.session.recv_frame()?);
            let frame = self.decoder.decode(&envelope, self.inbound_frame_limit)?;
            if frame.frame_type == PhantomOneFrameType::Keepalive {
                let policy = self
                    .cover_policy
                    .ok_or_else(|| protocol("cover traffic was not negotiated"))?;
                self.received_usage.reserve(self.inbound_budget, 0)?;
                self.received_cover_bytes = self
                    .received_cover_bytes
                    .saturating_add(envelope.len() as u64 + 32);
                if frame.payload != [0]
                    || !cover_budget_allows(
                        policy,
                        self.received_usage.payload_bytes,
                        self.received_cover_bytes,
                    )
                {
                    return Err(protocol("cover traffic exceeds policy"));
                }
                continue;
            }
            if frame.frame_type != PhantomOneFrameType::Data {
                return Err(protocol("unexpected policy frame type"));
            }
            self.received_usage
                .reserve(self.inbound_budget, frame.payload.len())?;
            return Ok(frame.payload.clone());
        }
        Err(ShphError::ResourceExhausted(
            "too many consecutive cover frames".into(),
        ))
    }
}

/// Datagram policy exchange on the authenticated QUIC control stream.
/// This wrapper deliberately owns all data-plane key/sequence state.
pub struct NegotiatedQuic {
    transport: crate::standards_quic::StandardsQuicConnection,
    encoder: PhantomOneEncoder,
    decoder: PhantomOneDecoder,
    send_cipher: shph_core::SendCipher,
    recv_cipher: shph_core::ReceiveCipher,
    outbound_frame_limit: usize,
    inbound_frame_limit: usize,
    outbound_budget: FrameBudget,
    inbound_budget: FrameBudget,
    sent_usage: FrameUsage,
    received_usage: FrameUsage,
    cover: crate::cover::CoverScheduler,
    cover_policy: Option<crate::cover::CoverPolicy>,
    received_cover: ReceivedCoverUsage,
    origin: Instant,
}

impl NegotiatedQuic {
    pub async fn establish(
        transport: crate::standards_quic::StandardsQuicConnection,
        config: PhantomOneConfig,
        frame_limit: usize,
        negotiation_timeout: Duration,
    ) -> Result<Self> {
        let offer = EnvelopeOffer::new(
            &transport.handshake.transcript_hash_hex,
            config,
            frame_limit,
        )?;
        Self::establish_with_offer(transport, offer, negotiation_timeout).await
    }

    pub async fn establish_with_offer(
        mut transport: crate::standards_quic::StandardsQuicConnection,
        mut offer: EnvelopeOffer,
        negotiation_timeout: Duration,
    ) -> Result<Self> {
        if transport.phantom_one_profile().is_some()
            || transport.phantom_one_negotiated()
            || negotiation_timeout.is_zero()
            || negotiation_timeout > Duration::from_secs(60)
            || offer.binding != parse_binding(&transport.handshake.transcript_hash_hex)?
        {
            transport
                .connection
                .close(0u32.into(), b"policy setup rejected");
            return Err(protocol(
                "policy exchange must be session-bound, precede data-plane enablement, and use a bounded timeout",
            ));
        }

        let carrier_limit = transport
            .connection
            .max_datagram_size()
            .and_then(|size| size.checked_sub(crate::standards_quic::SHPH_AEAD_OVERHEAD_BYTES))
            .ok_or_else(|| protocol("no usable QUIC datagram budget"))?;
        let outbound_limit = usize::from(offer.outbound_frame_limit).min(carrier_limit);
        let inbound_limit = usize::from(offer.inbound_frame_limit).min(carrier_limit);
        offer = offer.with_directional_limits(outbound_limit, inbound_limit)?;
        let cover_policy = offer.cover;

        let result = tokio::time::timeout(negotiation_timeout, async {
            transport.send_control(&offer.encode()).await?;
            let peer = EnvelopeOffer::decode(&transport.recv_control().await?)?;
            let agreement = offer.negotiate(&peer)?;
            let ack = offer.acknowledgement(&peer)?;
            transport.send_control(&ack).await?;
            if transport.recv_control().await?.as_slice() != ack {
                return Err(protocol("policy acknowledgement mismatch"));
            }
            Ok::<NegotiatedPolicy, ShphError>(agreement)
        })
        .await;
        let agreement = match result {
            Ok(Ok(agreement)) => agreement,
            Ok(Err(error)) => {
                transport
                    .connection
                    .close(0u32.into(), b"policy agreement failed");
                return Err(error);
            }
            Err(_) => {
                transport
                    .connection
                    .close(0u32.into(), b"policy agreement timed out");
                return Err(ShphError::Timeout);
            }
        };
        let generation = crate::phantom_one_generation_from_transcript(
            &transport.handshake.transcript_hash_hex,
        )?;
        let config = agreement.config;
        Ok(Self {
            encoder: PhantomOneEncoder::with_config(generation, config)?,
            decoder: PhantomOneDecoder::with_config(generation, config)?,
            send_cipher: shph_core::SendCipher::new(transport.handshake.session_keys.send_key),
            recv_cipher: shph_core::ReceiveCipher::new_with_replay_window(
                transport.handshake.session_keys.recv_key,
                64,
            ),
            transport,
            outbound_frame_limit: agreement.outbound_frame_limit,
            inbound_frame_limit: agreement.inbound_frame_limit,
            outbound_budget: agreement.outbound_budget,
            inbound_budget: agreement.inbound_budget,
            sent_usage: FrameUsage::default(),
            received_usage: FrameUsage::default(),
            cover: crate::cover::CoverScheduler::new(cover_policy)?,
            cover_policy,
            received_cover: ReceivedCoverUsage::default(),
            origin: Instant::now(),
        })
    }

    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        if self.sent_usage.frames >= self.outbound_budget.max_frames
            || self
                .sent_usage
                .payload_bytes
                .checked_add(payload.len() as u64)
                .is_none_or(|bytes| bytes > self.outbound_budget.max_payload_bytes)
        {
            return Err(ShphError::ResourceExhausted(
                "negotiated outbound frame budget exhausted".into(),
            ));
        }
        let limit = self.current_frame_limit(self.outbound_frame_limit)?;
        let envelope = Zeroizing::new(self.encoder.encode(
            PhantomOneFrameType::Data,
            payload,
            limit,
        )?);
        self.sent_usage
            .reserve(self.outbound_budget, payload.len())?;
        let ciphertext = self.send_cipher.encrypt(&envelope)?;
        self.transport.send_datagram_wait(&ciphertext).await?;
        self.cover
            .record_payload(self.origin.elapsed(), payload.len())
    }

    pub async fn send_control(&mut self, payload: &[u8]) -> Result<()> {
        self.transport.send_control(payload).await
    }

    pub async fn recv_control(&mut self) -> Result<Vec<u8>> {
        self.transport.recv_control().await
    }

    pub async fn send_cover_if_due(
        &mut self,
        payload_pending: bool,
        congested: bool,
        cancelled: bool,
    ) -> Result<bool> {
        if self.sent_usage.frames >= self.outbound_budget.max_frames {
            return Err(ShphError::ResourceExhausted(
                "negotiated outbound frame budget exhausted".into(),
            ));
        }
        let limit = self.current_frame_limit(self.outbound_frame_limit)?;
        let target = self.encoder.target_size(1, limit)?;
        if !self.cover.reserve(
            self.origin.elapsed(),
            target + crate::standards_quic::SHPH_AEAD_OVERHEAD_BYTES,
            payload_pending,
            congested,
            cancelled,
        )? {
            return Ok(false);
        }
        let envelope = Zeroizing::new(self.encoder.encode_with_target(
            PhantomOneFrameType::Keepalive,
            &[0],
            target,
            limit,
        )?);
        self.sent_usage.reserve(self.outbound_budget, 0)?;
        let ciphertext = self.send_cipher.encrypt(&envelope)?;
        self.transport.send_datagram_wait(&ciphertext).await?;
        Ok(true)
    }

    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        for _ in 0..32 {
            let ciphertext = self.transport.recv_datagram().await?;
            let limit = self.current_frame_limit(self.inbound_frame_limit)?;
            if ciphertext.len() > limit + crate::standards_quic::SHPH_AEAD_OVERHEAD_BYTES {
                return Err(protocol("received datagram exceeds agreed policy"));
            }
            let envelope = Zeroizing::new(self.recv_cipher.decrypt(&ciphertext)?);
            let frame = self.decoder.decode(&envelope, limit)?;
            if frame.frame_type == PhantomOneFrameType::Keepalive {
                let policy = self
                    .cover_policy
                    .ok_or_else(|| protocol("cover traffic was not negotiated"))?;
                if frame.payload != [0] {
                    return Err(protocol("cover traffic exceeds policy"));
                }
                self.received_cover.reserve(policy, ciphertext.len())?;
                self.received_usage.reserve(self.inbound_budget, 0)?;
                continue;
            }
            if frame.frame_type != PhantomOneFrameType::Data {
                return Err(protocol("unexpected policy frame type"));
            }
            let next_payload_bytes = self
                .received_usage
                .payload_bytes
                .checked_add(frame.payload.len() as u64)
                .ok_or_else(|| protocol("received payload byte counter overflow"))?;
            if let Some(policy) = self.cover_policy {
                self.received_cover
                    .validate_payload(policy, next_payload_bytes)?;
            }
            self.received_usage
                .reserve(self.inbound_budget, frame.payload.len())?;
            return Ok(frame.payload.clone());
        }
        Err(ShphError::ResourceExhausted(
            "too many consecutive cover frames".into(),
        ))
    }

    fn current_frame_limit(&self, negotiated_limit: usize) -> Result<usize> {
        self.transport
            .connection
            .max_datagram_size()
            .and_then(|size| size.checked_sub(crate::standards_quic::SHPH_AEAD_OVERHEAD_BYTES))
            .map(|current| current.min(negotiated_limit))
            .ok_or_else(|| protocol("no usable QUIC datagram budget"))
    }
}

impl Drop for NegotiatedQuic {
    fn drop(&mut self) {
        self.transport
            .connection
            .close(0u32.into(), b"policy session closed");
    }
}

#[cfg(test)]
pub(crate) async fn send_quic_cover_without_scheduler(session: &mut NegotiatedQuic) -> Result<()> {
    let target = crate::phantom_one::PHANTOM_ONE_HEADER_BYTES + 1;
    let envelope = Zeroizing::new(session.encoder.encode_with_target(
        PhantomOneFrameType::Keepalive,
        &[0],
        target,
        session.outbound_frame_limit,
    )?);
    let ciphertext = session.send_cipher.encrypt(&envelope)?;
    session.transport.send_datagram_wait(&ciphertext).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_cover_pair(cover: crate::cover::CoverPolicy) -> (NegotiatedTcp, NegotiatedTcp) {
        let transcript = "ab".repeat(32);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_transcript = transcript.clone();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let session = crate::SecureSession {
                inner: crate::SecureSessionInner::Tcp(Box::new(crate::SecureTcpSession::new(
                    stream, [2; 32], [1; 32],
                ))),
                transcript_hash_hex: server_transcript.clone(),
            };
            NegotiatedTcp::establish_with_cover(
                session,
                &server_transcript,
                PhantomOneConfig::new(0, 0).unwrap(),
                1360,
                Duration::from_secs(2),
                Some(cover),
            )
            .unwrap()
        });

        let stream = std::net::TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let session = crate::SecureSession {
            inner: crate::SecureSessionInner::Tcp(Box::new(crate::SecureTcpSession::new(
                stream, [1; 32], [2; 32],
            ))),
            transcript_hash_hex: transcript.clone(),
        };
        let sender = NegotiatedTcp::establish_with_cover(
            session,
            &transcript,
            PhantomOneConfig::new(0, 0).unwrap(),
            1360,
            Duration::from_secs(2),
            Some(cover),
        )
        .unwrap();
        (sender, server.join().unwrap())
    }

    fn send_tcp_cover_without_scheduler(session: &mut NegotiatedTcp) {
        let target = crate::phantom_one::PHANTOM_ONE_HEADER_BYTES + 1;
        let envelope = session
            .encoder
            .encode_with_target(
                PhantomOneFrameType::Keepalive,
                &[0],
                target,
                session.outbound_frame_limit,
            )
            .unwrap();
        session.session.send_frame(&envelope).unwrap();
    }

    #[test]
    fn receive_cover_budget_requires_data_and_caps_cumulative_bytes() {
        let policy = crate::cover::CoverPolicy {
            interval_ms: 100,
            idle_timeout_ms: 1_000,
            maximum_bytes: 500,
            overhead_percent: 10,
        };

        assert!(!cover_budget_allows(policy, 0, 1));
        assert!(cover_budget_allows(policy, 3_000, 300));
        assert!(!cover_budget_allows(policy, 3_000, 301));
        assert!(!cover_budget_allows(policy, 100_000, 501));
    }

    #[test]
    fn quic_cover_budget_handles_reordered_frames_and_caps_bytes() {
        let policy = crate::cover::CoverPolicy {
            interval_ms: 100,
            idle_timeout_ms: 1_000,
            maximum_bytes: 500,
            overhead_percent: 10,
        };
        let mut received = ReceivedCoverUsage::default();

        received.reserve(policy, 20).expect("cover before data");
        assert!(received.validate_payload(policy, 1_000).is_ok());
        assert!(received.validate_payload(policy, 100).is_err());
        assert!(received.reserve(policy, 481).is_err());
        assert_eq!(received.bytes, 20);
    }

    #[test]
    fn tcp_receive_rejects_cover_before_application_data() {
        let policy = crate::cover::CoverPolicy {
            interval_ms: 100,
            idle_timeout_ms: 1_000,
            maximum_bytes: 4_096,
            overhead_percent: 10,
        };
        let (mut sender, mut receiver) = tcp_cover_pair(policy);

        send_tcp_cover_without_scheduler(&mut sender);
        assert!(matches!(receiver.recv(), Err(ShphError::Protocol(_))));
    }

    #[test]
    fn tcp_receive_enforces_cumulative_cover_overhead() {
        let policy = crate::cover::CoverPolicy {
            interval_ms: 100,
            idle_timeout_ms: 1_000,
            maximum_bytes: 4_096,
            overhead_percent: 10,
        };
        let (mut sender, mut receiver) = tcp_cover_pair(policy);

        let payload = vec![0x5a; 1024];
        sender.send(&payload).unwrap();
        assert_eq!(receiver.recv().unwrap(), payload);
        send_tcp_cover_without_scheduler(&mut sender);
        sender.send(b"after-first-cover").unwrap();
        assert_eq!(receiver.recv().unwrap(), b"after-first-cover");
        send_tcp_cover_without_scheduler(&mut sender);
        assert!(matches!(receiver.recv(), Err(ShphError::Protocol(_))));
    }

    #[test]
    fn policy_codec_binding_and_downgrade_checks() {
        let config = PhantomOneConfig::for_profile(ProfileTier::Medium)
            .with_selection(SizeSelection::Weighted([1, 2, 3, 4, 5, 0, 0]))
            .unwrap()
            .with_padding_budget(10000);
        let offer = EnvelopeOffer::new(&"ab".repeat(32), config, 1360).unwrap();
        let encoded = offer.encode();
        assert_eq!(encoded.len(), OFFER_BYTES);
        assert_eq!(EnvelopeOffer::decode(&encoded).unwrap(), offer);
        for cut in 0..encoded.len() {
            assert!(EnvelopeOffer::decode(&encoded[..cut]).is_err());
        }
        let peer = EnvelopeOffer::new(&"ab".repeat(32), config, 1200).unwrap();
        assert_eq!(offer.agree(&peer).unwrap(), 1200);
        assert_eq!(
            offer.acknowledgement(&peer).unwrap(),
            peer.acknowledgement(&offer).unwrap()
        );
        assert!(offer
            .agree(&EnvelopeOffer::new(&"cd".repeat(32), config, 1360).unwrap())
            .is_err());
        assert!(offer
            .agree(
                &EnvelopeOffer::new(&"ab".repeat(32), PhantomOneConfig::default(), 1360).unwrap()
            )
            .is_err());
        let mut unknown = encoded;
        unknown[8] = 3;
        assert!(EnvelopeOffer::decode(&unknown).is_err());

        let mut excessive_profiles = offer.encode();
        excessive_profiles[42] |= 0b1000_0000;
        assert!(EnvelopeOffer::decode(&excessive_profiles).is_err());

        let mut zero_budget = offer.encode();
        zero_budget[76..84].fill(0);
        assert!(EnvelopeOffer::decode(&zero_budget).is_err());
    }

    #[test]
    fn policy_agreement_intersects_profiles_directional_limits_and_budgets() {
        let local = EnvelopeOffer::new(
            &"ab".repeat(32),
            PhantomOneConfig::for_profile(ProfileTier::Medium),
            1450,
        )
        .unwrap()
        .with_supported_profiles(&[ProfileTier::Medium, ProfileTier::High])
        .unwrap()
        .with_directional_limits(1450, 1250)
        .unwrap()
        .with_directional_budgets(
            FrameBudget {
                max_frames: 90,
                max_payload_bytes: 900,
            },
            FrameBudget {
                max_frames: 80,
                max_payload_bytes: 800,
            },
        )
        .unwrap();
        let peer = EnvelopeOffer::new(
            &"ab".repeat(32),
            PhantomOneConfig::for_profile(ProfileTier::High),
            1400,
        )
        .unwrap()
        .with_supported_profiles(&[ProfileTier::High, ProfileTier::Medium])
        .unwrap()
        .with_directional_limits(1170, 1340)
        .unwrap()
        .with_directional_budgets(
            FrameBudget {
                max_frames: 70,
                max_payload_bytes: 700,
            },
            FrameBudget {
                max_frames: 60,
                max_payload_bytes: 600,
            },
        )
        .unwrap();

        let negotiated = local.negotiate(&peer).unwrap();
        assert!(matches!(
            negotiated.config.profile(),
            ProfileTier::Medium | ProfileTier::High
        ));
        assert_eq!(negotiated.outbound_frame_limit, 1340);
        assert_eq!(negotiated.inbound_frame_limit, 1170);
        assert_eq!(
            negotiated.outbound_budget,
            FrameBudget {
                max_frames: 60,
                max_payload_bytes: 600,
            }
        );
        assert_eq!(
            negotiated.inbound_budget,
            FrameBudget {
                max_frames: 70,
                max_payload_bytes: 700,
            }
        );
        assert_eq!(
            local.acknowledgement(&peer).unwrap(),
            peer.acknowledgement(&local).unwrap()
        );
    }

    #[test]
    fn tcp_negotiates_before_roundtrip_and_fails_closed_on_mismatch() {
        for mismatch in [false, true] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let session = crate::SecureSession {
                    inner: crate::SecureSessionInner::Tcp(Box::new(crate::SecureTcpSession::new(
                        stream, [2; 32], [1; 32],
                    ))),
                    transcript_hash_hex: "ab".repeat(32),
                };
                let config = PhantomOneConfig::for_profile(if mismatch {
                    ProfileTier::High
                } else {
                    ProfileTier::Medium
                });
                let established = NegotiatedTcp::establish(
                    session,
                    &"ab".repeat(32),
                    config,
                    1360,
                    Duration::from_secs(2),
                );
                if mismatch {
                    assert!(established.is_err());
                    return;
                }
                let mut session = established.unwrap();
                assert_eq!(session.recv().unwrap(), b"hello");
                session.send(b"world").unwrap();
            });
            let stream = std::net::TcpStream::connect(address).unwrap();
            let session = crate::SecureSession {
                inner: crate::SecureSessionInner::Tcp(Box::new(crate::SecureTcpSession::new(
                    stream, [1; 32], [2; 32],
                ))),
                transcript_hash_hex: "ab".repeat(32),
            };
            let established = NegotiatedTcp::establish(
                session,
                &"ab".repeat(32),
                PhantomOneConfig::for_profile(ProfileTier::Medium),
                1360,
                Duration::from_secs(2),
            );
            if mismatch {
                assert!(established.is_err());
            } else {
                let mut session = established.unwrap();
                session.send(b"hello").unwrap();
                assert_eq!(session.recv().unwrap(), b"world");
            }
            server.join().unwrap();
        }
    }

    #[test]
    fn tcp_policy_rejects_a_caller_supplied_transcript_mismatch() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        let session = crate::SecureSession {
            inner: crate::SecureSessionInner::Tcp(Box::new(crate::SecureTcpSession::new(
                stream, [1; 32], [2; 32],
            ))),
            transcript_hash_hex: "ab".repeat(32),
        };

        let result = NegotiatedTcp::establish(
            session,
            &"cd".repeat(32),
            PhantomOneConfig::for_profile(ProfileTier::Medium),
            1360,
            Duration::from_secs(2),
        );

        assert!(matches!(result, Err(ShphError::Protocol(_))));
    }

    #[test]
    fn tcp_policy_negotiates_and_discards_cover_frames() {
        let transcript = "ab".repeat(32);
        let cover = crate::cover::CoverPolicy {
            interval_ms: 100,
            idle_timeout_ms: 2_000,
            maximum_bytes: 4_096,
            overhead_percent: 100,
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_transcript = transcript.clone();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let session = crate::SecureSession {
                inner: crate::SecureSessionInner::Tcp(Box::new(crate::SecureTcpSession::new(
                    stream, [2; 32], [1; 32],
                ))),
                transcript_hash_hex: server_transcript.clone(),
            };
            let mut session = NegotiatedTcp::establish_with_cover(
                session,
                &server_transcript,
                PhantomOneConfig::for_profile(ProfileTier::Medium),
                1360,
                Duration::from_secs(2),
                Some(cover),
            )
            .unwrap();
            assert_eq!(session.recv().unwrap(), vec![0x5a; 512]);
            assert_eq!(session.recv().unwrap(), b"after-cover");
        });

        let stream = std::net::TcpStream::connect(address).unwrap();
        let session = crate::SecureSession {
            inner: crate::SecureSessionInner::Tcp(Box::new(crate::SecureTcpSession::new(
                stream, [1; 32], [2; 32],
            ))),
            transcript_hash_hex: transcript.clone(),
        };
        let mut session = NegotiatedTcp::establish_with_cover(
            session,
            &transcript,
            PhantomOneConfig::for_profile(ProfileTier::Medium),
            1360,
            Duration::from_secs(2),
            Some(cover),
        )
        .unwrap();
        session.send(&vec![0x5a; 512]).unwrap();
        std::thread::sleep(Duration::from_millis(120));
        assert!(session.send_cover_if_due(false, false, false).unwrap());
        session.send(b"after-cover").unwrap();
        server.join().unwrap();
    }
}
