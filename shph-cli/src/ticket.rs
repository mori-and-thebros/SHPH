use base64::Engine as _;
use qrcode::render::unicode;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use shph_core::{Endpoint, Result, ShphError};
use shph_obfuscation::ProfileTier;

const TICKET_PREFIX: &str = "shph://v1:";
const MAX_TICKET_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct JoinTicket {
    pub endpoint: String,
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shroud_profile: Option<String>,
    #[serde(default)]
    pub phantom_one: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phantom_one_profile: Option<String>,
    pub server_identity_b64: String,
    pub server_signing_b64: String,
}

impl JoinTicket {
    pub(crate) fn encode(&self) -> Result<String> {
        validate_ticket(self)?;
        let payload = serde_json::to_vec(self)?;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        Ok(format!("{TICKET_PREFIX}{encoded}"))
    }

    pub(crate) fn decode(value: &str) -> Result<Self> {
        let value = value.trim();
        let encoded = value.strip_prefix(TICKET_PREFIX).ok_or_else(|| {
            ShphError::InvalidArgument("ticket must start with shph://v1:".into())
        })?;
        if encoded.is_empty() || encoded.len() > MAX_TICKET_BYTES {
            return Err(ShphError::InvalidArgument(
                "ticket payload is empty or exceeds the safety limit".into(),
            ));
        }
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ShphError::InvalidArgument("ticket is not valid base64url".into()))?;
        if payload.len() > MAX_TICKET_BYTES {
            return Err(ShphError::InvalidArgument(
                "decoded ticket exceeds the safety limit".into(),
            ));
        }
        let mut value: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|_| ShphError::InvalidArgument("ticket payload is invalid JSON".into()))?;
        migrate_legacy_ticket(&mut value)?;
        let ticket: Self = serde_json::from_value(value)
            .map_err(|_| ShphError::InvalidArgument("ticket payload is invalid JSON".into()))?;
        validate_ticket(&ticket)?;
        Ok(ticket)
    }
}

fn validate_ticket(ticket: &JoinTicket) -> Result<()> {
    let endpoint = Endpoint::parse(&ticket.endpoint)
        .map_err(|error| ShphError::InvalidArgument(format!("invalid ticket endpoint: {error}")))?;
    if endpoint.port == 0 {
        return Err(ShphError::InvalidArgument(
            "ticket endpoint port must be non-zero".into(),
        ));
    }
    if endpoint
        .host
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ShphError::InvalidArgument(
            "ticket endpoint host contains whitespace or control characters".into(),
        ));
    }
    if ticket.transport != "tcp"
        && ticket.transport != "quic"
        && ticket.transport != "quic-standard"
    {
        return Err(ShphError::InvalidArgument(
            "ticket transport must be tcp, quic, or quic-standard".into(),
        ));
    }
    if ticket.phantom_one {
        if ticket.shroud_profile.is_some() {
            return Err(ShphError::InvalidArgument(
                "Phantom One tickets must not contain a Shroud 2 profile".into(),
            ));
        }
        validate_phantom_one_profile(ticket.phantom_one_profile.as_deref())?;
    } else {
        let profile = ticket.shroud_profile.as_deref().ok_or_else(|| {
            ShphError::InvalidArgument("Shroud 2 tickets require shroud_profile".into())
        })?;
        if shph_core::shroud_profile_by_selection(profile).is_none() {
            return Err(ShphError::InvalidArgument(
                "ticket contains an unknown Shroud profile".into(),
            ));
        }
        if ticket.phantom_one_profile.is_some() {
            return Err(ShphError::InvalidArgument(
                "Shroud 2 tickets must not contain phantom_one_profile".into(),
            ));
        }
    }
    validate_key(&ticket.server_identity_b64, "server identity")?;
    validate_key(&ticket.server_signing_b64, "server signing key")?;
    Ok(())
}

fn validate_phantom_one_profile(value: Option<&str>) -> Result<ProfileTier> {
    let value = value.ok_or_else(|| {
        ShphError::InvalidArgument("Phantom One tickets require phantom_one_profile".into())
    })?;
    match value.trim().to_ascii_lowercase().as_str() {
        "low" => Ok(ProfileTier::Low),
        "medium" => Ok(ProfileTier::Medium),
        "high" => Ok(ProfileTier::High),
        "tuned-low" => Ok(ProfileTier::TunedLow),
        "tuned-medium" => Ok(ProfileTier::TunedMedium),
        "tuned-high" => Ok(ProfileTier::TunedHigh),
        _ => Err(ShphError::InvalidArgument(
            "unknown Phantom One profile; expected low, medium, high, tuned-low, tuned-medium, or tuned-high"
                .into(),
        )),
    }
}

fn migrate_legacy_ticket(value: &mut serde_json::Value) -> Result<()> {
    let Some(object) = value.as_object_mut() else {
        return Err(ShphError::InvalidArgument(
            "ticket payload must be a JSON object".into(),
        ));
    };
    let Some(old_value) = object.remove("shroud_version") else {
        return Ok(());
    };
    let old_version = old_value.as_str().ok_or_else(|| {
        ShphError::InvalidArgument("legacy ticket shroud_version must be 2.0 or 2.1".into())
    })?;
    let migrated_phantom_one = match old_version {
        "2.0" => false,
        "2.1" => true,
        _ => {
            return Err(ShphError::InvalidArgument(
                "legacy ticket shroud_version must be 2.0 or 2.1".into(),
            ))
        }
    };

    if let Some(configured) = object.get("phantom_one").and_then(|value| value.as_bool()) {
        if configured != migrated_phantom_one {
            return Err(ShphError::InvalidArgument(
                "legacy ticket shroud_version conflicts with phantom_one".into(),
            ));
        }
    } else {
        object.insert(
            "phantom_one".into(),
            serde_json::Value::Bool(migrated_phantom_one),
        );
    }

    if migrated_phantom_one && !object.contains_key("phantom_one_profile") {
        let legacy_profile = object
            .get("shroud_profile")
            .and_then(|value| value.as_str())
            .unwrap_or("medium")
            .to_owned();
        let profile = shph_core::shroud_profile_by_selection(&legacy_profile)
            .and_then(|profile| profile.map(ProfileTier::from_shroud_profile))
            .unwrap_or(ProfileTier::Medium);
        object.insert(
            "phantom_one_profile".into(),
            serde_json::Value::String(profile.as_str().into()),
        );
        object.remove("shroud_profile");
    }

    eprintln!(
        "Warning: migrated legacy ticket shroud_version in memory; the source ticket was not rewritten"
    );
    Ok(())
}

fn validate_key(value: &str, label: &str) -> Result<()> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|_| ShphError::InvalidArgument(format!("{label} is not valid base64")))?;
    if raw.len() != 32 {
        return Err(ShphError::InvalidArgument(format!(
            "{label} must decode to 32 bytes"
        )));
    }
    Ok(())
}

pub(crate) fn render_qr(value: &str) -> Result<String> {
    let code = QrCode::new(value.as_bytes())
        .map_err(|error| ShphError::Internal(format!("render QR code: {error}")))?;
    Ok(code.render::<unicode::Dense1x2>().quiet_zone(true).build())
}

#[cfg(test)]
mod tests {
    use super::{render_qr, JoinTicket, TICKET_PREFIX};
    use base64::Engine as _;

    fn ticket() -> JoinTicket {
        JoinTicket {
            endpoint: "198.51.100.10:443".into(),
            transport: "tcp".into(),
            shroud_profile: Some("medium".into()),
            phantom_one: false,
            phantom_one_profile: None,
            server_identity_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            server_signing_b64: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
        }
    }

    #[test]
    fn ticket_round_trips_and_renders() {
        let ticket = ticket();
        let encoded = ticket.encode().expect("encode ticket");
        assert!(encoded.starts_with("shph://v1:"));
        assert_eq!(JoinTicket::decode(&encoded).expect("decode ticket"), ticket);
        assert!(!render_qr(&encoded).expect("render QR").is_empty());
    }

    #[test]
    fn ticket_rejects_unknown_transport() {
        let mut ticket = ticket();
        ticket.transport = "not-a-transport".into();
        assert!(ticket.encode().is_err());
    }

    #[test]
    fn ticket_accepts_standards_quic() {
        let mut ticket = ticket();
        ticket.transport = "quic-standard".into();
        let encoded = ticket.encode().expect("encode standards QUIC ticket");
        assert_eq!(
            JoinTicket::decode(&encoded).expect("decode standards QUIC ticket"),
            ticket
        );
    }

    #[test]
    fn ticket_accepts_phantom_one_for_tcp() {
        let mut ticket = ticket();
        ticket.shroud_profile = None;
        ticket.phantom_one = true;
        ticket.phantom_one_profile = Some("tuned-medium".into());
        let encoded = ticket.encode().expect("encode Phantom One ticket");
        assert_eq!(
            JoinTicket::decode(&encoded).expect("decode Phantom One ticket"),
            ticket
        );
    }

    #[test]
    fn ticket_rejects_unknown_phantom_one_profile() {
        let mut ticket = ticket();
        ticket.shroud_profile = None;
        ticket.phantom_one = true;
        ticket.phantom_one_profile = Some("2.1".into());
        assert!(ticket.encode().is_err());
    }

    #[test]
    fn legacy_phantom_one_ticket_migrates_without_rewriting_shape() {
        let ticket = ticket();
        let mut value = serde_json::to_value(ticket).expect("serialize ticket");
        let object = value.as_object_mut().expect("ticket object");
        object.remove("phantom_one");
        object.remove("phantom_one_profile");
        object.insert(
            "shroud_version".into(),
            serde_json::Value::String("2.1".into()),
        );
        let encoded = format!(
            "{}{}",
            TICKET_PREFIX,
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&value).expect("serialize legacy ticket"))
        );
        let migrated = JoinTicket::decode(&encoded).expect("decode migrated ticket");
        assert!(migrated.phantom_one);
        assert_eq!(migrated.phantom_one_profile.as_deref(), Some("medium"));
        assert!(migrated.shroud_profile.is_none());
    }
}
