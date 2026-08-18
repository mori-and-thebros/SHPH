use base64::Engine as _;
use qrcode::render::unicode;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use shph_core::{Endpoint, Result, ShphError};

const TICKET_PREFIX: &str = "shph://v1:";
const MAX_TICKET_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct JoinTicket {
    pub endpoint: String,
    pub transport: String,
    pub shroud_profile: String,
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
        let ticket: Self = serde_json::from_slice(&payload)
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
    if ticket.transport != "tcp" && ticket.transport != "quic" {
        return Err(ShphError::InvalidArgument(
            "ticket transport must be tcp or quic".into(),
        ));
    }
    if shph_core::shroud_profile_by_selection(&ticket.shroud_profile).is_none() {
        return Err(ShphError::InvalidArgument(
            "ticket contains an unknown Shroud profile".into(),
        ));
    }
    validate_key(&ticket.server_identity_b64, "server identity")?;
    validate_key(&ticket.server_signing_b64, "server signing key")?;
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
    use super::{render_qr, JoinTicket};

    fn ticket() -> JoinTicket {
        JoinTicket {
            endpoint: "198.51.100.10:443".into(),
            transport: "tcp".into(),
            shroud_profile: "medium".into(),
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
        ticket.transport = "quic-standard".into();
        assert!(ticket.encode().is_err());
    }
}
