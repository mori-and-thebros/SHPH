use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MetadataEvent {
    pub event: &'static str,
    pub carrier: &'static str,
    pub outcome: &'static str,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RedactedMetadata {
    pub event: &'static str,
    pub carrier: &'static str,
    pub outcome: &'static str,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl From<MetadataEvent> for RedactedMetadata {
    fn from(event: MetadataEvent) -> Self {
        Self {
            event: event.event,
            carrier: event.carrier,
            outcome: event.outcome,
            bytes_in: event.bytes_in,
            bytes_out: event.bytes_out,
        }
    }
}

pub fn emit(event: MetadataEvent) {
    let safe = RedactedMetadata::from(event);
    tracing::info!(
        event = safe.event,
        carrier = safe.carrier,
        outcome = safe.outcome,
        bytes_in = safe.bytes_in,
        bytes_out = safe.bytes_out,
        "edge relay metadata"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_contains_only_metadata() {
        let event = MetadataEvent {
            event: "relay",
            carrier: "h2",
            outcome: "ok",
            bytes_in: 4,
            bytes_out: 8,
        };
        let encoded = serde_json::to_string(&RedactedMetadata::from(event)).expect("json");
        assert!(encoded.contains("bytes_in"));
        assert!(!encoded.contains("secret"));
        assert!(!encoded.contains("ticket"));
        assert!(!encoded.contains("password"));
    }
}
