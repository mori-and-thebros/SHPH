//! Opt-in adaptive Shroud 3 lab envelope.
//!
//! Shroud 3 uses the bounded caller-observation adaptation policy from Shroud
//! 2, but has a distinct `S3` wire marker. It is carried only inside an already
//! authenticated transport and does not change the SHPH handshake or transport
//! defaults. The marker is deliberately incompatible with Shroud 2.

use crate::shroud2::workload::{
    WorkloadConfig, WorkloadMetrics, WorkloadMorphology, WorkloadObservation,
};
use shph_core::{Result, ShphError};
use zeroize::Zeroize;

pub const SHROUD3_MAGIC: [u8; 2] = *b"S3";
pub const SHROUD3_VERSION: u8 = 1;
pub const SHROUD3_HEADER_BYTES: usize = 7;

/// Caller-observed adaptive envelope state. Each instance is scoped to one
/// authenticated connection and requires explicit observations for every send.
pub struct AdaptiveShroud3 {
    workload: WorkloadMorphology,
}

impl AdaptiveShroud3 {
    /// Create an adaptive engine with operating-system seeded size and padding
    /// randomness.
    pub fn new(config: WorkloadConfig) -> Result<Self> {
        Ok(Self {
            workload: WorkloadMorphology::new(config)?,
        })
    }

    /// Deterministic constructor for tests and reproducible lab experiments.
    /// Do not use it for production wire padding.
    pub fn from_seed(config: WorkloadConfig, seed: u64) -> Result<Self> {
        Ok(Self {
            workload: WorkloadMorphology::from_seed(config, seed)?,
        })
    }

    pub fn profile(&self) -> crate::shroud2::MorphologyProfile {
        self.workload.profile()
    }

    pub fn metrics(&self) -> WorkloadMetrics {
        self.workload.metrics()
    }

    pub fn next_delay(&mut self) -> std::time::Duration {
        self.workload.next_delay()
    }

    /// Encode one payload using explicit monotonic-time and queue-age inputs.
    pub fn encode(
        &mut self,
        payload: &[u8],
        path_mtu: usize,
        observation: WorkloadObservation,
    ) -> Result<Vec<u8>> {
        let mut datagram = self.workload.encode(
            payload,
            path_mtu,
            observation.observed_at,
            observation.queue_age,
        )?;
        if datagram.len() < SHROUD3_HEADER_BYTES
            || datagram[..2] != crate::shroud2::MORPHOLOGY_MAGIC
            || datagram[2] != crate::shroud2::MORPHOLOGY_VERSION
        {
            datagram.zeroize();
            return Err(ShphError::Protocol(
                "internal Shroud 2 encoder returned an invalid envelope".into(),
            ));
        }
        datagram[..2].copy_from_slice(&SHROUD3_MAGIC);
        datagram[2] = SHROUD3_VERSION;
        Ok(datagram)
    }
}

/// Decode one Shroud 3 envelope into its application payload.
pub fn decode(datagram: &[u8], path_mtu: usize) -> Result<Vec<u8>> {
    let mut decoded = datagram.to_vec();
    match decode_in_place(&mut decoded, path_mtu) {
        Ok(()) => Ok(decoded),
        Err(error) => {
            decoded.zeroize();
            Err(error)
        }
    }
}

/// Validate and remove one Shroud 3 envelope in a caller-owned buffer.
pub fn decode_in_place(datagram: &mut Vec<u8>, path_mtu: usize) -> Result<()> {
    if datagram.len() < SHROUD3_HEADER_BYTES || datagram.len() > path_mtu {
        datagram.zeroize();
        datagram.clear();
        return Err(ShphError::Protocol(
            "Shroud 3 datagram length is outside the negotiated limit".into(),
        ));
    }
    if datagram[..2] != SHROUD3_MAGIC || datagram[2] != SHROUD3_VERSION {
        datagram.zeroize();
        datagram.clear();
        return Err(ShphError::Protocol(
            "Shroud 3 envelope version mismatch".into(),
        ));
    }
    datagram[..2].copy_from_slice(&crate::shroud2::MORPHOLOGY_MAGIC);
    datagram[2] = crate::shroud2::MORPHOLOGY_VERSION;
    if let Err(error) = crate::shroud2::decode_datagram_in_place(datagram, path_mtu) {
        datagram.zeroize();
        datagram.clear();
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn adaptive_shroud3_round_trips_and_is_wire_distinct_from_shroud2() {
        let mut adaptive = AdaptiveShroud3::from_seed(
            WorkloadConfig {
                minimum_dwell: Duration::ZERO,
                use_arrivals: false,
                use_queue_age: false,
                ..WorkloadConfig::default()
            },
            73,
        )
        .unwrap();
        let payload = b"opt-in adaptive frame";
        let encoded = adaptive
            .encode(
                payload,
                1472,
                WorkloadObservation {
                    observed_at: Duration::from_millis(1),
                    queue_age: Duration::ZERO,
                },
            )
            .unwrap();

        assert_eq!(&encoded[..2], &SHROUD3_MAGIC);
        assert_eq!(encoded[2], SHROUD3_VERSION);
        assert_eq!(decode(&encoded, 1472).unwrap(), payload);
        assert!(crate::shroud2::decode_datagram(&encoded, 1472).is_err());
    }

    #[test]
    fn shroud3_rejects_shroud2_and_wipes_rejected_input() {
        let mut old_format = crate::shroud2::encode_datagram(b"old", 32, 1472).unwrap();
        let error = decode_in_place(&mut old_format, 1472).unwrap_err();
        assert!(matches!(error, ShphError::Protocol(_)));
        assert!(old_format.is_empty());
    }

    #[test]
    fn workload_observation_rejection_does_not_advance_shroud3_state() {
        let mut adaptive = AdaptiveShroud3::from_seed(WorkloadConfig::default(), 74).unwrap();
        let first = WorkloadObservation {
            observed_at: Duration::from_millis(10),
            queue_age: Duration::ZERO,
        };
        adaptive.encode(b"a", 1472, first).unwrap();
        let metrics = adaptive.metrics();
        let error = adaptive
            .encode(
                b"b",
                1472,
                WorkloadObservation {
                    observed_at: Duration::from_millis(9),
                    queue_age: Duration::ZERO,
                },
            )
            .unwrap_err();
        assert!(matches!(error, ShphError::InvalidArgument(_)));
        assert_eq!(adaptive.metrics(), metrics);
    }
}
