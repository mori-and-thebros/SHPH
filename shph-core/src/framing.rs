//! Framing layer for Shroud cells.
//!
//! Each cell has a fixed size and contains a header, frame type, length, and payload.

use crate::error::{Result, ShphError};
use crate::stealth::ShroudProfile;

pub const SHROUD_FRAME_HEADER: &[u8; 2] = b"SD";
pub const SHROUD_FRAME_DATA: u8 = 0x01;
pub const SHROUD_FRAME_CHAFF: u8 = 0x02;

#[derive(Debug, Clone)]
pub struct ShroudCell {
    pub data: Vec<u8>,
}

impl ShroudCell {
    pub fn new(profile: ShroudProfile, frame_type: u8, payload: &[u8]) -> Result<Self> {
        if !profile.is_valid() {
            return Err(ShphError::Protocol("invalid cell size".into()));
        }
        if !matches!(frame_type, SHROUD_FRAME_DATA | SHROUD_FRAME_CHAFF) {
            return Err(ShphError::Protocol("unsupported frame type".into()));
        }
        if payload.len() > profile.payload_capacity() {
            return Err(ShphError::Protocol("payload exceeds cell capacity".into()));
        }
        let mut cell = Vec::with_capacity(profile.cell_size);
        cell.extend_from_slice(SHROUD_FRAME_HEADER);
        cell.push(frame_type);
        cell.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        cell.extend_from_slice(payload);
        cell.resize(profile.cell_size, 0);
        Ok(Self { data: cell })
    }
}

pub fn encode_cell(profile: ShroudProfile, frame_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
    ShroudCell::new(profile, frame_type, payload).map(|c| c.data)
}

pub fn encode_data_cell(profile: ShroudProfile, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > profile.max_payload_chunk {
        return Err(ShphError::Protocol(
            "payload exceeds profile capacity".into(),
        ));
    }
    encode_cell(profile, SHROUD_FRAME_DATA, payload)
}

pub fn encode_chaff_cell(profile: ShroudProfile, payload: &[u8]) -> Result<Vec<u8>> {
    encode_cell(profile, SHROUD_FRAME_CHAFF, payload)
}

pub fn decode_cell(profile: ShroudProfile, cell: &[u8]) -> Result<Option<Vec<u8>>> {
    decode_cell_payload(profile, cell).map(|payload| payload.map(|bytes| bytes.to_vec()))
}

pub fn decode_cell_payload(profile: ShroudProfile, cell: &[u8]) -> Result<Option<&[u8]>> {
    if !profile.is_valid() {
        return Err(ShphError::Protocol("invalid cell size".into()));
    }
    if cell.len() != profile.cell_size {
        return Err(ShphError::Protocol("cell size mismatch".into()));
    }
    if &cell[..2] != SHROUD_FRAME_HEADER {
        return Err(ShphError::Protocol("frame header mismatch".into()));
    }
    let frame_type = cell[2];
    let payload_len = u16::from_be_bytes([cell[3], cell[4]]) as usize;
    if payload_len > profile.payload_capacity() {
        return Err(ShphError::Protocol(
            "payload length exceeds cell capacity".into(),
        ));
    }
    if cell[5 + payload_len..].iter().any(|byte| *byte != 0) {
        return Err(ShphError::Protocol("non-canonical cell padding".into()));
    }
    match frame_type {
        SHROUD_FRAME_DATA => Ok(Some(&cell[5..5 + payload_len])),
        SHROUD_FRAME_CHAFF => Ok(None),
        _ => Err(ShphError::Protocol("unsupported frame type".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_cell, encode_cell, encode_chaff_cell, encode_data_cell, SHROUD_FRAME_CHAFF,
        SHROUD_FRAME_DATA, SHROUD_FRAME_HEADER,
    };
    use crate::stealth::{profiles, BALANCED};

    #[test]
    fn oversize_payload_is_rejected_fail_closed() {
        let too_big = vec![0u8; BALANCED.payload_capacity() + 1];
        assert!(encode_cell(BALANCED, 0x01, &too_big).is_err());
    }

    #[test]
    fn every_profile_round_trips_data_and_chaff() {
        for profile in profiles() {
            let payload = vec![0x5a; profile.max_payload_chunk.min(32)];
            let data = encode_data_cell(*profile, &payload).expect("data");
            assert_eq!(data.len(), profile.cell_size);
            assert_eq!(
                decode_cell(*profile, &data).expect("decode data"),
                Some(payload)
            );

            let chaff = encode_chaff_cell(*profile, &[]).expect("chaff");
            assert_eq!(chaff.len(), profile.cell_size);
            assert_eq!(decode_cell(*profile, &chaff).expect("decode chaff"), None);
        }
    }

    #[test]
    fn profile_chunk_limit_is_enforced() {
        let payload = vec![0u8; BALANCED.max_payload_chunk + 1];
        assert!(encode_data_cell(BALANCED, &payload).is_err());
        assert!(encode_cell(BALANCED, SHROUD_FRAME_DATA, &payload).is_ok());
        assert!(encode_cell(BALANCED, SHROUD_FRAME_CHAFF, &payload).is_ok());
    }

    #[test]
    fn frame_type_is_rejected_at_encode_boundary() {
        assert!(encode_cell(BALANCED, 0x09, b"x").is_err());
    }

    #[test]
    fn header_constant_matches_encoded_cell() {
        let cell = encode_cell(BALANCED, SHROUD_FRAME_DATA, b"x").expect("encode");
        assert_eq!(&cell[..SHROUD_FRAME_HEADER.len()], SHROUD_FRAME_HEADER);
    }

    #[test]
    fn non_canonical_padding_is_rejected() {
        let mut cell = encode_cell(BALANCED, SHROUD_FRAME_DATA, b"x").expect("encode");
        let last = cell.len() - 1;
        cell[last] = 1;
        assert!(decode_cell(BALANCED, &cell).is_err());
    }

    #[test]
    fn invalid_cell_size_is_rejected() {
        // A cell buffer of the wrong length must be rejected, not indexed.
        let bad = vec![0u8; BALANCED.cell_size + 1];
        assert!(decode_cell(BALANCED, &bad).is_err());
    }

    #[test]
    fn invalid_profile_size_is_rejected_without_indexing() {
        let invalid = crate::stealth::ShroudProfile {
            name: "invalid",
            cell_size: 4,
            send_interval: BALANCED.send_interval,
            chaff_interval: BALANCED.chaff_interval,
            max_payload_chunk: 1,
            deterministic_padding: true,
            adaptive_chunking: false,
        };
        assert!(encode_cell(invalid, 0x01, b"").is_err());
        assert!(decode_cell(invalid, &[0u8; 4]).is_err());
    }

    #[test]
    fn malformed_header_is_rejected() {
        let mut cell = encode_cell(BALANCED, 0x01, b"x").expect("encode");
        // Corrupt the 2-byte header.
        cell[0] = b'X';
        cell[1] = b'X';
        assert!(decode_cell(BALANCED, &cell).is_err());
    }

    #[test]
    fn oversize_payload_length_is_rejected() {
        let mut cell = encode_cell(BALANCED, 0x01, b"x").expect("encode");
        // Claim a payload larger than capacity via the 2-byte length field.
        let over = (BALANCED.payload_capacity() + 1) as u16;
        cell[3..5].copy_from_slice(&over.to_be_bytes());
        assert!(decode_cell(BALANCED, &cell).is_err());
    }

    #[test]
    fn unsupported_frame_type_is_rejected() {
        let mut cell = encode_cell(BALANCED, SHROUD_FRAME_DATA, b"x").expect("encode");
        cell[2] = 0x09;
        assert!(decode_cell(BALANCED, &cell).is_err());
    }
}
