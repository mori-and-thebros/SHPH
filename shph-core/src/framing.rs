//! Framing layer for Shroud cells.
//!
//! Each cell has a fixed size and contains a header, frame type, length, and payload.

use crate::error::{Result, ShphError};
use crate::stealth::ShroudProfile;

const FRAME_HEADER: &[u8; 2] = b"SD";
const FRAME_DATA: u8 = 0x01;
const FRAME_CHAFF: u8 = 0x02;

#[derive(Debug, Clone)]
pub struct ShroudCell {
    pub data: Vec<u8>,
}

impl ShroudCell {
    pub fn new(profile: ShroudProfile, frame_type: u8, payload: &[u8]) -> Result<Self> {
        if profile.cell_size < 64 || profile.cell_size > 16 * 1024 {
            return Err(ShphError::Protocol("invalid cell size".into()));
        }
        if payload.len() > profile.payload_capacity() {
            return Err(ShphError::Protocol("payload exceeds cell capacity".into()));
        }
        let mut cell = Vec::with_capacity(profile.cell_size);
        cell.extend_from_slice(FRAME_HEADER);
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

pub fn decode_cell(profile: ShroudProfile, cell: &[u8]) -> Result<Option<Vec<u8>>> {
    if cell.len() != profile.cell_size {
        return Err(ShphError::Protocol("cell size mismatch".into()));
    }
    if &cell[..2] != FRAME_HEADER {
        return Err(ShphError::Protocol("frame header mismatch".into()));
    }
    let frame_type = cell[2];
    let payload_len = u16::from_be_bytes([cell[3], cell[4]]) as usize;
    if payload_len > profile.payload_capacity() {
        return Err(ShphError::Protocol(
            "payload length exceeds cell capacity".into(),
        ));
    }
    let payload = cell[5..5 + payload_len].to_vec();
    match frame_type {
        FRAME_DATA => Ok(Some(payload)),
        FRAME_CHAFF => Ok(None),
        _ => Err(ShphError::Protocol("unsupported frame type".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_cell, encode_cell};
    use crate::stealth::BALANCED;

    #[test]
    fn oversize_payload_is_rejected_fail_closed() {
        // payload_capacity = cell_size - 5; exceed it.
        let too_big = vec![0u8; BALANCED.payload_capacity() + 1];
        assert!(encode_cell(BALANCED, 0x01, &too_big).is_err());
    }

    #[test]
    fn invalid_cell_size_is_rejected() {
        // A cell buffer of the wrong length must be rejected, not indexed.
        let bad = vec![0u8; BALANCED.cell_size + 1];
        assert!(decode_cell(BALANCED, &bad).is_err());
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
        // Use a frame type byte that is neither DATA (0x01) nor CHAFF (0x02).
        assert!(encode_cell(BALANCED, 0x09, b"x").is_ok());
        let cell = encode_cell(BALANCED, 0x09, b"x").expect("encode");
        assert!(decode_cell(BALANCED, &cell).is_err());
    }
}
