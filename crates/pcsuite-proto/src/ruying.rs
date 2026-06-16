//! 8904 "ruying" super-clipboard frame.
//!
//! Layout (reversed from `PacketStreamFilter::MakePacket` / `ParsePacket`):
//!
//! ```text
//! off  size  field          notes
//! [0]   8    BE64 lenPrefix  = 30 + cipherLen   (bytes following the prefix)
//! [8]   1    version         must == 1
//! [9]   6    fieldA          srcDeviceId?
//! [15]  6    fieldB          dstDeviceId?
//! [21]  1    byteC           business type
//! [22]  1    byteD           business type
//! [23]  11   fieldE          sessionId?
//! [34]  4    BE32 cipherLen  = len(cipher)  (= plaintext + 16-byte tag)
//! [38]  N    cipher          AES-256-GCM ciphertext ‖ tag
//! ```
//!
//! Total = 38 + cipherLen; lenPrefix = 30 + cipherLen. The opaque fields are
//! carried verbatim (round-tripped) — see the crate-level notes for unknowns.

pub const PREFIX_LEN: usize = 8;
pub const INNER_LEN: usize = 30;
/// 8-byte length prefix + 30-byte inner header.
pub const HEADER_LEN: usize = PREFIX_LEN + INNER_LEN;
pub const VERSION: u8 = 0x01;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuyingFrame {
    pub version: u8,
    pub field_a: [u8; 6],
    pub field_b: [u8; 6],
    pub byte_c: u8,
    pub byte_d: u8,
    pub field_e: [u8; 11],
    /// GCM ciphertext ‖ tag.
    pub cipher: Vec<u8>,
}

impl Default for RuyingFrame {
    fn default() -> Self {
        Self {
            version: VERSION,
            field_a: [0; 6],
            field_b: [0; 6],
            byte_c: 0,
            byte_d: 0,
            field_e: [0; 11],
            cipher: Vec::new(),
        }
    }
}

impl RuyingFrame {
    /// Serialize to the wire format.
    pub fn build(&self) -> Vec<u8> {
        let clen = self.cipher.len();
        let mut out = Vec::with_capacity(HEADER_LEN + clen);
        out.extend_from_slice(&((INNER_LEN + clen) as u64).to_be_bytes());
        out.push(self.version);
        out.extend_from_slice(&self.field_a);
        out.extend_from_slice(&self.field_b);
        out.push(self.byte_c);
        out.push(self.byte_d);
        out.extend_from_slice(&self.field_e);
        out.extend_from_slice(&(clen as u32).to_be_bytes());
        out.extend_from_slice(&self.cipher);
        out
    }
}

/// Result of [`parse`].
#[derive(Debug)]
pub enum Parsed {
    /// A complete frame and the number of bytes it consumed.
    Frame(RuyingFrame, usize),
    /// Need at least this many total bytes before a frame can be parsed.
    NeedMore(usize),
    /// The buffer holds a malformed frame (bad version / length mismatch).
    Invalid,
}

/// Parse one frame from the front of `buf`.
pub fn parse(buf: &[u8]) -> Parsed {
    if buf.len() < PREFIX_LEN {
        return Parsed::NeedMore(PREFIX_LEN);
    }
    let total_rest = u64::from_be_bytes(buf[..PREFIX_LEN].try_into().unwrap()) as usize;
    if total_rest < INNER_LEN {
        return Parsed::Invalid;
    }
    let need = PREFIX_LEN + total_rest;
    if buf.len() < need {
        return Parsed::NeedMore(need);
    }
    let inner = &buf[PREFIX_LEN..PREFIX_LEN + INNER_LEN];
    if inner[0] != VERSION {
        return Parsed::Invalid;
    }
    let clen = u32::from_be_bytes(inner[26..30].try_into().unwrap()) as usize;
    if clen != total_rest - INNER_LEN {
        return Parsed::Invalid;
    }
    let frame = RuyingFrame {
        version: inner[0],
        field_a: inner[1..7].try_into().unwrap(),
        field_b: inner[7..13].try_into().unwrap(),
        byte_c: inner[13],
        byte_d: inner[14],
        field_e: inner[15..26].try_into().unwrap(),
        cipher: buf[PREFIX_LEN + INNER_LEN..need].to_vec(),
    };
    Parsed::Frame(frame, need)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let f = RuyingFrame {
            version: VERSION,
            field_a: *b"ABCDEF",
            field_b: *b"123456",
            byte_c: 1,
            byte_d: 8,
            field_e: *b"sess-000123", // 11 bytes
            cipher: vec![b'X'; 200],
        };
        let wire = f.build();
        assert_eq!(wire.len(), HEADER_LEN + 200);
        match parse(&wire) {
            Parsed::Frame(g, used) => {
                assert_eq!(used, wire.len());
                assert_eq!(g, f);
                assert_eq!(g.byte_c, 1);
                assert_eq!(g.byte_d, 8);
            }
            other => panic!("expected Frame, got {other:?}"),
        }
    }

    #[test]
    fn partial_buffers_need_more() {
        let wire = RuyingFrame { cipher: vec![0; 32], ..Default::default() }.build();
        assert!(matches!(parse(&wire[..5]), Parsed::NeedMore(PREFIX_LEN)));
        assert!(matches!(parse(&wire[..10]), Parsed::NeedMore(_)));
    }

    #[test]
    fn bad_version_invalid() {
        let mut wire = RuyingFrame { cipher: vec![0; 16], ..Default::default() }.build();
        wire[PREFIX_LEN] = 0x02; // version byte
        assert!(matches!(parse(&wire), Parsed::Invalid));
    }
}
