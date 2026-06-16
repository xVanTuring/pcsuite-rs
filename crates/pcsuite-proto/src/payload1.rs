//! 10191 transport framing.
//!
//! Both directions use `PAY_LOAD_1` (10 ASCII bytes) + a 4-byte big-endian body
//! length + the UTF-8 JSON body (14-byte header total). The request framing is
//! verified — the phone accepts frames built by [`encode`]. The reply framing is
//! modelled the same way, but static analysis left the exact receive offset
//! slightly uncertain, so [`parse_reply_lenient`] mirrors the proven Python
//! fallback (try offsets 14, then 4, then 0).

use crate::ProtoError;
use serde::Serialize;
use serde_json::Value;

pub const MAGIC: &[u8; 10] = b"PAY_LOAD_1";
/// 10-byte magic + 4-byte big-endian length.
pub const HEADER_LEN: usize = 14;

/// Frame a raw body: `MAGIC + BE32(len) + body`.
pub fn encode(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Serialize `v` to compact JSON and frame it.
pub fn encode_json<T: Serialize>(v: &T) -> Result<Vec<u8>, ProtoError> {
    Ok(encode(&serde_json::to_vec(v)?))
}

/// Strict single-frame decode of a magic-framed stream. Returns
/// `Some((body, total_consumed))` when a full frame is buffered, `None` when
/// more bytes are needed, or [`ProtoError::BadMagic`] if the prefix is wrong.
pub fn decode_strict(buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>, ProtoError> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }
    if &buf[..10] != MAGIC {
        return Err(ProtoError::BadMagic);
    }
    let len = u32::from_be_bytes(buf[10..14].try_into().unwrap()) as usize;
    let total = HEADER_LEN + len;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some((buf[HEADER_LEN..total].to_vec(), total)))
}

/// Tolerant reply parse. Tries to interpret the remainder after offset 14, then
/// 4, then 0 as a single JSON value, returning the first that parses along with
/// the offset used. Mirrors the (proven-working) Python receive path.
pub fn parse_reply_lenient(buf: &[u8]) -> Option<(Value, usize)> {
    for off in [HEADER_LEN, 4, 0] {
        if buf.len() > off {
            if let Ok(v) = serde_json::from_slice::<Value>(&buf[off..]) {
                return Some((v, off));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encode_then_decode_strict() {
        let body = br#"{"hello":"world"}"#;
        let framed = encode(body);
        assert_eq!(&framed[..10], MAGIC);
        assert_eq!(u32::from_be_bytes(framed[10..14].try_into().unwrap()) as usize, body.len());
        let (got, used) = decode_strict(&framed).unwrap().unwrap();
        assert_eq!(got, body);
        assert_eq!(used, framed.len());
    }

    #[test]
    fn decode_strict_needs_more() {
        let framed = encode(b"abcdef");
        assert!(decode_strict(&framed[..5]).unwrap().is_none()); // header incomplete
        assert!(decode_strict(&framed[..HEADER_LEN + 2]).unwrap().is_none()); // body incomplete
    }

    #[test]
    fn bad_magic_errors() {
        let mut framed = encode(b"x");
        framed[0] = b'Z';
        assert!(matches!(decode_strict(&framed), Err(ProtoError::BadMagic)));
    }

    #[test]
    fn reply_lenient_offset_14() {
        let framed = encode_json(&json!({"bytes":[1]})).unwrap();
        let (v, off) = parse_reply_lenient(&framed).unwrap();
        assert_eq!(off, HEADER_LEN);
        assert_eq!(v["bytes"][0], 1);
    }
}
