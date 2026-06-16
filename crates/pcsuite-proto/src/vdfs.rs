//! vdfs file-plane wire format (5678 fetch / 5679 serve).
//!
//! The super-clipboard carries **images/files by reference**: an 8904 clipboard
//! frame (`type:4`) gives only a path, and the bytes are moved over a separate
//! "vdfs" request/response channel. This module is the pure (de)serialization of
//! that channel; the crypto (AES-256-GCM, 12-byte nonce) and sockets live in the
//! caller.
//!
//! A request plaintext (before encryption):
//!
//! ```text
//! 05 00 00 00 | seq(1) | "0123456789abcdef"(16) | cmd(1) | body
//!   cmd=2 LIST : BE32 nameLen | name
//!   cmd=3 STAT : BE32 nameLen | name
//!   cmd=6 READ : BE64 size | BE64 offset | BE32 nameLen | name
//! name = <deviceId><path>
//! ```
//!
//! A STAT response plaintext is a 74-byte stat structure with the file size as a
//! BE64 at offset 30; a READ response plaintext is the raw file bytes.
//!
//! Framing differs per direction but both put the 16-byte GCM tag *before* the
//! ciphertext:
//! - request frame (to a vdfs server): `BE64(totalLen) ‖ tag(16) ‖ ciphertext`,
//!   where `totalLen` counts the whole frame (8 + 16 + cipherLen).
//! - response frame (from a vdfs server): `03 ‖ BE32(cipherLen+17) ‖ 00 ‖ tag(16) ‖
//!   ciphertext`. The ciphertext therefore starts at offset 22 in both a request
//!   (8+16+… no — see below) and a response.
//!
//! Concretely a request's ciphertext starts at offset **24** (`8 + 16`) and a
//! response's at offset **22** (`1 + 4 + 1 + 16`).

/// 16-byte constant embedded in every request plaintext.
pub const CONST16: &[u8; 16] = b"0123456789abcdef";

pub const CMD_LIST: u8 = 2;
pub const CMD_STAT: u8 = 3;
pub const CMD_READ: u8 = 6;

/// Offset of the GCM ciphertext inside a request frame (`BE64 len ‖ tag16 ‖ ct`).
pub const REQUEST_CT_OFFSET: usize = 24;
/// Offset of the GCM ciphertext inside a response frame (`03 ‖ BE32 ‖ 00 ‖ tag16 ‖ ct`).
pub const RESPONSE_CT_OFFSET: usize = 22;
/// Size of a STAT response plaintext (stat structure).
pub const STAT_PLAINTEXT_LEN: usize = 74;
/// Offset of the BE64 file-size field inside a STAT response plaintext.
pub const STAT_SIZE_OFFSET: usize = 30;

/// A decoded request (server side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub cmd: u8,
    /// READ: requested byte count (0 for LIST/STAT).
    pub size: u64,
    /// READ: byte offset (0 for LIST/STAT).
    pub offset: u64,
    /// `<deviceId><path>` bytes, verbatim.
    pub name: Vec<u8>,
}

fn request_plaintext(seq: u8, cmd: u8, body: &[u8]) -> Vec<u8> {
    let mut pt = Vec::with_capacity(4 + 1 + 16 + 1 + body.len());
    pt.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]);
    pt.push(seq);
    pt.extend_from_slice(CONST16);
    pt.push(cmd);
    pt.extend_from_slice(body);
    pt
}

/// Build a STAT request plaintext for `name` (`<deviceId><path>`).
pub fn stat_plaintext(seq: u8, name: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + name.len());
    body.extend_from_slice(&(name.len() as u32).to_be_bytes());
    body.extend_from_slice(name);
    request_plaintext(seq, CMD_STAT, &body)
}

/// Build a READ request plaintext for `size` bytes at `offset` of `name`.
pub fn read_plaintext(seq: u8, size: u64, offset: u64, name: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + 8 + 4 + name.len());
    body.extend_from_slice(&size.to_be_bytes());
    body.extend_from_slice(&offset.to_be_bytes());
    body.extend_from_slice(&(name.len() as u32).to_be_bytes());
    body.extend_from_slice(name);
    request_plaintext(seq, CMD_READ, &body)
}

/// Parse a request plaintext (after decryption). Returns `None` if malformed.
pub fn parse_request(pt: &[u8]) -> Option<Request> {
    // 4-byte tag + seq(1) + const16(16) + cmd(1) = 22 bytes minimum before the body.
    if pt.len() < 22 {
        return None;
    }
    let cmd = pt[21];
    let body = &pt[22..];
    match cmd {
        CMD_LIST | CMD_STAT => {
            let name_len = be32(body, 0)? as usize;
            let name = body.get(4..4 + name_len)?.to_vec();
            Some(Request { cmd, size: 0, offset: 0, name })
        }
        CMD_READ => {
            let size = be64(body, 0)?;
            let offset = be64(body, 8)?;
            let name_len = be32(body, 16)? as usize;
            let name = body.get(20..20 + name_len)?.to_vec();
            Some(Request { cmd, size, offset, name })
        }
        _ => None,
    }
}

/// Wrap an already-sealed `(ciphertext, tag)` as a request frame
/// (`BE64 totalLen ‖ tag ‖ ciphertext`).
pub fn request_frame(tag: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let total = (8 + 16 + ciphertext.len()) as u64;
    let mut out = Vec::with_capacity(8 + 16 + ciphertext.len());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(tag);
    out.extend_from_slice(ciphertext);
    out
}

/// The total frame length advertised by a request's 8-byte BE64 prefix.
pub fn request_total_len(head8: &[u8]) -> Option<usize> {
    if head8.len() < 8 {
        return None;
    }
    Some(u64::from_be_bytes(head8[..8].try_into().unwrap()) as usize)
}

/// The ciphertext slice of a complete request frame (bytes after `BE64 ‖ tag`).
pub fn request_ciphertext(frame: &[u8]) -> Option<&[u8]> {
    frame.get(REQUEST_CT_OFFSET..)
}

/// Wrap an already-sealed `(ciphertext, tag)` as a response frame
/// (`03 ‖ BE32(cipherLen+17) ‖ 00 ‖ tag ‖ ciphertext`).
pub fn response_frame(tag: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RESPONSE_CT_OFFSET + ciphertext.len());
    out.push(0x03);
    out.extend_from_slice(&((ciphertext.len() + 17) as u32).to_be_bytes());
    out.push(0x00);
    out.extend_from_slice(tag);
    out.extend_from_slice(ciphertext);
    out
}

/// The ciphertext slice of a response frame (bytes after the 22-byte header).
pub fn response_ciphertext(resp: &[u8]) -> Option<&[u8]> {
    resp.get(RESPONSE_CT_OFFSET..)
}

/// Read the file size (BE64 @ offset 30) from a decrypted STAT response plaintext.
pub fn stat_size(pt: &[u8]) -> Option<u64> {
    be64(pt, STAT_SIZE_OFFSET)
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
fn be64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_request_roundtrip() {
        let name = b"52467a/storage/emulated/0/DCIM/Camera/x.jpg";
        let pt = stat_plaintext(0x41, name);
        assert_eq!(&pt[..4], &[0x05, 0x00, 0x00, 0x00]);
        assert_eq!(pt[4], 0x41);
        assert_eq!(&pt[5..21], CONST16);
        assert_eq!(pt[21], CMD_STAT);
        let req = parse_request(&pt).unwrap();
        assert_eq!(req.cmd, CMD_STAT);
        assert_eq!(req.name, name);
        assert_eq!((req.size, req.offset), (0, 0));
    }

    #[test]
    fn read_request_roundtrip() {
        let name = b"pc0000\\Users\\me\\img.jpeg";
        let pt = read_plaintext(0x42, 922286, 16384, name);
        let req = parse_request(&pt).unwrap();
        assert_eq!(req.cmd, CMD_READ);
        assert_eq!(req.size, 922286);
        assert_eq!(req.offset, 16384);
        assert_eq!(req.name, name);
    }

    #[test]
    fn request_frame_layout() {
        let tag = [0xAAu8; 16];
        let ct = b"ciphertext-bytes";
        let frame = request_frame(&tag, ct);
        assert_eq!(request_total_len(&frame).unwrap(), frame.len());
        assert_eq!(frame.len(), 8 + 16 + ct.len());
        assert_eq!(&frame[8..24], &tag);
        assert_eq!(request_ciphertext(&frame).unwrap(), ct);
    }

    #[test]
    fn response_frame_layout() {
        let tag = [0xBBu8; 16];
        let ct = b"file-bytes-here";
        let frame = response_frame(&tag, ct);
        assert_eq!(frame[0], 0x03);
        assert_eq!(
            u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize,
            ct.len() + 17
        );
        assert_eq!(frame[5], 0x00);
        assert_eq!(&frame[6..22], &tag);
        assert_eq!(response_ciphertext(&frame).unwrap(), ct);
    }

    #[test]
    fn stat_size_reads_be64_at_30() {
        let mut pt = vec![0u8; STAT_PLAINTEXT_LEN];
        pt[STAT_SIZE_OFFSET..STAT_SIZE_OFFSET + 8].copy_from_slice(&12345u64.to_be_bytes());
        assert_eq!(stat_size(&pt), Some(12345));
        assert_eq!(stat_size(&pt[..20]), None);
    }
}
