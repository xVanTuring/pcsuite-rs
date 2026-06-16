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
//! A STAT response plaintext is a 74-byte POSIX-`stat` structure (QDataStream,
//! big-endian): `st_mode` is a BE32 at offset 12 (`& S_IFMT` distinguishes
//! dir/file/symlink), the file size a BE64 at offset 30, and `st_mtime` a BE64
//! (seconds) at offset 58. A READ response plaintext is the raw file bytes.
//!
//! A LIST (CMD_LIST) response plaintext is a sequence of directory entries with
//! **no leading count** (each is self-delimiting; parse to end of buffer). Per
//! entry, QDataStream big-endian:
//!
//! ```text
//! u32 reserved | u64 reserved | u16 nameLen | u8 dType | name (nameLen bytes + trailing NUL)
//!   dType: 4 = dir (DT_DIR), 8 = file (DT_REG), 0xa = symlink (DT_LNK)
//! ```
//!
//! The two reserved words are 0 from the desktop serializer; the client fills real
//! attributes by STATing each entry. See [`parse_dirent_list`] / [`Stat`].
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
/// Offset of the BE32 `st_mode` field inside a STAT response plaintext.
pub const STAT_MODE_OFFSET: usize = 12;
/// Offset of the BE64 file-size field inside a STAT response plaintext.
pub const STAT_SIZE_OFFSET: usize = 30;
/// Offset of the BE64 `st_mtime` (seconds) field inside a STAT response plaintext.
pub const STAT_MTIME_OFFSET: usize = 58;

/// `st_mode` file-type mask and the types we care about (POSIX values).
pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;

/// Directory-entry `d_type` values (POSIX `dirent`).
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 0xa;

/// Decoded file attributes from a STAT response (the fields Finder needs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stat {
    /// POSIX `st_mode` (type bits + permissions).
    pub mode: u32,
    /// File size in bytes.
    pub size: u64,
    /// Modification time, seconds since the Unix epoch.
    pub mtime: u64,
}

impl Stat {
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
    pub fn is_file(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }
}

/// One directory entry from a LIST response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// File name (UTF-8; lossily decoded). Not a full path.
    pub name: String,
    /// POSIX `d_type` ([`DT_DIR`] / [`DT_REG`] / [`DT_LNK`] / 0 = unknown).
    pub d_type: u8,
}

impl DirEntry {
    pub fn is_dir(&self) -> bool {
        self.d_type == DT_DIR
    }
    pub fn is_file(&self) -> bool {
        self.d_type == DT_REG
    }
}

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

/// Build a LIST request plaintext for `name` (`<deviceId><dirPath>`). The body is
/// identical to STAT (`BE32 nameLen ‖ name`); only the command byte differs.
pub fn list_plaintext(seq: u8, name: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + name.len());
    body.extend_from_slice(&(name.len() as u32).to_be_bytes());
    body.extend_from_slice(name);
    request_plaintext(seq, CMD_LIST, &body)
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

/// Parse a decrypted STAT response plaintext into [`Stat`] (mode, size, mtime).
/// Returns `None` if shorter than [`STAT_PLAINTEXT_LEN`].
pub fn parse_stat(pt: &[u8]) -> Option<Stat> {
    if pt.len() < STAT_PLAINTEXT_LEN {
        return None;
    }
    Some(Stat {
        mode: be32(pt, STAT_MODE_OFFSET)?,
        size: be64(pt, STAT_SIZE_OFFSET)?,
        mtime: be64(pt, STAT_MTIME_OFFSET)?,
    })
}

/// Parse a decrypted LIST response plaintext into directory entries (see the
/// module docs for the wire format). Entries are self-delimiting; parsing stops at
/// the end of the buffer or the first truncated entry. `.` and `..` are skipped.
pub fn parse_dirent_list(pt: &[u8]) -> Vec<DirEntry> {
    // header per entry: u32 + u64 + u16(nameLen) + u8(dType) = 15 bytes.
    const HDR: usize = 4 + 8 + 2 + 1;
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + HDR <= pt.len() {
        let name_len = match be16(pt, i + 12) {
            Some(v) => v as usize,
            None => break,
        };
        let d_type = pt[i + 14];
        let name_start = i + HDR;
        let name_end = match name_start.checked_add(name_len) {
            Some(e) if e <= pt.len() => e,
            _ => break, // truncated final entry
        };
        let name = String::from_utf8_lossy(&pt[name_start..name_end]).into_owned();
        // The serializer writes nameLen+1 bytes (name + trailing NUL); skip the NUL.
        i = name_end + 1;
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        out.push(DirEntry { name, d_type });
    }
    out
}

/// Serialize directory entries into a LIST response plaintext, mirroring the
/// phone-suite's `getDirentAttr` (per entry `u32(0) u64(0) u16 nameLen u8 dType
/// name+NUL`, big-endian, no leading count). Inverse of [`parse_dirent_list`].
pub fn serialize_dirent_list(entries: &[DirEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        let name = e.name.as_bytes();
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u64.to_be_bytes());
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.push(e.d_type);
        out.extend_from_slice(name);
        out.push(0x00); // trailing NUL (writeRawData wrote nameLen+1)
    }
    out
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
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

    #[test]
    fn list_request_roundtrip() {
        let name = b"52467a/storage/emulated/0/DCIM";
        let pt = list_plaintext(0x43, name);
        assert_eq!(pt[21], CMD_LIST);
        let req = parse_request(&pt).unwrap();
        assert_eq!(req.cmd, CMD_LIST);
        assert_eq!(req.name, name);
        assert_eq!((req.size, req.offset), (0, 0));
    }

    /// A real 74-byte STAT response captured from the phone-suite (a regular file).
    /// Validates the field offsets reverse-engineered from `AssembleAttrReply`.
    #[test]
    fn parse_stat_from_real_template() {
        let pt: [u8; STAT_PLAINTEXT_LEN] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0xf5, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x12, 0xae, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6a, 0x2f,
            0xd6, 0xa6, 0x00, 0x00, 0x00, 0x00, 0x6a, 0x2f, 0xd6, 0xa4, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let st = parse_stat(&pt).unwrap();
        assert_eq!(st.mode, 0o100600); // 0x8180 = S_IFREG | 0600
        assert!(st.is_file() && !st.is_dir() && !st.is_symlink());
        assert_eq!(st.size, 922286);
        assert_eq!(st.mtime, 0x6a2f_d6a4); // 2026-06-09, seconds
        assert_eq!(parse_stat(&pt[..40]), None);
    }

    #[test]
    fn stat_dir_mode_detected() {
        let mut pt = vec![0u8; STAT_PLAINTEXT_LEN];
        pt[STAT_MODE_OFFSET..STAT_MODE_OFFSET + 4].copy_from_slice(&0o040755u32.to_be_bytes());
        let st = parse_stat(&pt).unwrap();
        assert!(st.is_dir() && !st.is_file());
    }

    #[test]
    fn dirent_list_roundtrip_skips_dot_entries() {
        let entries = vec![
            DirEntry { name: ".".into(), d_type: DT_DIR },
            DirEntry { name: "..".into(), d_type: DT_DIR },
            DirEntry { name: "Camera".into(), d_type: DT_DIR },
            DirEntry { name: "截图".into(), d_type: DT_DIR }, // multibyte UTF-8
            DirEntry { name: "IMG_0001.jpg".into(), d_type: DT_REG },
        ];
        let wire = serialize_dirent_list(&entries);
        let parsed = parse_dirent_list(&wire);
        assert_eq!(
            parsed,
            vec![
                DirEntry { name: "Camera".into(), d_type: DT_DIR },
                DirEntry { name: "截图".into(), d_type: DT_DIR },
                DirEntry { name: "IMG_0001.jpg".into(), d_type: DT_REG },
            ]
        );
        assert!(parsed[0].is_dir() && parsed[2].is_file());
    }

    #[test]
    fn parse_dirent_list_tolerates_truncation() {
        let entries = vec![DirEntry { name: "a.txt".into(), d_type: DT_REG }];
        let wire = serialize_dirent_list(&entries);
        // chop the trailing NUL + part of the name: must not panic, drops the bad tail
        let _ = parse_dirent_list(&wire[..wire.len() - 3]);
        assert!(parse_dirent_list(&[]).is_empty());
        assert!(parse_dirent_list(&[0u8; 10]).is_empty()); // header-only, no body
    }
}
