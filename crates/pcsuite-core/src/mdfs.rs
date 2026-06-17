//! mdfs: the in-app file browser plane.
//!
//! The phone's connection server (10380, same port as the control WS) also serves
//! a small HTTP/JSON file-manager API — this is what the desktop app's "files" tab
//! uses, *not* the vdfs (5678) plane. Reversed from the desktop `app.asar`
//! (`adapter.ts`): the renderer POSTs JSON to `/pc_file_manager/*` with two routing
//! headers — `newToken` (the session connect-token) and `deviceId` (the phone's
//! `mobileDeviceId`). The server sniffs the first byte, so plain HTTP works (no TLS
//! needed, same as the USB `/version` handshake) and is robust over adb-forwarded
//! ports.
//!
//! There is **no separate access-authorization gate** here: a connected session can
//! list immediately (unlike the vdfs plane). [`list`] enumerates a media/file
//! category; the resulting `savePath`s feed [`crate::vdfs::fetch`] for download.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// The phone connection server port (control WS + this HTTP API).
pub const CONTROL_PORT: u16 = 10380;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const IO_TIMEOUT: Duration = Duration::from_secs(20);
/// File downloads stream a whole tar; allow much longer than a list request.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// A category of file listing, mapped to the phone's `REQUEST_POSTS_*` type and the
/// `groupBy`/`sortCondition` the desktop app pairs with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    /// Recent files grouped by day (`REQUEST_POSTS_ONE_MOTH_LIST`).
    Recent,
    Image,
    Video,
    Audio,
    /// Generic files (`REQUEST_POSTS_FILELIST`).
    File,
    /// Documents (`REQUEST_POSTS_DOCSLIST`).
    Doc,
    /// Home overview (`REQUEST_POSTS_HOMEDATA`).
    Home,
}

impl ListKind {
    /// Parse the CLI `--type` value.
    pub fn parse(s: &str) -> Option<ListKind> {
        Some(match s.to_ascii_lowercase().as_str() {
            "recent" | "month" | "" => ListKind::Recent,
            "image" | "images" | "photo" | "pic" => ListKind::Image,
            "video" | "videos" => ListKind::Video,
            "audio" | "audios" => ListKind::Audio,
            "file" | "files" => ListKind::File,
            "doc" | "docs" | "document" => ListKind::Doc,
            "home" => ListKind::Home,
            _ => return None,
        })
    }

    /// `(type, groupBy, sortCondition)` — mirrors the desktop request bodies.
    fn params(self) -> (&'static str, u8, u8) {
        match self {
            ListKind::Recent => ("REQUEST_POSTS_ONE_MOTH_LIST", 1, 5),
            ListKind::Image => ("REQUEST_POSTS_IMAGELIST", 0, 5),
            ListKind::Video => ("REQUEST_POSTS_VIDEOLIST", 0, 5),
            ListKind::Audio => ("REQUEST_POSTS_AUDIOLIST", 0, 5),
            ListKind::File => ("REQUEST_POSTS_FILELIST", 0, 5),
            ListKind::Doc => ("REQUEST_POSTS_DOCSLIST", 0, 5),
            ListKind::Home => ("REQUEST_POSTS_HOMEDATA", 0, 0),
        }
    }
}

/// One file/dir entry flattened from a channel response (group markers are dropped).
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    /// Phone-side absolute path (`savePath`); feed to [`crate::vdfs::fetch`].
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
    pub mime: String,
    /// Modification time in epoch milliseconds (0 if absent).
    pub date_ms: i64,
    /// Media duration in ms (audio/video; 0 otherwise).
    pub duration_ms: i64,
    /// Source bucket/album name (`dirName`), when grouped.
    pub dir_name: String,
}

/// List a phone file/media category. `host` is the control host (USB: `127.0.0.1`
/// with 10380 adb-forwarded; LAN: the phone IP). `token` is the session connect
/// token; `device_id` is the phone's `mobileDeviceId`.
pub async fn list(
    host: &str,
    token: &str,
    device_id: &str,
    kind: ListKind,
    page_number: u32,
) -> Result<Vec<Entry>> {
    let (req_type, group_by, sort) = kind.params();
    let body = json!({
        "type": req_type,
        "pageIndex": 0,
        "pageNumber": page_number,
        "sortCondition": sort,
        "groupBy": group_by,
        "category": "",
        "data": "",
        "fileCount": 0,
    });
    let v = post_json(host, token, device_id, "/pc_file_manager/channel", &body)
        .await
        .with_context(|| format!("mdfs list {req_type}"))?;
    Ok(flatten(&v))
}

/// Resolve a virtual file-manager id (from `HOMEDATA`/tab entries) to a phone path.
pub async fn get_path(host: &str, token: &str, device_id: &str, id: &str) -> Result<String> {
    let v = post_json(
        host,
        token,
        device_id,
        "/pc_file_manager/get_path",
        &json!({"id": id, "path_type": ""}),
    )
    .await
    .context("mdfs get_path")?;
    Ok(v.get("result_path")
        .and_then(|s| s.as_str())
        .unwrap_or_default()
        .to_string())
}

/// POST a JSON body to a `/pc_file_manager/*` route and parse the JSON reply.
pub async fn post_json(
    host: &str,
    token: &str,
    device_id: &str,
    route: &str,
    body: &Value,
) -> Result<Value> {
    let payload = serde_json::to_vec(body)?;
    let (status, resp) =
        http_request(host, CONTROL_PORT, "POST", route, token, device_id, Some(&payload), IO_TIMEOUT)
            .await?;
    if status != 200 {
        let snippet: String = String::from_utf8_lossy(&resp).trim().chars().take(160).collect();
        bail!("mdfs {route} -> HTTP {status}: {snippet}");
    }
    serde_json::from_slice(&resp)
        .with_context(|| format!("mdfs {route}: reply was not JSON ({} bytes)", resp.len()))
}

/// Download one phone file by path over the mdfs HTTP plane — the path the desktop
/// app uses, which works without the vdfs (5678) serving gate. Two steps:
///   1. `POST /pc_file_manager/download_info?id=<id>` registers the request
///      (`downloadList` = the phone paths, `total` = summed size).
///   2. `GET /pc_file_manager/download?id=<id>` streams a **tar** of those files.
/// Returns the bytes of the single requested file (the first tar entry).
pub async fn download(host: &str, token: &str, device_id: &str, save_path: &str) -> Result<Vec<u8>> {
    // A unique per-request transfer id correlates the two calls (the desktop app uses
    // an arbitrary id; the phone only needs the same value on both requests).
    let id = format!("pcsuite-{:08x}", fnv1a(save_path.as_bytes()));

    let info = json!({
        "downloadList": [save_path],
        "type": "FROM_PC_FILE_MANAGER",
        "total": 0,
    });
    let (st, resp) = http_request(
        host,
        CONTROL_PORT,
        "POST",
        &format!("/pc_file_manager/download_info?id={id}"),
        token,
        device_id,
        Some(&serde_json::to_vec(&info)?),
        IO_TIMEOUT,
    )
    .await
    .context("mdfs download_info")?;
    if st != 200 {
        let snippet: String = String::from_utf8_lossy(&resp).trim().chars().take(160).collect();
        bail!("mdfs download_info -> HTTP {st}: {snippet}");
    }

    let (st2, body) = http_request(
        host,
        CONTROL_PORT,
        "GET",
        &format!("/pc_file_manager/download?id={id}"),
        token,
        device_id,
        None,
        DOWNLOAD_TIMEOUT,
    )
    .await
    .context("mdfs download")?;
    if st2 != 200 {
        let snippet: String = String::from_utf8_lossy(&body).trim().chars().take(160).collect();
        bail!("mdfs download -> HTTP {st2}: {snippet}");
    }

    untar_first(&body).with_context(|| format!("download tar had no file entry for {save_path}"))
}

/// FNV-1a 32-bit — a tiny stable hash for the transfer id (no extra deps).
fn fnv1a(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in bytes {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// One plain-HTTP request to the connection server, with the `newToken`/`deviceId`
/// routing headers. `Connection: close` lets us read the whole body to EOF (mirrors
/// the USB `/version` handshake). Returns `(status, body)`; `status == 0` means the
/// reply was not HTTP (e.g. a bare `NotFound` from the router when a header is wrong).
async fn http_request(
    host: &str,
    port: u16,
    method: &str,
    route: &str,
    token: &str,
    device_id: &str,
    body: Option<&[u8]>,
    read_timeout: Duration,
) -> Result<(u16, Vec<u8>)> {
    let mut head = format!(
        "{method} {route} HTTP/1.1\r\nHost: {host}:{port}\r\n\
         newToken: {token}\r\ndeviceId: {device_id}\r\n\
         Accept: application/json\r\nConnection: close\r\n"
    );
    if let Some(b) = body {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            b.len()
        ));
    }
    head.push_str("\r\n");

    let mut s = timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .with_context(|| format!("connect {host}:{port} timed out"))?
        .with_context(|| format!("connect {host}:{port}"))?;
    s.set_nodelay(true).ok();
    s.write_all(head.as_bytes()).await?;
    if let Some(b) = body {
        s.write_all(b).await?;
    }
    s.flush().await?;

    let mut buf = Vec::new();
    let _ = timeout(read_timeout, s.read_to_end(&mut buf)).await;
    Ok(parse_http(&buf))
}

/// Split an HTTP response into `(status, body)`, de-chunking a `Transfer-Encoding:
/// chunked` body (the file-download stream uses it). Non-HTTP bytes → `(0, whole)`.
fn parse_http(buf: &[u8]) -> (u16, Vec<u8>) {
    let Some(sep) = find(buf, b"\r\n\r\n") else {
        return (0, buf.to_vec());
    };
    let head = &buf[..sep];
    let raw_body = &buf[sep + 4..];
    let head_str = std::str::from_utf8(head).unwrap_or("");
    let status = head_str
        .lines()
        .next()
        .filter(|line| line.starts_with("HTTP/"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let chunked = head_str
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.to_ascii_lowercase().contains("chunked"));
    let body = if chunked { dechunk(raw_body) } else { raw_body.to_vec() };
    (status, body)
}

/// Decode an HTTP/1.1 chunked body (`<hexlen>\r\n<data>\r\n…0\r\n\r\n`).
fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    loop {
        let Some(eol) = find(b, b"\r\n") else { break };
        let size_hex = std::str::from_utf8(&b[..eol]).unwrap_or("");
        let size = usize::from_str_radix(size_hex.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        b = &b[eol + 2..];
        if size == 0 {
            break;
        }
        let take = size.min(b.len());
        out.extend_from_slice(&b[..take]);
        b = &b[take..];
        if b.starts_with(b"\r\n") {
            b = &b[2..];
        }
    }
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Extract the first regular-file entry's bytes from a POSIX/ustar tar archive
/// (the file-download stream returns a tar of the requested paths). Skips pax/global
/// extended headers (`x`/`g` type flags); octal size is correct for files < 8 GiB.
fn untar_first(data: &[u8]) -> Result<Vec<u8>> {
    let mut off = 0usize;
    while off + 512 <= data.len() {
        let hdr = &data[off..off + 512];
        if hdr.iter().all(|&b| b == 0) {
            break; // end-of-archive marker
        }
        let size = tar_octal(&hdr[124..136]);
        let typeflag = hdr[156];
        off += 512;
        let data_blocks = size.div_ceil(512) * 512;
        // Regular file: typeflag '0' or NUL. Skip extended headers ('x'/'g') and others.
        if (typeflag == b'0' || typeflag == 0) && size > 0 {
            let end = (off + size).min(data.len());
            return Ok(data[off..end].to_vec());
        }
        off += data_blocks;
    }
    bail!("no regular file entry in tar ({} bytes)", data.len())
}

/// Parse a tar header octal field (space/NUL terminated).
fn tar_octal(field: &[u8]) -> usize {
    let s: String = field
        .iter()
        .take_while(|&&c| c != 0 && c != b' ')
        .map(|&c| c as char)
        .collect();
    usize::from_str_radix(s.trim(), 8).unwrap_or(0)
}

/// Walk a channel reply and collect every file/dir entry, regardless of whether the
/// payload is flat (`{dataList:[{...}],totalCount}`) or grouped
/// (`{dataList:[{dataList:{"bucket | type":[{...}]},time,dateFormat}]}`). Group
/// markers (`isGroup:true`, or rows with neither a name nor a path) are skipped.
fn flatten(v: &Value) -> Vec<Entry> {
    let mut out = Vec::new();
    walk(v, &mut out);
    out
}

fn walk(v: &Value, out: &mut Vec<Entry>) {
    match v {
        Value::Array(a) => {
            for x in a {
                walk(x, out);
            }
        }
        Value::Object(o) => {
            let is_group = o.get("isGroup").and_then(Value::as_bool).unwrap_or(false);
            let name = o.get("fileName").and_then(Value::as_str).unwrap_or("");
            let path = o.get("savePath").and_then(Value::as_str).unwrap_or("");
            if !is_group && (!name.is_empty() || !path.is_empty()) {
                out.push(Entry {
                    name: name.to_string(),
                    path: path.to_string(),
                    size: o.get("fileSize").and_then(Value::as_u64).unwrap_or(0),
                    is_dir: o.get("isDirectory").and_then(Value::as_bool).unwrap_or(false),
                    mime: o.get("mimeType").and_then(Value::as_str).unwrap_or("").to_string(),
                    date_ms: o.get("date").and_then(Value::as_i64).unwrap_or(0),
                    duration_ms: o.get("duration").and_then(Value::as_i64).unwrap_or(0),
                    dir_name: o.get("dirName").and_then(Value::as_str).unwrap_or("").to_string(),
                });
                return; // a leaf entry has no nested entries
            }
            for val in o.values() {
                walk(val, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":1}";
        let (status, body) = parse_http(raw);
        assert_eq!(status, 200);
        assert_eq!(body, b"{\"a\":1}");
    }

    #[test]
    fn parse_http_non_http_is_zero() {
        let (status, body) = parse_http(b"NotFound");
        assert_eq!(status, 0);
        assert_eq!(body, b"NotFound");
    }

    #[test]
    fn flatten_flat_list() {
        let v: Value = serde_json::from_str(
            r#"{"dataList":[{"duration":768,"date":1780543699000,"fileName":"v.mp4","fileSize":2367687,"isDirectory":false,"savePath":"/storage/emulated/0/DCIM/Camera/v.mp4"}],"totalCount":1}"#,
        )
        .unwrap();
        let e = flatten(&v);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].name, "v.mp4");
        assert_eq!(e[0].path, "/storage/emulated/0/DCIM/Camera/v.mp4");
        assert_eq!(e[0].size, 2367687);
        assert_eq!(e[0].duration_ms, 768);
    }

    #[test]
    fn dechunk_basic() {
        // "Wiki" + "pedia" in two chunks, then terminator.
        let raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(dechunk(raw), b"Wikipedia");
    }

    #[test]
    fn untar_first_extracts_single_file() {
        // Build a minimal ustar archive: 512 header + one 5-byte file + padding + 2 zero blocks.
        let mut tar = vec![0u8; 512];
        let name = b"hello.txt";
        tar[..name.len()].copy_from_slice(name);
        tar[124..136].copy_from_slice(b"00000000005\0"); // size field = octal 5
        tar[156] = b'0'; // regular file
        tar[257..262].copy_from_slice(b"ustar");
        let mut block = vec![0u8; 512];
        block[..5].copy_from_slice(b"world");
        tar.extend_from_slice(&block);
        tar.extend_from_slice(&[0u8; 1024]); // end-of-archive
        assert_eq!(untar_first(&tar).unwrap(), b"world");
    }

    #[test]
    fn flatten_grouped_skips_markers() {
        let v: Value = serde_json::from_str(
            r#"{"dataList":[
              {"groupCount":1,"groupName":"今天","isGroup":true,"date":-1,"fileName":"","fileSize":0,"savePath":""},
              {"dataList":{"截屏 | 图片":[{"dirName":"截屏","mimeType":"image/jpeg","date":1781656159000,"fileName":"s.jpg","fileSize":100,"isDirectory":false,"savePath":"/storage/emulated/0/Pictures/Screenshots/s.jpg"}]},"time":"今天","dateFormat":"2026/06/17 13:10"}
            ]}"#,
        )
        .unwrap();
        let e = flatten(&v);
        assert_eq!(e.len(), 1, "group marker should be skipped, one real entry kept");
        assert_eq!(e[0].name, "s.jpg");
        assert_eq!(e[0].dir_name, "截屏");
        assert_eq!(e[0].mime, "image/jpeg");
    }
}
