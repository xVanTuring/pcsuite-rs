//! vdfs file plane: move clipboard **image/file bytes** that the 8904 frame only
//! references by path.
//!
//! Two roles (mirrors the phone-suite's `vdfs` client + `vdfsServer`):
//! - *client* (phone→PC): [`fetch`] pulls a phone file by path (STAT for size, then
//!   READ), [`stat`] returns its [`vdfs::Stat`] (mode/size/mtime), and [`list_dir`]
//!   enumerates a directory — the operations a macOS File Provider needs to browse
//!   the phone. Connects to the phone's vdfs server (USB: `127.0.0.1:10382` via
//!   `adb forward`→5678; LAN: `<phone>:5678`).
//! - [`spawn_server`] — *server* on 5679: serve a local PC file to the phone (PC→
//!   phone paste). The phone STATs then READs (often in chunks); we answer each.
//!
//! Crypto is AES-256-GCM with a 12-byte nonce (`iv[..12]`), no AAD — sealed via
//! [`gcm12_seal`] (tag framed first) and read back via [`gcm12_open_noauth`] (the
//! phone never authenticates responses, so we CTR-decrypt with key+nonce only).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use pcsuite_crypto::{gcm12_open_noauth, gcm12_seal};
use pcsuite_proto::vdfs;

/// 74-byte STAT response structure (captured verbatim; the phone validates its
/// shape). Only the BE64 size at [`vdfs::STAT_SIZE_OFFSET`] is filled in per file.
const STAT_TEMPLATE: [u8; vdfs::STAT_PLAINTEXT_LEN] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0xf5, 0x00, 0x00,
    0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e,
    0x12, 0xae, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6a, 0x2f, 0xd6, 0xa6, 0x00, 0x00,
    0x00, 0x00, 0x6a, 0x2f, 0xd6, 0xa4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
];

const IO_TIMEOUT: Duration = Duration::from_secs(20);

// ───────────────────────────── client (phone → PC) ─────────────────────────────

/// Fetch a phone file by path. `device_id` is the phone's `mobileDeviceId`; `path`
/// is the phone-side path from the clipboard reference. Returns the file bytes.
pub async fn fetch(
    host: &str,
    port: u16,
    phone_key: &str,
    phone_iv: &str,
    device_id: &str,
    path: &str,
) -> Result<Vec<u8>> {
    let name = format!("{device_id}{path}").into_bytes();
    let size = stat_name(host, port, phone_key, phone_iv, &name)
        .await
        .context("vdfs stat")?
        .size;
    if size == 0 {
        bail!("vdfs stat returned size 0 for {path}");
    }
    read(host, port, phone_key, phone_iv, &name, size, 0)
        .await
        .context("vdfs read")
}

/// STAT a phone path, returning its [`vdfs::Stat`] (mode/size/mtime). `device_id`
/// is the phone's `mobileDeviceId`; `path` is the phone-side absolute path.
pub async fn stat(
    host: &str,
    port: u16,
    phone_key: &str,
    phone_iv: &str,
    device_id: &str,
    path: &str,
) -> Result<vdfs::Stat> {
    let name = format!("{device_id}{path}").into_bytes();
    stat_name(host, port, phone_key, phone_iv, &name)
        .await
        .context("vdfs stat")
}

/// List a phone directory, returning its entries (name + `d_type`). Attributes
/// (size/mtime) come from a follow-up [`stat`] per entry, as the desktop client does.
pub async fn list_dir(
    host: &str,
    port: u16,
    phone_key: &str,
    phone_iv: &str,
    device_id: &str,
    path: &str,
) -> Result<Vec<vdfs::DirEntry>> {
    let name = format!("{device_id}{path}").into_bytes();
    let (ct, tag) = gcm12_seal(&vdfs::list_plaintext(0x43, &name), phone_key.as_bytes(), phone_iv.as_bytes())
        .map_err(|e| anyhow::anyhow!("seal: {e}"))?;
    let frame = vdfs::request_frame(&tag, &ct);
    // LIST response length is unknown up front; read it from the response frame header.
    let resp = roundtrip_framed(host, port, &frame).await.context("vdfs list")?;
    let ctext = vdfs::response_ciphertext(&resp).context("short list response")?;
    let pt = gcm12_open_noauth(ctext, phone_key.as_bytes(), phone_iv.as_bytes())
        .map_err(|e| anyhow::anyhow!("open: {e}"))?;
    Ok(vdfs::parse_dirent_list(&pt))
}

async fn stat_name(host: &str, port: u16, key: &str, iv: &str, name: &[u8]) -> Result<vdfs::Stat> {
    let (ct, tag) = gcm12_seal(&vdfs::stat_plaintext(0x41, name), key.as_bytes(), iv.as_bytes())
        .map_err(|e| anyhow::anyhow!("seal: {e}"))?;
    let frame = vdfs::request_frame(&tag, &ct);
    // STAT response = 22-byte header + 74-byte stat structure.
    let resp = roundtrip(host, port, &frame, vdfs::RESPONSE_CT_OFFSET + vdfs::STAT_PLAINTEXT_LEN).await?;
    let ctext = vdfs::response_ciphertext(&resp).context("short stat response")?;
    let pt = gcm12_open_noauth(ctext, key.as_bytes(), iv.as_bytes())
        .map_err(|e| anyhow::anyhow!("open: {e}"))?;
    vdfs::parse_stat(&pt).context("stat parse failed")
}

async fn read(host: &str, port: u16, key: &str, iv: &str, name: &[u8], size: u64, offset: u64) -> Result<Vec<u8>> {
    let (ct, tag) =
        gcm12_seal(&vdfs::read_plaintext(0x42, size, offset, name), key.as_bytes(), iv.as_bytes())
            .map_err(|e| anyhow::anyhow!("seal: {e}"))?;
    let frame = vdfs::request_frame(&tag, &ct);
    let want = vdfs::RESPONSE_CT_OFFSET + size as usize;
    let resp = roundtrip(host, port, &frame, want).await?;
    let ctext = vdfs::response_ciphertext(&resp).context("short read response")?;
    let mut pt = gcm12_open_noauth(ctext, key.as_bytes(), iv.as_bytes())
        .map_err(|e| anyhow::anyhow!("open: {e}"))?;
    pt.truncate(size as usize);
    Ok(pt)
}

/// One request → response over a fresh connection (vdfs is one-file-per-connection).
/// Reads until at least `min_resp` bytes arrive (or EOF / timeout).
async fn roundtrip(host: &str, port: u16, frame: &[u8], min_resp: usize) -> Result<Vec<u8>> {
    let mut s = timeout(IO_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .with_context(|| format!("connect {host}:{port} timed out"))??;
    s.set_nodelay(true).ok();
    s.write_all(frame).await?;
    s.flush().await?;
    let mut buf = Vec::with_capacity(min_resp.min(1 << 20));
    let mut tmp = vec![0u8; 262144];
    while buf.len() < min_resp {
        let n = match timeout(IO_TIMEOUT, s.read(&mut tmp)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break, // read timeout: return what we have
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(buf)
}

/// Like [`roundtrip`] but for a response of unknown size: derive the total length
/// from the response frame header (`03 ‖ BE32(cipherLen+17) ‖ 00 ‖ tag16 ‖ ct`, so
/// total = 5 + BE32), then read exactly that. Used for LIST.
async fn roundtrip_framed(host: &str, port: u16, frame: &[u8]) -> Result<Vec<u8>> {
    let mut s = timeout(IO_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .with_context(|| format!("connect {host}:{port} timed out"))??;
    s.set_nodelay(true).ok();
    s.write_all(frame).await?;
    s.flush().await?;
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = vec![0u8; 65536];
    let mut total: Option<usize> = None;
    loop {
        if let Some(t) = total {
            if buf.len() >= t {
                break;
            }
        }
        let n = match timeout(IO_TIMEOUT, s.read(&mut tmp)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break, // read timeout: return what we have
        };
        if n == 0 {
            break; // EOF (vdfs closes after one response)
        }
        buf.extend_from_slice(&tmp[..n]);
        if total.is_none() && buf.len() >= 5 && buf[0] == 0x03 {
            let adv = u32::from_be_bytes(buf[1..5].try_into().unwrap()) as usize;
            total = Some(5 + adv); // 5 + (cipherLen + 17) = 22 + cipherLen
        }
    }
    Ok(buf)
}

// ───────────────────────────── server (PC → phone), port 5679 ─────────────────────────────

/// Accept phone connections on `listener` and serve local files (STAT/READ),
/// encrypting with the PC session key. `pc_id` prefixes the names the phone sends.
pub fn spawn_server(listener: TcpListener, pc_key: String, pc_iv: String, pc_id: String) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let (k, iv, id) = (pc_key.clone(), pc_iv.clone(), pc_id.clone());
                    tokio::spawn(async move {
                        if let Err(e) = serve_conn(stream, &k, &iv, &id).await {
                            tracing::debug!(%addr, err = %e, "vdfs 5679 connection ended");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(err = %e, "vdfs 5679 accept failed");
                    break;
                }
            }
        }
    })
}

async fn serve_conn(mut stream: TcpStream, key: &str, iv: &str, pc_id: &str) -> Result<()> {
    stream.set_nodelay(true).ok();
    // request frame: BE64 total ‖ tag16 ‖ ciphertext
    let mut head = [0u8; 8];
    stream.read_exact(&mut head).await?;
    let total = vdfs::request_total_len(&head).context("bad request head")?;
    if !(vdfs::REQUEST_CT_OFFSET..=64 << 20).contains(&total) {
        bail!("implausible vdfs request length {total}");
    }
    let mut body = vec![0u8; total - 8];
    stream.read_exact(&mut body).await?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&head);
    frame.extend_from_slice(&body);

    let ctext = vdfs::request_ciphertext(&frame).context("short request frame")?;
    let pt = gcm12_open_noauth(ctext, key.as_bytes(), iv.as_bytes())
        .map_err(|e| anyhow::anyhow!("open: {e}"))?;
    let req = vdfs::parse_request(&pt).context("unparseable vdfs request")?;
    let name = String::from_utf8_lossy(&req.name);
    let path = name_to_path(&name, pc_id);

    let resp_pt = match req.cmd {
        vdfs::CMD_STAT => {
            let st = build_stat_response(&path);
            tracing::info!(path = %path.display(), "vdfs STAT");
            st.to_vec()
        }
        vdfs::CMD_LIST => {
            let entries = list_local_dir(&path);
            tracing::info!(path = %path.display(), n = entries.len(), "vdfs LIST");
            vdfs::serialize_dirent_list(&entries)
        }
        vdfs::CMD_READ => {
            let data = read_file_range(&path, req.offset, req.size).unwrap_or_default();
            tracing::info!(path = %path.display(), offset = req.offset, want = req.size, got = data.len(), "vdfs READ");
            data
        }
        other => bail!("unsupported vdfs cmd {other}"),
    };

    let (ct, tag) = gcm12_seal(&resp_pt, key.as_bytes(), iv.as_bytes())
        .map_err(|e| anyhow::anyhow!("seal: {e}"))?;
    stream.write_all(&vdfs::response_frame(&tag, &ct)).await?;
    stream.flush().await?;
    Ok(())
}

/// Build a 74-byte STAT response for a local path: start from the captured
/// template, then overwrite mode/size/mtime from real metadata (so directories
/// report `S_IFDIR`). Missing metadata falls back to the template defaults.
fn build_stat_response(path: &std::path::Path) -> [u8; vdfs::STAT_PLAINTEXT_LEN] {
    let mut st = STAT_TEMPLATE;
    if let Ok(md) = std::fs::metadata(path) {
        st[vdfs::STAT_SIZE_OFFSET..vdfs::STAT_SIZE_OFFSET + 8].copy_from_slice(&md.len().to_be_bytes());
        let mode: u32 = if md.is_dir() {
            vdfs::S_IFDIR | 0o755
        } else {
            vdfs::S_IFREG | 0o644
        };
        st[vdfs::STAT_MODE_OFFSET..vdfs::STAT_MODE_OFFSET + 4].copy_from_slice(&mode.to_be_bytes());
        if let Ok(secs) = md
            .modified()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).map_err(std::io::Error::other))
        {
            st[vdfs::STAT_MTIME_OFFSET..vdfs::STAT_MTIME_OFFSET + 8]
                .copy_from_slice(&secs.as_secs().to_be_bytes());
        }
    }
    st
}

/// Enumerate a local directory into vdfs dir entries (name + `d_type`).
fn list_local_dir(dir: &std::path::Path) -> Vec<vdfs::DirEntry> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            let d_type = match ent.file_type() {
                Ok(ft) if ft.is_dir() => vdfs::DT_DIR,
                Ok(ft) if ft.is_symlink() => vdfs::DT_LNK,
                Ok(ft) if ft.is_file() => vdfs::DT_REG,
                _ => 0,
            };
            out.push(vdfs::DirEntry { name, d_type });
        }
    }
    out
}

fn read_file_range(path: &std::path::Path, offset: u64, size: u64) -> Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; size as usize];
    let mut filled = 0;
    while filled < buf.len() {
        let n = f.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Convert a phone-sent name (`<pcId>` prefix + a Windows-style backslash path) back
/// to a local filesystem path.
fn name_to_path(name: &str, pc_id: &str) -> PathBuf {
    let stripped = name.strip_prefix(pc_id).unwrap_or(name);
    let mut p = stripped.replace('\\', "/");
    while p.contains("//") {
        p = p.replace("//", "/");
    }
    PathBuf::from(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_to_path_strips_id_and_flips_slashes() {
        let p = name_to_path(r"pc0000\Users\me\Caches\pcsuite\img.jpeg", "pc0000");
        assert_eq!(p, PathBuf::from("/Users/me/Caches/pcsuite/img.jpeg"));
    }

    #[test]
    fn stat_template_size_roundtrips() {
        let mut st = STAT_TEMPLATE;
        st[vdfs::STAT_SIZE_OFFSET..vdfs::STAT_SIZE_OFFSET + 8].copy_from_slice(&7777u64.to_be_bytes());
        assert_eq!(vdfs::stat_size(&st), Some(7777));
    }

    /// Full client↔server loopback: the 5679 server serves a real file and the
    /// client STATs + READs it back. Exercises framing + gcm12 seal/open end to end
    /// without the phone.
    #[tokio::test]
    async fn client_server_loopback() {
        let key = "0123456789abcdef0123456789abcdef"; // 32 bytes
        let iv = "ABCDEFGHIJKLMNOP"; // 16 bytes (first 12 used)
        let pc_id = "pc0000";

        // a file big enough to span several GCM/CTR blocks
        let mut content = Vec::new();
        for i in 0..5000u32 {
            content.extend_from_slice(&i.to_le_bytes());
        }
        let file = std::env::temp_dir().join(format!("pcsuite_vdfs_loopback_{}.bin", std::process::id()));
        std::fs::write(&file, &content).unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let _srv = spawn_server(listener, key.into(), iv.into(), pc_id.into());

        // client name = device_id + path; using device_id == pc_id so the server
        // strips it back to the real absolute path.
        let path = file.to_string_lossy().to_string();
        let got = fetch("127.0.0.1", port, key, iv, pc_id, &path).await.unwrap();
        assert_eq!(got, content, "fetched bytes must match the served file");

        let _ = std::fs::remove_file(&file);
    }

    /// LIST + STAT over the loopback server: enumerate a directory (a subdir and a
    /// file) and STAT each, exercising the new dirent/stat parsers end to end.
    #[tokio::test]
    async fn list_and_stat_loopback() {
        let key = "0123456789abcdef0123456789abcdef";
        let iv = "ABCDEFGHIJKLMNOP";
        let pc_id = "pc0000";

        let root = std::env::temp_dir().join(format!("pcsuite_vdfs_ls_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("hello.txt"), b"hello world").unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let _srv = spawn_server(listener, key.into(), iv.into(), pc_id.into());

        let dir = root.to_string_lossy().to_string();
        let mut entries = list_dir("127.0.0.1", port, key, iv, pc_id, &dir).await.unwrap();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(entries.len(), 2, "expected sub/ and hello.txt");
        assert_eq!(entries[0], pcsuite_proto::vdfs::DirEntry { name: "hello.txt".into(), d_type: pcsuite_proto::vdfs::DT_REG });
        assert_eq!(entries[1], pcsuite_proto::vdfs::DirEntry { name: "sub".into(), d_type: pcsuite_proto::vdfs::DT_DIR });

        let file_st = stat("127.0.0.1", port, key, iv, pc_id, &format!("{dir}/hello.txt")).await.unwrap();
        assert!(file_st.is_file() && !file_st.is_dir());
        assert_eq!(file_st.size, 11);

        let dir_st = stat("127.0.0.1", port, key, iv, pc_id, &format!("{dir}/sub")).await.unwrap();
        assert!(dir_st.is_dir() && !dir_st.is_file());

        let _ = std::fs::remove_dir_all(&root);
    }
}
