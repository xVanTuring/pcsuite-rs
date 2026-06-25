//! Super-clipboard (text) over the 8904 relay.
//!
//! Flow: control WS `SHADOW_LIKE:startup` (declaring our key/iv + service ports)
//! → phone replies with its session key/iv → we send `SHADOW_LIKE:ready` → the
//! phone reverse-connects to our 8904 server → ruying frames carry GCM-encrypted
//! clipboard JSON (decrypt incoming with the phone key, encrypt outgoing with our
//! key). The PC-internal 9199 bus / worker-ack dance is intentionally omitted —
//! the phone only needs `startup` then `ready`.
//!
//! The OS clipboard is reached through the [`ClipboardBackend`] trait so the core
//! stays OS-agnostic (the frontend/CLI provides the backend).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;

use tokio::task::JoinHandle;

use pcsuite_crypto::{gcm_decrypt, gcm_encrypt};
use pcsuite_net::ws::WsFrame;
use pcsuite_proto::clip::{self, PcInfo};
use pcsuite_proto::ruying::{self, Parsed, RuyingFrame};

use crate::config;
use crate::session::ControlHandle;
use crate::vdfs;
use crate::wsconn::open_ws;

const ECHO_WINDOW: Duration = Duration::from_secs(6);

/// OS clipboard access, supplied by the frontend so the core stays portable.
///
/// Text is mandatory; the image methods are optional (default to "unsupported")
/// so a text-only backend keeps working and image sync just stays off.
pub trait ClipboardBackend: Send + Sync {
    /// Current clipboard text (`None` if empty / non-text).
    fn get_text(&self) -> Option<String>;
    /// Replace the clipboard text.
    fn set_text(&self, text: &str) -> Result<()>;
    /// A cheap fingerprint of the current clipboard image, or `None` if the
    /// clipboard holds no image. Used to detect *changes* without extracting the
    /// (possibly multi-megabyte) bytes every poll.
    fn image_signature(&self) -> Option<String> {
        None
    }
    /// Extract the current clipboard image as encoded bytes (e.g. JPEG).
    fn get_image(&self) -> Option<Vec<u8>> {
        None
    }
    /// Put an encoded image (with a mime hint like `"image/jpeg"`) on the clipboard.
    fn set_image(&self, _data: &[u8], _mime: &str) -> Result<()> {
        anyhow::bail!("image clipboard not supported by this backend")
    }
}

/// Where to run the clipboard relay.
pub struct ClipboardConfig {
    /// Control-WS host (`127.0.0.1` for USB; the phone IP for LAN).
    pub data_ip: String,
    /// Address the phone uses to reach our 8904 server (`127.0.0.1` over adb
    /// reverse for USB; our LAN IP otherwise).
    pub pc_ip: String,
    /// Local bind address for the 8904 server.
    pub bind_addr: String,
    pub token: String,
    pub open_id: String,
    pub device_name: String,
    /// `"USB"` or `"WLAN"`.
    pub connect_type: String,
    /// Host the phone's vdfs server is reachable at for image *fetch* (phone→PC).
    /// USB: `127.0.0.1` (adb-forwarded). LAN: the phone IP.
    pub vdfs_fetch_host: String,
    /// Port for the above. USB: `10382` (forward→phone 5678). LAN: `5678`.
    pub vdfs_fetch_port: u16,
    /// Direction: apply the phone's clipboard to this machine (phone→PC).
    pub recv_from_phone: bool,
    /// Direction: push this machine's clipboard to the phone (PC→phone).
    pub send_to_phone: bool,
}

pub(crate) struct Shared {
    pc_key: String,
    pc_iv: String,
    phone_key: Option<String>,
    phone_iv: Option<String>,
    phone_id: String,
    outgoing: Option<mpsc::Sender<Vec<u8>>>,
    last_text: Option<String>,
    recent: HashMap<String, Instant>,
    // ── image plane (vdfs) ──
    /// Where to reach the phone's vdfs server (host, port) for image fetch.
    fetch_host: String,
    fetch_port: u16,
    /// Last phone image path we fetched (suppress refetch on repeated refs).
    last_image_ref: Option<String>,
    /// Signature of the clipboard image we last handled in *either* direction
    /// (suppress bouncing a just-received image back to the phone).
    last_image_sig: Option<String>,
    /// When false, incoming phone clipboard frames are read but NOT written to the
    /// OS clipboard (used to make the relay PC→phone only).
    apply_incoming: bool,
}

impl Shared {
    fn mark(&mut self, text: &str) {
        let now = Instant::now();
        self.recent.insert(text.to_string(), now);
        self.recent.retain(|_, ts| now.duration_since(*ts) < ECHO_WINDOW);
    }
    fn recently_synced(&self, text: &str) -> bool {
        self.recent.get(text).is_some_and(|ts| ts.elapsed() < ECHO_WINDOW)
    }
}

pub(crate) type SharedRef = Arc<Mutex<Shared>>;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Random url-safe ASCII string used directly as raw key/iv bytes.
fn rand_chars(n: usize) -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut rng = rand::thread_rng();
    (0..n).map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char).collect()
}

fn pad6(s: &str) -> [u8; 6] {
    let mut a = [0u8; 6];
    let b = s.as_bytes();
    let n = b.len().min(6);
    a[..n].copy_from_slice(&b[..n]);
    a
}

/// GCM-encrypt `plain` and wrap it in a ruying frame.
fn build_frame(plain: &[u8], key: &str, iv: &str, field_a: &str, field_b: &str, byte_c: u8) -> Result<Vec<u8>> {
    let cipher = gcm_encrypt(plain, key.as_bytes(), iv.as_bytes(), b"")
        .map_err(|e| anyhow::anyhow!("gcm encrypt: {e}"))?;
    let frame = RuyingFrame {
        version: ruying::VERSION,
        field_a: pad6(field_a),
        field_b: pad6(field_b),
        byte_c,
        byte_d: 0,
        field_e: *b"00000000000",
        cipher,
    };
    Ok(frame.build())
}

fn preview(s: &str) -> String {
    s.chars().take(40).collect()
}

/// Extract a string-valued JSON field (`"key":"value"`) by simple scan. Good enough
/// for the controlled byteC=8 task envelopes; not a general JSON parser.
#[allow(dead_code)] // used by the byteC=8 record-response parser (WIP)
fn extract_json_str(s: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\":\"");
    let i = s.find(&pat)? + pat.len();
    let rest = &s[i..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Run the clipboard relay until the control WS closes.
pub async fn run_clipboard(cfg: ClipboardConfig, backend: Arc<dyn ClipboardBackend>) -> Result<()> {
    let pc_key = rand_chars(32);
    let pc_iv = rand_chars(16);
    let shared = new_shared(
        pc_key.clone(),
        pc_iv.clone(),
        cfg.vdfs_fetch_host.clone(),
        cfg.vdfs_fetch_port,
        cfg.recv_from_phone,
    );

    // 8904 relay server (phone reverse-connects here)
    let listener = TcpListener::bind(format!("{}:8904", cfg.bind_addr))
        .await
        .with_context(|| format!("bind {}:8904", cfg.bind_addr))?;
    tracing::info!(bind = %cfg.bind_addr, "8904 relay listening");

    // 5679 vdfs server (phone fetches PC images here; PC→phone paste)
    if cfg.send_to_phone {
        if let Err(e) = start_vdfs_server(&cfg.bind_addr, &pc_key, &pc_iv).await {
            tracing::warn!(err = %e, "vdfs 5679 server unavailable (PC→phone images off)");
        }
    }
    {
        let shared = shared.clone();
        let backend = backend.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        tracing::info!(%addr, "phone connected to 8904");
                        if let Err(e) = handle_8904(stream, shared.clone(), backend.clone()).await {
                            tracing::warn!(err = %e, "8904 connection ended");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(err = %e, "8904 accept failed");
                        break;
                    }
                }
            }
        });
    }

    // Mac/PC -> phone clipboard watcher
    if cfg.send_to_phone {
        let shared = shared.clone();
        let backend = backend.clone();
        let device_name = cfg.device_name.clone();
        tokio::spawn(async move { watcher(shared, backend, device_name).await });
    }

    // control WS + SHADOW_LIKE handshake (drives the session)
    let subproto = format!("{},{}", config::SUBPROTOCOL_BASE, cfg.token);
    let mut ws = open_ws(&cfg.data_ip, 10380, "/ws/heart-beat", &subproto, &cfg.token, 6)
        .await
        .context("control WS")?;
    tracing::info!("control WS 101; sending SHADOW_LIKE startup");
    let pc_id_s = config::clip_pc_id();
    let pcinfo = PcInfo {
        ip: &cfg.pc_ip,
        pc_device_id: &pc_id_s,
        pc_device_name: &cfg.device_name,
        key: &pc_key,
        iv: &pc_iv,
        account_open_id: &cfg.open_id,
        account_name: config::CLIP_NICK,
        connect_type: &cfg.connect_type,
    };
    ws.send_text(&clip::shadow_startup(&pcinfo, 8904, 5679)).await?;

    let mut last_ka = Instant::now();
    let mut ready_sent = false;
    loop {
        match timeout(Duration::from_secs(1), ws.recv()).await {
            Ok(Ok(WsFrame::Text(t))) => {
                if !ready_sent {
                    if let Some(sess) = clip::parse_shadow_reply(&t) {
                        {
                            let mut sh = shared.lock().await;
                            sh.phone_key = Some(sess.key);
                            sh.phone_iv = Some(sess.iv);
                            sh.phone_id = sess.mobile_device_id.clone();
                        }
                        ws.send_text(&clip::shadow_ready()).await?;
                        ready_sent = true;
                        tracing::info!(phone_id = %sess.mobile_device_id, "phone key received; sent SHADOW_LIKE ready");
                    }
                }
            }
            Ok(Ok(WsFrame::Ping(p))) => {
                ws.send_pong(&p).await.ok();
            }
            Ok(Ok(WsFrame::Close)) => break,
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                tracing::warn!(err = %e, "control WS recv");
                break;
            }
            Err(_) => {} // timeout -> keepalive below
        }
        if last_ka.elapsed() >= Duration::from_secs(3) {
            ws.send_text(pcsuite_proto::screen::KEEPALIVE).await.ok();
            last_ka = Instant::now();
        }
    }
    Ok(())
}

/// Handle one phone 8904 connection: handshake, then decrypt incoming frames.
async fn handle_8904(stream: TcpStream, shared: SharedRef, backend: Arc<dyn ClipboardBackend>) -> Result<()> {
    stream.set_nodelay(true).ok();
    let (mut rd, mut wr) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
    {
        let mut sh = shared.lock().await;
        sh.outgoing = Some(tx.clone());
    }

    // writer task drains the outgoing queue
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if wr.write_all(&frame).await.is_err() {
                break;
            }
        }
    });

    // handshake: command:1 (announce) + command:5 (request clipboard), byteC=100
    {
        let (pc_key, pc_iv, phone_id) = {
            let sh = shared.lock().await;
            (sh.pc_key.clone(), sh.pc_iv.clone(), sh.phone_id.clone())
        };
        let pc_id_owned = config::clip_pc_id();
        let pc_id = pc_id_owned.as_str();
        let f1 = build_frame(clip::command_announce(pc_id).as_bytes(), &pc_key, &pc_iv, &phone_id, pc_id, 100)?;
        let f2 = build_frame(clip::command_request_clipboard().as_bytes(), &pc_key, &pc_iv, &phone_id, pc_id, 100)?;
        tx.send(f1).await.ok();
        tx.send(f2).await.ok();
        tracing::info!("8904 handshake sent (command 1 + 5)");

        // opt-in: send a byteC=8 MediaStore sync request to try to pull the index.
        // Type/byteD overridable via env so we can probe without rebuilding.
        if std::env::var_os("PCSUITE_SYNC_REQ").is_some() {
            let ty: i64 = std::env::var("PCSUITE_SYNC_TYPE").ok().and_then(|s| s.parse().ok()).unwrap_or(1000);
            let byte_d: u8 = std::env::var("PCSUITE_SYNC_BYTED").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
            let task_id = uuid::Uuid::new_v4().to_string().to_uppercase();
            let inner = format!(
                r#"{{"sourceDeviceId":"{pc_id}","targetDeviceId":"{phone_id}","lastReceiveVersion":0,"modifiedTime":0,"syncTag":"{task_id}","syncedPublicDataCount":0,"syncedMaxPublicDataFilesId":0,"pubVersion":0}}"#
            );
            let inner_esc = inner.replace('\\', "\\\\").replace('"', "\\\"");
            let task = format!(r#"[{{"data":"{inner_esc}","taskId":"{task_id}","type":{ty}}}]"#);
            match gcm_encrypt(task.as_bytes(), pc_key.as_bytes(), pc_iv.as_bytes(), b"") {
                Ok(cipher) => {
                    let frame = RuyingFrame {
                        version: ruying::VERSION,
                        field_a: pad6(&phone_id),
                        field_b: pad6(pc_id),
                        byte_c: 8,
                        byte_d,
                        field_e: *b"00000000000",
                        cipher,
                    };
                    tx.send(frame.build()).await.ok();
                    tracing::info!(ty, byte_d, req = %task, "[sync] sent byteC=8 sync request");
                }
                Err(e) => tracing::warn!(err = %e, "[sync] encrypt failed"),
            }
        }
    }

    // opt-in on-demand vdfs browse/download test: proves list/stat/read work any
    // time the session is up (no image-copy trigger). PCSUITE_BROWSE=<path>[;<path>],
    // PCSUITE_PULL=<remote file> downloads to /tmp/pull_<name>.
    if let Ok(spec) = std::env::var("PCSUITE_BROWSE") {
        let (pk, piv, pid, fhost, fport) = {
            let sh = shared.lock().await;
            (sh.phone_key.clone(), sh.phone_iv.clone(), sh.phone_id.clone(), sh.fetch_host.clone(), sh.fetch_port)
        };
        if let (Some(pk), Some(piv)) = (pk, piv) {
            for path in spec.split(';').filter(|s| !s.is_empty()) {
                match vdfs::list_dir(&fhost, fport, &pk, &piv, &pid, path).await {
                    Ok(entries) => {
                        let dirs = entries.iter().filter(|e| e.is_dir()).count();
                        let files = entries.iter().filter(|e| e.is_file()).count();
                        tracing::info!(%path, n = entries.len(), dirs, files, "[browse] list_dir OK");
                        for e in entries.iter().take(40) {
                            let kind = if e.is_dir() { "DIR " } else { "FILE" };
                            let full = format!("{}/{}", path.trim_end_matches('/'), e.name);
                            let sz = if e.is_file() {
                                vdfs::stat(&fhost, fport, &pk, &piv, &pid, &full).await.map(|s| s.size as i64).unwrap_or(-1)
                            } else { -1 };
                            tracing::info!("[browse]   {kind} {sz:>11}  {}", e.name);
                        }
                    }
                    Err(e) => tracing::warn!(err = %e, %path, "[browse] list_dir FAILED"),
                }
            }
            if let Ok(rp) = std::env::var("PCSUITE_PULL") {
                match vdfs::fetch(&fhost, fport, &pk, &piv, &pid, &rp).await {
                    Ok(bytes) => {
                        let out = format!("/tmp/pull_{}", rp.rsplit('/').next().unwrap_or("file"));
                        let _ = std::fs::write(&out, &bytes);
                        tracing::info!(n = bytes.len(), %out, "[browse] download OK");
                    }
                    Err(e) => tracing::warn!(err = %e, %rp, "[browse] download FAILED"),
                }
            }
        } else {
            tracing::warn!("[browse] no phone key yet");
        }
    }

    // read loop
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 65536];
    loop {
        let n = rd.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        loop {
            match ruying::parse(&buf) {
                Parsed::Frame(frame, used) => {
                    buf.drain(..used);
                    on_frame(&frame, &shared, &backend).await;
                }
                Parsed::NeedMore(_) => break,
                Parsed::Invalid => {
                    tracing::warn!("invalid 8904 frame; clearing buffer");
                    buf.clear();
                    break;
                }
            }
        }
    }

    {
        let mut sh = shared.lock().await;
        sh.outgoing = None;
    }
    writer.abort();
    Ok(())
}

/// Process one inbound ruying frame (phone -> PC).
async fn on_frame(frame: &RuyingFrame, shared: &SharedRef, backend: &Arc<dyn ClipboardBackend>) {
    let (phone_key, phone_iv) = {
        let sh = shared.lock().await;
        (sh.phone_key.clone(), sh.phone_iv.clone())
    };
    let (Some(pk), Some(piv)) = (phone_key, phone_iv) else {
        tracing::debug!(byte_c = frame.byte_c, "8904 frame (no phone key yet)");
        return;
    };
    let plain = match gcm_decrypt(&frame.cipher, pk.as_bytes(), piv.as_bytes(), b"") {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(err = %e, byte_c = frame.byte_c, "frame decrypt failed");
            return;
        }
    };
    let text = String::from_utf8_lossy(&plain);
    tracing::debug!(
        byte_c = frame.byte_c,
        len = plain.len(),
        content = %text.chars().take(90).collect::<String>(),
        "8904 frame in"
    );

    match frame.byte_c {
        2 => {
            if let Some(clip_text) = clip::clip_text_from_json(&text) {
                let write = {
                    let mut sh = shared.lock().await;
                    if !sh.apply_incoming
                        || sh.last_text.as_deref() == Some(clip_text.as_str())
                        || sh.recently_synced(&clip_text)
                    {
                        false
                    } else {
                        sh.last_text = Some(clip_text.clone());
                        sh.mark(&clip_text);
                        true
                    }
                };
                if write {
                    let backend = backend.clone();
                    let t = clip_text.clone();
                    let _ = tokio::task::spawn_blocking(move || backend.set_text(&t)).await;
                    tracing::info!(text = %preview(&clip_text), "[phone→PC] clipboard text → OS clipboard");
                }
            } else if let Some(img) = clip::clip_image_from_json(&text) {
                // Image clipboard: the frame carries only a path; pull the bytes over
                // vdfs and drop them on the OS clipboard. Done off the 8904 read loop.
                let proceed = {
                    let mut sh = shared.lock().await;
                    if !sh.apply_incoming || sh.last_image_ref.as_deref() == Some(img.path.as_str()) {
                        false
                    } else {
                        sh.last_image_ref = Some(img.path.clone());
                        true
                    }
                };
                if proceed {
                    tokio::spawn(fetch_image_task(img, shared.clone(), backend.clone()));
                }
            }
        }
        100 => {
            // 8904 command bus (phone↔PC). Logged at info so the next live
            // connection shows exactly which commands the phone sends.
            tracing::info!(cmd = %preview(&text), "[phone] command frame");
            // The phone announces itself with command:1 (carrying its localDevice +
            // key/iv) right after reverse-connecting. The original relay answers with
            // command:6, which registers the PC as a routable device on the phone
            // (v.n()+r.K()+setCipherKey → "pc notify connect"). Without this, the
            // phone never pushes *change* clipboards back to us (only the one-shot
            // command:5 response). Echo localDevice → remoteDevice, mark online.
            if let Some(local_device) = clip::command_local_device(&text) {
                let (pc_key, pc_iv, phone_id, out) = {
                    let sh = shared.lock().await;
                    (sh.pc_key.clone(), sh.pc_iv.clone(), sh.phone_id.clone(), sh.outgoing.clone())
                };
                let pc_id_owned = config::clip_pc_id();
                let payload = clip::command_register_remote(&local_device);
                match build_frame(payload.as_bytes(), &pc_key, &pc_iv, &phone_id, &pc_id_owned, 100) {
                    Ok(frame) => {
                        if let Some(out) = out {
                            let _ = out.send(frame).await;
                            tracing::info!("[8904] command:1 → replied command:6 (register PC as clipboard partner)");
                        } else {
                            tracing::warn!("[8904] got command:1 but no outgoing channel to reply command:6");
                        }
                    }
                    Err(e) => tracing::warn!(err = %e, "[8904] build command:6 reply failed"),
                }
            }
        }
        8 => {
            // byteC=8 = MediaStore index (the data behind the original's file page).
            // Opt-in dump (PCSUITE_INDEX_DUMP=1) so we can reverse its format.
            if std::env::var_os("PCSUITE_INDEX_DUMP").is_some() {
                use std::io::Write;
                let path = "/tmp/vdfs_index_dump.bin";
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                    let _ = f.write_all(&plain);
                }
                let head: String = text.chars().take(160).collect();
                tracing::info!(
                    len = plain.len(), byte_d = frame.byte_d,
                    field_a = %hex::encode(frame.field_a), field_b = %hex::encode(frame.field_b),
                    field_e = ?String::from_utf8_lossy(&frame.field_e),
                    head = %head, "[index] byteC=8 frame → {path}"
                );
            }
            // Respond to the phone's type-10005 sync beacon with a SyncRequestBean,
            // reusing the beacon's taskId (correlation). Knobs via env.
            if std::env::var_os("PCSUITE_SYNC_REPLY").is_some() && text.contains("\"type\":10005") {
                {
                    let (pc_key, pc_iv, phone_id, out) = {
                        let sh = shared.lock().await;
                        (sh.pc_key.clone(), sh.pc_iv.clone(), sh.phone_id.clone(), sh.outgoing.clone())
                    };
                    let pc_id_owned = config::clip_pc_id();
                    let pc_id = pc_id_owned.as_str();
                    // Reversed from vivorelay Database_operations::SyncRequestBean + GetFormatData:
                    // on the phone's type-10005 beacon, the PC replies with a fresh-UUID envelope
                    // of type 1000 carrying the 8-field sync state (full sync = all zero/empty).
                    let ty: i64 = std::env::var("PCSUITE_SYNC_TYPE").ok().and_then(|s| s.parse().ok()).unwrap_or(1000);
                    let byte_d: u8 = std::env::var("PCSUITE_SYNC_BYTED").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
                    // syncTag MUST be a fresh UUID (empty "" is treated as no-op by the phone);
                    // the session's envelope taskId == syncTag (confirmed from the original's relay.log).
                    let task_id = uuid::Uuid::new_v4().to_string().to_uppercase();
                    let inner = format!(
                        r#"{{"sourceDeviceId":"{pc_id}","targetDeviceId":"{phone_id}","lastReceiveVersion":0,"modifiedTime":0,"syncTag":"{task_id}","syncedPublicDataCount":0,"syncedMaxPublicDataFilesId":0,"pubVersion":0}}"#
                    );
                    let inner = if std::env::var_os("PCSUITE_SYNC_ARR").is_some() { format!("[{inner}]") } else { inner };
                    let inner_esc = inner.replace('\\', "\\\\").replace('"', "\\\"");
                    let task = format!(r#"[{{"data":"{inner_esc}","taskId":"{task_id}","type":{ty}}}]"#);
                    if let (Some(out), Ok(cipher)) =
                        (out, gcm_encrypt(task.as_bytes(), pc_key.as_bytes(), pc_iv.as_bytes(), b""))
                    {
                        let frame = RuyingFrame {
                            version: ruying::VERSION,
                            field_a: pad6(&phone_id),
                            field_b: pad6(pc_id),
                            byte_c: 8,
                            byte_d,
                            field_e: *b"00000000000",
                            cipher,
                        };
                        let _ = out.send(frame.build()).await;
                        tracing::info!(ty, byte_d, %task_id, "[sync] replied to 10005 beacon");
                    }
                }
            }
        }
        _ => {} // 101 (heartbeat) etc. ignored for text relay
    }
}

/// Fetch a phone image referenced by an 8904 frame and put it on the OS clipboard.
async fn fetch_image_task(img: clip::ImageRef, shared: SharedRef, backend: Arc<dyn ClipboardBackend>) {
    let (pk, piv, pid, host, port) = {
        let sh = shared.lock().await;
        (sh.phone_key.clone(), sh.phone_iv.clone(), sh.phone_id.clone(), sh.fetch_host.clone(), sh.fetch_port)
    };
    let (Some(pk), Some(piv)) = (pk, piv) else {
        tracing::warn!("image ref but no phone key yet; skipping fetch");
        return;
    };
    let bytes = match vdfs::fetch(&host, port, &pk, &piv, &pid, &img.path).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(err = %e, path = %img.path, "[phone→PC] image fetch failed");
            return;
        }
    };

    // ── opt-in real-device probe (PCSUITE_VDFS_PROBE=1): the phone's vdfs port is
    // open right now (we just fetched), so exercise the new list_dir/stat against it.
    if std::env::var_os("PCSUITE_VDFS_PROBE").is_some() {
        let img_dir = img.path.rsplit_once('/').map(|(d, _)| d).unwrap_or("/").to_string();
        // list the image's own dir, plus a path that contains subdirectories so we
        // can confirm DT_DIR (d_type==4) decoding on real hardware.
        for dir in [img_dir.as_str(), "/storage/emulated/0"] {
            match vdfs::list_dir(&host, port, &pk, &piv, &pid, dir).await {
                Ok(entries) => {
                    let dirs = entries.iter().filter(|e| e.is_dir()).count();
                    let files = entries.iter().filter(|e| e.is_file()).count();
                    tracing::info!(%dir, n = entries.len(), dirs, files, "[vdfs-probe] list_dir OK");
                    for e in entries.iter().take(30) {
                        let kind = if e.is_dir() { "DIR " } else if e.is_file() { "FILE" } else { "?   " };
                        tracing::info!("[vdfs-probe]   {kind} {}", e.name);
                    }
                }
                Err(e) => tracing::warn!(err = %e, %dir, "[vdfs-probe] list_dir failed"),
            }
        }
        match vdfs::stat(&host, port, &pk, &piv, &pid, &img.path).await {
            Ok(st) => tracing::info!(
                mode = format!("0o{:o}", st.mode), size = st.size, mtime = st.mtime,
                is_dir = st.is_dir(), is_file = st.is_file(), "[vdfs-probe] stat OK"
            ),
            Err(e) => tracing::warn!(err = %e, "[vdfs-probe] stat failed"),
        }
    }

    let n = bytes.len();
    let mime = mime_from_path(&img.path).to_string();
    let b = backend.clone();
    let set = tokio::task::spawn_blocking(move || b.set_image(&bytes, &mime)).await;
    match set {
        Ok(Ok(())) => {
            // record the resulting clipboard signature so the watcher won't bounce it back
            let b2 = backend.clone();
            if let Ok(Some(sig)) = tokio::task::spawn_blocking(move || b2.image_signature()).await {
                shared.lock().await.last_image_sig = Some(sig);
            }
            tracing::info!(path = %img.path, bytes = n, "[phone→PC] image → OS clipboard");
        }
        Ok(Err(e)) => tracing::warn!(err = %e, "[phone→PC] set_image failed"),
        Err(e) => tracing::warn!(err = %e, "[phone→PC] set_image task join failed"),
    }
}

/// Poll the OS clipboard and forward changes to the phone (PC -> phone). Text is
/// sent inline; an image is staged to a temp file and sent as a vdfs reference (the
/// phone then fetches it from our 5679 server).
async fn watcher(shared: SharedRef, backend: Arc<dyn ClipboardBackend>, device_name: String) {
    // seed last_text/image so we don't immediately resend whatever is already there
    {
        let b = backend.clone();
        if let Ok(Some(cur)) = tokio::task::spawn_blocking(move || b.get_text()).await {
            shared.lock().await.last_text = Some(cur);
        }
        let b = backend.clone();
        if let Ok(sig) = tokio::task::spawn_blocking(move || b.image_signature()).await {
            shared.lock().await.last_image_sig = sig;
        }
    }

    loop {
        tokio::time::sleep(Duration::from_millis(700)).await;
        let cur = {
            let b = backend.clone();
            tokio::task::spawn_blocking(move || b.get_text()).await.ok().flatten()
        };
        let cur = cur.unwrap_or_default();

        if !cur.is_empty() {
            // ── text ──
            let to_send = {
                let mut sh = shared.lock().await;
                if sh.outgoing.is_none()
                    || sh.last_text.as_deref() == Some(cur.as_str())
                    || sh.recently_synced(&cur)
                {
                    None
                } else {
                    sh.last_text = Some(cur.clone());
                    sh.mark(&cur);
                    let pc_id = config::clip_pc_id();
                    let json =
                        clip::clip_text_json(&pc_id, &device_name, config::CLIP_NICK, &cur, now_ms());
                    match build_frame(json.as_bytes(), &sh.pc_key, &sh.pc_iv, &sh.phone_id, &pc_id, 2) {
                        Ok(frame) => sh.outgoing.clone().map(|tx| (tx, frame)),
                        Err(e) => {
                            tracing::warn!(err = %e, "build clipboard frame");
                            None
                        }
                    }
                }
            };
            if let Some((tx, frame)) = to_send {
                let _ = tx.send(frame).await;
                tracing::info!(text = %preview(&cur), "[PC→phone] clipboard text");
            }
            continue;
        }

        // ── image (text empty) ── only bother extracting bytes when the cheap
        // signature shows a *new* image and a phone is connected.
        let sig = {
            let b = backend.clone();
            tokio::task::spawn_blocking(move || b.image_signature()).await.ok().flatten()
        };
        let Some(sig) = sig else { continue };
        let fresh = {
            let sh = shared.lock().await;
            sh.outgoing.is_some() && sh.last_image_sig.as_deref() != Some(sig.as_str())
        };
        if !fresh {
            continue;
        }
        let bytes = {
            let b = backend.clone();
            tokio::task::spawn_blocking(move || b.get_image()).await.ok().flatten()
        };
        let Some(bytes) = bytes else {
            // mark seen anyway so we don't retry a non-extractable image every 700ms
            shared.lock().await.last_image_sig = Some(sig);
            continue;
        };
        let macpath = match write_clip_image(&bytes, now_ms()) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(err = %e, "stage clipboard image failed");
                continue;
            }
        };
        let backslash = macpath.replace('/', "\\");
        let to_send = {
            let mut sh = shared.lock().await;
            sh.last_image_sig = Some(sig);
            let pc_id = config::clip_pc_id();
            let json = clip::clip_image_ref_json(
                &pc_id,
                &device_name,
                config::CLIP_NICK,
                &backslash,
                "image/jpeg",
                now_ms(),
            );
            match build_frame(json.as_bytes(), &sh.pc_key, &sh.pc_iv, &sh.phone_id, &pc_id, 2) {
                Ok(frame) => sh.outgoing.clone().map(|tx| (tx, frame)),
                Err(e) => {
                    tracing::warn!(err = %e, "build image-ref frame");
                    None
                }
            }
        };
        if let Some((tx, frame)) = to_send {
            let _ = tx.send(frame).await;
            tracing::info!(bytes = bytes.len(), path = %macpath, "[PC→phone] clipboard image (ref → 5679 serve)");
        }
    }
}

// ───────────────────────── shared building blocks (used by the unified session) ─────────────────────────

/// Generate a fresh PC key (32 chars) + iv (16 chars) for the relay.
pub(crate) fn rand_clip_keys() -> (String, String) {
    (rand_chars(32), rand_chars(16))
}

/// Build the shared relay state. `fetch_host`/`fetch_port` locate the phone's vdfs
/// server for image fetch (phone→PC).
pub(crate) fn new_shared(
    pc_key: String,
    pc_iv: String,
    fetch_host: String,
    fetch_port: u16,
    apply_incoming: bool,
) -> SharedRef {
    Arc::new(Mutex::new(Shared {
        pc_key,
        pc_iv,
        phone_key: None,
        phone_iv: None,
        phone_id: "52467a".into(),
        outgoing: None,
        last_text: None,
        recent: HashMap::new(),
        fetch_host,
        fetch_port,
        last_image_ref: None,
        last_image_sig: None,
        apply_incoming,
    }))
}

/// Bind and spawn the vdfs 5679 server (serves PC images to the phone). The phone
/// reaches it over `adb reverse` (USB) or our LAN IP.
pub(crate) async fn start_vdfs_server(bind_addr: &str, pc_key: &str, pc_iv: &str) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(format!("{bind_addr}:5679"))
        .await
        .with_context(|| format!("bind {bind_addr}:5679"))?;
    tracing::info!(bind = %bind_addr, "vdfs 5679 serving (PC→phone images)");
    Ok(vdfs::spawn_server(listener, pc_key.into(), pc_iv.into(), config::clip_pc_id()))
}

/// Mime hint from a path's extension (defaults to JPEG).
fn mime_from_path(path: &str) -> &'static str {
    match path.rsplit('.').next().map(str::to_ascii_lowercase).as_deref() {
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("bmp") => "image/bmp",
        Some("tif") | Some("tiff") => "image/tiff",
        _ => "image/jpeg",
    }
}

/// Persist clipboard image bytes to a temp file the phone can later fetch over the
/// 5679 server. Returns the local path.
fn write_clip_image(bytes: &[u8], ts: u64) -> Result<String> {
    let dir = std::env::temp_dir().join("pcsuite-clip");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("img_{ts}.jpeg"));
    std::fs::write(&path, bytes)?;
    Ok(path.to_string_lossy().into_owned())
}

/// Spawn the 8904 accept loop (phone reverse-connections).
pub(crate) fn spawn_8904_server(
    listener: TcpListener,
    shared: SharedRef,
    backend: Arc<dyn ClipboardBackend>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    tracing::info!(%addr, "phone connected to 8904");
                    if let Err(e) = handle_8904(stream, shared.clone(), backend.clone()).await {
                        tracing::warn!(err = %e, "8904 connection ended");
                    }
                }
                Err(e) => {
                    tracing::warn!(err = %e, "8904 accept failed");
                    break;
                }
            }
        }
    })
}

/// Spawn the OS-clipboard watcher (PC → phone).
pub(crate) fn spawn_watcher(
    shared: SharedRef,
    backend: Arc<dyn ClipboardBackend>,
    device_name: String,
) -> JoinHandle<()> {
    tokio::spawn(async move { watcher(shared, backend, device_name).await })
}

/// Drive the SHADOW_LIKE handshake over a shared control channel: send `startup`,
/// wait for the phone's key/iv, store them, send `ready`.
pub(crate) async fn clip_handshake(control: ControlHandle, shared: SharedRef, startup_msg: String) {
    use tokio::sync::broadcast::error::RecvError;
    // Subscribe before sending, so we can't miss a reply to our own startup...
    let mut rx = control.subscribe();
    let _ = control.send(startup_msg).await;
    // ...but the phone may have announced its key *before* we subscribed, so also
    // check the retained last-SHADOW_LIKE.
    if let Some(t) = control.last_shadow() {
        if apply_shadow(&control, &shared, &t).await {
            return;
        }
    }
    loop {
        match rx.recv().await {
            Ok(t) => {
                if apply_shadow(&control, &shared, &t).await {
                    return;
                }
            }
            Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => return,
        }
    }
}

/// If `t` is a phone SHADOW_LIKE reply carrying a key, store it and send `ready`.
async fn apply_shadow(control: &ControlHandle, shared: &SharedRef, t: &str) -> bool {
    let Some(sess) = clip::parse_shadow_reply(t) else {
        return false;
    };
    {
        let mut sh = shared.lock().await;
        sh.phone_key = Some(sess.key);
        sh.phone_iv = Some(sess.iv);
        sh.phone_id = sess.mobile_device_id;
    }
    let _ = control.send(clip::shadow_ready()).await;
    tracing::info!("clipboard: phone key received; sent SHADOW_LIKE ready");
    true
}
