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
use crate::wsconn::open_ws;

const ECHO_WINDOW: Duration = Duration::from_secs(6);

/// OS clipboard access, supplied by the frontend so the core stays portable.
pub trait ClipboardBackend: Send + Sync {
    /// Current clipboard text (`None` if empty / non-text).
    fn get_text(&self) -> Option<String>;
    /// Replace the clipboard text.
    fn set_text(&self, text: &str) -> Result<()>;
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

/// Run the clipboard relay until the control WS closes.
pub async fn run_clipboard(cfg: ClipboardConfig, backend: Arc<dyn ClipboardBackend>) -> Result<()> {
    let pc_key = rand_chars(32);
    let pc_iv = rand_chars(16);
    let shared: SharedRef = Arc::new(Mutex::new(Shared {
        pc_key: pc_key.clone(),
        pc_iv: pc_iv.clone(),
        phone_key: None,
        phone_iv: None,
        phone_id: "52467a".into(),
        outgoing: None,
        last_text: None,
        recent: HashMap::new(),
    }));

    // 8904 relay server (phone reverse-connects here)
    let listener = TcpListener::bind(format!("{}:8904", cfg.bind_addr))
        .await
        .with_context(|| format!("bind {}:8904", cfg.bind_addr))?;
    tracing::info!(bind = %cfg.bind_addr, "8904 relay listening");
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
    {
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
    let pcinfo = PcInfo {
        ip: &cfg.pc_ip,
        pc_device_id: config::CLIP_PC_ID,
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
        let pc_id = config::CLIP_PC_ID;
        let f1 = build_frame(clip::command_announce(pc_id).as_bytes(), &pc_key, &pc_iv, &phone_id, pc_id, 100)?;
        let f2 = build_frame(clip::command_request_clipboard().as_bytes(), &pc_key, &pc_iv, &phone_id, pc_id, 100)?;
        tx.send(f1).await.ok();
        tx.send(f2).await.ok();
        tracing::info!("8904 handshake sent (command 1 + 5)");
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
                    if sh.last_text.as_deref() == Some(clip_text.as_str()) || sh.recently_synced(&clip_text) {
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
            }
        }
        100 => tracing::debug!(cmd = %preview(&text), "[phone] command frame"),
        _ => {} // byteC=8 (vdfs) / 101 (heartbeat) ignored for text relay
    }
}

/// Poll the OS clipboard and forward changes to the phone (PC -> phone).
async fn watcher(shared: SharedRef, backend: Arc<dyn ClipboardBackend>, device_name: String) {
    // seed last_text so we don't immediately resend whatever is already there
    if let Ok(Some(cur)) = {
        let b = backend.clone();
        tokio::task::spawn_blocking(move || b.get_text()).await
    } {
        shared.lock().await.last_text = Some(cur);
    }

    loop {
        tokio::time::sleep(Duration::from_millis(700)).await;
        let cur = {
            let b = backend.clone();
            tokio::task::spawn_blocking(move || b.get_text()).await.ok().flatten()
        };
        let Some(cur) = cur else { continue };
        if cur.is_empty() {
            continue;
        }

        // build the outgoing frame under the lock, send after releasing it
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
                let json = clip::clip_text_json(config::CLIP_PC_ID, &device_name, config::CLIP_NICK, &cur, now_ms());
                match build_frame(json.as_bytes(), &sh.pc_key, &sh.pc_iv, &sh.phone_id, config::CLIP_PC_ID, 2) {
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
    }
}

// ───────────────────────── shared building blocks (used by the unified session) ─────────────────────────

/// Generate a fresh PC key (32 chars) + iv (16 chars) for the relay.
pub(crate) fn rand_clip_keys() -> (String, String) {
    (rand_chars(32), rand_chars(16))
}

/// Build the shared relay state.
pub(crate) fn new_shared(pc_key: String, pc_iv: String) -> SharedRef {
    Arc::new(Mutex::new(Shared {
        pc_key,
        pc_iv,
        phone_key: None,
        phone_iv: None,
        phone_id: "52467a".into(),
        outgoing: None,
        last_text: None,
        recent: HashMap::new(),
    }))
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
