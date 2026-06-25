//! `pcsuite-ffi` — swift-bridge bindings over `pcsuite-core` for a SwiftUI macOS app.
//!
//! Design: **Swift only ever calls Rust** (no Rust→Swift delegates), which keeps
//! the boundary free of `Send`/threading hazards.
//! - `pcsuite_connect_usb` / `pcsuite_connect_lan` — blocking; return a `PcSession`.
//! - `start_screen()` → a `PcScreen`; poll `next_frame()` (blocking) on a background
//!   thread to pull raw HEVC frames (empty `Vec` = stream ended). No decode here —
//!   decode with VideoToolbox on the Swift side.
//! - `mouse/scroll/tap` — blocking input injection (need `start_screen()` first).
//! - `enable_verify()` then poll `next_verify_code()` (blocking; `"code\tsign"`,
//!   empty = session ended).
//! - `enable_clipboard()` — full text+image sync via a built-in macOS backend.
//!
//! A single global multi-threaded tokio runtime drives everything; the blocking
//! calls park the *calling* thread while the runtime's workers keep the session's
//! background tasks (control WS, video loop, clipboard relay) alive. Call the
//! blocking pollers (`next_frame`, `next_verify_code`) and the seconds-long
//! `connect_*` calls **off the main thread**.

// swift-bridge's generated glue (the `#[swift_bridge::bridge]` expansion) trips a
// couple of cosmetic lints; they're not in our hand-written code.
#![allow(clippy::unnecessary_cast, clippy::while_let_loop)]

use std::sync::OnceLock;

use tokio::runtime::Runtime;

use pcsuite_core::{
    config, pair, register, usb, ClipboardConfig, InputHandle, MouseAction, MouseButton,
    PhoneNotify, RegisterConfig, Registration, ScreenParams, ScreenStream, Session, UsbConfig,
};

mod clipboard_mac;
use clipboard_mac::MacClipboard;

// NOTE: keep this module free of `///` doc comments — the swift-bridge *build*
// parser (separate from the macro) rejects them. Use plain `//` here; the real
// docs live on the Rust impls below and in SWIFT_INTEGRATION.md.
#[swift_bridge::bridge]
mod ffi {
    extern "Rust" {
        type PcScreen;
        // Block until the next raw HEVC frame; empty Vec = stream ended OR stop()
        // was called. Loop this on a background thread.
        fn next_frame(&self) -> Vec<u8>;
        // Ask the frame pump to stop: the next (or in-flight) next_frame() returns
        // an empty Vec within ~300ms so the polling thread can break and release
        // this PcScreen. Lets Swift tear mirroring down without dropping the handle
        // out from under a parked next_frame() call.
        fn stop(&self);
        // Block for the next privacy / secure-screen event. Returns one of
        // "clear" (back to a normal screen), "password", "safety" (FLAG_SECURE,
        // e.g. fingerprint), or "lockScreen". Returns "" when the stream ends or
        // stop() is called. Loop this on a background thread: when the phone hits
        // a secure surface it stops the video, so show a "handle on phone" hint.
        fn next_privacy_event(&self) -> String;
        // Block for the next IME caret report from the phone, as "x,y" (caret
        // position in the mirror's pixel space) or "off" (focused field went
        // away). Returns "" when the stream ends / stop() is called. Use it to
        // place the PC's IME candidate window at the on-device caret.
        fn next_input_cursor(&self) -> String;
    }

    extern "Rust" {
        type PcSession;

        // Start screen mirroring; returns a PcScreen to poll. Also arms input.
        // `max_size` caps the longer screen edge (px): lower = lower resolution =
        // less encode/decode latency. Pass 0 for the full-resolution default.
        // Drop the PcScreen (or call stop()) to stop mirroring.
        fn start_screen(&self, max_size: i64) -> Result<PcScreen, String>;
        // Enable clipboard sync (text + images), built-in macOS backend. Direction:
        // recv = apply the phone's clipboard to this Mac (phone→PC); send = push this
        // Mac's clipboard to the phone (PC→phone). Pass both true for bidirectional.
        fn enable_clipboard(&self, recv: bool, send: bool) -> Result<(), String>;
        // Gracefully disconnect before teardown: send the literal "close" on the
        // control WS, exactly as the official app does (ws.send("close")). The phone
        // runs its full PC-disconnect cleanup on it. REQUIRED for clean reconnects:
        // without it a bare socket close leaves stale phone-side state and phone→PC
        // clipboard sync silently dies on the next connect. Call on user-initiated
        // disconnect, before releasing the session. Blocking but fast (~200ms flush);
        // no-op if the link is already dead.
        fn stop_clipboard(&self);
        // Arm SMS verify-code relay; then poll next_verify_code().
        fn enable_verify(&self);
        // Block for the next SMS code as "code\tsign"; empty = session ended OR
        // stop_verify() was called.
        fn next_verify_code(&self) -> String;
        // Ask the verify poller to stop: the next (or in-flight) next_verify_code()
        // returns an empty String within ~300ms so its thread can break and release
        // this PcSession (mirror of PcScreen::stop for the verify-code loop).
        fn stop_verify(&self);

        // Arm phone notification relay; then poll next_notification().
        fn enable_notify(&self);
        // Block for the next phone notification, tab-separated as
        // "appName\ttitle\tcontent\tpackageName\tpendingIntentId"; empty = session
        // ended OR stop_notify() was called.
        fn next_notification(&self) -> String;
        // Ask the notify poller to stop (mirror of stop_verify for notifications).
        fn stop_notify(&self);

        // Fetch phone device facts (storage capacity, model, OS) via the 10380
        // /base-info gateway. Returns tab-separated fields, in order:
        //   name, brand, product, androidVersion, osVersion, widthPx, heightPx,
        //   fold(0/1), totalStorageGb, availableStorageGb, availableBytes, account
        // Blocking (one HTTP round-trip) — call off the main thread.
        fn device_info(&self) -> Result<String, String>;

        // Block until the connection is lost (the shared 10380 control WS — used by
        // both USB and LAN — closed or errored), returning a short reason string.
        // Returns "" if stop_watch() was called first (intentional teardown). Loop
        // this on a background thread: a non-empty return means the link dropped, so
        // the app can tear down and reconnect. Covers idle and mid-mirror drops alike.
        fn wait_disconnect(&self) -> String;
        // Ask wait_disconnect() to return "" within ~300ms so its watcher thread can
        // break and release this PcSession before the handle is dropped.
        fn stop_watch(&self);

        // Inject a mouse event. action: 0=down,1=up,2=move. button: 1=left,2=right.
        // Coordinates are in your reference frame (w, h); the phone scales.
        fn mouse(&self, action: u8, button: u8, x: i64, y: i64, w: i64, h: i64) -> bool;
        // Inject a scroll. vscroll > 0 up, < 0 down.
        fn scroll(&self, vscroll: i64, x: i64, y: i64, w: i64, h: i64) -> bool;
        // Commit text into the phone's focused input field (IME commitText).
        // Carries full Unicode (Chinese/emoji) — the path for keyboard typing.
        // Needs start_screen() first (shares its /mirror/control channel).
        fn text(&self, s: String) -> bool;
        // Delete `before` chars before and `after` chars after the cursor
        // (IME deleteSurroundingText) — used for Backspace.
        fn delete_surrounding(&self, before: i64, after: i64) -> bool;
        // Tap (down+up, left button) at (x, y) in the reference frame (w, h).
        fn tap(&self, x: i64, y: i64, w: i64, h: i64) -> bool;
        // Press an Android key (down+up). keycode is a KEYCODE_* value, e.g.
        // BACK=4, HOME=3, APP_SWITCH=187. Drives the on-screen navigation keys.
        fn key(&self, keycode: i64) -> bool;
    }

    extern "Rust" {
        // Initialize tracing/logging (honours RUST_LOG). Safe to call once.
        fn pcsuite_log_init();
        // ABI version of this library.
        fn pcsuite_abi_version() -> u32;
        // Set the LAN pairing identity at runtime (empty field = leave default).
        // Call before pcsuite_connect_lan. USB ignores these.
        fn pcsuite_set_identity(open_id: String, pc_mac: String, account: String, device_name: String);
        // Set (empty seed = clear) the stored pairing seed for one phone IP, used by
        // the LAN connectType=2 path. Call before pcsuite_connect_lan.
        fn pcsuite_set_seed(phone_ip: String, seed: String);
        // Set (empty = default) the super-clipboard PC device id. Must match the id
        // the phone registered for this PC at pairing, or phone→PC clipboard won't
        // push. Used by both USB and LAN. Call before connecting.
        fn pcsuite_set_clip_id(clip_id: String);
        // Connect over USB (adb). Blocks a few seconds — call off the main thread.
        fn pcsuite_connect_usb() -> Result<PcSession, String>;
        // Connect over LAN/Tailscale. remote=true uses connectType=1 (no seed).
        fn pcsuite_connect_lan(phone_ip: String, remote: bool) -> Result<PcSession, String>;
        // Begin QR pairing (local ls=true variant — pure LAN, no cloud/seed/10191).
        // `lip` = this machine's LAN IP to advertise in the QR; pass "" to auto-detect.
        // Render qr_url() as a QR for the phone to scan via PCSuite 扫码连接电脑.
        fn pcsuite_pair_begin(lip: String) -> PcPairing;
    }

    extern "Rust" {
        type PcPairing;
        // The QR payload to render (the phone scans it; it carries a self-made token
        // the phone stores, plus ls=true + our lip so it reports back over the LAN).
        fn qr_url(&self) -> String;
        // The LAN IP chosen for the QR (where the phone POSTs notifyConnection).
        fn lan_ip(&self) -> String;
        // Block up to timeout_ms for the phone to scan and report its IP to :9199.
        // Returns a PcPaired (call connect() on it) or an error on timeout. Call off
        // the main thread.
        fn wait_phone(&self, timeout_ms: u32) -> Result<PcPaired, String>;
        // Abort an in-flight wait_phone() from another thread: it returns an error
        // within ~300ms and frees the :9199 listener so a re-pair can rebind.
        fn cancel(&self);
    }

    extern "Rust" {
        type PcPaired;
        // The phone's LAN IP (the data-plane host).
        fn phone_ip(&self) -> String;
        // The phone's device id (bleId, e.g. "52467a") — the clipboard routing id.
        fn ble_id(&self) -> String;
        // The phone's display name (e.g. "iQOO 15").
        fn device_name(&self) -> String;
        // The phone's logged-in account (masked, e.g. "173****991").
        fn vivo_account(&self) -> String;
        // "phone" or "pad".
        fn device_type(&self) -> String;
        // Open the data plane over the paired phone — the QR token is already trusted,
        // so this skips the 10191 sign. Blocks ~1s; returns a PcSession. Off-main.
        fn connect(&self) -> Result<PcSession, String>;
    }
}

// ───────────────────────────── runtime ─────────────────────────────

static RT: OnceLock<Runtime> = OnceLock::new();

fn rt() -> &'static Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime")
    })
}

/// Local interface IP that routes toward `peer` (UDP connect picks the route).
fn local_ip_toward(peer: &str) -> Option<String> {
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect((peer, 9)).ok()?;
    Some(sock.local_addr().ok()?.ip().to_string())
}

// ───────────────────────────── handles ─────────────────────────────

/// A connected control session. All methods take `&self` (state is behind locks)
/// so the polling loops and one-off control calls can run on different threads.
pub struct PcSession {
    session: tokio::sync::Mutex<Session>,
    input: std::sync::Mutex<Option<InputHandle>>,
    verify_rx: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<String>>>,
    // Set by stop_verify(); the verify poller checks it between short recv timeouts.
    verify_stop: std::sync::atomic::AtomicBool,
    // Notification relay — mirror of the verify channel/stop pair.
    notify_rx: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<String>>>,
    notify_stop: std::sync::atomic::AtomicBool,
    // Cached phone mobileDeviceId for /base-info; resolved lazily without re-sending
    // a SHADOW startup when one is already on the wire (see resolve_device_id).
    device_id_cache: std::sync::Mutex<String>,
    // True once clipboard is enabled. While set, resolve_device_id() must NOT send its
    // own SHADOW startup (it would rotate the clipboard keys mid-handshake and break
    // phone→PC sync) — it waits for the clipboard handshake's retained reply instead.
    clipboard_active: std::sync::atomic::AtomicBool,
    // Liveness of the shared control WS; reads `true` once the connection is lost.
    dead_rx: tokio::sync::Mutex<tokio::sync::watch::Receiver<bool>>,
    // Set by stop_watch(); the disconnect watcher checks it between short timeouts.
    watch_stop: std::sync::atomic::AtomicBool,
    token: String,
    data_ip: String,
    pc_ip: String,
    bind_addr: String,
    connect_type: String,
    vdfs_fetch_host: String,
    vdfs_fetch_port: u16,
    open_id: String,
    device_name: String,
    usb_adb: Option<String>,
    _reg: Option<Registration>,
}

/// A live screen-mirror stream. Poll [`PcScreen::next_frame`]; call [`PcScreen::stop`]
/// (or drop it) to stop.
pub struct PcScreen {
    frames: tokio::sync::Mutex<ScreenStream>,
    // Privacy/secure-screen events, polled on a thread separate from frames so
    // the two blocking pollers never contend for one lock.
    events: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<String>>,
    // IME caret reports, polled on its own thread for the same reason.
    cursor: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<String>>,
    // Set by stop(); the next_*() pollers observe it between short recv timeouts
    // and return empty so the polling threads break and drop this.
    stop: std::sync::atomic::AtomicBool,
}

impl PcScreen {
    fn next_frame(&self) -> Vec<u8> {
        use std::sync::atomic::Ordering;
        use std::time::Duration;
        rt().block_on(async {
            let mut frames = self.frames.lock().await;
            loop {
                if self.stop.load(Ordering::Relaxed) {
                    return Vec::new();
                }
                // Short timeout so a stop() (or natural end) is noticed promptly even
                // when the phone screen is static and no frames are arriving.
                match tokio::time::timeout(Duration::from_millis(300), frames.next_frame()).await {
                    Ok(opt) => return opt.unwrap_or_default(),
                    Err(_) => continue,
                }
            }
        })
    }

    fn stop(&self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn next_privacy_event(&self) -> String {
        use std::sync::atomic::Ordering;
        use std::time::Duration;
        rt().block_on(async {
            let mut events = self.events.lock().await;
            loop {
                if self.stop.load(Ordering::Relaxed) {
                    return String::new();
                }
                match tokio::time::timeout(Duration::from_millis(300), events.recv()).await {
                    Ok(Some(tok)) => return tok,    // a privacy state token
                    Ok(None) => return String::new(), // channel closed (stream ended)
                    Err(_) => continue,             // timeout -> re-check stop
                }
            }
        })
    }

    fn next_input_cursor(&self) -> String {
        use std::sync::atomic::Ordering;
        use std::time::Duration;
        rt().block_on(async {
            let mut cursor = self.cursor.lock().await;
            loop {
                if self.stop.load(Ordering::Relaxed) {
                    return String::new();
                }
                match tokio::time::timeout(Duration::from_millis(300), cursor.recv()).await {
                    Ok(Some(s)) => return s,        // "x,y" or "off"
                    Ok(None) => return String::new(),
                    Err(_) => continue,
                }
            }
        })
    }
}

impl PcSession {
    fn start_screen(&self, max_size: i64) -> Result<PcScreen, String> {
        let mut params = ScreenParams::default();
        if max_size > 0 {
            params.max_size = max_size;
        }
        let mut stream = rt()
            .block_on(async {
                let mut s = self.session.lock().await;
                s.enable_screen(params).await
            })
            .map_err(|e| format!("{e:#}"))?;
        *self.input.lock().unwrap() = stream.input();
        let events = stream.take_events();
        let cursor = stream.take_cursor();
        Ok(PcScreen {
            frames: tokio::sync::Mutex::new(stream),
            events: tokio::sync::Mutex::new(events),
            cursor: tokio::sync::Mutex::new(cursor),
            stop: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn enable_clipboard(&self, recv: bool, send: bool) -> Result<(), String> {
        if let Some(adb) = self.usb_adb.clone() {
            // USB: the phone reaches our relay/vdfs over adb reverse, and we reach
            // the phone's vdfs over adb forward.
            rt().block_on(async move {
                pcsuite_core::adb::run_ok(&adb, &["reverse", "tcp:8904", "tcp:8904"]).await;
                pcsuite_core::adb::run_ok(&adb, &["reverse", "tcp:5679", "tcp:5679"]).await;
                pcsuite_core::adb::run_ok(&adb, &["forward", "tcp:10382", "tcp:5678"]).await;
            });
        }
        let cfg = ClipboardConfig {
            data_ip: self.data_ip.clone(),
            pc_ip: self.pc_ip.clone(),
            bind_addr: self.bind_addr.clone(),
            token: self.token.clone(),
            open_id: self.resolve_clip_open_id(),
            device_name: self.device_name.clone(),
            connect_type: self.connect_type.clone(),
            vdfs_fetch_host: self.vdfs_fetch_host.clone(),
            vdfs_fetch_port: self.vdfs_fetch_port,
            recv_from_phone: recv,
            send_to_phone: send,
        };
        let r = rt().block_on(async {
            let mut s = self.session.lock().await;
            s.enable_clipboard(cfg, std::sync::Arc::new(MacClipboard)).await
        })
        .map_err(|e| format!("{e:#}"));
        if r.is_ok() {
            // From now on resolve_device_id() must reuse the clipboard handshake's
            // SHADOW reply, never send a competing startup (it rotates the clip keys).
            self.clipboard_active.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        r
    }

    fn stop_clipboard(&self) {
        rt().block_on(async {
            let s = self.session.lock().await;
            s.shutdown_clipboard().await;
        });
    }

    /// The account openId for the cowork clipboard `SHADOW_LIKE` handshake (the phone
    /// gates relay-clipboard on it matching its account). Prefer a configured value —
    /// including one learned from `/base-info` on an earlier connect and applied via
    /// `set_identity` — over the connect-time snapshot, so a re-pair after the openId
    /// was learned uses the real value. We deliberately do NOT fetch `/base-info` here:
    /// before the cowork handshake the phone answers it very slowly (~20s), which would
    /// stall `connect`. openId is learned post-connect instead (see `device_info` /
    /// the app's `autoFillOpenID`) and takes effect from the next connect.
    fn resolve_clip_open_id(&self) -> String {
        if config::has_open_id() {
            config::default_identity().open_id
        } else {
            self.open_id.clone()
        }
    }

    fn enable_verify(&self) {
        self.verify_stop.store(false, std::sync::atomic::Ordering::Relaxed);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        *self.verify_rx.lock().unwrap() = Some(rx);
        rt().block_on(async {
            let mut s = self.session.lock().await;
            s.enable_verify(move |code, sign| {
                let _ = tx.send(format!("{code}\t{sign}"));
            });
        });
    }

    fn next_verify_code(&self) -> String {
        use std::sync::atomic::Ordering;
        use std::time::Duration;
        // Take the receiver out so we don't hold the std lock across the blocking
        // recv, then put it back.
        let rx = self.verify_rx.lock().unwrap().take();
        let Some(mut rx) = rx else { return String::new() };
        let code = rt().block_on(async {
            loop {
                if self.verify_stop.load(Ordering::Relaxed) {
                    return None;
                }
                // Short timeout so stop_verify() (or session end) is noticed promptly.
                match tokio::time::timeout(Duration::from_millis(300), rx.recv()).await {
                    Ok(v) => return v, // Some(code) or None (channel closed)
                    Err(_) => continue,
                }
            }
        });
        *self.verify_rx.lock().unwrap() = Some(rx);
        code.unwrap_or_default()
    }

    fn stop_verify(&self) {
        self.verify_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn enable_notify(&self) {
        self.notify_stop.store(false, std::sync::atomic::Ordering::Relaxed);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        *self.notify_rx.lock().unwrap() = Some(rx);
        rt().block_on(async {
            let mut s = self.session.lock().await;
            s.enable_notify(move |n| {
                let _ = tx.send(format!(
                    "{}\t{}\t{}\t{}\t{}",
                    n.app_name, n.title, n.content, n.package_name, n.pending_intent_id
                ));
            });
        });
    }

    fn next_notification(&self) -> String {
        use std::sync::atomic::Ordering;
        use std::time::Duration;
        let rx = self.notify_rx.lock().unwrap().take();
        let Some(mut rx) = rx else { return String::new() };
        let msg = rt().block_on(async {
            loop {
                if self.notify_stop.load(Ordering::Relaxed) {
                    return None;
                }
                match tokio::time::timeout(Duration::from_millis(300), rx.recv()).await {
                    Ok(v) => return v, // Some(line) or None (channel closed)
                    Err(_) => continue,
                }
            }
        });
        *self.notify_rx.lock().unwrap() = Some(rx);
        msg.unwrap_or_default()
    }

    fn stop_notify(&self) {
        self.notify_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn device_info(&self) -> Result<String, String> {
        let device_id = self.resolve_device_id()?;
        let info = rt()
            .block_on(pcsuite_core::device::fetch(&self.data_ip, &self.token, &device_id))
            .map_err(|e| format!("{e:#}"))?;
        Ok(format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            info.mobile_device_name,
            info.mobile_brand,
            info.product,
            info.android_version,
            info.os_version,
            info.width_pixels,
            info.height_pixels,
            info.fold_screen as i32,
            info.total_storage_gb,
            info.available_storage_gb,
            info.available_bytes,
            info.vivo_account,
            info.open_id,
        ))
    }

    /// Resolve (and cache) the phone's `mobileDeviceId` for `/base-info`. Prefers a
    /// SHADOW reply already on the wire (reading it sends nothing, so it can't disturb
    /// an active clipboard session); only asks — a harmless `startup`, no `ready` — if
    /// nothing has announced yet.
    fn resolve_device_id(&self) -> Result<String, String> {
        {
            let c = self.device_id_cache.lock().unwrap();
            if !c.is_empty() {
                return Ok(c.clone());
            }
        }
        let clip_active = self.clipboard_active.load(std::sync::atomic::Ordering::Relaxed);
        let id = rt()
            .block_on(async {
                // Fast path: the (clipboard) handshake already retained the phone's
                // SHADOW reply.
                {
                    let s = self.session.lock().await;
                    if let Some(id) = s.known_device_id() {
                        return Ok::<String, anyhow::Error>(id);
                    }
                }
                // With clipboard active a startup is in flight; wait for its reply
                // rather than sending our own (a second startup rotates the clipboard
                // keys mid-handshake → phone→PC sync dies). Poll the retained reply.
                if clip_active {
                    for _ in 0..50 {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        let s = self.session.lock().await;
                        if let Some(id) = s.known_device_id() {
                            return Ok(id);
                        }
                    }
                    anyhow::bail!("device id unavailable: clipboard handshake produced no SHADOW reply within 5s (not sending a competing startup, which would rotate the clipboard keys)");
                }
                // No clipboard in flight (e.g. browse-only) → safe to ask ourselves.
                let s = self.session.lock().await;
                let identity = config::default_identity();
                let p = s.phone_info(&self.pc_ip, &self.connect_type, &identity).await?;
                Ok(p.mobile_device_id)
            })
            .map_err(|e| format!("{e:#}"))?;
        *self.device_id_cache.lock().unwrap() = id.clone();
        Ok(id)
    }

    fn wait_disconnect(&self) -> String {
        use std::sync::atomic::Ordering;
        use std::time::Duration;
        rt().block_on(async {
            let mut rx = self.dead_rx.lock().await;
            loop {
                if self.watch_stop.load(Ordering::Relaxed) {
                    return String::new(); // intentional teardown
                }
                if *rx.borrow() {
                    return "connection lost".to_string();
                }
                // Short timeout so stop_watch() is noticed promptly even while the
                // connection is still healthy and the signal hasn't changed.
                match tokio::time::timeout(Duration::from_millis(300), rx.changed()).await {
                    Ok(Ok(())) => {
                        if *rx.borrow() {
                            return "connection lost".to_string();
                        }
                    }
                    // Sender dropped without flipping the flag — the session was
                    // dropped out from under us; treat as a (benign) disconnect.
                    Ok(Err(_)) => return "connection lost".to_string(),
                    Err(_) => continue, // timeout -> re-check the stop flag
                }
            }
        })
    }

    fn stop_watch(&self) {
        self.watch_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn mouse(&self, action: u8, button: u8, x: i64, y: i64, w: i64, h: i64) -> bool {
        let Some(input) = self.input.lock().unwrap().clone() else {
            return false;
        };
        let a = match action {
            0 => MouseAction::Down,
            1 => MouseAction::Up,
            _ => MouseAction::Move,
        };
        let b = match button {
            2 => MouseButton::Right,
            _ => MouseButton::Left,
        };
        rt().block_on(input.mouse(a, b, x, y, w, h)).is_ok()
    }

    fn scroll(&self, vscroll: i64, x: i64, y: i64, w: i64, h: i64) -> bool {
        let Some(input) = self.input.lock().unwrap().clone() else {
            return false;
        };
        rt().block_on(input.scroll(vscroll, x, y, w, h)).is_ok()
    }

    fn text(&self, s: String) -> bool {
        let Some(input) = self.input.lock().unwrap().clone() else {
            return false;
        };
        rt().block_on(input.text(&s)).is_ok()
    }

    fn delete_surrounding(&self, before: i64, after: i64) -> bool {
        let Some(input) = self.input.lock().unwrap().clone() else {
            return false;
        };
        rt().block_on(input.delete_surrounding(before, after)).is_ok()
    }

    fn tap(&self, x: i64, y: i64, w: i64, h: i64) -> bool {
        let Some(input) = self.input.lock().unwrap().clone() else {
            return false;
        };
        rt().block_on(input.tap(x, y, w, h)).is_ok()
    }

    fn key(&self, keycode: i64) -> bool {
        let Some(input) = self.input.lock().unwrap().clone() else {
            return false;
        };
        rt().block_on(input.key(keycode)).is_ok()
    }
}

impl Drop for PcSession {
    fn drop(&mut self) {
        // Remove the USB forwards we added; Session/Registration drop afterwards,
        // aborting all background tasks and stopping SSDP presence.
        if let Some(adb) = self.usb_adb.clone() {
            rt().block_on(async move {
                pcsuite_core::adb::run_ok(&adb, &["reverse", "--remove", "tcp:8904"]).await;
                pcsuite_core::adb::run_ok(&adb, &["reverse", "--remove", "tcp:5679"]).await;
                pcsuite_core::adb::run_ok(&adb, &["forward", "--remove", "tcp:10382"]).await;
                usb::cleanup(&adb).await;
            });
        }
    }
}

// ───────────────────────────── free functions ─────────────────────────────

fn pcsuite_log_init() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init();
}

fn pcsuite_abi_version() -> u32 {
    1
}

fn pcsuite_set_identity(open_id: String, pc_mac: String, account: String, device_name: String) {
    config::set_identity(open_id, pc_mac, account, device_name);
}

fn pcsuite_set_seed(phone_ip: String, seed: String) {
    config::set_seed(phone_ip, seed);
}

fn pcsuite_set_clip_id(clip_id: String) {
    config::set_clip_pc_id(clip_id);
}

fn pcsuite_connect_usb() -> Result<PcSession, String> {
    let id = config::default_identity();
    let (u, session) = rt()
        .block_on(async {
            let u = usb::prepare(UsbConfig {
                pc_name: Some(id.device_name.clone()),
                ..UsbConfig::default()
            })
            .await?;
            // Best-effort, bounded: announce our display name *before* the WS comes
            // up (which freezes the phone's "已连接" notification text). USB has no
            // earlier name channel that reaches that notification; failures are
            // harmless (the post-connect device-info fetch still sets the in-app
            // name). Time-boxed so it can never stall the connect.
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                pcsuite_core::device::announce_pc_name("127.0.0.1", &u.token, &id.device_name),
            )
            .await;
            let session = Session::connect("127.0.0.1", &u.token).await?;
            Ok::<_, anyhow::Error>((u, session))
        })
        .map_err(|e| format!("{e:#}"))?;
    let dead_rx = session.dead_signal();
    Ok(PcSession {
        session: tokio::sync::Mutex::new(session),
        input: std::sync::Mutex::new(None),
        verify_rx: std::sync::Mutex::new(None),
        verify_stop: std::sync::atomic::AtomicBool::new(false),
        notify_rx: std::sync::Mutex::new(None),
        notify_stop: std::sync::atomic::AtomicBool::new(false),
        device_id_cache: std::sync::Mutex::new(String::new()),
        clipboard_active: std::sync::atomic::AtomicBool::new(false),
        dead_rx: tokio::sync::Mutex::new(dead_rx),
        watch_stop: std::sync::atomic::AtomicBool::new(false),
        token: u.token,
        data_ip: "127.0.0.1".into(),
        pc_ip: "127.0.0.1".into(),
        bind_addr: "127.0.0.1".into(),
        connect_type: "USB".into(),
        vdfs_fetch_host: "127.0.0.1".into(),
        vdfs_fetch_port: 10382,
        open_id: id.open_id,
        device_name: id.device_name,
        usb_adb: Some(u.adb),
        _reg: None,
    })
}

fn pcsuite_connect_lan(phone_ip: String, remote: bool) -> Result<PcSession, String> {
    let stored_seed = if remote {
        None
    } else {
        config::default_stored_seed(&phone_ip)
    };
    let (reg, token, session) = rt()
        .block_on(async {
            let reg = register(RegisterConfig {
                reg_ip: phone_ip.clone(),
                identity: config::default_identity(),
                stored_seed,
                remote,
                token: None,
                conn_id: None,
                presence: true,
            })
            .await?;
            let token = reg.token.clone();
            let session = Session::connect(&phone_ip, &token).await?;
            Ok::<_, anyhow::Error>((reg, token, session))
        })
        .map_err(|e| format!("{e:#}"))?;
    Ok(build_wlan_session(session, token, phone_ip, Some(reg)))
}

/// Build a WLAN-flavoured [`PcSession`] from an already-connected control session.
/// Shared by `pcsuite_connect_lan` (with its SSDP-presence `Registration`) and the
/// QR-pairing `connect()` (no registration — the QR delivered the token).
fn build_wlan_session(
    session: Session,
    token: String,
    phone_ip: String,
    reg: Option<Registration>,
) -> PcSession {
    let id = config::default_identity();
    let pc_ip = local_ip_toward(&phone_ip).unwrap_or_else(|| "0.0.0.0".into());
    let dead_rx = session.dead_signal();
    PcSession {
        session: tokio::sync::Mutex::new(session),
        input: std::sync::Mutex::new(None),
        verify_rx: std::sync::Mutex::new(None),
        verify_stop: std::sync::atomic::AtomicBool::new(false),
        notify_rx: std::sync::Mutex::new(None),
        notify_stop: std::sync::atomic::AtomicBool::new(false),
        device_id_cache: std::sync::Mutex::new(String::new()),
        clipboard_active: std::sync::atomic::AtomicBool::new(false),
        dead_rx: tokio::sync::Mutex::new(dead_rx),
        watch_stop: std::sync::atomic::AtomicBool::new(false),
        token,
        data_ip: phone_ip.clone(),
        pc_ip,
        bind_addr: "0.0.0.0".into(),
        connect_type: "WLAN".into(),
        vdfs_fetch_host: phone_ip,
        vdfs_fetch_port: 5678,
        open_id: id.open_id,
        device_name: id.device_name,
        usb_adb: None,
        _reg: reg,
    }
}

// ───────────────────────────── QR pairing ─────────────────────────────

/// This machine's LAN IPv4 (en0/en1/en2), skipping Tailscale (100.x). macOS path via
/// `ipconfig getifaddr`; falls back to the route toward a private LAN address.
fn local_lan_ip() -> Option<String> {
    for iface in ["en0", "en1", "en2"] {
        if let Ok(out) = std::process::Command::new("ipconfig")
            .args(["getifaddr", iface])
            .output()
        {
            let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !ip.is_empty() && !ip.starts_with("100.") {
                return Some(ip);
            }
        }
    }
    local_ip_toward("192.168.0.1").filter(|ip| !ip.starts_with("100."))
}

/// In-progress QR pairing: the self-made token + the QR payload to show. Holds no
/// network state — the listener only runs while [`PcPairing::wait_phone`] is awaited.
pub struct PcPairing {
    token: String,
    url: String,
    lip: String,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

fn pcsuite_pair_begin(lip: String) -> PcPairing {
    let id = config::default_identity();
    let lip = if lip.trim().is_empty() {
        local_lan_ip().unwrap_or_else(|| "0.0.0.0".into())
    } else {
        lip
    };
    let token = pair::random_token();
    let url = pair::qr_url(&token, &lip, &id);
    PcPairing {
        token,
        url,
        lip,
        stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }
}

impl PcPairing {
    fn qr_url(&self) -> String {
        self.url.clone()
    }

    fn lan_ip(&self) -> String {
        self.lip.clone()
    }

    fn wait_phone(&self, timeout_ms: u32) -> Result<PcPaired, String> {
        let dur = std::time::Duration::from_millis(timeout_ms as u64);
        let notify = rt()
            .block_on(pair::wait_for_phone_until(pair::NOTIFY_PORT, dur, &self.stop))
            .map_err(|e| format!("{e:#}"))?;
        Ok(PcPaired {
            token: self.token.clone(),
            notify,
        })
    }

    fn cancel(&self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A phone that scanned the QR and reported its IP. Call [`PcPaired::connect`] to
/// open the data plane.
pub struct PcPaired {
    token: String,
    notify: PhoneNotify,
}

impl PcPaired {
    fn phone_ip(&self) -> String {
        self.notify.phone_ip.clone()
    }
    fn ble_id(&self) -> String {
        self.notify.ble_id.clone()
    }
    fn device_name(&self) -> String {
        self.notify.device_name.clone()
    }
    fn vivo_account(&self) -> String {
        self.notify.vivo_account.clone()
    }
    fn device_type(&self) -> String {
        self.notify.device_type.clone()
    }

    fn connect(&self) -> Result<PcSession, String> {
        let phone_ip = self.notify.phone_ip.clone();
        let token = self.token.clone();
        let session = rt()
            .block_on(Session::connect(&phone_ip, &token))
            .map_err(|e| format!("{e:#}"))?;
        Ok(build_wlan_session(session, token, phone_ip, None))
    }
}
