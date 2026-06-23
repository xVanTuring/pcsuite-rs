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
    config, register, usb, ClipboardConfig, InputHandle, MouseAction, MouseButton, RegisterConfig,
    Registration, ScreenParams, ScreenStream, Session, UsbConfig,
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
        // Arm SMS verify-code relay; then poll next_verify_code().
        fn enable_verify(&self);
        // Block for the next SMS code as "code\tsign"; empty = session ended OR
        // stop_verify() was called.
        fn next_verify_code(&self) -> String;
        // Ask the verify poller to stop: the next (or in-flight) next_verify_code()
        // returns an empty String within ~300ms so its thread can break and release
        // this PcSession (mirror of PcScreen::stop for the verify-code loop).
        fn stop_verify(&self);

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
        // Connect over USB (adb). Blocks a few seconds — call off the main thread.
        fn pcsuite_connect_usb() -> Result<PcSession, String>;
        // Connect over LAN/Tailscale. remote=true uses connectType=1 (no seed).
        fn pcsuite_connect_lan(phone_ip: String, remote: bool) -> Result<PcSession, String>;
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
            open_id: self.open_id.clone(),
            device_name: self.device_name.clone(),
            connect_type: self.connect_type.clone(),
            vdfs_fetch_host: self.vdfs_fetch_host.clone(),
            vdfs_fetch_port: self.vdfs_fetch_port,
            recv_from_phone: recv,
            send_to_phone: send,
        };
        rt().block_on(async {
            let mut s = self.session.lock().await;
            s.enable_clipboard(cfg, std::sync::Arc::new(MacClipboard)).await
        })
        .map_err(|e| format!("{e:#}"))
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

fn pcsuite_connect_usb() -> Result<PcSession, String> {
    let id = config::default_identity();
    let (u, session) = rt()
        .block_on(async {
            let u = usb::prepare(UsbConfig::default()).await?;
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
    let id = config::default_identity();
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
    let pc_ip = local_ip_toward(&phone_ip).unwrap_or_else(|| "0.0.0.0".into());
    let dead_rx = session.dead_signal();
    Ok(PcSession {
        session: tokio::sync::Mutex::new(session),
        input: std::sync::Mutex::new(None),
        verify_rx: std::sync::Mutex::new(None),
        verify_stop: std::sync::atomic::AtomicBool::new(false),
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
        _reg: Some(reg),
    })
}
