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
        // Block until the next raw HEVC frame; empty Vec = stream ended. Loop this
        // on a background thread.
        fn next_frame(&self) -> Vec<u8>;
    }

    extern "Rust" {
        type PcSession;

        // Start screen mirroring; returns a PcScreen to poll. Also arms input.
        // Drop the PcScreen to stop mirroring.
        fn start_screen(&self) -> Result<PcScreen, String>;
        // Enable bidirectional clipboard sync (text + images), built-in macOS backend.
        fn enable_clipboard(&self) -> Result<(), String>;
        // Arm SMS verify-code relay; then poll next_verify_code().
        fn enable_verify(&self);
        // Block for the next SMS code as "code\tsign"; empty = session ended.
        fn next_verify_code(&self) -> String;

        // Inject a mouse event. action: 0=down,1=up,2=move. button: 1=left,2=right.
        // Coordinates are in your reference frame (w, h); the phone scales.
        fn mouse(&self, action: u8, button: u8, x: i64, y: i64, w: i64, h: i64) -> bool;
        // Inject a scroll. vscroll > 0 up, < 0 down.
        fn scroll(&self, vscroll: i64, x: i64, y: i64, w: i64, h: i64) -> bool;
        // Tap (down+up, left button) at (x, y) in the reference frame (w, h).
        fn tap(&self, x: i64, y: i64, w: i64, h: i64) -> bool;
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

/// A live screen-mirror stream. Poll [`PcScreen::next_frame`]; drop to stop.
pub struct PcScreen {
    frames: tokio::sync::Mutex<ScreenStream>,
}

impl PcScreen {
    fn next_frame(&self) -> Vec<u8> {
        rt().block_on(async { self.frames.lock().await.next_frame().await })
            .unwrap_or_default()
    }
}

impl PcSession {
    fn start_screen(&self) -> Result<PcScreen, String> {
        let stream = rt()
            .block_on(async {
                let mut s = self.session.lock().await;
                s.enable_screen(ScreenParams::default()).await
            })
            .map_err(|e| format!("{e:#}"))?;
        *self.input.lock().unwrap() = stream.input();
        Ok(PcScreen { frames: tokio::sync::Mutex::new(stream) })
    }

    fn enable_clipboard(&self) -> Result<(), String> {
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
        };
        rt().block_on(async {
            let mut s = self.session.lock().await;
            s.enable_clipboard(cfg, std::sync::Arc::new(MacClipboard)).await
        })
        .map_err(|e| format!("{e:#}"))
    }

    fn enable_verify(&self) {
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
        // Take the receiver out so we don't hold the std lock across the blocking
        // recv, then put it back.
        let rx = self.verify_rx.lock().unwrap().take();
        let Some(mut rx) = rx else { return String::new() };
        let code = rt().block_on(rx.recv()).unwrap_or_default();
        *self.verify_rx.lock().unwrap() = Some(rx);
        code
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

    fn tap(&self, x: i64, y: i64, w: i64, h: i64) -> bool {
        let Some(input) = self.input.lock().unwrap().clone() else {
            return false;
        };
        rt().block_on(input.tap(x, y, w, h)).is_ok()
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
    Ok(PcSession {
        session: tokio::sync::Mutex::new(session),
        input: std::sync::Mutex::new(None),
        verify_rx: std::sync::Mutex::new(None),
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
    Ok(PcSession {
        session: tokio::sync::Mutex::new(session),
        input: std::sync::Mutex::new(None),
        verify_rx: std::sync::Mutex::new(None),
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
