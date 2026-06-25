//! `pcsuite` — headless CLI over `pcsuite-core`.
//!
//! Pure-Rust replacement for the Python screen-mirror scripts: get a token onto
//! the phone (LAN ConnectFlow, or USB via adb), open the screen-mirror data
//! plane, and either count frames (self-test) or dump the raw HEVC bitstream.
//!
//! Usage:
//!   pcsuite screen --usb [--seconds <N>] [--out <file.h265>]
//!   pcsuite screen --phone <IP> [--reg-ip <IP>] [--data-ip <IP>]
//!                  [--remote] [--seconds <N>] [--out <file.h265>]
//!
//!   --usb       wired path: adb forward + launch app + /version (no --phone needed)
//!   --phone     phone IP (LAN or Tailscale); default for both reg-ip and data-ip
//!   --reg-ip    IP for the 10191 sign registration (default: --phone)
//!   --data-ip   IP for control+video (default: --phone) — can be a Tailscale IP
//!   --remote    use connectType=1 (no pre-shared seed; works on any network)
//!   --seconds   run duration; 0 = run until Ctrl-C (default: 6)
//!   --out       append raw HEVC frames to this file (playable later with ffplay)

use std::io::IsTerminal;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use pcsuite_core::{
    config, device, mdfs, pair, register, run_clipboard, run_notify, run_verify, usb,
    ClipboardBackend, ClipboardConfig, ListKind, NotifyConfig, RegisterConfig, Registration, Screen,
    ScreenParams, Session, UsbConfig, VerifyConfig,
};

struct Args {
    cmd: String,
    usb: bool,
    /// Pair via QR (local `ls=true` variant): show a QR, wait for the phone to scan
    /// and report its IP to `:9199/notifyConnection`, then run any feature over it.
    pair: bool,
    /// This machine's LAN IP to advertise in the QR (`lip=`); auto-detected if unset.
    lip: Option<String>,
    phone: Option<String>,
    reg_ip: Option<String>,
    data_ip: Option<String>,
    remote: bool,
    seconds: Option<f64>,
    out: Option<String>,
    input_test: bool,
    feat_screen: bool,
    feat_clipboard: bool,
    feat_verify: bool,
    feat_notify: bool,
    /// `ls` category: recent|image|video|audio|file|doc|home.
    list_type: Option<String>,
    /// `pull` phone-side absolute path.
    path: Option<String>,
}

fn parse_args() -> Args {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let cmd = raw.first().cloned().unwrap_or_default();
    let mut a = Args {
        cmd,
        usb: false,
        pair: false,
        lip: None,
        phone: None,
        reg_ip: None,
        data_ip: None,
        remote: false,
        seconds: None,
        out: None,
        input_test: false,
        feat_screen: false,
        feat_clipboard: false,
        feat_verify: false,
        feat_notify: false,
        list_type: None,
        path: None,
    };
    let mut i = 1;
    while i < raw.len() {
        let flag = raw[i].clone();
        match flag.as_str() {
            "--usb" => a.usb = true,
            "--pair" => a.pair = true,
            "--remote" => a.remote = true,
            "--lip" => {
                i += 1;
                a.lip = raw.get(i).cloned();
            }
            "--input-test" => a.input_test = true,
            "--screen" => a.feat_screen = true,
            "--clipboard" => a.feat_clipboard = true,
            "--verify" => a.feat_verify = true,
            "--notify" => a.feat_notify = true,
            "--phone" => {
                i += 1;
                a.phone = raw.get(i).cloned();
            }
            "--reg-ip" => {
                i += 1;
                a.reg_ip = raw.get(i).cloned();
            }
            "--data-ip" => {
                i += 1;
                a.data_ip = raw.get(i).cloned();
            }
            "--seconds" => {
                i += 1;
                a.seconds = raw.get(i).and_then(|s| s.parse().ok());
            }
            "--out" => {
                i += 1;
                a.out = raw.get(i).cloned();
            }
            "--type" => {
                i += 1;
                a.list_type = raw.get(i).cloned();
            }
            "--path" => {
                i += 1;
                a.path = raw.get(i).cloned();
            }
            _ => {}
        }
        i += 1;
    }
    a
}

fn print_help() {
    eprintln!(
        "pcsuite — headless phone screen-mirror core (pure Rust)\n\n\
         USAGE:\n  \
         pcsuite screen --usb [--seconds <N>] [--out <file.h265>]\n  \
         pcsuite screen --phone <IP> [--reg-ip <IP>] [--data-ip <IP>] [--remote] \
         [--seconds <N>] [--out <file.h265>] [--input-test]\n  \
         pcsuite clipboard  (--usb | --phone <IP> [--remote]) [--seconds <N>]\n  \
         pcsuite verify-code (--usb | --phone <IP> [--remote]) [--seconds <N>]\n  \
         pcsuite notify (--usb | --phone <IP> [--remote]) [--seconds <N>]\n  \
         pcsuite info (--usb | --phone <IP> [--remote])   (device model/OS + storage capacity)\n  \
         pcsuite ls (--usb | --phone <IP> [--remote]) [--type recent|image|video|audio|file|doc|home]\n  \
         pcsuite pull (--usb | --phone <IP> [--remote]) --path <phone-path> [--out <file>]\n  \
         pcsuite all (--usb | --phone <IP> [--remote]) [--screen|--clipboard|--verify|--notify] \
         [--seconds <N>] [--out <f>]\n\
         \x20                                       (clipboard+verify+notify in the background; type\n\
         \x20                                        `screen on`/`screen off` at the prompt to\n\
         \x20                                        toggle mirroring. --screen starts it on.)\n\n\
         Transports: --usb (adb forward/reverse), --phone <IP> (LAN ConnectFlow;\n\
         add --remote for connectType=1 / Tailscale), or --pair (QR: show a code,\n\
         scan it with the phone's PCSuite 扫码连接电脑; no IP/seed needed — works on\n\
         any command, e.g. `pcsuite screen --pair`, `pcsuite all --pair`; --lip <IP>\n\
         overrides the auto-detected LAN IP). Over LAN the phone reverse-connects to\n\
         this machine's IP for clipboard + images, so allow inbound 8904/5679 if a\n\
         firewall is on. --input-test scrolls to verify injection."
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let args = parse_args();
    match args.cmd.as_str() {
        "screen" => cmd_screen(args).await,
        "clipboard" => cmd_clipboard(args).await,
        "verify-code" => cmd_verify(args).await,
        "notify" => cmd_notify(args).await,
        "info" => cmd_info(args).await,
        "ls" => cmd_ls(args).await,
        "pull" => cmd_pull(args).await,
        "all" => cmd_all(args).await,
        "" | "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}\n");
            print_help();
            Ok(())
        }
    }
}

/// Everything a feature needs, resolved for either transport (USB adb / LAN-remote).
struct Transport {
    /// Control + video host (and the 8904-handshake host).
    data_ip: String,
    token: String,
    /// IP the phone uses to reverse-connect to our 8904/5679 (SHADOW_LIKE `pcInfo.ip`).
    pc_ip: String,
    /// Where we bind our 8904/5679 servers.
    bind_addr: String,
    /// SHADOW_LIKE `pcInfo.connectType`: `"USB"` or `"WLAN"`.
    connect_type: String,
    /// Host:port of the phone's vdfs server for image fetch (phone→PC).
    vdfs_fetch_host: String,
    vdfs_fetch_port: u16,
    /// `Some(adb)` over USB — drives the clipboard port forwards + cleanup.
    usb_adb: Option<String>,
    /// Holds the LAN SSDP-presence task alive until the session ends.
    _reg: Option<Registration>,
}

/// Resolve the transport: USB (adb) when `--usb`, else LAN/remote ConnectFlow.
///
/// USB tunnels everything through `127.0.0.1` (the phone reaches our servers over
/// `adb reverse`, we reach the phone's vdfs over `adb forward`). LAN binds our
/// servers on all interfaces and tells the phone our real interface IP; image
/// fetch goes straight to `<phone>:5678`.
async fn resolve_transport(args: &Args, feature: &str) -> Result<Transport> {
    if args.pair {
        // QR pairing (local ls=true): show a QR, wait for the phone to scan + report
        // its IP, then run the normal LAN data plane with the QR-delivered token.
        let identity = config::default_identity();
        let lip = args
            .lip
            .clone()
            .or_else(local_lan_ip)
            .context("could not auto-detect this machine's LAN IP — pass --lip <IP>")?;
        let token = pair::random_token();
        let url = pair::qr_url(&token, &lip, &identity);
        tracing::info!(feature, %lip, "QR pairing mode");
        println!("\n📲 扫码配对 — 用手机 vivo PCSuite「扫码连接电脑」扫这个码:\n");
        render_qr(&url);
        println!("    (手动转码也行)  {url}");
        println!("    本机 LAN IP(lip)={lip}   监听 :{}   等手机扫码(最多 180s)…\n", pair::NOTIFY_PORT);

        let notify = pair::wait_for_phone(pair::NOTIFY_PORT, Duration::from_secs(180)).await?;
        println!(
            "✅ 手机已回投: {} (phoneIp={}, bleId={}, {})",
            notify.device_name, notify.phone_ip, notify.ble_id, notify.device_type
        );
        let data_ip = notify.phone_ip.clone();
        let pc_ip = local_ip_toward(&data_ip).unwrap_or(lip);
        return Ok(Transport {
            data_ip: data_ip.clone(),
            token,
            pc_ip,
            bind_addr: "0.0.0.0".into(),
            connect_type: "WLAN".into(),
            vdfs_fetch_host: data_ip,
            vdfs_fetch_port: 5678,
            usb_adb: None,
            _reg: None,
        });
    }
    if args.usb {
        tracing::info!(feature, "USB (adb) mode");
        let session = usb::prepare(UsbConfig {
            pc_name: Some(pcsuite_core::config::default_identity().device_name),
            ..UsbConfig::default()
        })
        .await?;
        Ok(Transport {
            data_ip: "127.0.0.1".into(),
            token: session.token,
            pc_ip: "127.0.0.1".into(),
            bind_addr: "127.0.0.1".into(),
            connect_type: "USB".into(),
            vdfs_fetch_host: "127.0.0.1".into(),
            vdfs_fetch_port: 10382,
            usb_adb: Some(session.adb),
            _reg: None,
        })
    } else {
        let phone = args.phone.clone().context("--phone <IP> is required (or use --usb)")?;
        let reg_ip = args.reg_ip.clone().unwrap_or_else(|| phone.clone());
        let data_ip = args.data_ip.clone().unwrap_or_else(|| phone.clone());
        let stored_seed = if args.remote {
            None
        } else {
            config::default_stored_seed(&reg_ip)
        };
        tracing::info!(feature, %reg_ip, %data_ip, remote = args.remote, "LAN mode");
        let reg = register(RegisterConfig {
            reg_ip,
            identity: config::default_identity(),
            stored_seed,
            remote: args.remote,
            token: None,
            conn_id: None,
            presence: true,
        })
        .await?;
        let token = reg.token.clone();
        let pc_ip = local_ip_toward(&data_ip)
            .context("could not determine this machine's IP toward the phone")?;
        tracing::info!(%pc_ip, "phone will reverse-connect to this IP for clipboard/images");
        Ok(Transport {
            data_ip: data_ip.clone(),
            token,
            pc_ip,
            bind_addr: "0.0.0.0".into(),
            connect_type: "WLAN".into(),
            vdfs_fetch_host: data_ip,
            vdfs_fetch_port: 5678,
            usb_adb: None,
            _reg: Some(reg),
        })
    }
}

/// Tear down whatever [`resolve_transport`] set up. `clipboard` removes the
/// clipboard-specific USB forwards too.
async fn cleanup_transport(t: &Transport, clipboard: bool) {
    if let Some(adb) = &t.usb_adb {
        if clipboard {
            teardown_clipboard_forwards(adb).await;
        }
        usb::cleanup(adb).await;
    }
}

/// The local interface IP that routes toward `peer` (UDP "connect" picks the route
/// without sending a packet). Works for both LAN and Tailscale peers.
fn local_ip_toward(peer: &str) -> Option<String> {
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect((peer, 9)).ok()?; // discard service; no traffic sent
    Some(sock.local_addr().ok()?.ip().to_string())
}

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

/// Render the pairing QR for scanning (best-effort). On macOS, generate a PNG via
/// CoreImage (`swift`) and open it in Preview; the caller always prints the URL too,
/// so a headless box can still turn it into a QR by hand.
fn render_qr(url: &str) {
    if let Err(e) = render_qr_macos(url) {
        tracing::debug!(err = %e, "QR PNG render unavailable — scan the URL above");
    }
}

fn render_qr_macos(url: &str) -> Result<()> {
    let dir = std::env::temp_dir();
    let swift = dir.join("pcsuite_qrgen.swift");
    let png = dir.join("pcsuite_pair_qr.png");
    std::fs::write(&swift, QRGEN_SWIFT)?;
    let out = std::process::Command::new("swift")
        .arg(&swift)
        .arg(url)
        .arg(&png)
        .output()
        .context("run swift (needs Xcode CLT) to render QR")?;
    if !out.status.success() {
        anyhow::bail!("qrgen: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let _ = std::process::Command::new("open").arg(&png).status();
    println!("    🟦 QR 已生成并打开预览: {}", png.display());
    Ok(())
}

/// Offline CoreImage QR generator (mirrors `re/lan/qrgen.swift`). Embedded so the CLI
/// has no extra crate dependency for QR rendering.
const QRGEN_SWIFT: &str = r#"import Foundation
import CoreImage
import AppKit
let args = CommandLine.arguments
guard args.count >= 3 else { exit(2) }
guard let f = CIFilter(name: "CIQRCodeGenerator") else { exit(3) }
f.setValue(args[1].data(using: .utf8)!, forKey: "inputMessage")
f.setValue("M", forKey: "inputCorrectionLevel")
guard let base = f.outputImage else { exit(4) }
let img = base.transformed(by: CGAffineTransform(scaleX: 12, y: 12))
let ctx = CIContext()
guard let cg = ctx.createCGImage(img, from: img.extent) else { exit(5) }
let rep = NSBitmapImageRep(cgImage: cg)
guard let png = rep.representation(using: .png, properties: [:]) else { exit(6) }
try! png.write(to: URL(fileURLWithPath: args[2]))
"#;

async fn cmd_screen(args: Args) -> Result<()> {
    let t = resolve_transport(&args, "screen").await?;
    tracing::info!(token = %&t.token[..10.min(t.token.len())], "token ready (…)");
    let result = stream_screen(&t.data_ip, &t.token, &args).await;
    cleanup_transport(&t, false).await;
    result
}

/// Open the data plane and consume frames (count / dump) for the configured time.
async fn stream_screen(data_ip: &str, token: &str, args: &Args) -> Result<()> {
    let mut screen = Screen::open(data_ip, token, ScreenParams::default()).await?;

    // Optional: prove control input works by scrolling the phone at screen centre.
    if args.input_test {
        match screen.input() {
            Some(handle) => {
                tracing::info!("input-test: scrolling phone centre (watch the device)");
                tokio::spawn(async move {
                    // reference frame 1000x2000 -> centre = (500, 1000)
                    for i in 0..10 {
                        tokio::time::sleep(Duration::from_millis(400)).await;
                        let dir = if i < 5 { -1 } else { 1 };
                        let _ = handle.scroll(dir, 500, 1000, 1000, 2000).await;
                    }
                });
            }
            None => tracing::warn!("--input-test: control-input channel unavailable"),
        }
    }

    let mut out = match &args.out {
        Some(path) => Some(std::fs::File::create(path)?),
        None => None,
    };
    let seconds = args.seconds.unwrap_or(6.0);
    let t0 = Instant::now();
    let limit = (seconds > 0.0).then(|| Duration::from_secs_f64(seconds));
    let mut frames = 0u64;
    let mut bytes = 0u64;

    loop {
        if let Some(lim) = limit {
            if t0.elapsed() >= lim {
                break;
            }
        }
        let next = match limit {
            Some(lim) => {
                let remaining = lim.saturating_sub(t0.elapsed()).max(Duration::from_millis(1));
                match tokio::time::timeout(remaining, screen.next_frame()).await {
                    Ok(f) => f,
                    Err(_) => break,
                }
            }
            None => screen.next_frame().await,
        };
        let Some(frame) = next else { break };
        frames += 1;
        bytes += frame.len() as u64;
        if let Some(f) = out.as_mut() {
            use std::io::Write;
            f.write_all(&frame)?;
        }
        if frames % 30 == 0 {
            tracing::info!(frames, kb = bytes / 1024, secs = t0.elapsed().as_secs_f64(), "…streaming");
        }
    }

    let dt = t0.elapsed().as_secs_f64();
    let fps = if dt > 0.0 { frames as f64 / dt } else { 0.0 };
    tracing::info!(frames, kb = bytes / 1024, secs = dt, fps, "done");
    if frames > 0 {
        println!(
            "✅ pure-Rust core: token ok → control WS → req_authrity → mirror WS → {frames} HEVC frames ({} KB, {fps:.1} fps)",
            bytes / 1024
        );
    } else {
        println!("⚠ connected but received 0 frames (screen static? permission prompt?)");
    }
    Ok(())
}

async fn cmd_clipboard(args: Args) -> Result<()> {
    let identity = config::default_identity();
    let t = resolve_transport(&args, "clipboard").await?;
    if let Some(adb) = &t.usb_adb {
        setup_clipboard_forwards(adb).await;
    }

    let cfg = ClipboardConfig {
        data_ip: t.data_ip.clone(),
        pc_ip: t.pc_ip.clone(),
        bind_addr: t.bind_addr.clone(),
        token: t.token.clone(),
        open_id: identity.open_id.clone(),
        device_name: identity.device_name.clone(),
        connect_type: t.connect_type.clone(),
        vdfs_fetch_host: t.vdfs_fetch_host.clone(),
        vdfs_fetch_port: t.vdfs_fetch_port,
        recv_from_phone: true,
        send_to_phone: true,
    };
    let backend: Arc<dyn ClipboardBackend> = Arc::new(MacClipboard);

    println!("📋 clipboard relay running — copy text or an image on Mac or phone to sync. Ctrl-C to stop.");
    let run = run_clipboard(cfg, backend);
    let seconds = args.seconds.unwrap_or(0.0); // clipboard default: run forever
    let result = if seconds > 0.0 {
        match tokio::time::timeout(Duration::from_secs_f64(seconds), run).await {
            Ok(r) => r,
            Err(_) => {
                tracing::info!("clipboard: time limit reached");
                Ok(())
            }
        }
    } else {
        run.await
    };

    cleanup_transport(&t, true).await;
    result
}

/// Wire up the USB port plumbing the clipboard relay needs:
/// - reverse 8904: phone reverse-connects to our 8904 relay
/// - reverse 5679: phone fetches PC images from our vdfs server (PC→phone paste)
/// - forward 10382→5678: we fetch phone images from its vdfs server (phone→PC paste)
async fn setup_clipboard_forwards(adb: &str) {
    pcsuite_core::adb::run_ok(adb, &["reverse", "tcp:8904", "tcp:8904"]).await;
    pcsuite_core::adb::run_ok(adb, &["reverse", "tcp:5679", "tcp:5679"]).await;
    pcsuite_core::adb::run_ok(adb, &["forward", "tcp:10382", "tcp:5678"]).await;
}

async fn teardown_clipboard_forwards(adb: &str) {
    pcsuite_core::adb::run_ok(adb, &["reverse", "--remove", "tcp:8904"]).await;
    pcsuite_core::adb::run_ok(adb, &["reverse", "--remove", "tcp:5679"]).await;
    pcsuite_core::adb::run_ok(adb, &["forward", "--remove", "tcp:10382"]).await;
}

/// macOS clipboard backend via `pbpaste`/`pbcopy` (text) and `osascript` (images).
struct MacClipboard;

impl ClipboardBackend for MacClipboard {
    fn get_text(&self) -> Option<String> {
        let out = std::process::Command::new("pbpaste").output().ok()?;
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn set_text(&self, text: &str) -> Result<()> {
        use std::io::Write;
        let mut child = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()?;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(text.as_bytes())?;
        }
        child.wait()?;
        Ok(())
    }

    fn image_signature(&self) -> Option<String> {
        // `clipboard info` is cheap and changes with the image; gate on an image class.
        let out = std::process::Command::new("osascript")
            .args(["-e", "clipboard info"])
            .output()
            .ok()?;
        let info = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let is_image = ["picture", "PNGf", "TIFF", "8BPS", "JPEG"]
            .iter()
            .any(|k| info.contains(k));
        is_image.then_some(info)
    }

    fn get_image(&self) -> Option<Vec<u8>> {
        // Coerce the clipboard to JPEG, write to a temp file, read it back. Fails
        // (→ None) when the clipboard holds no image.
        let dest = std::env::temp_dir().join("pcsuite_clip_get.jpeg");
        let dest_s = dest.to_string_lossy();
        let script = format!(
            "set d to (the clipboard as JPEG picture)\n\
             set f to (open for access (POSIX file \"{dest_s}\") with write permission)\n\
             set eof f to 0\nwrite d to f\nclose access f"
        );
        let ok = std::process::Command::new("osascript")
            .args(["-e", &script])
            .output()
            .ok()
            .is_some_and(|o| o.status.success());
        if !ok {
            return None;
        }
        std::fs::read(&dest).ok().filter(|b| !b.is_empty())
    }

    fn set_image(&self, data: &[u8], mime: &str) -> Result<()> {
        let (ext, class) = match mime {
            "image/png" => ("png", "«class PNGf»"),
            "image/gif" => ("gif", "GIF picture"),
            "image/tiff" => ("tiff", "TIFF picture"),
            "image/bmp" => ("bmp", "«class BMP »"),
            _ => ("jpeg", "JPEG picture"),
        };
        let path = std::env::temp_dir().join(format!("pcsuite_clip_set.{ext}"));
        std::fs::write(&path, data)?;
        let path_s = path.to_string_lossy();
        let script = format!("set the clipboard to (read (POSIX file \"{path_s}\") as {class})");
        let out = std::process::Command::new("osascript")
            .args(["-e", &script])
            .output()?;
        if !out.status.success() {
            anyhow::bail!("osascript set image: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }
}

async fn cmd_verify(args: Args) -> Result<()> {
    let t = resolve_transport(&args, "verify-code").await?;
    let cfg = VerifyConfig {
        data_ip: t.data_ip.clone(),
        token: t.token.clone(),
    };
    println!("🔑 verify-code relay running — receive an SMS code on the phone; it'll be copied to the Mac clipboard. Ctrl-C to stop.");
    let run = run_verify(cfg, |code, sign| {
        println!("★ SMS code: {code}  (from: {sign})");
        copy_to_clipboard(code);
    });
    let seconds = args.seconds.unwrap_or(0.0);
    let result = if seconds > 0.0 {
        match tokio::time::timeout(Duration::from_secs_f64(seconds), run).await {
            Ok(r) => r,
            Err(_) => {
                tracing::info!("verify-code: time limit reached");
                Ok(())
            }
        }
    } else {
        run.await
    };
    cleanup_transport(&t, false).await;
    result
}

fn copy_to_clipboard(text: &str) {
    use std::io::Write;
    if let Ok(mut child) = std::process::Command::new("pbcopy")
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        if let Some(stdin) = child.stdin.as_mut() {
            let _ = stdin.write_all(text.as_bytes());
        }
        let _ = child.wait();
    }
}

/// Relay phone notifications: each one the phone forwards is printed and shown as a
/// native macOS notification.
async fn cmd_notify(args: Args) -> Result<()> {
    let t = resolve_transport(&args, "notify").await?;
    let cfg = NotifyConfig {
        data_ip: t.data_ip.clone(),
        token: t.token.clone(),
    };
    println!("🔔 notification relay running — phone notifications will appear on the Mac. Ctrl-C to stop.");
    let run = run_notify(cfg, show_phone_notification);
    let seconds = args.seconds.unwrap_or(0.0);
    let result = if seconds > 0.0 {
        match tokio::time::timeout(Duration::from_secs_f64(seconds), run).await {
            Ok(r) => r,
            Err(_) => {
                tracing::info!("notify: time limit reached");
                Ok(())
            }
        }
    } else {
        run.await
    };
    cleanup_transport(&t, false).await;
    result
}

/// Print a forwarded phone notification and surface it as a native macOS banner.
fn show_phone_notification(n: &pcsuite_core::Notification) {
    let title = if n.title.is_empty() { &n.app_name } else { &n.title };
    println!("🔔 [{}] {} — {}", n.app_name, title, n.content);
    display_mac_notification(title, &n.app_name, &n.content);
}

/// Post a native macOS notification via `osascript` (best-effort, fire-and-forget).
fn display_mac_notification(title: &str, subtitle: &str, body: &str) {
    // Escape backslashes and double-quotes for the AppleScript string literals.
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }
    let script = format!(
        "display notification \"{}\" with title \"{}\" subtitle \"{}\"",
        esc(body),
        esc(title),
        esc(subtitle),
    );
    let _ = std::process::Command::new("osascript")
        .arg("-e")
        .arg(script)
        .output();
}

/// Show phone device info (storage capacity, model, OS) via the 10380 `/base-info`
/// gateway — the desktop app's device-panel data. Opens the control session to learn
/// the phone's `mobileDeviceId`, then fetches.
async fn cmd_info(args: Args) -> Result<()> {
    let identity = config::default_identity();
    let t = resolve_transport(&args, "info").await?;
    let session = Session::connect(&t.data_ip, &t.token).await?;
    let phone = session.phone_info(&t.pc_ip, &t.connect_type, &identity).await?;

    let result = device::fetch(&t.data_ip, &t.token, &phone.mobile_device_id).await;
    drop(session);
    cleanup_transport(&t, false).await;

    let info = result?;
    let brand = if info.mobile_brand.is_empty() { String::new() } else { format!(" ({})", info.mobile_brand) };
    println!("📱 {}{}", phone.mobile_device_name, brand);
    if !info.product.is_empty() || !info.android_version.is_empty() {
        println!("   型号 {}   Android {}   OS {}", info.product, info.android_version, info.os_version);
    }
    if info.width_pixels > 0 {
        let fold = if info.fold_screen { "  折叠屏" } else { "" };
        println!("   屏幕 {}×{}{}", info.width_pixels, info.height_pixels, fold);
    }
    println!(
        "   存储 {} GB 可用 / {} GB 总  ({} 可用)",
        info.available_storage_gb, info.total_storage_gb, human_size(info.available_bytes)
    );
    if !info.vivo_account.is_empty() {
        println!("   账号 {}", info.vivo_account);
    }
    if !info.open_id.is_empty() {
        println!("   openId {}", info.open_id);
    }
    Ok(())
}

/// Browse a phone file/media category over the mdfs HTTP API (10380). Opens the
/// control session (to learn the phone's `mobileDeviceId`), then lists.
async fn cmd_ls(args: Args) -> Result<()> {
    let identity = config::default_identity();
    let kind = match args.list_type.as_deref() {
        Some(s) => ListKind::parse(s)
            .with_context(|| format!("unknown --type {s:?} (recent|image|video|audio|file|doc|home)"))?,
        None => ListKind::Recent,
    };

    let t = resolve_transport(&args, "ls").await?;
    let session = Session::connect(&t.data_ip, &t.token).await?;
    let phone = session.phone_info(&t.pc_ip, &t.connect_type, &identity).await?;
    tracing::info!(device = %phone.mobile_device_id, name = %phone.mobile_device_name, "phone session resolved");

    let result = mdfs::list(&t.data_ip, &t.token, &phone.mobile_device_id, kind, 500).await;
    drop(session);
    cleanup_transport(&t, false).await;

    let entries = result?;
    println!("📂 {:?} — {} item(s) on {}", kind, entries.len(), phone.mobile_device_name);
    for e in &entries {
        let tag = if e.is_dir { "d" } else { "-" };
        let extra = if e.duration_ms > 0 {
            format!("  [{}s]", e.duration_ms / 1000)
        } else {
            String::new()
        };
        println!("{tag} {:>9}  {}{}", human_size(e.size), e.path, extra);
    }
    Ok(())
}

/// Download one phone file by path over the mdfs HTTP plane (`download_info` +
/// `download` tar stream on 10380) — the desktop app's path, which works without the
/// vdfs (5678) serving gate.
async fn cmd_pull(args: Args) -> Result<()> {
    let identity = config::default_identity();
    let path = args.path.clone().context("--path <phone-path> is required")?;

    let t = resolve_transport(&args, "pull").await?;
    let session = Session::connect(&t.data_ip, &t.token).await?;
    let phone = session.phone_info(&t.pc_ip, &t.connect_type, &identity).await?;
    tracing::info!(device = %phone.mobile_device_id, %path, "pulling");

    let fetched = mdfs::download(&t.data_ip, &t.token, &phone.mobile_device_id, &path).await;
    drop(session);
    cleanup_transport(&t, false).await;

    let bytes = fetched?;
    let out = args.out.clone().unwrap_or_else(|| {
        std::path::Path::new(&path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "pulled.bin".into())
    });
    std::fs::write(&out, &bytes).with_context(|| format!("write {out}"))?;
    println!("✅ pulled {} → {out} ({} bytes)", path, bytes.len());
    Ok(())
}

/// Human-readable byte count.
fn human_size(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// Unified session: screen + clipboard + verify-code over one control connection.
async fn cmd_all(args: Args) -> Result<()> {
    // Background features (clipboard + verify + notify) default on; screen does NOT
    // auto-start — toggle it at runtime from the prompt (or pass --screen to start on).
    let any = args.feat_screen || args.feat_clipboard || args.feat_verify || args.feat_notify;
    let (start_screen, do_clip, do_verify, do_notify) = if any {
        (args.feat_screen, args.feat_clipboard, args.feat_verify, args.feat_notify)
    } else {
        (false, true, true, true)
    };
    let identity = config::default_identity();
    tracing::info!(
        screen = start_screen,
        clipboard = do_clip,
        verify = do_verify,
        notify = do_notify,
        "pcsuite all"
    );

    let t = resolve_transport(&args, "all").await?;
    if do_clip {
        if let Some(adb) = &t.usb_adb {
            setup_clipboard_forwards(adb).await;
        }
    }

    let mut session = Session::connect(&t.data_ip, &t.token).await?;

    if do_verify {
        session.enable_verify(|code, sign| {
            println!("★ SMS code: {code}  (from: {sign})");
            copy_to_clipboard(code);
        });
    }
    if do_notify {
        session.enable_notify(show_phone_notification);
    }
    if do_clip {
        let cfg = ClipboardConfig {
            data_ip: t.data_ip.clone(),
            pc_ip: t.pc_ip.clone(),
            bind_addr: t.bind_addr.clone(),
            token: t.token.clone(),
            open_id: identity.open_id.clone(),
            device_name: identity.device_name.clone(),
            connect_type: t.connect_type.clone(),
            vdfs_fetch_host: t.vdfs_fetch_host.clone(),
            vdfs_fetch_port: t.vdfs_fetch_port,
            recv_from_phone: true,
            send_to_phone: true,
        };
        session.enable_clipboard(cfg, Arc::new(MacClipboard)).await?;
    }

    let bg = format!(
        "{}{}{}",
        if do_clip { "clipboard " } else { "" },
        if do_verify { "verify-code " } else { "" },
        if do_notify { "notify" } else { "" }
    );
    let interactive = args.seconds.is_none() && std::io::stdin().is_terminal();
    let result = run_session(&mut session, &args, start_screen, bg.trim(), interactive).await;

    drop(session); // aborts all feature tasks
    cleanup_transport(&t, do_clip).await;
    result
}

/// Runtime control of the screen feature over the live unified session: a handle
/// whose presence means mirroring is on (dropping/aborting it stops mirroring).
#[derive(Default)]
struct ScreenToggle {
    task: Option<tokio::task::JoinHandle<()>>,
    frames: Arc<std::sync::atomic::AtomicU64>,
}

impl ScreenToggle {
    fn is_on(&self) -> bool {
        self.task.is_some()
    }

    async fn on(&mut self, session: &mut Session, args: &Args) {
        use std::sync::atomic::{AtomicU64, Ordering};
        if self.task.is_some() {
            println!("· screen already on");
            return;
        }
        let mut stream = match session.enable_screen(ScreenParams::default()).await {
            Ok(s) => s,
            Err(e) => {
                println!("✗ screen failed: {e}");
                return;
            }
        };
        let frames = Arc::new(AtomicU64::new(0));
        let fc = frames.clone();
        let out_path = args.out.clone();
        let task = tokio::spawn(async move {
            let mut out = out_path.and_then(|p| std::fs::File::create(p).ok());
            while let Some(frame) = stream.next_frame().await {
                let n = fc.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some(f) = out.as_mut() {
                    use std::io::Write;
                    let _ = f.write_all(&frame);
                }
                if n % 120 == 0 {
                    tracing::info!(frames = n, "…streaming");
                }
            }
        });
        self.frames = frames;
        self.task = Some(task);
        let note = args.out.as_deref().map(|p| format!(" → {p}")).unwrap_or_default();
        println!("▶ screen ON{note}");
    }

    fn off(&mut self) {
        use std::sync::atomic::Ordering;
        match self.task.take() {
            Some(t) => {
                t.abort();
                println!("⏹ screen OFF ({} frames)", self.frames.load(Ordering::Relaxed));
            }
            None => println!("· screen already off"),
        }
    }
}

/// Drive the live session: start `start_screen`, then either block (non-interactive)
/// or run a tiny prompt to toggle screen on demand (interactive TTY, no --seconds).
async fn run_session(
    session: &mut Session,
    args: &Args,
    start_screen: bool,
    bg: &str,
    interactive: bool,
) -> Result<()> {
    let mut screen = ScreenToggle::default();
    if start_screen {
        screen.on(session, args).await;
    }

    if !interactive {
        println!("🚀 unified session running (background: {bg}) — Ctrl-C to stop.");
        let seconds = args.seconds.unwrap_or(0.0);
        if seconds > 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(seconds)).await;
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
        if screen.is_on() {
            screen.off();
        }
        return Ok(());
    }

    println!("🚀 unified session running (background: {bg}).");
    print_repl_help();

    // Read stdin lines on a blocking thread; deliver them to the async loop.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(8);
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::stdin().lock().lines() {
            match line {
                Ok(l) => {
                    if tx.blocking_send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    loop {
        tokio::select! {
            maybe = rx.recv() => {
                let Some(line) = maybe else { break }; // stdin closed (EOF / Ctrl-D)
                match line.trim() {
                    "" => {}
                    "screen on" | "s on" | "on" => screen.on(session, args).await,
                    "screen off" | "s off" | "off" => screen.off(),
                    "status" | "st" => println!(
                        "─ background: {bg} | screen: {}",
                        if screen.is_on() {
                            format!("ON ({} frames)", screen.frames.load(std::sync::atomic::Ordering::Relaxed))
                        } else {
                            "off".to_string()
                        }
                    ),
                    "help" | "h" | "?" => print_repl_help(),
                    "quit" | "exit" | "q" => break,
                    other => println!("? unknown: {other:?}  (screen on | screen off | status | quit)"),
                }
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    if screen.is_on() {
        screen.off();
    }
    Ok(())
}

fn print_repl_help() {
    println!("  commands: screen on | screen off | status | help | quit   (clipboard/verify/notify run in the background)");
}
