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

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use pcsuite_core::{
    config, register, run_clipboard, run_verify, usb, ClipboardBackend, ClipboardConfig,
    RegisterConfig, Registration, Screen, ScreenParams, Session, UsbConfig, VerifyConfig,
};

struct Args {
    cmd: String,
    usb: bool,
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
}

fn parse_args() -> Args {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let cmd = raw.first().cloned().unwrap_or_default();
    let mut a = Args {
        cmd,
        usb: false,
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
    };
    let mut i = 1;
    while i < raw.len() {
        let flag = raw[i].clone();
        match flag.as_str() {
            "--usb" => a.usb = true,
            "--remote" => a.remote = true,
            "--input-test" => a.input_test = true,
            "--screen" => a.feat_screen = true,
            "--clipboard" => a.feat_clipboard = true,
            "--verify" => a.feat_verify = true,
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
         pcsuite all (--usb | --phone <IP> [--remote]) [--screen|--clipboard|--verify] \
         [--seconds <N>] [--out <f>]\n\
         \x20                                       (all features on one connection; default = all)\n\n\
         Transports: --usb (adb forward/reverse) or --phone <IP> (LAN ConnectFlow;\n\
         add --remote for connectType=1 / Tailscale). Over LAN the phone reverse-\n\
         connects to this machine's IP for clipboard + images, so allow inbound\n\
         8904/5679 if a firewall is on. --input-test scrolls to verify injection."
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
    if args.usb {
        tracing::info!(feature, "USB (adb) mode");
        let session = usb::prepare(UsbConfig::default()).await?;
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

/// Unified session: screen + clipboard + verify-code over one control connection.
async fn cmd_all(args: Args) -> Result<()> {
    // default to every feature when none is explicitly requested
    let any = args.feat_screen || args.feat_clipboard || args.feat_verify;
    let (do_screen, do_clip, do_verify) = if any {
        (args.feat_screen, args.feat_clipboard, args.feat_verify)
    } else {
        (true, true, true)
    };
    let identity = config::default_identity();
    tracing::info!(screen = do_screen, clipboard = do_clip, verify = do_verify, "pcsuite all");

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
        };
        session.enable_clipboard(cfg, Arc::new(MacClipboard)).await?;
    }

    println!(
        "🚀 unified session running ({}{}{}) — Ctrl-C to stop.",
        if do_screen { "screen " } else { "" },
        if do_clip { "clipboard " } else { "" },
        if do_verify { "verify-code" } else { "" }
    );

    let result: Result<()> = if do_screen {
        let mut stream = session.enable_screen(ScreenParams::default()).await?;
        let mut out = match &args.out {
            Some(p) => Some(std::fs::File::create(p)?),
            None => None,
        };
        let seconds = args.seconds.unwrap_or(0.0);
        let t0 = Instant::now();
        let limit = (seconds > 0.0).then(|| Duration::from_secs_f64(seconds));
        let mut frames = 0u64;
        loop {
            if let Some(lim) = limit {
                if t0.elapsed() >= lim {
                    break;
                }
            }
            let next = match limit {
                Some(lim) => {
                    let remaining = lim.saturating_sub(t0.elapsed()).max(Duration::from_millis(1));
                    match tokio::time::timeout(remaining, stream.next_frame()).await {
                        Ok(f) => f,
                        Err(_) => break,
                    }
                }
                None => stream.next_frame().await,
            };
            let Some(frame) = next else { break };
            frames += 1;
            if let Some(f) = out.as_mut() {
                use std::io::Write;
                f.write_all(&frame)?;
            }
            if frames % 60 == 0 {
                tracing::info!(frames, "…streaming");
            }
        }
        tracing::info!(frames, "screen stream ended");
        Ok(())
    } else {
        let seconds = args.seconds.unwrap_or(0.0);
        if seconds > 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(seconds)).await;
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
        Ok(())
    };

    drop(session); // aborts all feature tasks
    cleanup_transport(&t, do_clip).await;
    result
}
