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
    config, register, run_clipboard, usb, ClipboardBackend, ClipboardConfig, RegisterConfig, Screen,
    ScreenParams, UsbConfig,
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
    };
    let mut i = 1;
    while i < raw.len() {
        let flag = raw[i].clone();
        match flag.as_str() {
            "--usb" => a.usb = true,
            "--remote" => a.remote = true,
            "--input-test" => a.input_test = true,
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
         pcsuite clipboard --usb [--seconds <N>]   (text sync; --seconds 0 = forever)\n\n\
         Gets a token onto the phone (USB adb, or LAN ConnectFlow), opens the\n\
         screen-mirror data plane, and counts frames (or dumps raw HEVC with --out).\n\
         --input-test scrolls the phone centre to verify mouse/scroll injection."
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

async fn cmd_screen(args: Args) -> Result<()> {
    // Resolve (data_ip, token) per mode. `_reg` keeps the LAN presence task alive;
    // `usb_adb` triggers adb-forward cleanup at the end.
    let (data_ip, token, _reg, usb_adb): (String, String, Option<_>, Option<String>) = if args.usb {
        tracing::info!("pcsuite screen — USB (adb) mode");
        let session = usb::prepare(UsbConfig::default()).await?;
        let adb = session.adb.clone();
        ("127.0.0.1".to_string(), session.token, None, Some(adb))
    } else {
        let phone = args.phone.clone().context("--phone <IP> is required (or use --usb)")?;
        let reg_ip = args.reg_ip.clone().unwrap_or_else(|| phone.clone());
        let data_ip = args.data_ip.clone().unwrap_or_else(|| phone.clone());
        let stored_seed = if args.remote {
            None
        } else {
            config::default_stored_seed(&reg_ip)
        };
        tracing::info!(%reg_ip, %data_ip, remote = args.remote, "pcsuite screen — LAN mode");
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
        (data_ip, token, Some(reg), None)
    };
    tracing::info!(token = %&token[..10.min(token.len())], "token ready (…)");

    let result = stream_screen(&data_ip, &token, &args).await;

    if let Some(adb) = usb_adb {
        usb::cleanup(&adb).await;
    }
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
    if !args.usb {
        anyhow::bail!("`clipboard` currently supports --usb only (LAN support coming next)");
    }
    let identity = config::default_identity();
    tracing::info!("pcsuite clipboard — USB (adb) mode");
    let session = usb::prepare(UsbConfig::default()).await?;
    // let the phone reach our 8904 relay via its own localhost
    pcsuite_core::adb::run_ok(&session.adb, &["reverse", "tcp:8904", "tcp:8904"]).await;

    let cfg = ClipboardConfig {
        data_ip: "127.0.0.1".into(),
        pc_ip: "127.0.0.1".into(),
        bind_addr: "127.0.0.1".into(),
        token: session.token.clone(),
        open_id: identity.open_id.clone(),
        device_name: identity.device_name.clone(),
        connect_type: "USB".into(),
    };
    let backend: Arc<dyn ClipboardBackend> = Arc::new(MacClipboard);

    println!("📋 clipboard relay running — copy text on Mac or phone to sync. Ctrl-C to stop.");
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

    pcsuite_core::adb::run_ok(&session.adb, &["reverse", "--remove", "tcp:8904"]).await;
    usb::cleanup(&session.adb).await;
    result
}

/// macOS clipboard backend via `pbpaste`/`pbcopy`.
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
}
