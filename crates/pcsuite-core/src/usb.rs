//! Wired/USB entry path.
//!
//! Unlike the LAN path (10191 ConnectFlow + sign), the USB path hands the token
//! to the phone directly via `am start-service … --es token <TOKEN>`, forwards
//! 10380/10381 over adb, and confirms readiness with a plain-HTTP `POST /version`
//! handshake. After [`prepare`] succeeds, drive [`crate::Screen::open`] against
//! `127.0.0.1` with the returned token.
//!
//! The `am` intent / service names below are the phone's own component names
//! (required to launch its service); they are not crate/package names.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::adb;

/// Inputs to [`prepare`].
#[derive(Default)]
pub struct UsbConfig {
    pub adb_path: Option<String>,
    pub token: Option<String>,
    pub conn_id: Option<String>,
    /// PC display name handed to the phone's `AdbPortalService` (`--es pc_name` /
    /// `--es user_name`). The phone shows it during the USB connect; empty/None
    /// falls back to a generic label. The persistent "已连接" card name comes from
    /// the `/base-info` `pc_name` (see [`crate::device::fetch`]) — set both to the
    /// same value so the connect-time and connected names match.
    pub pc_name: Option<String>,
}

/// Result of a successful [`prepare`]: drive `Screen::open("127.0.0.1", &token, …)`.
pub struct UsbSession {
    pub adb: String,
    pub token: String,
    pub conn_id: String,
}

/// Single-quote a string for the *device* shell that `adb shell` hands the command
/// to, so spaces/apostrophes in a `--es` value can't split or break the `am` line.
/// Wraps in `'…'` and rewrites each embedded `'` as `'\''`.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// adb-forward ports, launch the phone app + portal service with our token,
/// and confirm via `/version`. Returns once the phone answers `"0000"`.
pub async fn prepare(cfg: UsbConfig) -> Result<UsbSession> {
    let adb = adb::resolve_adb(cfg.adb_path.as_deref());
    let token = cfg.token.unwrap_or_else(random_token);
    let conn_id = cfg
        .conn_id
        .unwrap_or_else(|| format!("pcsuite_{}", epoch_secs()));
    // PC display name for the phone's AdbPortalService; blank/None → generic label.
    // `adb shell` joins the post-`shell` argv with spaces and the *device* shell
    // re-splits them, so a name with spaces/apostrophes (e.g. "xvan's MacBook Pro")
    // would break the `am` command and the portal service never starts. Single-quote
    // it for the remote shell so it arrives as one `--es` value.
    let pc_name = sh_quote(
        &cfg.pc_name
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "pcsuite".to_string()),
    );

    // require a device in the "device" state
    let devices = adb::run(&adb, &["devices"]).await?;
    let connected = devices
        .lines()
        .skip(1)
        .any(|l| l.trim_end().ends_with("\tdevice"));
    if !connected {
        bail!("no adb device in 'device' state — plug in USB + authorize debugging:\n{devices}");
    }
    // A long-running phone app can wedge and stop listening on 10380; force-stop
    // it so `am start` below relaunches a clean instance.
    adb::run_ok(&adb, &["shell", "am", "force-stop", "com.vivo.pcsuite"]).await;
    tracing::info!("adb device connected; forwarding 10380/10381");

    adb::run(&adb, &["forward", "tcp:10380", "tcp:10380"]).await?;
    adb::run(&adb, &["forward", "tcp:10381", "tcp:10381"]).await?;

    // wake, keep awake, dismiss (non-secure) keyguard
    adb::run_ok(&adb, &["shell", "input", "keyevent", "224"]).await;
    adb::run_ok(&adb, &["shell", "svc", "power", "stayon", "true"]).await;
    adb::run_ok(&adb, &["shell", "settings", "put", "system", "screen_off_timeout", "600000"]).await;
    adb::run_ok(&adb, &["shell", "wm", "dismiss-keyguard"]).await;

    // launch the phone app (foreground) then the portal service carrying our token
    adb::run_ok(
        &adb,
        &[
            "shell", "am", "start", "-a", "vivo.intent.action.PCSUITE_INTENT", "-f", "268435456",
            "--ei", "intent_from", "1104",
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    adb::run_ok(
        &adb,
        &[
            "shell", "am", "start-service", "-n", "com.vivo.pcsuite/.service.AdbPortalService",
            "--es", "from", "pc", "--ei", "foreground", "0", "--es", "pc_name", &pc_name,
            "--es", "token", &token, "--es", "user_name", &pc_name, "--es", "connectionId",
            &conn_id, "--ei", "isTransferConnect", "0",
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // /version readiness handshake (plain HTTP on the forwarded 10380)
    tracing::info!("waiting for /version 0000 (unlock + keep screen on if it stalls)");
    let mut ok = false;
    for _ in 0..25 {
        match version_handshake(&token, &conn_id).await {
            Ok(body) if body.contains("\"0000\"") => {
                ok = true;
                break;
            }
            Ok(body) => {
                let snippet: String = body.trim().chars().take(70).collect();
                tracing::info!(resp = %snippet, "/version");
            }
            Err(e) => tracing::info!(err = %e, "/version connect"),
        }
        adb::run_ok(&adb, &["shell", "input", "keyevent", "224"]).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    if !ok {
        bail!("/version never returned 0000 — unlock the phone, keep the screen on, and retry");
    }
    tracing::info!("/version 0000 — USB session ready");

    Ok(UsbSession { adb, token, conn_id })
}

/// Remove the adb port forwards.
pub async fn cleanup(adb: &str) {
    adb::run_ok(adb, &["forward", "--remove", "tcp:10380"]).await;
    adb::run_ok(adb, &["forward", "--remove", "tcp:10381"]).await;
}

/// One plain-HTTP `POST /version` to the forwarded 10380; returns the body.
async fn version_handshake(token: &str, conn_id: &str) -> Result<String> {
    let body = serde_json::to_vec(&serde_json::json!({
        "version": "6.0.1",
        "connBaseVersionCode": 3082,
        "pcSuiteVersionCode": 60011,
        "timestamp": now_ms(),
        "connectionId": conn_id,
        "pcDeviceId": "pcsuite01",
        "token": token,
        "isAutoConnect": false,
    }))?;
    let req = format!(
        "POST /version HTTP/1.1\r\nHost:127.0.0.1:10380\r\nX-ES-HTTP-VERSION:1\r\n\
         newToken:{token}\r\ntoken:{token}\r\ncontent-type:application/json\r\n\
         Connection:close\r\nContent-Length:{}\r\n\r\n",
        body.len()
    );
    let mut s = tokio::time::timeout(
        Duration::from_secs(6),
        TcpStream::connect(("127.0.0.1", 10380u16)),
    )
    .await
    .context("connect 10380 timed out")??;
    s.write_all(req.as_bytes()).await?;
    s.write_all(&body).await?;
    s.flush().await?;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf);
    Ok(text.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}
