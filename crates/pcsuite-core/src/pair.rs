//! Headless QR pairing — local `ls=true` variant (pure LAN, no cloud).
//!
//! The PC shows a QR carrying a self-made `token`; the phone, after scanning via
//! vivo PCSuite, stores it (`GlobalSettings.setRemoteToken`) and — because the QR
//! says `ls=true` with our LAN IP in `lip` — POSTs its own IP straight back to
//! `PC:9199/notifyConnection` over the LAN (no cloud rendezvous). The phone then
//! authorizes our 10380 control WS by **string-equality** on that token (phone-side
//! `ControlVersionController`/`TokenCheckController`), so there is no 10191 sign and
//! no per-IP seed. The official desktop app hard-codes `ls=false` (always cloud);
//! `ls=true`+`lip` is a phone-supported path it never emits.
//!
//! This module is protocol-only: it builds the QR payload and runs the 9199
//! listener, returning the phone's IP + token for the normal data plane
//! ([`crate::session::Session::connect`]). Rendering the QR is the frontend's job.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

use pcsuite_proto::PcIdentity;

/// Cloud gateway base the official QR uses. The phone does not validate the host
/// for the local path (it only reads `t`/`ls`/`lip`/wifi fields), but we keep the
/// real value so a scanner that pre-validates the URL shape is happy.
pub const GATEWAY: &str = "https://psuite.vivo.com.cn/vbusiness";
/// Port the phone POSTs `notifyConnection` to (hard-wired phone-side).
pub const NOTIFY_PORT: u16 = 9199;

/// A fresh 64-hex token to register via the QR.
pub fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// Build the pairing QR payload (local `ls=true` variant). `lip` is this machine's
/// LAN IP — where the phone will POST `notifyConnection` after scanning. `token` is
/// the credential the phone stores and we present on the 10380 control WS.
///
/// The phone's local path only consumes `t/ls/lip`; `u/d/mac/id` are informational
/// (display / cloud) and are URL-encoded so a stray space/apostrophe in the device
/// name can't break `Uri.parse` on the phone.
pub fn qr_url(token: &str, lip: &str, identity: &PcIdentity) -> String {
    format!(
        "{GATEWAY}?s=&f=pc&t={t}&u={u}&d={d}&mac={mac}&id={id}&ls=true&lip={lip}&pb=0",
        t = token,
        u = pct(&identity.account),
        d = pct(&identity.device_name),
        mac = pct(&identity.pc_mac),
        id = pct(&identity.pc_mac),
        lip = lip,
    )
}

/// What the phone reports when it scans (local `ls=true` → `GET /notifyConnection`).
#[derive(Debug, Clone)]
pub struct PhoneNotify {
    /// The phone's LAN IP (data-plane host). Falls back to the TCP peer IP if the
    /// `phoneIp` query field is absent.
    pub phone_ip: String,
    /// The phone's device id (`bleId`, e.g. `52467a`) — the clipboard routing id.
    pub ble_id: String,
    pub device_name: String,
    pub vivo_account: String,
    /// `"phone"` or `"pad"`.
    pub device_type: String,
}

/// Bind `0.0.0.0:port` and wait (up to `dur`) for the phone's
/// `GET /notifyConnection?phoneIp=…&bleId=…` after it scans the QR. Replies `200`
/// and returns the parsed report. Non-matching requests are answered `404` and the
/// listener keeps waiting.
pub async fn wait_for_phone(port: u16, dur: Duration) -> Result<PhoneNotify> {
    let never = std::sync::atomic::AtomicBool::new(false);
    wait_for_phone_until(port, dur, &never).await
}

/// Like [`wait_for_phone`], but abortable: set `stop` to make it return an error
/// within ~300ms and release the `:port` listener — so a cancelled pairing doesn't
/// leave the port bound and block a re-pair.
pub async fn wait_for_phone_until(
    port: u16,
    dur: Duration,
    stop: &std::sync::atomic::AtomicBool,
) -> Result<PhoneNotify> {
    use std::sync::atomic::Ordering;
    let listener = TcpListener::bind(("0.0.0.0", port))
        .await
        .with_context(|| format!("bind 0.0.0.0:{port} (port busy — official app / cowork running?)"))?;
    tracing::info!(port, "notifyConnection listener up; waiting for phone to scan");

    let deadline = tokio::time::Instant::now() + dur;
    loop {
        if stop.load(Ordering::Relaxed) {
            anyhow::bail!("pairing cancelled");
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!(
                "no phone within {dur:?} — same LAN? scanned via PCSuite 扫码连接? lip correct? firewall blocking {port}?"
            );
        }
        // Wake at least every 300ms to re-check `stop` and the overall deadline.
        let slice = remaining.min(Duration::from_millis(300));
        let (mut sock, peer) = match timeout(slice, listener.accept()).await {
            Err(_) => continue, // tick
            Ok(Ok(conn)) => conn,
            Ok(Err(_)) => continue,
        };

        // Read the request (small GET). Bound the per-connection read so a silent
        // stray connection can't stall pairing.
        let mut buf = Vec::with_capacity(2048);
        let mut tmp = [0u8; 2048];
        let read_ok = timeout(Duration::from_secs(5), async {
            loop {
                match sock.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16384 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        })
        .await
        .is_ok();

        let req = String::from_utf8_lossy(&buf);
        let target = req
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("");

        let (path, q) = target.split_once('?').unwrap_or((target, ""));
        if read_ok && path == "/notifyConnection" {
            let params = parse_query(q);
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
            let _ = sock.flush().await;
            let phone_ip = params
                .get("phoneIp")
                .filter(|s| !s.is_empty())
                .cloned()
                .unwrap_or_else(|| peer.ip().to_string());
            return Ok(PhoneNotify {
                phone_ip,
                ble_id: params.get("bleId").cloned().unwrap_or_default(),
                device_name: params.get("deviceName").cloned().unwrap_or_default(),
                vivo_account: params.get("vivoAccount").cloned().unwrap_or_default(),
                device_type: params.get("deviceType").cloned().unwrap_or_default(),
            });
        }
        let _ = sock
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    }
}

/// Parse a `k=v&k=v` query string into a map (percent-decoding values).
fn parse_query(q: &str) -> HashMap<String, String> {
    q.split('&')
        .filter(|kv| !kv.is_empty())
        .filter_map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next()?;
            let v = it.next().unwrap_or("");
            Some((k.to_string(), pct_decode(v)))
        })
        .collect()
}

/// Percent-decode (`%XX` and `+` → space). Leaves malformed escapes as-is.
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                let h = (hex_val(b[i + 1]), hex_val(b[i + 2]));
                if let (Some(hi), Some(lo)) = h {
                    out.push(hi << 4 | lo);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encode everything outside the URL unreserved set (`A-Z a-z 0-9 - _ . ~`).
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~') {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident() -> PcIdentity {
        PcIdentity {
            open_id: "openid".into(),
            pc_mac: "d11410aabbcc".into(),
            account: "173****991".into(),
            device_name: "xvan's MacBook Pro".into(),
            service_id: "com.vivo.pcsuite.SERVICE".into(),
            frame_id: 87654321,
        }
    }

    #[test]
    fn qr_url_has_local_fields_and_is_url_safe() {
        let url = qr_url("deadbeef", "192.168.31.43", &ident());
        assert!(url.contains("f=pc"));
        assert!(url.contains("t=deadbeef"));
        assert!(url.contains("ls=true"));
        assert!(url.contains("lip=192.168.31.43"));
        // device name spaces/apostrophe must be encoded, not raw.
        assert!(!url.contains(' '));
        assert!(url.contains("d=xvan%27s%20MacBook%20Pro"));
    }

    #[test]
    fn token_is_64_hex() {
        let t = random_token();
        assert_eq!(t.len(), 64);
        assert!(t.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn query_parse_decodes_values() {
        let m = parse_query("phoneIp=192.168.31.252&bleId=52467a&deviceName=iQOO%2015&deviceType=phone");
        assert_eq!(m.get("phoneIp").unwrap(), "192.168.31.252");
        assert_eq!(m.get("bleId").unwrap(), "52467a");
        assert_eq!(m.get("deviceName").unwrap(), "iQOO 15");
        assert_eq!(m.get("deviceType").unwrap(), "phone");
    }
}
