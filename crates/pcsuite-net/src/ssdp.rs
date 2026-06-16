//! SSDP-style presence/discovery on UDP 2200.
//!
//! Announcements are HTTP-ish datagrams carrying a base64 `compatGsonStr` JSON
//! blob describing the peer. We send our presence (multicast for discovery, or
//! unicast to a known phone for the direct/Tailscale path) and read the phone's
//! announcements back.

use std::net::SocketAddr;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::time::timeout;

pub const SSDP_PORT: u16 = 2200;
pub const MCAST_ADDR: &str = "239.255.255.250";

/// A static HTTP date; the phone ignores this header, so the exact value is
/// irrelevant (and avoids pulling a date-formatting dependency).
pub const STATIC_DATE: &str = "Mon, 16 Jun 2025 00:00:00 GMT";

/// Build a presence announcement datagram from a base64 `compatGsonStr`.
pub fn build_announce(compat_gson_b64: &str) -> Vec<u8> {
    format!(
        "RESPONSE * HTTP/1.1\r\nDATE:{STATIC_DATE}\r\ncompatGsonStr:{compat_gson_b64}\r\n\r\n"
    )
    .into_bytes()
}

/// Extract and base64-decode the `compatGsonStr` line into a JSON value.
fn parse_compat_gson(datagram: &[u8]) -> Option<serde_json::Value> {
    let text = std::str::from_utf8(datagram).ok()?;
    for line in text.lines() {
        if let Some(b64) = line.strip_prefix("compatGsonStr:") {
            let raw = STANDARD.decode(b64.trim()).ok()?;
            return serde_json::from_slice(&raw).ok();
        }
    }
    None
}

/// Continuously unicast `announce` to `phone_ip:2200` every `interval`.
///
/// Runs forever; spawn it with `tokio::spawn` and abort the handle when done.
/// This is the direct/Tailscale presence path (no multicast).
pub async fn presence_loop(
    phone_ip: String,
    announce: Vec<u8>,
    interval: Duration,
) -> std::io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let target = format!("{phone_ip}:{SSDP_PORT}");
    loop {
        let _ = sock.send_to(&announce, &target).await;
        tokio::time::sleep(interval).await;
    }
}

/// Multicast discovery: announce ourselves and wait for a phone (`deviceType ==
/// "mobile"`) to reply. Returns `(phone_ip, its compatGson JSON)`.
pub async fn discover(announce: Vec<u8>, overall_timeout: Duration) -> std::io::Result<Option<(String, serde_json::Value)>> {
    // Bind 0.0.0.0:2200 with SO_REUSEADDR so we coexist with anything else on the port.
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    let bind: SocketAddr = "0.0.0.0:2200".parse().unwrap();
    socket.bind(&bind.into())?;
    let udp = UdpSocket::from_std(socket.into())?;
    udp.set_multicast_ttl_v4(2).ok();

    let mcast: SocketAddr = format!("{MCAST_ADDR}:{SSDP_PORT}").parse().unwrap();

    let deadline = tokio::time::Instant::now() + overall_timeout;
    let mut buf = vec![0u8; 65535];
    while tokio::time::Instant::now() < deadline {
        let _ = udp.send_to(&announce, mcast).await;
        // listen for ~1.4s between re-announcements
        let listen_until = tokio::time::Instant::now() + Duration::from_millis(1400);
        while tokio::time::Instant::now() < listen_until {
            let remaining = listen_until - tokio::time::Instant::now();
            match timeout(remaining, udp.recv_from(&mut buf)).await {
                Ok(Ok((n, addr))) => {
                    if let Some(json) = parse_compat_gson(&buf[..n]) {
                        if json.get("deviceType").and_then(|v| v.as_str()) == Some("mobile") {
                            return Ok(Some((addr.ip().to_string(), json)));
                        }
                    }
                }
                _ => break,
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announce_contains_compat_gson() {
        let a = build_announce("BASE64HERE");
        let s = String::from_utf8(a).unwrap();
        assert!(s.starts_with("RESPONSE * HTTP/1.1\r\n"));
        assert!(s.contains("compatGsonStr:BASE64HERE\r\n"));
    }

    #[test]
    fn parse_roundtrip() {
        let json = serde_json::json!({"deviceType":"mobile","deviceName":"iqoo"});
        let b64 = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&json).unwrap());
        let datagram = build_announce(&b64);
        let parsed = parse_compat_gson(&datagram).unwrap();
        assert_eq!(parsed["deviceType"], "mobile");
        assert_eq!(parsed["deviceName"], "iqoo");
    }
}
