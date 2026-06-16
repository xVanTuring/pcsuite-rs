//! Shared helper for opening a TLS WebSocket with the phone's custom upgrade,
//! used by both the screen and clipboard sessions.

use std::time::Duration;

use anyhow::{bail, Result};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use pcsuite_net::tls;
use pcsuite_net::ws::WsClient;

/// The concrete stream type the WS client wraps.
pub type Tls = TlsStream<TcpStream>;

/// Open a TLS WebSocket and perform the upgrade, retrying a few times (the
/// phone's TLS occasionally EOFs mid-handshake, especially over adb-forwarded
/// USB ports). Returns the upgraded client on a `101`.
pub async fn open_ws(
    data_ip: &str,
    port: u16,
    path: &str,
    subprotocol: &str,
    token: &str,
    attempts: usize,
) -> Result<WsClient<Tls>> {
    let mut last = String::from("(no attempt)");
    for _ in 0..attempts {
        match tls::connect_tls(data_ip, port).await {
            Ok(stream) => {
                let mut ws = WsClient::new(stream);
                let host = format!("{data_ip}:{port}");
                match ws.upgrade(&host, path, subprotocol, token).await {
                    Ok(line) if line.contains("101") => return Ok(ws),
                    Ok(line) => last = line,
                    Err(e) => last = e.to_string(),
                }
            }
            Err(e) => last = format!("tls: {e:#}"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("WS {path} on {port} failed after {attempts} attempts: {last}");
}
