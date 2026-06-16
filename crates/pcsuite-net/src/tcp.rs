//! Small TCP helpers.

use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Open a TCP connection with `TCP_NODELAY` set.
pub async fn connect(ip: &str, port: u16) -> std::io::Result<TcpStream> {
    let s = TcpStream::connect((ip, port)).await?;
    s.set_nodelay(true).ok();
    Ok(s)
}

/// Probe whether `ip:port` accepts a connection within `dur`.
pub async fn port_open(ip: &str, port: u16, dur: Duration) -> bool {
    matches!(timeout(dur, TcpStream::connect((ip, port))).await, Ok(Ok(_)))
}
