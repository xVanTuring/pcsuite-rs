//! Minimal RFC6455 WebSocket client over any async stream.
//!
//! The phone's control/mirror WS use custom upgrade headers (`newToken`/`token`/
//! `self_device`) and custom subprotocols, plus line-style text control messages
//! and `FRAME:`-prefixed binary frames — so we hand-roll the client rather than
//! fight a generic library over the non-standard handshake. Client frames are
//! masked per spec; server frames arrive unmasked.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A decoded WebSocket frame.
#[derive(Debug)]
pub enum WsFrame {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// A WebSocket client wrapping an async stream (typically a TLS stream).
pub struct WsClient<S> {
    stream: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsClient<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Perform the HTTP/1.1 upgrade with the phone's custom headers. Returns the
    /// HTTP status line (caller checks for "101"). Reads the response headers
    /// byte-by-byte so no frame bytes are accidentally consumed.
    pub async fn upgrade(
        &mut self,
        host: &str,
        path: &str,
        subprotocol: &str,
        token: &str,
    ) -> std::io::Result<String> {
        let key = STANDARD.encode(rand_bytes::<16>());
        let req = format!(
            "GET {path} HTTP/1.1\r\n\
             Sec-WebSocket-Protocol: {subprotocol}\r\n\
             newToken: {token}\r\n\
             token: {token}\r\n\
             self_device: false\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Host: {host}\r\n\r\n"
        );
        self.stream.write_all(req.as_bytes()).await?;
        self.stream.flush().await?;

        let mut buf: Vec<u8> = Vec::with_capacity(256);
        let mut one = [0u8; 1];
        loop {
            self.stream.read_exact(&mut one).await?;
            buf.push(one[0]);
            if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
                break;
            }
            if buf.len() > 8192 {
                break;
            }
        }
        let head = String::from_utf8_lossy(&buf);
        Ok(head.lines().next().unwrap_or("").to_string())
    }

    async fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
        let n = payload.len();
        let mut header = Vec::with_capacity(14);
        header.push(0x80 | opcode); // FIN + opcode
        if n < 126 {
            header.push(0x80 | n as u8);
        } else if n < 65536 {
            header.push(0x80 | 126);
            header.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            header.push(0x80 | 127);
            header.extend_from_slice(&(n as u64).to_be_bytes());
        }
        let mask = rand_bytes::<4>();
        header.extend_from_slice(&mask);
        let mut masked = Vec::with_capacity(n);
        for (i, b) in payload.iter().enumerate() {
            masked.push(b ^ mask[i & 3]);
        }
        self.stream.write_all(&header).await?;
        self.stream.write_all(&masked).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn send_text(&mut self, s: &str) -> std::io::Result<()> {
        self.send_frame(0x1, s.as_bytes()).await
    }

    pub async fn send_binary(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.send_frame(0x2, b).await
    }

    pub async fn send_pong(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.send_frame(0xA, b).await
    }

    pub async fn send_ping(&mut self) -> std::io::Result<()> {
        self.send_frame(0x9, &[]).await
    }

    /// Read one frame. Unfragmented frames only (the phone never fragments);
    /// a continuation opcode is surfaced as `Binary`.
    pub async fn recv(&mut self) -> std::io::Result<WsFrame> {
        let mut h = [0u8; 2];
        self.stream.read_exact(&mut h).await?;
        let opcode = h[0] & 0x0f;
        let masked = h[1] & 0x80 != 0;
        let mut len = (h[1] & 0x7f) as usize;
        if len == 126 {
            let mut e = [0u8; 2];
            self.stream.read_exact(&mut e).await?;
            len = u16::from_be_bytes(e) as usize;
        } else if len == 127 {
            let mut e = [0u8; 8];
            self.stream.read_exact(&mut e).await?;
            len = u64::from_be_bytes(e) as usize;
        }
        let mask = if masked {
            let mut m = [0u8; 4];
            self.stream.read_exact(&mut m).await?;
            Some(m)
        } else {
            None
        };
        let mut payload = vec![0u8; len];
        if len > 0 {
            self.stream.read_exact(&mut payload).await?;
        }
        if let Some(m) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= m[i & 3];
            }
        }
        Ok(match opcode {
            0x1 => WsFrame::Text(String::from_utf8_lossy(&payload).into_owned()),
            0x2 | 0x0 => WsFrame::Binary(payload),
            0x8 => WsFrame::Close,
            0x9 => WsFrame::Ping(payload),
            0xA => WsFrame::Pong(payload),
            _ => WsFrame::Binary(payload),
        })
    }
}
