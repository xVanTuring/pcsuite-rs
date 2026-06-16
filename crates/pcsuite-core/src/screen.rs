//! Screen-mirror data plane + control input.
//!
//! Opens three WebSockets on the phone:
//! - 10380 `/ws/heart-beat` — control (keepalive + `req_authrity` trigger),
//! - 10381 `/mirror/screen`  — raw HEVC frames (delivered verbatim; no decode),
//! - 10381 `/mirror/control` — mouse/scroll injection (best-effort; view-only if
//!   it fails to open).
//!
//! Frames arrive via [`Screen::next_frame`]; input is driven via the cloneable
//! [`InputHandle`] from [`Screen::input`].

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};

use pcsuite_net::tcp;
use pcsuite_net::ws::{WsClient, WsFrame};
use pcsuite_proto::input::{self, MouseAction, MouseButton};
use pcsuite_proto::screen::{self, ScreenParams};

use crate::config;
use crate::wsconn::{open_ws, Tls};

/// A cloneable handle for injecting input over the `/mirror/control` channel.
/// Coordinates are relative to the reported `(w, h)` reference frame.
#[derive(Clone)]
pub struct InputHandle {
    tx: mpsc::Sender<String>,
}

impl InputHandle {
    /// Wrap a raw sender (used by the unified session).
    pub(crate) fn from_sender(tx: mpsc::Sender<String>) -> Self {
        Self { tx }
    }

    /// Send a mouse event (down/up/move, left/right).
    pub async fn mouse(
        &self,
        action: MouseAction,
        button: MouseButton,
        x: i64,
        y: i64,
        w: i64,
        h: i64,
    ) -> Result<()> {
        self.send(input::mouse_event(action, button, x, y, w, h)).await
    }

    /// Send a scroll event (`vscroll > 0` scrolls up).
    pub async fn scroll(&self, vscroll: i64, x: i64, y: i64, w: i64, h: i64) -> Result<()> {
        self.send(input::scroll_event(vscroll, x, y, w, h)).await
    }

    /// A convenience tap: down then up at the same point.
    pub async fn tap(&self, x: i64, y: i64, w: i64, h: i64) -> Result<()> {
        self.mouse(MouseAction::Down, MouseButton::Left, x, y, w, h).await?;
        self.mouse(MouseAction::Up, MouseButton::Left, x, y, w, h).await
    }

    /// Send a pre-built `/mirror/control` text message (escape hatch).
    pub async fn raw(&self, msg: String) -> Result<()> {
        self.send(msg).await
    }

    async fn send(&self, msg: String) -> Result<()> {
        self.tx
            .send(msg)
            .await
            .map_err(|_| anyhow!("control-input channel closed"))
    }
}

/// An open screen-mirror session. Frames arrive via [`Screen::next_frame`].
/// Dropping the `Screen` tears down all background tasks.
pub struct Screen {
    frames: mpsc::Receiver<Vec<u8>>,
    input: Option<InputHandle>,
    control: JoinHandle<()>,
    video: JoinHandle<()>,
    input_task: Option<JoinHandle<()>>,
}

impl Drop for Screen {
    fn drop(&mut self) {
        self.control.abort();
        self.video.abort();
        if let Some(t) = &self.input_task {
            t.abort();
        }
    }
}

impl Screen {
    /// Open the control + mirror + input channels on `data_ip` using `token`.
    pub async fn open(data_ip: &str, token: &str, params: ScreenParams) -> Result<Screen> {
        // ── control WS (10380) ──
        let subproto = format!("{},{}", config::SUBPROTOCOL_BASE, token);
        let mut control = open_ws(data_ip, 10380, "/ws/heart-beat", &subproto, token, 6)
            .await
            .context("control WS (token auth)")?;
        tracing::info!("control WS 101 (token accepted)");

        // trigger the phone to open the mirror service
        control.send_text(&screen::req_authrity(1)).await?;

        let mut opened = false;
        for _ in 0..25 {
            if tcp::port_open(data_ip, 10381, Duration::from_secs(1)).await {
                opened = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(600)).await;
        }
        if !opened {
            bail!("10381 did not open (phone may be prompting for screen-record permission)");
        }

        // ── mirror WS (10381 /mirror/screen) ──
        let mut video = open_ws(data_ip, 10381, "/mirror/screen", config::SUBPROTOCOL_BASE, token, 6)
            .await
            .context("mirror WS")?;
        video.send_text(&screen::screen_start(&params)).await?;
        tracing::info!("mirror WS 101; SCREEN_START sent");

        // ── control-input WS (10381 /mirror/control), best-effort ──
        let (input, input_task) =
            match open_ws(data_ip, 10381, "/mirror/control", config::SUBPROTOCOL_BASE, token, 3).await {
                Ok(ws) => {
                    tracing::info!("control-input WS 101 (/mirror/control)");
                    let (itx, irx) = mpsc::channel::<String>(64);
                    let task = tokio::spawn(input_loop(ws, irx));
                    (Some(InputHandle { tx: itx }), Some(task))
                }
                Err(e) => {
                    tracing::warn!(err = %e, "control-input channel unavailable (view-only)");
                    (None, None)
                }
            };

        let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
        let control = tokio::spawn(control_loop(control));
        let video = tokio::spawn(video_loop(video, tx));

        Ok(Screen {
            frames: rx,
            input,
            control,
            video,
            input_task,
        })
    }

    /// Await the next raw HEVC frame, or `None` once the stream ends.
    pub async fn next_frame(&mut self) -> Option<Vec<u8>> {
        self.frames.recv().await
    }

    /// A cloneable input handle, if the control-input channel opened.
    pub fn input(&self) -> Option<InputHandle> {
        self.input.clone()
    }
}

/// Keepalive: send "normal" every ~3s and answer pings; exit on close/error.
async fn control_loop(mut ws: WsClient<Tls>) {
    let mut last = Instant::now();
    loop {
        match timeout(Duration::from_secs(1), ws.recv()).await {
            Ok(Ok(WsFrame::Ping(p))) => {
                if ws.send_pong(&p).await.is_err() {
                    break;
                }
            }
            Ok(Ok(WsFrame::Close)) => break,
            Ok(Ok(_)) => {}
            Ok(Err(_)) => break,
            Err(_) => {} // recv timed out -> fall through to keepalive
        }
        if last.elapsed() >= Duration::from_secs(3) {
            if ws.send_text(screen::KEEPALIVE).await.is_err() {
                break;
            }
            last = Instant::now();
        }
    }
}

/// Read mirror frames, strip the optional `FRAME:` prefix, push to the channel.
pub(crate) async fn video_loop(mut ws: WsClient<Tls>, tx: mpsc::Sender<Vec<u8>>) {
    loop {
        match ws.recv().await {
            Ok(WsFrame::Binary(b)) => {
                let frame = screen::strip_frame_prefix(&b).to_vec();
                if tx.send(frame).await.is_err() {
                    break; // receiver dropped
                }
            }
            Ok(WsFrame::Ping(p)) => {
                if ws.send_pong(&p).await.is_err() {
                    break;
                }
            }
            Ok(WsFrame::Close) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// Forward queued input messages and ping every 2s so the idle handler doesn't
/// drop the channel. Never reads incoming (we only need to send here).
pub(crate) async fn input_loop(mut ws: WsClient<Tls>, mut rx: mpsc::Receiver<String>) {
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Some(m) => {
                    if ws.send_text(&m).await.is_err() {
                        break;
                    }
                }
                None => break, // all senders dropped
            },
            _ = interval.tick() => {
                if ws.send_ping().await.is_err() {
                    break;
                }
            }
        }
    }
}
