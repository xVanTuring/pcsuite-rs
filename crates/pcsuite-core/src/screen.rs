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
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant, MissedTickBehavior};

use pcsuite_net::tcp;
use pcsuite_net::ws::{WsClient, WsFrame};
use pcsuite_proto::input::{self, KeyAction, MouseAction, MouseButton};
use pcsuite_proto::screen::{self, ScreenParams};

use crate::config;
use crate::wsconn::{open_ws, Tls};

/// A frame to write on the `/mirror/control` channel. The reader half asks the
/// writer half to emit `Pong`s; [`InputHandle`] sends `Text`.
pub(crate) enum WsCmd {
    Text(String),
    Pong(Vec<u8>),
}

/// A cloneable handle for injecting input over the `/mirror/control` channel.
/// Coordinates are relative to the reported `(w, h)` reference frame.
#[derive(Clone)]
pub struct InputHandle {
    tx: mpsc::Sender<WsCmd>,
}

impl InputHandle {
    /// Commit `text` into the phone's focused input field (IME `commitText`).
    /// Carries full Unicode — the right path for keyboard typing.
    pub async fn text(&self, text: &str) -> Result<()> {
        self.send(input::text_commit(text)).await
    }

    /// Delete `before` chars before and `after` chars after the cursor
    /// (IME `deleteSurroundingText`) — used for Backspace.
    pub async fn delete_surrounding(&self, before: i64, after: i64) -> Result<()> {
        self.send(input::text_delete_surrounding(before, after)).await
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

    /// Send a single key transition (down or up) for an Android `KEYCODE_*` value.
    pub async fn key_action(&self, action: KeyAction, keycode: i64) -> Result<()> {
        self.send(input::keycode_event(action, keycode, 0, 0)).await
    }

    /// A convenience key press: down then up for `keycode` (e.g. BACK=4, HOME=3,
    /// APP_SWITCH=187). Used to drive the Android navigation keys.
    pub async fn key(&self, keycode: i64) -> Result<()> {
        self.key_action(KeyAction::Down, keycode).await?;
        self.key_action(KeyAction::Up, keycode).await
    }

    /// Send a pre-built `/mirror/control` text message (escape hatch).
    pub async fn raw(&self, msg: String) -> Result<()> {
        self.send(msg).await
    }

    async fn send(&self, msg: String) -> Result<()> {
        self.tx
            .send(WsCmd::Text(msg))
            .await
            .map_err(|_| anyhow!("control-input channel closed"))
    }
}

/// Open the input/control half-duplex pair on an already-upgraded
/// `/mirror/control` WS: a reader task (parks on `recv`, forwards `NOTIFY_PASS`
/// privacy events, answers pings) and a writer task (injects input, 2s
/// keepalive ping). Splitting the socket keeps the non-cancellation-safe `recv`
/// off the same task that sends, so a frequent input send can never tear a
/// half-read frame.
pub(crate) struct InputChannels {
    pub handle: InputHandle,
    pub tasks: Vec<JoinHandle<()>>,
    /// Privacy/secure-screen state tokens (see [`screen::PrivacyState::token`]).
    pub events: mpsc::Receiver<String>,
    /// IME state: `"x,y"` (caret, phone pixel space), `"on"` (field focused), or
    /// `"off"` (focus lost).
    pub cursor: mpsc::Receiver<String>,
}

pub(crate) fn setup_input(ws: WsClient<Tls>) -> InputChannels {
    let (rd, wr) = ws.split();
    let (cmd_tx, cmd_rx) = mpsc::channel::<WsCmd>(64);
    let (evt_tx, evt_rx) = mpsc::channel::<String>(16);
    let (cur_tx, cur_rx) = mpsc::channel::<String>(32);
    let reader = tokio::spawn(input_read_loop(rd, evt_tx, cur_tx, cmd_tx.clone()));
    let writer = tokio::spawn(input_write_loop(wr, cmd_rx));
    InputChannels {
        handle: InputHandle { tx: cmd_tx },
        tasks: vec![reader, writer],
        events: evt_rx,
        cursor: cur_rx,
    }
}

/// An events receiver that is already closed — for the view-only case where the
/// `/mirror/control` channel could not be opened (no input, no privacy events).
pub(crate) fn closed_events() -> mpsc::Receiver<String> {
    let (_tx, rx) = mpsc::channel::<String>(1);
    rx
}

/// An open screen-mirror session. Frames arrive via [`Screen::next_frame`].
/// Dropping the `Screen` tears down all background tasks.
pub struct Screen {
    frames: mpsc::Receiver<Vec<u8>>,
    input: Option<InputHandle>,
    events: mpsc::Receiver<String>,
    cursor: mpsc::Receiver<String>,
    control: JoinHandle<()>,
    video: JoinHandle<()>,
    input_tasks: Vec<JoinHandle<()>>,
}

impl Drop for Screen {
    fn drop(&mut self) {
        self.control.abort();
        self.video.abort();
        for t in &self.input_tasks {
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
        let (input, events, cursor, input_tasks) =
            match open_ws(data_ip, 10381, "/mirror/control", config::SUBPROTOCOL_BASE, token, 3).await {
                Ok(ws) => {
                    tracing::info!("control-input WS 101 (/mirror/control)");
                    let ic = setup_input(ws);
                    (Some(ic.handle), ic.events, ic.cursor, ic.tasks)
                }
                Err(e) => {
                    tracing::warn!(err = %e, "control-input channel unavailable (view-only)");
                    (None, closed_events(), closed_events(), Vec::new())
                }
            };

        let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
        let control = tokio::spawn(control_loop(control));
        let video = tokio::spawn(video_loop(video, tx));

        Ok(Screen {
            frames: rx,
            input,
            events,
            cursor,
            control,
            video,
            input_tasks,
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

    /// Await the next privacy/secure-screen event token, or `None` once the
    /// control channel ends (see [`screen::PrivacyState::token`]).
    pub async fn next_event(&mut self) -> Option<String> {
        self.events.recv().await
    }

    /// Await the next IME caret report (`"x,y"` / `"off"`), or `None` at end.
    pub async fn next_input_cursor(&mut self) -> Option<String> {
        self.cursor.recv().await
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

/// Read the `/mirror/control` channel: forward parsed `NOTIFY_PASS` privacy
/// events to `evt_tx`, and relay incoming pings to the writer half as pongs.
/// `recv` is never cancelled here, so a half-read frame can't be lost.
async fn input_read_loop(
    mut rd: WsClient<ReadHalf<Tls>>,
    evt_tx: mpsc::Sender<String>,
    cur_tx: mpsc::Sender<String>,
    cmd_tx: mpsc::Sender<WsCmd>,
) {
    loop {
        match rd.recv().await {
            Ok(WsFrame::Text(t)) => {
                if let Some(state) = screen::parse_notify_pass(&t) {
                    // Privacy events are rare; drop rather than block if unread.
                    let _ = evt_tx.try_send(state.token().to_string());
                } else if let Some(ev) = input::parse_input_event(&t) {
                    let s = match ev {
                        input::InputEvent::Cursor { x, y } => format!("{x},{y}"),
                        input::InputEvent::Focus(true) => "on".to_string(),
                        input::InputEvent::Focus(false) => "off".to_string(),
                    };
                    let _ = cur_tx.try_send(s);
                }
            }
            Ok(WsFrame::Ping(p)) => {
                if cmd_tx.send(WsCmd::Pong(p)).await.is_err() {
                    break;
                }
            }
            Ok(WsFrame::Close) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// Write the `/mirror/control` channel: drain queued input/pong frames and ping
/// every 2s so the phone's idle handler doesn't drop the channel.
async fn input_write_loop(mut wr: WsClient<WriteHalf<Tls>>, mut cmd_rx: mpsc::Receiver<WsCmd>) {
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                Some(WsCmd::Text(m)) => {
                    if wr.send_text(&m).await.is_err() {
                        break;
                    }
                }
                Some(WsCmd::Pong(p)) => {
                    if wr.send_pong(&p).await.is_err() {
                        break;
                    }
                }
                None => break, // all senders (handle + reader) dropped
            },
            _ = interval.tick() => {
                if wr.send_ping().await.is_err() {
                    break;
                }
            }
        }
    }
}
