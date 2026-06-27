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
        let video = tokio::spawn(video_loop(video, tx, data_ip.to_string()));

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

/// Per-second wire-level mirror diagnostics, measured at the WS read — *before* the
/// channel, FFI, and decode — so the numbers reflect the **transport** (the USB vs
/// LAN comparison) rather than PC-side decode cost. Emits one line per second at
/// `target: "mirror_stats"`, plus a cumulative `kind=summary` line when the stream
/// ends.
///
/// - `gap` — inter-arrival time between consecutive frames (the felt smoothness; a
///   high p95/max means stalls, high `jitter` means uneven delivery).
/// - `backlog` — frames still unread in the channel right after a send. A direct
///   buffering-latency proxy: a persistently non-zero backlog means frames arrive
///   faster than they drain, i.e. lag that grows over time (classic on a saturated
///   LAN link; ~always 0 on USB).
struct MirrorStats {
    tag: String,
    started: Instant,
    window_start: Instant,
    last_frame: Option<Instant>,
    // current 1s window
    gaps: Vec<f64>,
    bytes: u64,
    frames: u64,
    backlog_max: usize,
    // cumulative (whole stream)
    all_gaps: Vec<f64>,
    total_bytes: u64,
    total_frames: u64,
    backlog_peak: usize,
}

impl MirrorStats {
    fn new(tag: String) -> Self {
        let now = Instant::now();
        Self {
            tag,
            started: now,
            window_start: now,
            last_frame: None,
            gaps: Vec::new(),
            bytes: 0,
            frames: 0,
            backlog_max: 0,
            all_gaps: Vec::new(),
            total_bytes: 0,
            total_frames: 0,
            backlog_peak: 0,
        }
    }

    /// Record one arrived frame: its inter-arrival gap and payload size.
    fn record_frame(&mut self, len: usize) {
        let now = Instant::now();
        if let Some(prev) = self.last_frame {
            let gap = now.duration_since(prev).as_secs_f64() * 1000.0;
            self.gaps.push(gap);
            // Bounded so an hours-long session can't grow without limit: past the cap
            // we keep counting frames/bytes but freeze the percentile sample.
            if self.all_gaps.len() < 300_000 {
                self.all_gaps.push(gap);
            }
        }
        self.last_frame = Some(now);
        self.frames += 1;
        self.total_frames += 1;
        self.bytes += len as u64;
        self.total_bytes += len as u64;
    }

    /// Fold in the post-send backlog and flush a 1s line once the window elapses.
    fn tick(&mut self, backlog: usize) {
        self.backlog_max = self.backlog_max.max(backlog);
        self.backlog_peak = self.backlog_peak.max(backlog);
        let elapsed = self.window_start.elapsed().as_secs_f64();
        if elapsed < 1.0 {
            return;
        }
        let mut gaps = std::mem::take(&mut self.gaps);
        gaps.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let avg = mean(&gaps);
        tracing::info!(
            target: "mirror_stats",
            tag = %self.tag,
            fps = r1(self.frames as f64 / elapsed),
            gap_mean_ms = r1(avg),
            gap_p95_ms = r1(percentile(&gaps, 95.0)),
            gap_max_ms = r1(gaps.last().copied().unwrap_or(0.0)),
            jitter_ms = r1(stddev(&gaps, avg)),
            kbit_frame = r1(avg_frame_kbit(self.bytes, self.frames)),
            mbps = r2(self.bytes as f64 * 8.0 / elapsed / 1.0e6),
            backlog_max = self.backlog_max,
            "mirror wire (1s)"
        );
        self.window_start = Instant::now();
        self.frames = 0;
        self.bytes = 0;
        self.backlog_max = 0;
    }

    /// Emit a cumulative summary for the whole stream (run once, on end).
    fn summary(&self) {
        if self.total_frames == 0 {
            return;
        }
        let secs = self.started.elapsed().as_secs_f64().max(0.001);
        let mut gaps = self.all_gaps.clone();
        gaps.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        tracing::info!(
            target: "mirror_stats",
            tag = %self.tag,
            kind = "summary",
            secs = r1(secs),
            frames = self.total_frames,
            fps_avg = r1(self.total_frames as f64 / secs),
            mbps_avg = r2(self.total_bytes as f64 * 8.0 / secs / 1.0e6),
            gap_p50_ms = r1(percentile(&gaps, 50.0)),
            gap_p95_ms = r1(percentile(&gaps, 95.0)),
            gap_p99_ms = r1(percentile(&gaps, 99.0)),
            gap_max_ms = r1(gaps.last().copied().unwrap_or(0.0)),
            backlog_peak = self.backlog_peak,
            "mirror wire summary"
        );
    }
}

fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        0.0
    } else {
        xs.iter().sum::<f64>() / xs.len() as f64
    }
}

fn stddev(xs: &[f64], mean: f64) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / xs.len() as f64;
    var.sqrt()
}

/// Nearest-rank percentile; `sorted` must be ascending.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn avg_frame_kbit(bytes: u64, frames: u64) -> f64 {
    if frames == 0 {
        0.0
    } else {
        bytes as f64 * 8.0 / frames as f64 / 1000.0
    }
}

fn r1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}
fn r2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

/// Inspects non-video binaries on the mirror WS (the audio packets the phone
/// interleaves when `no_audio:false`). Audio isn't decoded yet — this logs the wire
/// shape (size + a head sample) so the codec/framing can be reverse-engineered,
/// while [`video_loop`] keeps these bytes out of the HEVC decoder.
#[derive(Default)]
struct AudioProbe {
    packets: u64,
}

impl AudioProbe {
    fn observe(&mut self, b: &[u8]) {
        self.packets += 1;
        // First packet (identify codec/framing) then a light heartbeat — don't spam.
        if self.packets == 1 || self.packets % 200 == 0 {
            let head = b
                .iter()
                .take(16)
                .map(|x| format!("{x:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            tracing::info!(
                target: "mirror_stats",
                kind = "audio_probe",
                packets = self.packets,
                len = b.len(),
                head = %head,
                "non-video binary on mirror WS (audio? — not decoded)"
            );
        }
    }
}

/// Read mirror frames, strip the optional `FRAME:` prefix, push to the channel.
///
/// `tag` labels the [`MirrorStats`] lines: we pass the data IP, which distinguishes
/// a USB adb-forward loopback from a LAN phone IP in a combined capture.
pub(crate) async fn video_loop(mut ws: WsClient<Tls>, tx: mpsc::Sender<Vec<u8>>, tag: String) {
    let mut stats = MirrorStats::new(tag);
    let mut audio = AudioProbe::default();
    loop {
        match ws.recv().await {
            Ok(WsFrame::Binary(b)) => {
                if !screen::is_video_frame(&b) {
                    // Non-video binary — audio packets arrive here when no_audio=false.
                    // We don't decode audio yet; record the shape for RE and, crucially,
                    // keep it out of the HEVC decoder (feeding it would corrupt video).
                    audio.observe(&b);
                    continue;
                }
                let frame = screen::strip_frame_prefix(&b).to_vec();
                stats.record_frame(frame.len());
                if tx.send(frame).await.is_err() {
                    break; // receiver dropped
                }
                // Frames still queued, unread by the consumer — buffering latency.
                let backlog = tx.max_capacity().saturating_sub(tx.capacity());
                stats.tick(backlog);
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
    stats.summary();
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
