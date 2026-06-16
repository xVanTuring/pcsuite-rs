//! Unified session: one control WS (10380) shared by screen, clipboard, and
//! verify-code. The phone allows only one control connection, so all features
//! multiplex over a single [`ControlHandle`]: a background task owns the WS,
//! drains an outgoing text queue, answers pings/keepalive, and broadcasts every
//! incoming text message to subscribed features.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use pcsuite_net::tcp;
use pcsuite_net::ws::{WsClient, WsFrame};
use pcsuite_proto::clip::{self, PcInfo};
use pcsuite_proto::screen as screenmsg;
use pcsuite_proto::screen::ScreenParams;

use crate::clipboard::{self, ClipboardBackend, ClipboardConfig};
use crate::config;
use crate::screen::InputHandle;
use crate::wsconn::{open_ws, Tls};

/// Handle to the shared control channel.
#[derive(Clone)]
pub struct ControlHandle {
    out_tx: mpsc::Sender<String>,
    in_tx: broadcast::Sender<String>,
    /// Most recent `SHADOW_LIKE:` message, retained so a feature that subscribes
    /// slightly late (the phone announces its key very fast) doesn't miss it.
    last_shadow: Arc<Mutex<Option<String>>>,
}

impl ControlHandle {
    /// Queue a text message to send on the control WS.
    pub async fn send(&self, msg: impl Into<String>) -> Result<()> {
        self.out_tx
            .send(msg.into())
            .await
            .map_err(|_| anyhow::anyhow!("control channel closed"))
    }
    /// Subscribe to incoming control-WS text messages.
    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.in_tx.subscribe()
    }
    /// The most recent retained `SHADOW_LIKE:` message, if any.
    pub fn last_shadow(&self) -> Option<String> {
        self.last_shadow.lock().ok().and_then(|g| g.clone())
    }
}

/// A connected control session. Enable features; they share the one control WS.
pub struct Session {
    control: ControlHandle,
    data_ip: String,
    token: String,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Session {
    /// Open the shared control WS on `data_ip` with `token`.
    pub async fn connect(data_ip: &str, token: &str) -> Result<Session> {
        let subproto = format!("{},{}", config::SUBPROTOCOL_BASE, token);
        let ws = open_ws(data_ip, 10380, "/ws/heart-beat", &subproto, token, 6)
            .await
            .context("control WS")?;
        tracing::info!("control WS 101 (shared session)");
        let (out_tx, out_rx) = mpsc::channel::<String>(64);
        let (in_tx, _) = broadcast::channel::<String>(128);
        let last_shadow = Arc::new(Mutex::new(None));
        let control = ControlHandle {
            out_tx,
            in_tx: in_tx.clone(),
            last_shadow: last_shadow.clone(),
        };
        let task = tokio::spawn(control_task(ws, out_rx, in_tx, last_shadow));
        Ok(Session {
            control,
            data_ip: data_ip.to_string(),
            token: token.to_string(),
            tasks: vec![task],
        })
    }

    /// A clone of the control handle.
    pub fn control(&self) -> ControlHandle {
        self.control.clone()
    }

    /// Enable SMS verify-code relay.
    pub fn enable_verify<F>(&mut self, on_code: F)
    where
        F: Fn(&str, &str) + Send + 'static,
    {
        let control = self.control.clone();
        self.tasks
            .push(tokio::spawn(crate::verify::verify_feature(control, on_code)));
    }

    /// Enable text clipboard sync (8904 relay + SHADOW_LIKE over the shared WS).
    pub async fn enable_clipboard(
        &mut self,
        cfg: ClipboardConfig,
        backend: Arc<dyn ClipboardBackend>,
    ) -> Result<()> {
        let (pc_key, pc_iv) = clipboard::rand_clip_keys();
        let shared = clipboard::new_shared(
            pc_key.clone(),
            pc_iv.clone(),
            cfg.vdfs_fetch_host.clone(),
            cfg.vdfs_fetch_port,
        );
        let listener = TcpListener::bind(format!("{}:8904", cfg.bind_addr))
            .await
            .with_context(|| format!("bind {}:8904", cfg.bind_addr))?;
        tracing::info!(bind = %cfg.bind_addr, "8904 relay listening");
        self.tasks
            .push(clipboard::spawn_8904_server(listener, shared.clone(), backend.clone()));

        // 5679 vdfs server (phone fetches PC images here; PC→phone paste)
        match clipboard::start_vdfs_server(&cfg.bind_addr, &pc_key, &pc_iv).await {
            Ok(task) => self.tasks.push(task),
            Err(e) => tracing::warn!(err = %e, "vdfs 5679 server unavailable (PC→phone images off)"),
        }
        self.tasks
            .push(clipboard::spawn_watcher(shared.clone(), backend, cfg.device_name.clone()));

        let pcinfo = PcInfo {
            ip: &cfg.pc_ip,
            pc_device_id: config::CLIP_PC_ID,
            pc_device_name: &cfg.device_name,
            key: &pc_key,
            iv: &pc_iv,
            account_open_id: &cfg.open_id,
            account_name: config::CLIP_NICK,
            connect_type: &cfg.connect_type,
        };
        let startup = clip::shadow_startup(&pcinfo, 8904, 5679);
        let control = self.control.clone();
        self.tasks
            .push(tokio::spawn(clipboard::clip_handshake(control, shared, startup)));
        Ok(())
    }

    /// Enable screen mirroring; returns a [`ScreenStream`] of raw HEVC frames.
    pub async fn enable_screen(&mut self, params: ScreenParams) -> Result<ScreenStream> {
        self.control.send(screenmsg::req_authrity(1)).await?;

        let mut opened = false;
        for _ in 0..25 {
            if tcp::port_open(&self.data_ip, 10381, Duration::from_secs(1)).await {
                opened = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(600)).await;
        }
        if !opened {
            anyhow::bail!("10381 did not open (screen-record permission?)");
        }

        let mut video =
            open_ws(&self.data_ip, 10381, "/mirror/screen", config::SUBPROTOCOL_BASE, &self.token, 6)
                .await
                .context("mirror WS")?;
        video.send_text(&screenmsg::screen_start(&params)).await?;
        tracing::info!("mirror WS 101; SCREEN_START sent");

        let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
        let mut tasks = vec![tokio::spawn(crate::screen::video_loop(video, tx))];

        let input = match open_ws(
            &self.data_ip,
            10381,
            "/mirror/control",
            config::SUBPROTOCOL_BASE,
            &self.token,
            3,
        )
        .await
        {
            Ok(ws) => {
                tracing::info!("control-input WS 101 (/mirror/control)");
                let (itx, irx) = mpsc::channel::<String>(64);
                tasks.push(tokio::spawn(crate::screen::input_loop(ws, irx)));
                Some(InputHandle::from_sender(itx))
            }
            Err(e) => {
                tracing::warn!(err = %e, "control-input channel unavailable (view-only)");
                None
            }
        };

        Ok(ScreenStream {
            frames: rx,
            input,
            tasks,
        })
    }
}

/// Raw HEVC frame stream + input handle from [`Session::enable_screen`].
pub struct ScreenStream {
    frames: mpsc::Receiver<Vec<u8>>,
    input: Option<InputHandle>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for ScreenStream {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl ScreenStream {
    /// Await the next raw HEVC frame.
    pub async fn next_frame(&mut self) -> Option<Vec<u8>> {
        self.frames.recv().await
    }
    /// A cloneable input handle, if the control-input channel opened.
    pub fn input(&self) -> Option<InputHandle> {
        self.input.clone()
    }
}

/// The control-WS owner: read+broadcast incoming, drain+send outgoing, keepalive.
async fn control_task(
    mut ws: WsClient<Tls>,
    mut out_rx: mpsc::Receiver<String>,
    in_tx: broadcast::Sender<String>,
    last_shadow: Arc<Mutex<Option<String>>>,
) {
    let mut last_ka = Instant::now();
    loop {
        match timeout(Duration::from_millis(200), ws.recv()).await {
            Ok(Ok(WsFrame::Text(t))) => {
                if t.starts_with("SHADOW_LIKE:") {
                    if let Ok(mut g) = last_shadow.lock() {
                        *g = Some(t.clone());
                    }
                }
                let _ = in_tx.send(t);
            }
            Ok(Ok(WsFrame::Ping(p))) => {
                if ws.send_pong(&p).await.is_err() {
                    break;
                }
            }
            Ok(Ok(WsFrame::Close)) => break,
            Ok(Ok(_)) => {}
            Ok(Err(_)) => break,
            Err(_) => {} // recv timeout -> flush outgoing + keepalive
        }
        loop {
            match out_rx.try_recv() {
                Ok(msg) => {
                    if ws.send_text(&msg).await.is_err() {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
        if last_ka.elapsed() >= Duration::from_secs(3) {
            if ws.send_text(screenmsg::KEEPALIVE).await.is_err() {
                break;
            }
            last_ka = Instant::now();
        }
    }
}
