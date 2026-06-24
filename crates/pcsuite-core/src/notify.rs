//! Phone notification relay.
//!
//! Opens the control WS, declares `notify:true`/`notifyOn:true` via `PC_CONFIG`
//! (shared with the verify-code relay — one config drives the whole relay family),
//! and invokes `on_notify` for every `NOTIFY_RECEIVED_NOTIFICATION` the phone
//! forwards. Independent of clipboard/screen — only the control WS is needed.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::time::timeout;

use pcsuite_net::ws::WsFrame;
use pcsuite_proto::notify::{self, Notification, NotifyMsg};
use pcsuite_proto::verify;

use crate::config;
use crate::session::ControlHandle;
use crate::wsconn::open_ws;

/// Where to run the notification relay.
pub struct NotifyConfig {
    /// Control-WS host (`127.0.0.1` for USB; the phone IP for LAN).
    pub data_ip: String,
    pub token: String,
}

/// Run the relay until the control WS closes, calling `on_notify(&n)` for each
/// notification the phone posts.
pub async fn run_notify<F>(cfg: NotifyConfig, on_notify: F) -> Result<()>
where
    F: Fn(&Notification) + Send + 'static,
{
    let subproto = format!("{},{}", config::SUBPROTOCOL_BASE, cfg.token);
    let mut ws = open_ws(&cfg.data_ip, 10380, "/ws/heart-beat", &subproto, &cfg.token, 6)
        .await
        .context("control WS")?;
    tracing::info!("control WS 101; sending PC_CONFIG (notify:true)");
    ws.send_text(&verify::pc_config()).await?;

    let mut last_ka = Instant::now();
    loop {
        match timeout(Duration::from_secs(1), ws.recv()).await {
            Ok(Ok(WsFrame::Text(t))) => dispatch(&t, &on_notify),
            Ok(Ok(WsFrame::Ping(p))) => {
                ws.send_pong(&p).await.ok();
            }
            Ok(Ok(WsFrame::Close)) => break,
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                tracing::warn!(err = %e, "control WS recv");
                break;
            }
            Err(_) => {}
        }
        if last_ka.elapsed() >= Duration::from_secs(3) {
            ws.send_text(pcsuite_proto::screen::KEEPALIVE).await.ok();
            last_ka = Instant::now();
        }
    }
    Ok(())
}

/// Notification relay as a feature on a shared control channel (for the unified
/// session): send `PC_CONFIG`, then call `on_notify` for every posted notification.
pub async fn notify_feature<F>(control: ControlHandle, on_notify: F)
where
    F: Fn(&Notification) + Send + 'static,
{
    use tokio::sync::broadcast::error::RecvError;
    let mut rx = control.subscribe();
    let _ = control.send(verify::pc_config()).await;
    tracing::info!("notify-relay: sent PC_CONFIG (notify:true)");
    loop {
        match rx.recv().await {
            Ok(t) => dispatch(&t, &on_notify),
            Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => break,
        }
    }
}

/// Classify one control-WS text frame and forward posted notifications.
fn dispatch<F: Fn(&Notification)>(text: &str, on_notify: &F) {
    match notify::parse(text) {
        Some(NotifyMsg::Posted(n)) => {
            tracing::info!(app = %n.app_name, title = %n.title, "★ phone notification");
            on_notify(&n);
        }
        Some(NotifyMsg::Removed(_)) => {
            tracing::debug!("notification dismissed on phone");
        }
        None => {
            // Unmatched message that still looks notification-shaped — surface at
            // debug so an unknown variant can be spotted while calibrating. Narrowed
            // to `NOTIFICATION` so verify-code (`NOTIFY_RECEIVED_SMS_CODE`),
            // `NOTIFY_PASS`, `FunctionSupported`, etc. — handled elsewhere — stay quiet.
            if text.contains("NOTIFICATION") {
                tracing::debug!(msg = %text.chars().take(200).collect::<String>(), "unparsed notification-shaped control msg");
            }
        }
    }
}
