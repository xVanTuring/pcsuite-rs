//! SMS verify-code relay.
//!
//! Opens the control WS, declares `verifyCode:true` via `PC_CONFIG`, and invokes
//! `on_code` for every `NOTIFY_RECEIVED_SMS_CODE` the phone forwards. Independent
//! of clipboard/screen — only the control WS is needed.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::time::timeout;

use pcsuite_net::ws::WsFrame;
use pcsuite_proto::verify;

use crate::config;
use crate::session::ControlHandle;
use crate::wsconn::open_ws;

/// Where to run the verify-code relay.
pub struct VerifyConfig {
    /// Control-WS host (`127.0.0.1` for USB; the phone IP for LAN).
    pub data_ip: String,
    pub token: String,
}

/// Run the relay until the control WS closes, calling `on_code(code, sign)` on
/// each forwarded SMS code.
pub async fn run_verify<F>(cfg: VerifyConfig, on_code: F) -> Result<()>
where
    F: Fn(&str, &str) + Send + 'static,
{
    let subproto = format!("{},{}", config::SUBPROTOCOL_BASE, cfg.token);
    let mut ws = open_ws(&cfg.data_ip, 10380, "/ws/heart-beat", &subproto, &cfg.token, 6)
        .await
        .context("control WS")?;
    tracing::info!("control WS 101; sending PC_CONFIG (verifyCode:true)");
    ws.send_text(&verify::pc_config()).await?;

    let mut last_ka = Instant::now();
    loop {
        match timeout(Duration::from_secs(1), ws.recv()).await {
            Ok(Ok(WsFrame::Text(t))) => {
                if let Some(sms) = verify::parse_sms_code(&t) {
                    tracing::info!(code = %sms.code, sign = %sms.sign, "★ SMS verify code");
                    on_code(&sms.code, &sms.sign);
                } else if !t.contains("normal") && !t.trim().is_empty() {
                    tracing::debug!(msg = %t.chars().take(120).collect::<String>(), "control WS msg");
                }
            }
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

/// Verify-code as a feature on a shared control channel (for the unified session):
/// send `PC_CONFIG`, then call `on_code` for every forwarded SMS code.
pub async fn verify_feature<F>(control: ControlHandle, on_code: F)
where
    F: Fn(&str, &str) + Send + 'static,
{
    use tokio::sync::broadcast::error::RecvError;
    let mut rx = control.subscribe();
    let _ = control.send(verify::pc_config()).await;
    tracing::info!("verify-code: sent PC_CONFIG (verifyCode:true)");
    loop {
        match rx.recv().await {
            Ok(t) => {
                if let Some(sms) = verify::parse_sms_code(&t) {
                    tracing::info!(code = %sms.code, sign = %sms.sign, "★ SMS verify code");
                    on_code(&sms.code, &sms.sign);
                }
            }
            Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => break,
        }
    }
}
