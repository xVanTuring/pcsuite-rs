//! ConnectFlow registration on 10191.
//!
//! Registers a self-made token with the phone so it opens the 10380 control
//! service. This is the pure-Rust replacement for the desktop connection-service
//! binary. Success is confirmed by polling 10380.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};

use pcsuite_proto::connect::{self, Presence};
use pcsuite_proto::{payload1, PcIdentity};
use pcsuite_net::{ssdp, tcp};

use crate::config;

/// Inputs to [`register`].
pub struct RegisterConfig {
    /// IP to run the 10191 ConnectFlow against (LAN IP, or the phone's
    /// Tailscale IP for the remote path).
    pub reg_ip: String,
    /// PC identity advertised to the phone.
    pub identity: PcIdentity,
    /// Per-IP stored seed for the LAN `connectType=2` path. Ignored when `remote`.
    pub stored_seed: Option<String>,
    /// Use the `connectType=1` remote path (`key = SHA256(seed_b)`, no pre-shared
    /// seed) so registration works on any network.
    pub remote: bool,
    /// Token to register; a fresh 64-hex token is generated when `None`.
    pub token: Option<String>,
    /// Connection id; a timestamped id is generated when `None`.
    pub conn_id: Option<String>,
    /// Continuously unicast SSDP presence to `reg_ip` for the session.
    pub presence: bool,
}

/// A successful registration. Holds the presence task for the session's lifetime;
/// dropping it stops the presence announcements.
pub struct Registration {
    pub phone_ip: String,
    pub token: String,
    pub conn_id: String,
    presence_task: Option<JoinHandle<std::io::Result<()>>>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(h) = self.presence_task.take() {
            h.abort();
        }
    }
}

fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read from `sock` until a ConnectFlow reply JSON can be parsed (or timeout).
async fn read_reply(sock: &mut TcpStream, dur: Duration) -> Option<serde_json::Value> {
    let deadline = Instant::now() + dur;
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(remaining, sock.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some((v, _off)) = payload1::parse_reply_lenient(&buf) {
                    return Some(v);
                }
            }
            _ => break,
        }
    }
    None
}

/// Run the full ConnectFlow and return once the phone opens 10380.
pub async fn register(cfg: RegisterConfig) -> Result<Registration> {
    let token = cfg.token.clone().unwrap_or_else(random_token);
    let conn_id = cfg
        .conn_id
        .clone()
        .unwrap_or_else(|| format!("pcsuite_{}", epoch_secs()));

    // Presence (direct/Tailscale path): keep announcing ourselves to the phone.
    let presence_task = if cfg.presence {
        let pres = Presence {
            device_id: &cfg.identity.pc_mac,
            open_id: &cfg.identity.open_id,
            account: &cfg.identity.account,
            device_name: &cfg.identity.device_name,
            service_record: config::SERVICE_RECORD,
            port: 10191,
            device_type: "pc",
            extra: "null",
        };
        let b64 = STANDARD.encode(serde_json::to_vec(&pres)?);
        let announce = ssdp::build_announce(&b64);
        let handle = tokio::spawn(ssdp::presence_loop(
            cfg.reg_ip.clone(),
            announce,
            Duration::from_secs(2),
        ));
        // give the phone a moment to register us as an active nearby peer
        tokio::time::sleep(Duration::from_secs(2)).await;
        Some(handle)
    } else {
        None
    };

    tracing::info!(reg_ip = %cfg.reg_ip, remote = cfg.remote, "ConnectFlow: connecting 10191");
    let mut sock = tcp::connect(&cfg.reg_ip, 10191)
        .await
        .context("connect 10191 (phone idle / WiFi off?)")?;

    // [1] device-info exchange
    let dframe = payload1::encode_json(&connect::device_info_frame(&cfg.identity, 22))?;
    sock.write_all(&dframe).await?;
    sock.flush().await?;
    if let Some(v) = read_reply(&mut sock, Duration::from_secs(8)).await {
        tracing::info!(code = ?connect::reply_code(&v), "device_info reply");
    }

    // [2] compute sign
    let seed = if cfg.remote {
        String::new()
    } else {
        cfg.stored_seed
            .clone()
            .context("LAN mode needs a stored_seed for this IP (or pass remote = true)")?
    };
    let seed_b = uuid::Uuid::new_v4().to_string().to_uppercase();
    let sign = pcsuite_crypto::make_sign(&cfg.identity.open_id, &conn_id, &token, &seed, &seed_b);
    let connect_type = if cfg.remote { 1 } else { 2 };

    // [3] connect frame (seed + sign)
    let cframe = payload1::encode_json(&connect::connect_frame(
        &cfg.identity,
        &seed_b,
        &sign,
        connect_type,
    ))?;
    sock.write_all(&cframe).await?;
    sock.flush().await?;
    let reply_code = read_reply(&mut sock, Duration::from_secs(8))
        .await
        .and_then(|v| connect::reply_code(&v));
    tracing::info!(?reply_code, "connect reply");
    drop(sock);

    // [4] confirm: phone opens 10380
    let mut opened = false;
    for _ in 0..8 {
        if tcp::port_open(&cfg.reg_ip, 10380, Duration::from_secs(2)).await {
            opened = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if !opened {
        bail!(
            "10380 did not open (reply code {:?}) — token not accepted. \
             LAN needs the per-IP stored seed; otherwise pass remote = true (connectType=1).",
            reply_code
        );
    }

    tracing::info!(token = %token, "registration accepted; 10380 open");
    Ok(Registration {
        phone_ip: cfg.reg_ip,
        token,
        conn_id,
        presence_task,
    })
}
