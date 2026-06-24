//! Protocol-mandated wire constants and runtime-loaded PC identity.
//!
//! The string constants below (`service_id`, `serviceRecord`, the WS subprotocol)
//! contain the upstream vendor name because the **phone requires those exact
//! values on the wire** — they are protocol identifiers, not names we are free to
//! choose. They are intentionally the only place such strings appear.
//!
//! The *identity* values — account openId, PC MAC, display name, and the per-IP
//! pairing seeds — are deployment-specific and are NEVER hardcoded here. They are
//! loaded at runtime (see [`default_identity`] / [`default_stored_seed`]) from, in
//! priority order:
//!   1. environment variables (`PCSUITE_OPEN_ID`, `PCSUITE_PC_MAC`,
//!      `PCSUITE_ACCOUNT`, `PCSUITE_DEVICE_NAME`, `PCSUITE_SEED`),
//!   2. a JSON config file (`$PCSUITE_CONFIG`, else `./pcsuite.json`, else
//!      `$HOME/.config/pcsuite/config.json`),
//!   3. obviously-fake placeholder defaults.
//! See `pcsuite.example.json` for the file format.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use pcsuite_proto::PcIdentity;

/// Service id the phone matches against (protocol-mandated wire constant).
pub const SERVICE_ID: &str = "com.vivo.pcsuite.SERVICE";

/// SSDP `serviceRecord` advertised in presence (protocol-mandated wire constant).
pub const SERVICE_RECORD: &str = "com.vivo.pcsuite.SERVICE--com.vivo.share.CONNECT_PC";

/// Base WebSocket subprotocol for the control/mirror channels (protocol-mandated).
/// The control channel appends `,<token>`; the mirror channel uses it bare.
pub const SUBPROTOCOL_BASE: &str = "v1.hc.vivo.com.cn";

/// PC device id used for the super-clipboard (6 chars; goes in the ruying frame
/// `fieldB` and the clipboard JSON `deviceid`). A neutral placeholder — override
/// the constant if you want a per-machine value.
pub const CLIP_PC_ID: &str = "pc0000";

/// Display nickname announced in SHADOW_LIKE / clipboard content.
pub const CLIP_NICK: &str = "pcsuite";

/// Fixed JSON `id` field used in ConnectFlow frames.
pub const FRAME_ID: i64 = 87654321;

/// Runtime identity + pairing seeds, parsed once from env / config file.
struct UserConfig {
    open_id: String,
    pc_mac: String,
    account: String,
    device_name: String,
    /// Optional single seed used for any IP without a per-IP entry.
    default_seed: Option<String>,
    /// Per-IP stored pairing seeds (`ip` -> seed UUID).
    seeds: HashMap<String, String>,
}

fn load() -> &'static UserConfig {
    static CFG: OnceLock<UserConfig> = OnceLock::new();
    CFG.get_or_init(|| {
        let file = read_config_file();
        // env var wins over file value, file value wins over the placeholder.
        let pick = |env_key: &str, json_key: &str, default: &str| -> String {
            std::env::var(env_key)
                .ok()
                .or_else(|| file.get(json_key).and_then(|v| v.as_str()).map(str::to_owned))
                .unwrap_or_else(|| default.to_owned())
        };

        let mut seeds = HashMap::new();
        if let Some(map) = file.get("seeds").and_then(|v| v.as_object()) {
            for (ip, v) in map {
                if let Some(s) = v.as_str() {
                    seeds.insert(ip.clone(), s.to_owned());
                }
            }
        }
        let default_seed = std::env::var("PCSUITE_SEED")
            .ok()
            .or_else(|| file.get("seed").and_then(|v| v.as_str()).map(str::to_owned));

        UserConfig {
            open_id: pick("PCSUITE_OPEN_ID", "open_id", "0000000000000000"),
            pc_mac: pick("PCSUITE_PC_MAC", "pc_mac", "000000000000"),
            account: pick("PCSUITE_ACCOUNT", "account", ""),
            device_name: pick("PCSUITE_DEVICE_NAME", "device_name", "pcsuite-pc"),
            default_seed,
            seeds,
        }
    })
}

/// Locate and parse the JSON config file; returns `Null` if absent/unreadable.
fn read_config_file() -> serde_json::Value {
    let path = std::env::var("PCSUITE_CONFIG")
        .ok()
        .map(std::path::PathBuf::from)
        .filter(|p| p.exists())
        .or_else(|| {
            let cwd = std::path::PathBuf::from("pcsuite.json");
            cwd.exists().then_some(cwd)
        })
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| std::path::PathBuf::from(h).join(".config/pcsuite/config.json"))
                .filter(|p| p.exists())
        });

    if let Some(p) = path {
        match std::fs::read_to_string(&p) {
            Ok(text) => match serde_json::from_str(&text) {
                Ok(v) => return v,
                Err(e) => {
                    tracing::warn!(path = %p.display(), %e, "invalid PCSUITE config JSON; using defaults")
                }
            },
            Err(e) => {
                tracing::warn!(path = %p.display(), %e, "cannot read PCSUITE config; using defaults")
            }
        }
    }
    serde_json::Value::Null
}

/// Runtime overrides set by an embedding app (e.g. the SwiftUI settings panel via
/// FFI). Take precedence over the env/file/placeholder base, so a GUI can supply
/// the pairing identity without a config file. Empty strings clear a field.
#[derive(Default)]
struct Overrides {
    open_id: Option<String>,
    pc_mac: Option<String>,
    account: Option<String>,
    device_name: Option<String>,
    seeds: HashMap<String, String>,
}

fn overrides() -> &'static RwLock<Overrides> {
    static O: OnceLock<RwLock<Overrides>> = OnceLock::new();
    O.get_or_init(|| RwLock::new(Overrides::default()))
}

/// Override the PC identity at runtime. An empty field falls back to the
/// env/file/placeholder value. Call before connecting.
pub fn set_identity(open_id: String, pc_mac: String, account: String, device_name: String) {
    let opt = |s: String| (!s.is_empty()).then_some(s);
    let mut o = overrides().write().unwrap();
    o.open_id = opt(open_id);
    o.pc_mac = opt(pc_mac);
    o.account = opt(account);
    o.device_name = opt(device_name);
}

/// Override (or, with an empty `seed`, clear) the stored pairing seed for one IP.
pub fn set_seed(ip: String, seed: String) {
    let mut o = overrides().write().unwrap();
    if seed.is_empty() {
        o.seeds.remove(&ip);
    } else {
        o.seeds.insert(ip, seed);
    }
}

/// The PC identity used by default: runtime overrides win, then env / config file
/// / placeholders. With nothing configured it returns obviously-fake values that
/// will not pair with a real phone.
pub fn default_identity() -> PcIdentity {
    let c = load();
    let o = overrides().read().unwrap();
    let pick = |ov: &Option<String>, base: &str| ov.clone().unwrap_or_else(|| base.to_owned());
    PcIdentity {
        open_id: pick(&o.open_id, &c.open_id),
        pc_mac: pick(&o.pc_mac, &c.pc_mac),
        account: pick(&o.account, &c.account),
        device_name: pick(&o.device_name, &c.device_name),
        service_id: SERVICE_ID.into(),
        frame_id: FRAME_ID,
    }
}

/// Per-IP stored pairing seed (historyPhone `ext.seeds`), used for the LAN
/// `connectType=2` path. Runtime override wins, then the per-IP config entry, then
/// the single `PCSUITE_SEED` / `"seed"` value. The remote `connectType=1` path
/// needs no seed.
pub fn default_stored_seed(ip: &str) -> Option<String> {
    if let Some(s) = overrides().read().unwrap().seeds.get(ip) {
        return Some(s.clone());
    }
    let c = load();
    c.seeds.get(ip).cloned().or_else(|| c.default_seed.clone())
}
