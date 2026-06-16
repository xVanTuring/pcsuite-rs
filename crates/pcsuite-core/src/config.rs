//! Default identity and protocol-mandated wire constants.
//!
//! The string constants below (`service_id`, `serviceRecord`, the WS subprotocol)
//! contain the upstream vendor name because the **phone requires those exact
//! values on the wire** — they are protocol identifiers, not names we are free to
//! choose. They are intentionally the only place such strings appear.

use pcsuite_proto::PcIdentity;

/// Service id the phone matches against (protocol-mandated wire constant).
pub const SERVICE_ID: &str = "com.vivo.pcsuite.SERVICE";

/// SSDP `serviceRecord` advertised in presence (protocol-mandated wire constant).
pub const SERVICE_RECORD: &str = "com.vivo.pcsuite.SERVICE--com.vivo.share.CONNECT_PC";

/// Base WebSocket subprotocol for the control/mirror channels (protocol-mandated).
/// The control channel appends `,<token>`; the mirror channel uses it bare.
pub const SUBPROTOCOL_BASE: &str = "v1.hc.vivo.com.cn";

/// PC device id used for the super-clipboard (6 chars; goes in the ruying frame
/// `fieldB` and the clipboard JSON `deviceid`).
pub const CLIP_PC_ID: &str = "pc0000";

/// Display nickname announced in SHADOW_LIKE / clipboard content.
pub const CLIP_NICK: &str = "pcsuite";

/// Fixed JSON `id` field used in ConnectFlow frames.
pub const FRAME_ID: i64 = 87654321;

/// The PC identity used by default. These are this machine's own pairing values
/// (not secrets); override per-deployment as needed.
pub fn default_identity() -> PcIdentity {
    PcIdentity {
        open_id: "0123456789abcdef".into(),
        pc_mac: "001122334455".into(),
        account: "138****000".into(),
        device_name: "pcsuite-pc".into(),
        service_id: SERVICE_ID.into(),
        frame_id: FRAME_ID,
    }
}

/// Per-IP stored pairing seed (historyPhone `ext.seeds`), used for the LAN
/// `connectType=2` path. The remote `connectType=1` path needs no seed.
pub fn default_stored_seed(ip: &str) -> Option<String> {
    match ip {
        "192.168.1.42" => Some("00000000-0000-4000-8000-000000000000".into()),
        "100.64.0.1" => Some("00000000-0000-4000-8000-000000000000".into()),
        _ => None,
    }
}
