//! `pcsuite-proto` — pure, I/O-free (de)serialization of the phone-suite wire
//! formats. No sockets, no crypto, no config: every function takes its inputs
//! explicitly so the whole crate is offline-testable.
//!
//! Modules:
//! - [`payload1`] — the 10191 transport framing (`PAY_LOAD_1` + BE32 len + JSON).
//! - [`connect`]  — ConnectFlow device-info / connect JSON frames + reply codes.
//! - [`ruying`]   — the 8904 "ruying" super-clipboard frame (binary header + cipher).
//! - [`screen`]   — control-WS text messages (`SCREEN_START`, `req_authrity`, …).
//!
//! Identity/config values (openId, MAC, account, service id) live in the caller
//! and are passed in via [`connect::PcIdentity`]; this crate hardcodes only the
//! protocol-mandated wire constants.

pub mod clip;
pub mod connect;
pub mod input;
pub mod payload1;
pub mod ruying;
pub mod screen;

pub use connect::PcIdentity;

/// Errors from (de)serialization.
#[derive(Debug)]
pub enum ProtoError {
    /// A framed buffer did not start with the expected magic.
    BadMagic,
    /// JSON (de)serialization failed.
    Json(serde_json::Error),
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoError::BadMagic => write!(f, "frame did not start with PAY_LOAD_1 magic"),
            ProtoError::Json(e) => write!(f, "json: {e}"),
        }
    }
}
impl std::error::Error for ProtoError {}
impl From<serde_json::Error> for ProtoError {
    fn from(e: serde_json::Error) -> Self {
        ProtoError::Json(e)
    }
}
