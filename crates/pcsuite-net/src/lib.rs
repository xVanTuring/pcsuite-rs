//! `pcsuite-net` — the transport layer.
//!
//! - [`ssdp`] — UDP presence/discovery on port 2200.
//! - [`tls`]  — a rustls client that accepts the phone's self-signed cert
//!   (no chain/hostname verification), matching the Python `_create_unverified_context`.
//! - [`ws`]   — a minimal RFC6455 WebSocket client (custom upgrade headers,
//!   masked client frames) over any async stream.
//! - [`tcp`]  — small TCP helpers (`connect`, `port_open`).

pub mod ssdp;
pub mod tcp;
pub mod tls;
pub mod ws;

pub use ws::{WsClient, WsFrame};
