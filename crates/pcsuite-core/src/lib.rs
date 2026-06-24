//! `pcsuite-core` — session orchestration that ties crypto + proto + net into the
//! end-to-end flow, exposed as a small boundary-agnostic API:
//!
//! 1. [`connect::register`] — run ConnectFlow on 10191 to register a self-made
//!    token, returning once the phone opens its 10380 control service.
//! 2. [`screen::Screen`] — open the control + mirror WebSockets and deliver raw
//!    HEVC frame bytes over an async channel (no decoding — that's the frontend's
//!    job). `Screen::next_frame().await` yields each frame.
//!
//! No UI, no FFI, no decode: a frontend (FFI lib, IPC daemon, …) can wrap this.

pub mod adb;
pub mod clipboard;
pub mod config;
pub mod connect;
pub mod device;
pub mod mdfs;
pub mod notify;
pub mod screen;
pub mod session;
pub mod usb;
pub mod vdfs;
pub mod verify;
pub mod wsconn;

pub use clipboard::{run_clipboard, ClipboardBackend, ClipboardConfig};
pub use connect::{register, RegisterConfig, Registration};
pub use device::DeviceInfo;
pub use mdfs::{Entry as FileEntry, ListKind};
pub use notify::{run_notify, NotifyConfig};
pub use screen::{InputHandle, Screen};
pub use session::{ControlHandle, ScreenStream, Session};
pub use usb::{UsbConfig, UsbSession};
pub use verify::{run_verify, VerifyConfig};

// Re-exports so frontends/CLIs depend only on this crate.
pub use pcsuite_proto::input::{MouseAction, MouseButton};
pub use pcsuite_proto::notify::Notification;
pub use pcsuite_proto::screen::ScreenParams;
pub use pcsuite_proto::PcIdentity;
