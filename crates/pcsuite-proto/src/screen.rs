//! Control-WS text messages (sent over the 10380 control WS / 10381 mirror WS).
//!
//! These are line-style messages: a literal keyword optionally followed by a
//! compact JSON object (sometimes with a `:` separator, sometimes glued on).

use serde::Serialize;

/// `SCREEN_START:` parameters (sent on the mirror WS to start the HEVC stream).
///
/// Field names match the wire exactly (note the lone camelCase `screenPrivacy`).
/// Defaults mirror the known-good values used by the working client.
#[derive(Serialize, Clone, Debug)]
pub struct ScreenParams {
    pub device_type: i64,
    pub first_file_open: bool,
    pub frame_with_time: bool,
    pub image_quality: i64,
    pub max_size: i64,
    pub mime_type: String,
    pub msg_send_key_mode: String,
    pub need_open_file: bool,
    pub no_audio: bool,
    pub pc_version: String,
    #[serde(rename = "screenPrivacy")]
    pub screen_privacy: bool,
    pub show_touch_spot: bool,
    pub split_frame: bool,
    pub support_drag: bool,
}

impl Default for ScreenParams {
    fn default() -> Self {
        Self {
            device_type: 1,
            first_file_open: true,
            frame_with_time: false,
            image_quality: 3,
            max_size: 2336,
            mime_type: "video/hevc".into(),
            msg_send_key_mode: "0".into(),
            need_open_file: true,
            no_audio: true,
            pc_version: "6.0.1".into(),
            screen_privacy: false,
            show_touch_spot: false,
            split_frame: false,
            support_drag: true,
        }
    }
}

/// Build the `SCREEN_START:{...}` text message.
pub fn screen_start(p: &ScreenParams) -> String {
    format!(
        "SCREEN_START:{}",
        serde_json::to_string(p).expect("ScreenParams serialize")
    )
}

/// Build the `req_authrity{"source":N}` text message (note: no `:` separator).
pub fn req_authrity(source: i64) -> String {
    format!("req_authrity{{\"source\":{source}}}")
}

/// Periodic control-WS keepalive text.
pub const KEEPALIVE: &str = "normal";

/// Mirror-WS binary frames are sometimes prefixed with this ASCII tag before the
/// raw HEVC payload; strip it if present.
pub const FRAME_PREFIX: &[u8; 6] = b"FRAME:";

/// Strip a leading `FRAME:` tag from a binary mirror frame, if present.
pub fn strip_frame_prefix(payload: &[u8]) -> &[u8] {
    if payload.len() >= FRAME_PREFIX.len() && &payload[..FRAME_PREFIX.len()] == FRAME_PREFIX {
        &payload[FRAME_PREFIX.len()..]
    } else {
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_start_default_keys() {
        let s = screen_start(&ScreenParams::default());
        assert!(s.starts_with("SCREEN_START:"));
        let json: serde_json::Value = serde_json::from_str(&s["SCREEN_START:".len()..]).unwrap();
        assert_eq!(json["mime_type"], "video/hevc");
        assert_eq!(json["max_size"], 2336);
        assert_eq!(json["screenPrivacy"], false);
        assert_eq!(json["no_audio"], true);
    }

    #[test]
    fn req_authrity_format() {
        assert_eq!(req_authrity(1), r#"req_authrity{"source":1}"#);
    }

    #[test]
    fn frame_prefix_strip() {
        assert_eq!(strip_frame_prefix(b"FRAME:abc"), b"abc");
        assert_eq!(strip_frame_prefix(b"abc"), b"abc");
        assert_eq!(strip_frame_prefix(b"FRAME:"), b"");
    }
}
