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
    /// Encoder bitrate override (bps). The phone falls back to its own default
    /// (~4 Mbps) when this field is absent — so we omit it on the wire when 0,
    /// keeping the default `SCREEN_START` byte-identical to the official client.
    #[serde(skip_serializing_if = "is_zero")]
    pub bit_rate: i64,
    /// Encoder frame-rate cap (fps). Omitted when 0 (phone picks its default).
    #[serde(skip_serializing_if = "is_zero")]
    pub frame_rate: i64,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
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
            bit_rate: 0,
            frame_rate: 0,
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

/// Does this binary mirror message carry a video frame? When `no_audio:false` the
/// phone interleaves non-video (audio) packets on the same WS; feeding those to the
/// HEVC decoder would corrupt the picture, so the data plane must demux. Video is
/// either `FRAME:`-prefixed or a bare Annex-B unit (NAL start code); anything else
/// (e.g. AAC/Opus audio) is treated as non-video.
pub fn is_video_frame(payload: &[u8]) -> bool {
    if payload.len() >= FRAME_PREFIX.len() && &payload[..FRAME_PREFIX.len()] == FRAME_PREFIX {
        return true;
    }
    payload.starts_with(&[0, 0, 0, 1]) || payload.starts_with(&[0, 0, 1])
}

/// Privacy / secure-screen state the phone reports via `NOTIFY_PASS:`. When the
/// phone shows a secure surface (fingerprint, password entry, lock screen) it
/// stops the mirror stream and sends this so the PC can show a "handle on phone"
/// prompt instead of a frozen / black picture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivacyState {
    /// Back to a normal, mirrorable screen.
    Clear,
    /// A password / PIN entry surface.
    Password,
    /// A `FLAG_SECURE` window (e.g. fingerprint, banking, DRM).
    Secure,
    /// The device lock screen.
    LockScreen,
}

impl PrivacyState {
    /// Stable wire token used across the FFI boundary (matches the phone's
    /// `privacyState` strings; `Clear` collapses the "not secure" cases).
    pub fn token(self) -> &'static str {
        match self {
            PrivacyState::Clear => "clear",
            PrivacyState::Password => "password",
            PrivacyState::Secure => "safety",
            PrivacyState::LockScreen => "lockScreen",
        }
    }
}

/// Parse a `NOTIFY_PASS:{…}` control message into a [`PrivacyState`].
/// Returns `None` for any other message. `isPass=false` → [`PrivacyState::Clear`].
pub fn parse_notify_pass(line: &str) -> Option<PrivacyState> {
    let body = line.strip_prefix("NOTIFY_PASS:")?;
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    if !v.get("isPass").and_then(|x| x.as_bool()).unwrap_or(false) {
        return Some(PrivacyState::Clear);
    }
    Some(match v.get("privacyState").and_then(|x| x.as_str()).unwrap_or("") {
        "password" => PrivacyState::Password,
        "lockScreen" => PrivacyState::LockScreen,
        // "safety" or any other non-empty state under isPass=true → treat as secure.
        _ => PrivacyState::Secure,
    })
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

    #[test]
    fn notify_pass_parse() {
        assert_eq!(parse_notify_pass("MOUSE_EVENT:{}"), None);
        assert_eq!(
            parse_notify_pass(r#"NOTIFY_PASS:{"appName":"x","isPass":false,"privacyState":""}"#),
            Some(PrivacyState::Clear)
        );
        assert_eq!(
            parse_notify_pass(r#"NOTIFY_PASS:{"isPass":true,"privacyState":"password"}"#),
            Some(PrivacyState::Password)
        );
        assert_eq!(
            parse_notify_pass(r#"NOTIFY_PASS:{"isPass":true,"privacyState":"safety"}"#),
            Some(PrivacyState::Secure)
        );
        assert_eq!(
            parse_notify_pass(r#"NOTIFY_PASS:{"isPass":true,"privacyState":"lockScreen"}"#),
            Some(PrivacyState::LockScreen)
        );
    }
}
