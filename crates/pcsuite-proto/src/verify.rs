//! Verify-code relay messages (carried as text on the 10380 control WS).
//!
//! The PC declares `verifyCode:true` via `PC_CONFIG`; the phone then forwards any
//! recognised SMS verification code as `NOTIFY_RECEIVED_SMS_CODE:{…}`.

use serde_json::{json, Value};

/// Build the `PC_CONFIG:{…}` message declaring which relay features are enabled
/// (including `verifyCode`).
pub fn pc_config() -> String {
    let cfg = json!({
        "update_place": "all",
        "call": false,
        "notify": true,
        "brower": false,
        "picture": true,
        "note_relay": true,
        "phoneCall": true,
        "verifyCode": true,
        "notifyOn": true,
        "clipboard_switch": true
    });
    format!("PC_CONFIG:{cfg}")
}

/// A forwarded SMS verification code.
pub struct SmsCode {
    pub code: String,
    pub sign: String,
}

/// Parse a `NOTIFY_RECEIVED_SMS_CODE:{…}` control-WS message.
pub fn parse_sms_code(text: &str) -> Option<SmsCode> {
    if !text.contains("NOTIFY_RECEIVED_SMS_CODE") {
        return None;
    }
    let start = text.find('{')?;
    let j: Value = serde_json::from_str(&text[start..]).ok()?;
    let code = j
        .get("smsCode")
        .or_else(|| j.get("code"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if code.is_empty() {
        return None;
    }
    let sign = j
        .get("smsSign")
        .or_else(|| j.get("sign"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Some(SmsCode { code, sign })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pc_config_enables_verify() {
        let s = pc_config();
        assert!(s.starts_with("PC_CONFIG:"));
        let v: Value = serde_json::from_str(&s["PC_CONFIG:".len()..]).unwrap();
        assert_eq!(v["verifyCode"], true);
        assert_eq!(v["notify"], true);
    }

    #[test]
    fn parse_code() {
        let m = r#"NOTIFY_RECEIVED_SMS_CODE:{"smsCode":"123456","smsSign":"WeChat"}"#;
        let c = parse_sms_code(m).unwrap();
        assert_eq!(c.code, "123456");
        assert_eq!(c.sign, "WeChat");
        assert!(parse_sms_code("normal").is_none());
        assert!(parse_sms_code(r#"NOTIFY_RECEIVED_SMS_CODE:{"smsCode":""}"#).is_none());
    }
}
