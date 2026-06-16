//! Super-clipboard wire messages.
//!
//! Two layers:
//! - SHADOW_LIKE handshake (text messages on the 10380 control WS): the PC sends
//!   `startup` (declaring its key/iv + service ports), the phone replies with its
//!   session key/iv, then the PC sends `ready` to make the phone reverse-connect
//!   to the 8904 relay.
//! - clipboard content JSON (carried, GCM-encrypted, inside 8904 ruying frames).

use serde_json::{json, Value};

/// PC identity/keys announced in SHADOW_LIKE `startup`.
pub struct PcInfo<'a> {
    pub ip: &'a str,
    pub pc_device_id: &'a str,
    pub pc_device_name: &'a str,
    pub key: &'a str,
    pub iv: &'a str,
    pub account_open_id: &'a str,
    pub account_name: &'a str,
    pub connect_type: &'a str,
}

/// Phone session key/iv recovered from a SHADOW_LIKE reply.
pub struct PhoneSession {
    pub key: String,
    pub iv: String,
    pub mobile_device_id: String,
    pub mobile_device_name: String,
}

/// Build the `SHADOW_LIKE:{type:startup,…}` control-WS message.
pub fn shadow_startup(pc: &PcInfo, relay_port: u16, vdfs_port: u16) -> String {
    let app_info = json!([
        {"appName": "vdfs", "port": vdfs_port, "version": 3},
        {"appName": "anywhere_control", "port": relay_port, "version": 100},
        {"appName": "super_clipboard", "switchEnable": true, "port": relay_port, "version": 100},
        {"appName": "vivo_relay", "version": 1}
    ]);
    let msg = json!({
        "type": "startup",
        "data": {
            "version": 1,
            "pcInfo": {
                "ip": pc.ip,
                "pcDeviceId": pc.pc_device_id,
                "pcDeviceName": pc.pc_device_name,
                "key": pc.key,
                "iv": pc.iv,
                "accountOpenId": pc.account_open_id,
                "accountName": pc.account_name,
                "connectType": pc.connect_type,
            },
            "appInfo": app_info,
        }
    });
    format!("SHADOW_LIKE:{msg}")
}

/// Build the `SHADOW_LIKE:{type:ready,…}` message that triggers the phone to
/// reverse-connect to the 8904 relay.
pub fn shadow_ready() -> String {
    let msg = json!({
        "type": "ready",
        "data": {"state": {"relay": true, "vdfsServer": true, "vdfsClient": true}}
    });
    format!("SHADOW_LIKE:{msg}")
}

/// Parse a phone SHADOW_LIKE reply, returning its session key/iv if present.
pub fn parse_shadow_reply(text: &str) -> Option<PhoneSession> {
    let body = text.strip_prefix("SHADOW_LIKE:")?;
    let j: Value = serde_json::from_str(body).ok()?;
    let mdi = j.get("data")?.get("mobileDeviceInfo")?;
    let key = mdi.get("key")?.as_str()?.to_string();
    if key.is_empty() {
        return None;
    }
    Some(PhoneSession {
        key,
        iv: mdi.get("iv").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        mobile_device_id: mdi
            .get("mobileDeviceId")
            .and_then(|v| v.as_str())
            .unwrap_or("52467a")
            .to_string(),
        mobile_device_name: mdi
            .get("mobileDeviceName")
            .and_then(|v| v.as_str())
            .unwrap_or("phone")
            .to_string(),
    })
}

/// Clipboard content JSON for a text payload (`type:1`).
pub fn clip_text_json(pc_id: &str, device_name: &str, nick: &str, text: &str, ts_ms: u64) -> String {
    json!({
        "callingapk": "com.vivo.pcsuite",
        "deviceid": pc_id,
        "devicename": device_name,
        "devicetype": 64,
        "flag": "",
        "items": [{"text": text, "htmltext": "", "path": "", "uri": ""}],
        "lable": "",
        "mimetypes": ["text/plain"],
        "nickname": nick,
        "timestamp": ts_ms,
        "type": 1
    })
    .to_string()
}

/// Extract clipboard text (`items[0].text`) from a content JSON, if non-empty.
pub fn clip_text_from_json(text: &str) -> Option<String> {
    let j: Value = serde_json::from_str(text).ok()?;
    let t = j.get("items")?.as_array()?.first()?.get("text")?.as_str()?;
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// 8904 command-frame payloads (byteC=100): announce + request-clipboard.
pub fn command_announce(pc_id: &str) -> String {
    json!({"command": 1, "deviceId": pc_id}).to_string()
}
pub fn command_request_clipboard() -> String {
    json!({"command": 5, "packageName": "clipboard"}).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_then_parse_reply() {
        let pc = PcInfo {
            ip: "127.0.0.1",
            pc_device_id: "pc0000",
            pc_device_name: "mac",
            key: "K",
            iv: "I",
            account_open_id: "0123456789abcdef",
            account_name: "nick",
            connect_type: "USB",
        };
        let s = shadow_startup(&pc, 8904, 5679);
        assert!(s.starts_with("SHADOW_LIKE:"));
        let v: Value = serde_json::from_str(&s["SHADOW_LIKE:".len()..]).unwrap();
        assert_eq!(v["data"]["pcInfo"]["key"], "K");
        assert_eq!(v["data"]["appInfo"][2]["appName"], "super_clipboard");

        let reply = r#"SHADOW_LIKE:{"type":"startup","data":{"mobileDeviceInfo":{"key":"PHONEKEY","iv":"PHONEIV","mobileDeviceId":"52467a","mobileDeviceName":"iQOO 15"}}}"#;
        let sess = parse_shadow_reply(reply).unwrap();
        assert_eq!(sess.key, "PHONEKEY");
        assert_eq!(sess.iv, "PHONEIV");
        assert_eq!(sess.mobile_device_id, "52467a");

        // a reply with no key returns None
        assert!(parse_shadow_reply(r#"SHADOW_LIKE:{"type":"ack","data":{}}"#).is_none());
    }

    #[test]
    fn clip_text_roundtrip() {
        let j = clip_text_json("pc0000", "mac", "nick", "hello 世界", 123);
        assert_eq!(clip_text_from_json(&j).as_deref(), Some("hello 世界"));
        // empty text -> None
        let e = clip_text_json("pc0000", "mac", "nick", "", 0);
        assert!(clip_text_from_json(&e).is_none());
    }
}
