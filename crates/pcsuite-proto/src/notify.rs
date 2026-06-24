//! Notification-relay messages (carried as text on the 10380 control WS).
//!
//! The PC declares `notify:true`/`notifyOn:true` via `PC_CONFIG` (see
//! [`crate::verify::pc_config`]); the phone's `NotificationListenerService` then
//! forwards each posted notification as `NOTIFY_RECEIVED_NOTIFICATION:{…}` and each
//! dismissal as `NOTIFY_REMOVE_NOTIFICATION…`. The PC can ask the phone to open the
//! originating app by echoing `PC_CLICK_NOTIFICATION:<pendingIntentId>`.
//!
//! Wire shape comes from the phone app's `NotificationContent` (gson, camelCase):
//! `{appName, content, isCloneApp, packageName, pendingIntentId, title, unReadCount}`.

use serde_json::Value;

/// Prefix the phone actually uses for a newly posted notification (followed by
/// JSON). Real device traffic is `NOTIFY_CLIENT_RECEIVED_NOTIFICATION:`; the
/// `HttpConst` table's `NOTIFY_RECEIVED_NOTIFICATION:` is the un-prefixed form.
/// [`parse`] matches on the shared `RECEIVED_NOTIFICATION` tail so both work.
pub const RECEIVED_PREFIX: &str = "NOTIFY_CLIENT_RECEIVED_NOTIFICATION:";
/// Tail shared by every posted-notification spelling (used for matching).
const RECEIVED_TAG: &str = "RECEIVED_NOTIFICATION";
/// Tail shared by every dismissal spelling (the JSON payload, if any, is optional).
const REMOVE_TAG: &str = "REMOVE_NOTIFICATION";
/// Prefix the PC sends to make the phone open the notification's app. On the 10380
/// control WS the phone reads the remainder as a bare `pendingIntentId` string
/// (`WebSocketController` does `substring(22)`), not JSON.
pub const CLICK_PREFIX: &str = "PC_CLICK_NOTIFICATION:";

/// A phone notification forwarded to the PC (the phone's `NotificationContent`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Notification {
    pub package_name: String,
    pub app_name: String,
    pub title: String,
    pub content: String,
    /// Opaque handle the phone uses to re-open the source app (echo it back via
    /// [`click`]). `0` when the notification had no content intent.
    pub pending_intent_id: i64,
    pub is_clone_app: bool,
    pub unread_count: i64,
}

/// A parsed notification-relay control-WS message.
#[derive(Debug, Clone, PartialEq)]
pub enum NotifyMsg {
    /// A new notification was posted on the phone.
    Posted(Notification),
    /// A notification was dismissed on the phone (payload often absent).
    Removed(Option<Notification>),
}

/// Parse a notification-relay message, or `None` if `text` is some other control
/// message (keepalive, shadow, screen event, …).
pub fn parse(text: &str) -> Option<NotifyMsg> {
    // Match on the shared tail so `NOTIFY_CLIENT_RECEIVED_NOTIFICATION:` (real
    // device) and `NOTIFY_RECEIVED_NOTIFICATION:` (docs/HttpConst) both parse.
    // `parse_content` finds the `{`, so the exact prefix length doesn't matter.
    if text.contains(RECEIVED_TAG) {
        return Some(NotifyMsg::Posted(parse_content(text)?));
    }
    if text.contains(REMOVE_TAG) {
        // The dismissal may or may not carry a JSON body; surface whatever is there.
        let body = parse_content(text);
        return Some(NotifyMsg::Removed(body));
    }
    None
}

/// Parse a `NotificationContent` JSON object out of `s` (which may carry leading
/// text before the `{`). Returns `None` if nothing identifiable is present.
fn parse_content(s: &str) -> Option<Notification> {
    let start = s.find('{')?;
    let j: Value = serde_json::from_str(&s[start..]).ok()?;
    let text = |k: &str| j.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    // `pendingIntentId`/`unReadCount` are ints on the wire, but tolerate strings.
    let int = |k: &str| {
        j.get(k)
            .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
            .unwrap_or(0)
    };
    let n = Notification {
        package_name: text("packageName"),
        app_name: text("appName"),
        title: text("title"),
        content: text("content"),
        pending_intent_id: int("pendingIntentId"),
        is_clone_app: j.get("isCloneApp").and_then(Value::as_bool).unwrap_or(false),
        unread_count: int("unReadCount"),
    };
    // Drop empty shells (no app, no text) — nothing worth surfacing.
    if n.package_name.is_empty()
        && n.app_name.is_empty()
        && n.title.is_empty()
        && n.content.is_empty()
    {
        return None;
    }
    Some(n)
}

/// Build the `PC_CLICK_NOTIFICATION:<id>` message that asks the phone to open the
/// app behind a forwarded notification (fires its `pendingIntentId`).
pub fn click(pending_intent_id: i64) -> String {
    format!("{CLICK_PREFIX}{pending_intent_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_posted_real_device_frame() {
        // Captured verbatim from a real phone (2026-06-24): note the CLIENT_ infix
        // and the very large pendingIntentId.
        let m = r#"NOTIFY_CLIENT_RECEIVED_NOTIFICATION:{"appName":"微信","content":"1个联系人发来1条消息","isCloneApp":false,"packageName":"com.tencent.mm","pendingIntentId":966950649,"title":"微信","unReadCount":0}"#;
        match parse(m).unwrap() {
            NotifyMsg::Posted(n) => {
                assert_eq!(n.package_name, "com.tencent.mm");
                assert_eq!(n.app_name, "微信");
                assert_eq!(n.title, "微信");
                assert_eq!(n.content, "1个联系人发来1条消息");
                assert_eq!(n.pending_intent_id, 966_950_649);
                assert_eq!(n.unread_count, 0);
                assert!(!n.is_clone_app);
            }
            other => panic!("expected Posted, got {other:?}"),
        }
    }

    #[test]
    fn parse_posted_legacy_prefix_still_works() {
        // The un-prefixed spelling from the HttpConst table must still parse.
        let m = r#"NOTIFY_RECEIVED_NOTIFICATION:{"appName":"QQ","title":"张三","content":"在吗","pendingIntentId":42}"#;
        match parse(m).unwrap() {
            NotifyMsg::Posted(n) => {
                assert_eq!(n.app_name, "QQ");
                assert_eq!(n.pending_intent_id, 42);
            }
            other => panic!("expected Posted, got {other:?}"),
        }
    }

    #[test]
    fn parse_removed_with_and_without_body() {
        let bare = parse("NOTIFY_CLIENT_REMOVE_NOTIFICATION").unwrap();
        assert_eq!(bare, NotifyMsg::Removed(None));
        let with =
            parse(r#"NOTIFY_CLIENT_REMOVE_NOTIFICATION:{"packageName":"a","title":"t"}"#).unwrap();
        match with {
            NotifyMsg::Removed(Some(n)) => assert_eq!(n.package_name, "a"),
            other => panic!("expected Removed(Some), got {other:?}"),
        }
    }

    #[test]
    fn ignores_other_and_empty() {
        assert!(parse("normal").is_none());
        assert!(parse("SHADOW_LIKE:{}").is_none());
        // `FunctionSupported` mentions `notify_relay` but is not a notification.
        assert!(parse(r#"FunctionSupported:{"notify_relay":{"pc_enable_switch":true}}"#).is_none());
        // posted-prefix but an empty shell → dropped
        assert!(parse(r#"NOTIFY_CLIENT_RECEIVED_NOTIFICATION:{"unReadCount":0}"#).is_none());
    }

    #[test]
    fn tolerates_string_pending_id() {
        let m = r#"NOTIFY_RECEIVED_NOTIFICATION:{"appName":"X","pendingIntentId":"77"}"#;
        match parse(m).unwrap() {
            NotifyMsg::Posted(n) => assert_eq!(n.pending_intent_id, 77),
            other => panic!("expected Posted, got {other:?}"),
        }
    }

    #[test]
    fn click_builds_bare_id() {
        assert_eq!(click(42), "PC_CLICK_NOTIFICATION:42");
    }
}
