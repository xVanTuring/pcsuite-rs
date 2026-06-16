//! Control-input messages (sent over the 10381 `/mirror/control` WS).
//!
//! Coordinates are expressed in a reference frame of `(w, h)`: the phone scales
//! `point_x/point_y` from our reported `screen_width/screen_height` onto the real
//! display, so a caller can drive by fractions (e.g. centre = `w/2, h/2`).

use serde_json::json;

/// `MotionEvent` action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseAction {
    Down = 0,
    Up = 1,
    Move = 2,
}

/// Mouse button (matches Android `BUTTON_PRIMARY`/`BUTTON_SECONDARY`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseButton {
    Left = 1,
    Right = 2,
}

/// Build a `MOUSE_EVENT:{…}` text message.
///
/// NB: the JSON key is `"position"` (gson `@SerializedName`) — the Java field is
/// `unPackedPosition`, but sending that name makes the phone drop the event.
pub fn mouse_event(action: MouseAction, button: MouseButton, x: i64, y: i64, w: i64, h: i64) -> String {
    format!(
        "MOUSE_EVENT:{}",
        json!({
            "id": 0,
            "action": action as i64,
            "buttons": button as i64,
            "position": {"point_x": x, "point_y": y, "screen_width": w, "screen_height": h},
        })
    )
}

/// Build a `SCROLL_EVENT:{…}` text message. `vscroll > 0` scrolls up.
pub fn scroll_event(vscroll: i64, x: i64, y: i64, w: i64, h: i64) -> String {
    format!(
        "SCROLL_EVENT:{}",
        json!({
            "hscroll": 0,
            "vscroll": vscroll,
            "wheel_radio": 1.0, // intentional spelling: matches the wire key exactly
            "position": {"point_x": x, "point_y": y, "screen_width": w, "screen_height": h},
        })
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mouse_uses_position_key() {
        let m = mouse_event(MouseAction::Down, MouseButton::Left, 5, 6, 100, 200);
        assert!(m.starts_with("MOUSE_EVENT:"));
        let v: serde_json::Value = serde_json::from_str(&m["MOUSE_EVENT:".len()..]).unwrap();
        assert_eq!(v["action"], 0);
        assert_eq!(v["buttons"], 1);
        assert!(v.get("position").is_some(), "key must be 'position'");
        assert!(v.get("unPackedPosition").is_none());
        assert_eq!(v["position"]["point_x"], 5);
        assert_eq!(v["position"]["screen_width"], 100);
    }

    #[test]
    fn scroll_keys() {
        let s = scroll_event(-1, 10, 20, 100, 200);
        let v: serde_json::Value = serde_json::from_str(&s["SCROLL_EVENT:".len()..]).unwrap();
        assert_eq!(v["vscroll"], -1);
        assert_eq!(v["wheel_radio"], 1.0);
        assert_eq!(v["hscroll"], 0);
    }
}
