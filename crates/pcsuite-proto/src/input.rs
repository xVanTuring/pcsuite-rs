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

/// Android `KeyEvent` action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAction {
    Down = 0,
    Up = 1,
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

/// `TextEvent` kind (matches the phone's `TextEvent` constants).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextAction {
    /// Commit `text` and honour `newCursorPosition` (IME `commitText(text, pos)`).
    /// NB: prefer this over `COMMIT_TEXT`(=1): on phones using the screen core
    /// SDK, type-1 commits with `newCursorPosition=0` (cursor lands *before* the
    /// inserted text, so typing reverses); type-2 passes our `1` through so the
    /// cursor advances past the text.
    CommitPos = 2,
    /// Set composing `text` (IME `setComposingText`).
    Composing = 3,
    /// Delete `before`/`after` chars around the cursor (IME `deleteSurroundingText`).
    DeleteSurrounding = 4,
}

/// Build a `TEXT_EVENT:{…}` message that commits `text` into the focused input
/// field via the phone's input-method connection. Unlike `KEYCODE_EVENT` this
/// carries full Unicode (Chinese, emoji, …), so it is the right path for typing.
pub fn text_commit(text: &str) -> String {
    format!(
        "TEXT_EVENT:{}",
        json!({
            "textEventType": TextAction::CommitPos as i64,
            "text": text,
            "newCursorPosition": 1,   // place the cursor right after the inserted text
        })
    )
}

/// Build a `TEXT_EVENT:{…}` that deletes `before` chars before the cursor and
/// `after` chars after it (IME `deleteSurroundingText`) — used for Backspace.
pub fn text_delete_surrounding(before: i64, after: i64) -> String {
    format!(
        "TEXT_EVENT:{}",
        json!({
            "textEventType": TextAction::DeleteSurrounding as i64,
            "beforeLength": before,
            "afterLength": after,
        })
    )
}

/// Build a `KEYCODE_EVENT:{…}` text message — injects an Android `KeyEvent`.
/// `keycode` is an Android `KEYCODE_*` value (e.g. BACK=4, HOME=3, APP_SWITCH=187);
/// `metastate`/`scancode` are 0 for an ordinary press.
pub fn keycode_event(action: KeyAction, keycode: i64, metastate: i64, scancode: i64) -> String {
    format!(
        "KEYCODE_EVENT:{}",
        json!({
            "action": action as i64,
            "keycode": keycode,
            "metastate": metastate,
            "scancode": scancode,
        })
    )
}

/// The phone's report about the focused text field, used to place the PC's IME
/// candidate window at the on-device caret (`PHONE_TO_PAD_INPUT_CURSOR_POSITION`
/// / `PHONE_TO_PAD_INPUT_READY`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum InputEvent {
    /// Caret position in the phone's mirror pixel space (top-left origin).
    /// Implies a focused field.
    Cursor { x: f32, y: f32 },
    /// A text field gained (`true`) or lost (`false`) focus on the phone. Drives
    /// "keyboard only types when the phone is in input mode".
    Focus(bool),
}

/// Parse a `PHONE_TO_PAD_INPUT_CURSOR_POSITION:` / `PHONE_TO_PAD_INPUT_READY:`
/// message. The caret point is `horizontal + cursorX`, `markerTop + cursorY`
/// (the insertion-marker offset plus the editor's on-screen translation).
pub fn parse_input_event(line: &str) -> Option<InputEvent> {
    if let Some(body) = line.strip_prefix("PHONE_TO_PAD_INPUT_CURSOR_POSITION:") {
        let v: serde_json::Value = serde_json::from_str(body).ok()?;
        // NB: `isInput` is unreliable here — phones on the screen-core SDK leave
        // it `false` even with a live caret — so a CURSOR_POSITION message always
        // means "there is a caret at (x, y)". Focus on/off comes from READY.
        let f = |k: &str| v.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
        return Some(InputEvent::Cursor {
            x: f("horizontal") + f("cursorX"),
            y: f("markerTop") + f("cursorY"),
        });
    }
    if let Some(body) = line.strip_prefix("PHONE_TO_PAD_INPUT_READY:") {
        let v: serde_json::Value = serde_json::from_str(body).ok()?;
        // READY's `isInput` IS the focus signal: true = a field is focused.
        let is_input = v.get("isInput").and_then(|x| x.as_bool()).unwrap_or(false);
        return Some(InputEvent::Focus(is_input));
    }
    None
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

    #[test]
    fn text_commit_shape() {
        let t = text_commit("你好a");
        assert!(t.starts_with("TEXT_EVENT:"));
        let v: serde_json::Value = serde_json::from_str(&t["TEXT_EVENT:".len()..]).unwrap();
        assert_eq!(v["textEventType"], 2);
        assert_eq!(v["text"], "你好a");
        assert_eq!(v["newCursorPosition"], 1);
    }

    #[test]
    fn text_delete_shape() {
        let t = text_delete_surrounding(1, 0);
        let v: serde_json::Value = serde_json::from_str(&t["TEXT_EVENT:".len()..]).unwrap();
        assert_eq!(v["textEventType"], 4);
        assert_eq!(v["beforeLength"], 1);
        assert_eq!(v["afterLength"], 0);
        assert!(v.get("text").is_none());
    }

    #[test]
    fn input_event_parse() {
        assert_eq!(parse_input_event("MOUSE_EVENT:{}"), None);
        assert_eq!(
            parse_input_event(r#"PHONE_TO_PAD_INPUT_CURSOR_POSITION:{"isInput":true,"horizontal":100.0,"markerTop":200.0,"cursorX":5.0,"cursorY":7.0}"#),
            Some(InputEvent::Cursor { x: 105.0, y: 207.0 })
        );
        // isInput=false on a CURSOR_POSITION is still a caret (core-SDK quirk).
        assert_eq!(
            parse_input_event(r#"PHONE_TO_PAD_INPUT_CURSOR_POSITION:{"isInput":false,"horizontal":768.0,"cursorX":160.0,"markerTop":140.0,"cursorY":221.0}"#),
            Some(InputEvent::Cursor { x: 928.0, y: 361.0 })
        );
        assert_eq!(
            parse_input_event(r#"PHONE_TO_PAD_INPUT_READY:{"isInput":false}"#),
            Some(InputEvent::Focus(false))
        );
        assert_eq!(
            parse_input_event(r#"PHONE_TO_PAD_INPUT_READY:{"isInput":true}"#),
            Some(InputEvent::Focus(true))
        );
    }

    #[test]
    fn keycode_event_shape() {
        let k = keycode_event(KeyAction::Down, 4, 0, 0);
        assert!(k.starts_with("KEYCODE_EVENT:"));
        let v: serde_json::Value = serde_json::from_str(&k["KEYCODE_EVENT:".len()..]).unwrap();
        assert_eq!(v["action"], 0);
        assert_eq!(v["keycode"], 4);
        assert_eq!(v["metastate"], 0);
        assert_eq!(v["scancode"], 0);
        assert_eq!(keycode_event(KeyAction::Up, 187, 0, 0).matches("\"action\":1").count(), 1);
    }
}
