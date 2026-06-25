//! Phone device facts (storage capacity, model, OS) via the 10380 `/base-info`
//! HTTP gateway — the data the desktop app shows in its device panel.
//!
//! `POST /base-info` returns a `ChannelBean{code,data,message}`; the phone fills
//! `data` (a `BaseInfoBean`) with storage + identity. Storage is computed on the
//! phone via `StatFs`: `totalStorage` rounded up to a power-of-two GB (the marketing
//! size), `availableStorage` the free GB to two decimals, `availableByte` the exact
//! free bytes. Reuses [`crate::mdfs::post_json`] — same gateway, same `newToken`/
//! `deviceId` routing headers.

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::config;
use crate::mdfs;

/// Selected phone facts from `POST /base-info` (`ChannelBean.data`).
#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    /// Nominal total storage in GB, rounded to a power of two ("128"/"256"/"512").
    pub total_storage_gb: String,
    /// Free storage in GB, two decimals (e.g. "182.34").
    pub available_storage_gb: String,
    /// Exact free bytes (`availableByte`).
    pub available_bytes: u64,
    pub mobile_brand: String,
    pub mobile_device_name: String,
    /// Internal product/model code (`product`).
    pub product: String,
    pub android_version: String,
    /// OriginOS/Funtouch version string (`osVersion`).
    pub os_version: String,
    pub width_pixels: i64,
    pub height_pixels: i64,
    pub fold_screen: bool,
    /// Masked login account, e.g. "138****000".
    pub vivo_account: String,
    /// Real vivo-account openId (16-hex) — the value the phone matches LAN sign +
    /// super-clipboard against. The phone returns it here (`BaseInfoBean.openid`,
    /// from `BBKAccountManager.getOpenid()`), so a session that connected without a
    /// pre-set openId (e.g. QR pairing) can learn it and self-fill. Empty if the
    /// phone isn't logged in.
    pub open_id: String,
}

/// Fetch the phone's `/base-info` over the 10380 control-HTTP gateway. `device_id`
/// is the phone's `mobileDeviceId` (from [`crate::Session::phone_info`]); `token` is
/// the session connect-token.
pub async fn fetch(host: &str, token: &str, device_id: &str) -> Result<DeviceInfo> {
    // The controller only needs a non-null request body; identify ourselves but omit
    // `token` — a non-empty PC token that mismatched the phone's stored remote token
    // makes it bail early, whereas an empty token skips that equality check.
    //
    // `pc_name` is the PC display name the phone shows on its "已连接 \"%s\"" card:
    // its `ControlPhoneInfoController` does `F0(baseInfoBean.getPcHostname())` —
    // `pcHostname` is `@SerializedName("pc_name")` — and that field IS the card text.
    // Omitting it makes Gson leave it null, so the phone overwrites the connect-time
    // name with `"null"` (USB has no connect-time name → `""`). Send our device name
    // here so every transport (USB / QR / LAN) shows the real PC name post-connect.
    let body = json!({
        "pcDeviceId": config::clip_pc_id(),
        "pcSystemType": "mac",
        "pc_name": config::default_identity().device_name,
    });
    let reply = mdfs::post_json(host, token, device_id, "/base-info", &body)
        .await
        .context("/base-info")?;
    Ok(parse_base_info(&reply))
}

/// Best-effort *early* PC-name announce, for the USB path only.
///
/// The phone freezes its "已连接 \"%s\"" notification text at its internal
/// connect-success event (which fires when the heartbeat WS comes up), reading a
/// field it only learns from `/base-info`'s `pc_name`. For USB nothing sets that
/// field earlier (unlike LAN/QR, whose connect dialog seeds it), so the normal
/// post-connect [`fetch`] lands too late and the notification keeps the stale empty
/// name. Sending a minimal `/base-info` here — after the USB `/version` handshake
/// but *before* opening the WS — sets the name in time.
///
/// Routes by path with an empty `deviceId` header (same as the USB `/version`
/// probe); the phone applies `pc_name` before any token check, so the bare token is
/// fine. The caller ignores the result — on any failure the later [`fetch`] still
/// updates the in-app device panel / "设备互联" name.
pub async fn announce_pc_name(host: &str, token: &str, pc_name: &str) -> Result<()> {
    let body = json!({
        "pcDeviceId": config::clip_pc_id(),
        "pcSystemType": "mac",
        "pc_name": pc_name,
    });
    mdfs::post_json(host, token, "", "/base-info", &body)
        .await
        .context("/base-info (early announce)")?;
    Ok(())
}

/// Extract a [`DeviceInfo`] from a `/base-info` reply. Unwraps the `ChannelBean`
/// envelope (`{code,data,message}`) and tolerates a flat object; missing fields fall
/// back to defaults.
fn parse_base_info(reply: &Value) -> DeviceInfo {
    let d = reply.get("data").filter(|v| v.is_object()).unwrap_or(reply);
    let text = |k: &str| d.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let int = |k: &str| d.get(k).and_then(Value::as_i64).unwrap_or(0);

    DeviceInfo {
        total_storage_gb: text("totalStorage"),
        available_storage_gb: text("availableStorage"),
        available_bytes: d.get("availableByte").and_then(Value::as_u64).unwrap_or(0),
        mobile_brand: text("mobileBrand"),
        mobile_device_name: text("mobileDeviceName"),
        product: text("product"),
        android_version: text("androidVersion"),
        os_version: text("osVersion"),
        width_pixels: int("widthPixels"),
        height_pixels: int("heightPixels"),
        fold_screen: d.get("isFoldScreen").and_then(Value::as_bool).unwrap_or(false),
        vivo_account: text("vivoAccount"),
        open_id: text("openid"), // BaseInfoBean.openid — lowercase, no @SerializedName
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_real_base_info() {
        // Shape captured from a real iQOO 15 (2026-06-24): ChannelBean envelope
        // with storage in `data`.
        let reply = json!({
            "code": "0000",
            "message": "success",
            "data": {
                "mobileBrand": "vivo",
                "mobileDeviceName": "iQOO 15",
                "product": "PD2505",
                "androidVersion": "16",
                "osVersion": "16.0",
                "widthPixels": 1440,
                "heightPixels": 3168,
                "isFoldScreen": false,
                "totalStorage": "512",
                "availableStorage": "327.55",
                "availableByte": 327_553_000_000u64,
                "vivoAccount": "138****000",
                "openid": "66ee212fde7a06a1"
            }
        });
        let d = parse_base_info(&reply);
        assert_eq!(d.total_storage_gb, "512");
        assert_eq!(d.available_storage_gb, "327.55");
        assert_eq!(d.available_bytes, 327_553_000_000);
        assert_eq!(d.mobile_device_name, "iQOO 15");
        assert_eq!(d.product, "PD2505");
        assert_eq!(d.width_pixels, 1440);
        assert!(!d.fold_screen);
        assert_eq!(d.open_id, "66ee212fde7a06a1");
        assert_eq!(d.vivo_account, "138****000");
    }

    #[test]
    fn parse_flat_and_missing() {
        // No envelope + sparse fields → defaults, no panic.
        let d = parse_base_info(&json!({ "totalStorage": "256" }));
        assert_eq!(d.total_storage_gb, "256");
        assert_eq!(d.available_bytes, 0);
        assert_eq!(d.mobile_device_name, "");
    }
}
