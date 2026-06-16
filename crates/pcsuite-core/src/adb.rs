//! Thin async wrapper around the `adb` CLI (used only by the USB path).

use anyhow::{Context, Result};
use tokio::process::Command;

/// Resolve the adb binary: explicit override, the standard macOS SDK location,
/// then `adb` on `PATH`.
pub fn resolve_adb(explicit: Option<&str>) -> String {
    if let Some(p) = explicit {
        return p.to_string();
    }
    if let Ok(home) = std::env::var("HOME") {
        let candidate = format!("{home}/Library/Android/sdk/platform-tools/adb");
        if std::path::Path::new(&candidate).exists() {
            return candidate;
        }
    }
    "adb".to_string()
}

/// Run `adb <args...>` and return stdout (stderr is folded in on failure).
pub async fn run(adb: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(adb)
        .args(args)
        .output()
        .await
        .with_context(|| format!("spawn `{adb} {}`", args.join(" ")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("adb {} failed: {}", args.join(" "), err.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Best-effort `adb` call that ignores failures (for wake/keyguard nudges).
pub async fn run_ok(adb: &str, args: &[&str]) {
    let _ = Command::new(adb).args(args).output().await;
}
