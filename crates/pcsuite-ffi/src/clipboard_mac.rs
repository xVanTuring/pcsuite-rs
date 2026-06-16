//! Built-in macOS clipboard backend (text via `pbcopy`/`pbpaste`, images via
//! `osascript`). Lets the SwiftUI app call `enable_clipboard()` and get full
//! text+image sync with no Swift-side work. (Swap for an NSPasteboard-backed
//! delegate later if you want tighter integration.)

use anyhow::Result;
use pcsuite_core::ClipboardBackend;

pub struct MacClipboard;

impl ClipboardBackend for MacClipboard {
    fn get_text(&self) -> Option<String> {
        let out = std::process::Command::new("pbpaste").output().ok()?;
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn set_text(&self, text: &str) -> Result<()> {
        use std::io::Write;
        let mut child = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()?;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(text.as_bytes())?;
        }
        child.wait()?;
        Ok(())
    }

    fn image_signature(&self) -> Option<String> {
        let out = std::process::Command::new("osascript")
            .args(["-e", "clipboard info"])
            .output()
            .ok()?;
        let info = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let is_image = ["picture", "PNGf", "TIFF", "8BPS", "JPEG"]
            .iter()
            .any(|k| info.contains(k));
        is_image.then_some(info)
    }

    fn get_image(&self) -> Option<Vec<u8>> {
        let dest = std::env::temp_dir().join("pcsuite_clip_get.jpeg");
        let dest_s = dest.to_string_lossy();
        let script = format!(
            "set d to (the clipboard as JPEG picture)\n\
             set f to (open for access (POSIX file \"{dest_s}\") with write permission)\n\
             set eof f to 0\nwrite d to f\nclose access f"
        );
        let ok = std::process::Command::new("osascript")
            .args(["-e", &script])
            .output()
            .ok()
            .is_some_and(|o| o.status.success());
        if !ok {
            return None;
        }
        std::fs::read(&dest).ok().filter(|b| !b.is_empty())
    }

    fn set_image(&self, data: &[u8], mime: &str) -> Result<()> {
        let (ext, class) = match mime {
            "image/png" => ("png", "«class PNGf»"),
            "image/gif" => ("gif", "GIF picture"),
            "image/tiff" => ("tiff", "TIFF picture"),
            "image/bmp" => ("bmp", "«class BMP »"),
            _ => ("jpeg", "JPEG picture"),
        };
        let path = std::env::temp_dir().join(format!("pcsuite_clip_set.{ext}"));
        std::fs::write(&path, data)?;
        let path_s = path.to_string_lossy();
        let script = format!("set the clipboard to (read (POSIX file \"{path_s}\") as {class})");
        let out = std::process::Command::new("osascript")
            .args(["-e", &script])
            .output()?;
        if !out.status.success() {
            anyhow::bail!("osascript set image: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }
}
