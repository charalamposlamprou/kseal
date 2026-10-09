//! Clipboard: the system clipboard via arboard, or an OSC 52 escape to the
//! terminal — which reaches the LOCAL clipboard over SSH and works headless,
//! where arboard has no display to talk to.

use std::sync::Mutex;

/// Kept alive for the app's lifetime: on X11 the clipboard contents are
/// served by the process that owns them, so dropping it would empty it.
static CLIP: Mutex<Option<arboard::Clipboard>> = Mutex::new(None);

/// Over SSH the system clipboard (if any) is the REMOTE one — use OSC 52.
pub fn prefer_osc52() -> bool {
    std::env::var_os("SSH_TTY").is_some() || std::env::var_os("SSH_CONNECTION").is_some()
}

/// Set the system clipboard. Blocking — run it off the UI thread.
pub fn system_copy(text: &str) -> Result<(), String> {
    let mut guard = CLIP.lock().map_err(|e| e.to_string())?;
    if guard.is_none() {
        *guard = Some(arboard::Clipboard::new().map_err(|e| e.to_string())?);
    }
    guard.as_mut().expect("initialised above").set_text(text).map_err(|e| e.to_string())
}

/// The OSC 52 "set clipboard" sequence, wrapped for tmux passthrough.
pub fn osc52(text: &str) -> String {
    let seq = format!("\x1b]52;c;{}\x07", crate::core::b64_encode(text));
    if std::env::var_os("TMUX").is_some() {
        format!("\x1bPtmux;{}\x1b\\", seq.replace('\x1b', "\x1b\x1b"))
    } else {
        seq
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn osc52_sequence() {
        if std::env::var_os("TMUX").is_none() {
            assert_eq!(super::osc52("hi"), "\x1b]52;c;aGk=\x07");
        }
    }
}
