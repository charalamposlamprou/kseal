//! Small reusable widgets: a single-line text input and a filterable picker.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::prelude::*;

pub const MASK: char = '•';

/// Single-line text input with a char-indexed cursor.
#[derive(Debug, Clone, Default)]
pub struct Input {
    value: String,
    cursor: usize, // in chars
}

impl Input {
    pub fn new(v: impl Into<String>) -> Self {
        let value = v.into();
        let cursor = value.chars().count();
        Self { value, cursor }
    }
    pub fn value(&self) -> &str {
        &self.value
    }
    pub fn set(&mut self, v: impl Into<String>) {
        *self = Self::new(v);
    }
    pub fn clear(&mut self) {
        self.set("");
    }
    fn byte_at(&self, char_idx: usize) -> usize {
        self.value.char_indices().nth(char_idx).map_or(self.value.len(), |(i, _)| i)
    }
    pub fn insert_str(&mut self, s: &str) {
        let at = self.byte_at(self.cursor);
        self.value.insert_str(at, s);
        self.cursor += s.chars().count();
    }

    /// Handle an editing key. Returns true if the value changed.
    pub fn handle(&mut self, k: KeyEvent) -> bool {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let len = self.value.chars().count();
        match k.code {
            KeyCode::Char('u') if ctrl => {
                let changed = !self.value.is_empty();
                self.clear();
                return changed;
            }
            KeyCode::Char('a') if ctrl => self.cursor = 0,
            KeyCode::Char(c) if !ctrl => {
                self.insert_str(c.encode_utf8(&mut [0; 4]));
                return true;
            }
            KeyCode::Backspace if self.cursor > 0 => {
                self.cursor -= 1;
                let at = self.byte_at(self.cursor);
                self.value.remove(at);
                return true;
            }
            KeyCode::Delete if self.cursor < len => {
                let at = self.byte_at(self.cursor);
                self.value.remove(at);
                return true;
            }
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(len),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = len,
            _ => {}
        }
        false
    }

    /// Render text (optionally masked) scrolled so the cursor stays visible.
    /// Returns the line and the cursor column relative to `width`.
    pub fn view(&self, width: u16, masked: bool) -> (String, u16) {
        let chars: Vec<char> = if masked {
            std::iter::repeat_n(MASK, self.value.chars().count()).collect()
        } else {
            self.value.chars().map(visible).collect()
        };
        let w = width.max(1) as usize;
        let start = self.cursor.saturating_sub(w.saturating_sub(1));
        let shown: String = chars.iter().skip(start).take(w).collect();
        (shown, (self.cursor - start) as u16)
    }
}

/// Make control characters visible in a single-line view.
pub fn visible(c: char) -> char {
    match c {
        '\n' => '⏎',
        '\t' => '⇥',
        c if c.is_control() => '�',
        c => c,
    }
}

pub fn one_line(s: &str) -> String {
    s.chars().map(visible).collect()
}

/// A modal list picker with type-to-filter.
#[derive(Debug, Clone)]
pub struct Picker {
    pub title: String,
    pub items: Vec<String>,
    pub filter: Input,
    pub selected: usize,
    /// Allow accepting the typed filter text as a custom value (e.g. a custom Secret type).
    pub allow_custom: bool,
}

impl Picker {
    pub fn new(title: impl Into<String>, items: Vec<String>, current: &str, allow_custom: bool) -> Self {
        let mut p = Self { title: title.into(), items, filter: Input::default(), selected: 0, allow_custom };
        if let Some(i) = p.items.iter().position(|s| s == current) {
            p.selected = i;
        }
        p
    }
    pub fn visible(&self) -> Vec<&String> {
        let f = self.filter.value().to_lowercase();
        self.items.iter().filter(|s| f.is_empty() || s.to_lowercase().contains(&f)).collect()
    }
    /// Returns Some(choice) when the user accepts.
    pub fn handle(&mut self, k: KeyEvent) -> Option<String> {
        let n = self.visible().len();
        match k.code {
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down => self.selected = (self.selected + 1).min(n.saturating_sub(1)),
            KeyCode::PageUp => self.selected = self.selected.saturating_sub(10),
            KeyCode::PageDown => self.selected = (self.selected + 10).min(n.saturating_sub(1)),
            KeyCode::Enter => {
                let vis = self.visible();
                if let Some(s) = vis.get(self.selected) {
                    return Some((*s).clone());
                }
                if self.allow_custom && !self.filter.value().is_empty() {
                    return Some(self.filter.value().to_string());
                }
            }
            _ => {
                if self.filter.handle(k) {
                    self.selected = 0;
                }
            }
        }
        None
    }
}

/// Centered rect of the given size (clamped to `area`).
pub fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h }
}

/// Expand a leading `~` to the home directory.
pub fn expand_tilde(p: &str) -> std::path::PathBuf {
    if let Some(rest) = p.strip_prefix("~/").or_else(|| (p == "~").then_some("")) {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return std::path::PathBuf::from(home).join(rest);
        }
    }
    std::path::PathBuf::from(p)
}

/// Tab-completion for a path input: extends to the longest common prefix of
/// matching directory entries (appending `/` for a unique directory).
pub fn complete_path(input: &str) -> Option<String> {
    let sep_idx = input.rfind(['/', std::path::MAIN_SEPARATOR]).map(|i| i + 1).unwrap_or(0);
    let (dir_part, stem) = input.split_at(sep_idx);
    let dir = if dir_part.is_empty() { std::path::PathBuf::from(".") } else { expand_tilde(dir_part) };
    let mut matches: Vec<(String, bool)> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            (name.starts_with(stem) && (stem.starts_with('.') || !name.starts_with('.')))
                .then(|| (name, e.file_type().map(|t| t.is_dir()).unwrap_or(false)))
        })
        .collect();
    if matches.is_empty() {
        return None;
    }
    matches.sort();
    let first = &matches[0].0;
    let mut common = first.len();
    for (m, _) in &matches[1..] {
        common = first.char_indices().zip(m.chars()).take_while(|((_, a), b)| a == b).count().min(common);
    }
    let prefix: String = first.chars().take(common).collect();
    let mut out = format!("{dir_part}{prefix}");
    if matches.len() == 1 && matches[0].1 {
        out.push('/');
    }
    (out != input).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEvent;

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    #[test]
    fn input_editing_is_char_safe() {
        let mut i = Input::new("café");
        i.handle(key(KeyCode::Backspace));
        assert_eq!(i.value(), "caf");
        i.handle(key(KeyCode::Home));
        i.handle(key(KeyCode::Char('ü')));
        assert_eq!(i.value(), "ücaf");
        i.handle(key(KeyCode::Delete));
        assert_eq!(i.value(), "üaf");
        let (s, cur) = i.view(10, true);
        assert_eq!((s.as_str(), cur), ("•••", 1));
    }

    #[test]
    fn picker_filters_and_accepts_custom() {
        let mut p = Picker::new("t", vec!["Opaque".into(), "kubernetes.io/tls".into()], "Opaque", true);
        for c in "tls".chars() {
            p.handle(key(KeyCode::Char(c)));
        }
        assert_eq!(p.handle(key(KeyCode::Enter)).as_deref(), Some("kubernetes.io/tls"));
        let mut p = Picker::new("t", vec!["Opaque".into()], "", true);
        for c in "example.com/x".chars() {
            p.handle(key(KeyCode::Char(c)));
        }
        assert_eq!(p.handle(key(KeyCode::Enter)).as_deref(), Some("example.com/x"));
    }

    #[test]
    fn path_completion() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("prod.env"), "").unwrap();
        std::fs::write(d.path().join("prod.yaml"), "").unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        let base = format!("{}/", d.path().display());
        assert_eq!(complete_path(&format!("{base}pr")), Some(format!("{base}prod.")));
        assert_eq!(complete_path(&format!("{base}s")), Some(format!("{base}sub/")));
        assert_eq!(complete_path(&format!("{base}zzz")), None);
    }
}
