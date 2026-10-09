//! TUI state and update logic, Elm-style: [`App`] is the whole model, keys
//! and background results ([`Msg`]) are the only inputs, and anything that
//! touches the outside world (cluster, files, clipboard, `$EDITOR`) is queued
//! as an [`Effect`] for the event loop to run. Nothing here blocks or does
//! I/O, so every guard below is unit-tested without a terminal or a cluster.
//!
//! ## Staleness guards (same rules as the Tk app)
//!
//! * `out_gen` — bumped whenever what the YAML / sealed panes describe changes
//!   ([`App::invalidate_outputs`]). Seal / validate / template / editor-file
//!   results capture it at dispatch and are discarded on landing if it moved.
//! * `kv_edit_gen` — bumped on every row add / remove / real edit. Results
//!   that would REPLACE all rows (file open, template load) also check it, so
//!   an in-place edit made while they were in flight is never clobbered.
//! * newest-wins tokens per fetch key ([`App::claim`]) — two in-flight
//!   lookups for the SAME selection can't be told apart by value checks, so
//!   only the latest claim lands. The template key includes (ctx, ns, secret)
//!   so switching away and back doesn't drop a still-valid fetch.
//! * controller cache per context — `Some(None)` is "looked up, no
//!   controller", distinct from absent ("never looked up"). Ctrl+R clears it
//!   and bumps `ctl_refresh_gen`; a successful lookup dispatched before the
//!   refresh is discarded and re-run rather than shown or cached.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;
use serde_json::Value;

use super::widgets::{Input, Picker, complete_path};
use crate::cluster::Contexts;
use crate::core::{self, Carryover, Entry, EntryKind, FileKind, Pairs};
use crate::seal::Scope;

pub const STATUS_DURATION: Duration = Duration::from_millis(4000);
/// Lossy-result statuses (metadata skipped / binary dropped) linger longer
/// so they survive a glance away.
pub const WARN_DURATION: Duration = Duration::from_millis(10000);

pub type Tok = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Encode,
    Decode,
    Seal,
}

impl Tab {
    pub const ALL: [Tab; 3] = [Tab::Encode, Tab::Decode, Tab::Seal];
    pub fn title(self) -> &'static str {
        match self {
            Tab::Encode => "Encode",
            Tab::Decode => "Decode",
            Tab::Seal => "Seal",
        }
    }
    fn idx(self) -> usize {
        self as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    // Encode
    SvIn,
    SvOut,
    EncCtx,
    EncNs,
    EncSecret,
    Rows,
    SecName,
    SecNs,
    SecType,
    Yaml,
    // Decode
    DvIn,
    DvOut,
    DecRows,
    // Seal
    SealCtx,
    Scope,
    CtlName,
    CtlNs,
    Cert,
    Sealed,
}

impl Focus {
    pub fn order(tab: Tab) -> &'static [Focus] {
        use Focus::*;
        match tab {
            Tab::Encode => &[SvIn, SvOut, EncCtx, EncNs, EncSecret, Rows, SecName, SecNs, SecType, Yaml],
            Tab::Decode => &[DvIn, DvOut, DecRows],
            Tab::Seal => &[SealCtx, Scope, CtlName, CtlNs, Cert, Sealed],
        }
    }
    /// Fields that take typed text (so `?` and letters are input, not keys).
    pub fn is_text(self) -> bool {
        use Focus::*;
        matches!(self, SvIn | DvIn | SecName | SecNs | CtlName | CtlNs | Cert)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ok,
    Err,
    Dim,
}

#[derive(Debug, Clone)]
pub struct Status {
    pub msg: String,
    pub kind: Kind,
    until: Option<Instant>,
}

impl Status {
    fn ready() -> Self {
        Self { msg: "Ready".into(), kind: Kind::Dim, until: None }
    }
}

/// One key/value row of the Encode editor. A `binary` row holds its ORIGINAL
/// base64 in `value`: it can't be edited as text, and Generate re-emits it
/// verbatim (unless an editable row of the same key overrides it).
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub key: String,
    pub value: String,
    pub binary: bool,
    pub shown: bool,
}

/// One row of the Decode table. `value` is what Copy hands back (decoded
/// text, or the original string for binary / invalid entries).
#[derive(Debug, Clone)]
pub struct DecRow {
    pub key: String,
    pub value: String,
    pub kind: EntryKind,
    pub shown: bool,
}

impl DecRow {
    pub fn display(&self) -> String {
        match self.kind {
            EntryKind::Binary => "⟨binary — copy gives base64⟩".into(),
            EntryKind::Invalid => "⟨not valid base64 — copy gives raw value⟩".into(),
            EntryKind::Text if self.shown => self.value.clone(),
            EntryKind::Text => "•".repeat(self.value.chars().count().min(32)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickTarget {
    EncCtx,
    EncNs,
    EncSecret,
    SecType,
    SealCtx,
    Scope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathPurpose {
    /// Encode: .env or Secret YAML into the editor; Decode: Secret YAML into
    /// the table; Seal: the offline certificate.
    Open(Tab),
    Save(SaveWhat),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveWhat {
    Yaml,
    Sealed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadPurpose {
    Editor,
    Decode,
}

#[derive(Debug)]
pub enum Modal {
    Picker { target: PickTarget, picker: Picker },
    Path { purpose: PathPurpose, input: Input },
    RowEdit { idx: Option<usize>, key: Input, value: Input, on_value: bool, shown: bool },
    Overwrite { path: String, content: String, what: SaveWhat, skipped: usize },
    Help,
}

/// Side effects for the event loop to run. Results come back as [`Msg`]s.
#[derive(Debug)]
pub enum Effect {
    LoadContexts {
        tok: Tok,
    },
    LoadNamespaces {
        tok: Tok,
        ctx: String,
    },
    LoadSecrets {
        tok: Tok,
        ctx: String,
        ns: String,
    },
    DetectController {
        tok: Tok,
        ctx: String,
        ctl_gen: u64,
    },
    FetchTemplate {
        tok: Tok,
        ctx: String,
        ns: String,
        sec: String,
        out_gen: u64,
        kv_gen: u64,
    },
    ReadFile {
        tok: Tok,
        purpose: ReadPurpose,
        path: String,
        out_gen: u64,
        kv_gen: u64,
    },
    WriteFile {
        path: String,
        content: String,
        overwrite: bool,
        what: SaveWhat,
        skipped: usize,
    },
    Seal {
        out_gen: u64,
        yaml: String,
        scope: Scope,
        ctx: String,
        cert: Option<String>,
        ctl: (String, String),
    },
    Validate {
        out_gen: u64,
        sealed: String,
        ctx: String,
        ctl: (String, String),
    },
    Copy {
        text: String,
        skipped: Option<usize>,
    },
    /// Clipboard fallback for SSH / headless: an OSC 52 escape to the terminal.
    Osc52 {
        text: String,
    },
    /// Suspend the TUI and edit one row's value in `$EDITOR`.
    EditValue {
        row: usize,
        key: String,
        value: String,
        kv_gen: u64,
    },
    ClearClients,
}

#[derive(Debug)]
pub enum WriteError {
    Exists(String),
    Io(String),
}

/// Background results.
#[derive(Debug)]
pub enum Msg {
    Contexts {
        tok: Tok,
        res: Result<Contexts, String>,
    },
    Namespaces {
        tok: Tok,
        ctx: String,
        res: Result<Vec<String>, String>,
    },
    Secrets {
        tok: Tok,
        ctx: String,
        ns: String,
        res: Result<Vec<String>, String>,
    },
    Controller {
        tok: Tok,
        ctx: String,
        ctl_gen: u64,
        res: Result<Option<(String, String)>, String>,
    },
    Template {
        tok: Tok,
        ctx: String,
        ns: String,
        sec: String,
        out_gen: u64,
        kv_gen: u64,
        res: Result<Value, String>,
    },
    FileRead {
        tok: Tok,
        purpose: ReadPurpose,
        path: String,
        out_gen: u64,
        kv_gen: u64,
        res: Result<String, String>,
    },
    Written {
        path: String,
        what: SaveWhat,
        skipped: usize,
        res: Result<(), WriteError>,
    },
    Sealed {
        out_gen: u64,
        res: Result<String, String>,
    },
    Validated {
        out_gen: u64,
        res: Result<bool, String>,
    },
    /// `Ok(how)` names the mechanism used; `Err` hands the text back so the
    /// app can fall back to OSC 52.
    Copied {
        skipped: Option<usize>,
        res: Result<&'static str, (String, String)>,
    },
    Edited {
        row: usize,
        key: String,
        original: String,
        kv_gen: u64,
        res: Result<String, String>,
    },
}

/// Heights of the scrollable areas from the last draw (for paging/clamping).
#[derive(Debug, Default, Clone, Copy)]
pub struct View {
    pub rows_h: u16,
    pub dec_h: u16,
    pub yaml_h: u16,
    pub sealed_h: u16,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Scroll {
    pub y: u16,
    pub x: u16,
}

pub struct App {
    pub tab: Tab,
    focus: [Focus; 3],
    pub modal: Option<Modal>,
    pub status: Status,
    pub quit: bool,
    pub effects: Vec<Effect>,
    pub view: View,
    next_tok: Tok,
    latest: HashMap<String, Tok>,

    // Encode — single value
    pub sv_in: Input,
    pub sv_shown: bool,
    // Encode — .env → Secret
    pub file_label: String,
    pub contexts: Vec<String>,
    pub enc_ctx: String,
    pub enc_ns: String,
    pub enc_sec: String,
    pub namespaces: Vec<String>,
    pub secrets: Vec<String>,
    pub rows: Vec<Row>,
    pub rows_state: TableState,
    pub sec_name: Input,
    pub sec_ns: Input,
    pub sec_type: String,
    /// Auto-guess the type from the keys while it was never chosen by hand
    /// (or set from a loaded doc).
    type_auto: bool,
    pub yaml_out: String,
    pub yaml_scroll: Scroll,
    carry: Carryover,
    pub skipped: usize,

    // Decode
    pub dv_in: Input,
    pub dv_shown: bool,
    pub dec_label: String,
    pub dec_hint: Option<String>,
    pub dec_rows: Vec<DecRow>,
    pub dec_state: TableState,

    // Seal
    pub seal_ctx: String,
    pub scope: Scope,
    pub ctl_name: Input,
    pub ctl_ns: Input,
    pub cert: Input,
    pub sealed_out: String,
    /// The sealed pane holds a real manifest (not an error dump). An explicit
    /// flag so Copy / Save / Validate never treat an error as a manifest.
    pub sealed_ok: bool,
    pub sealed_scroll: Scroll,
    pub sealing: bool,
    pub validating: bool,
    /// Context whose controller lookup is in flight.
    pub ctl_pending: Option<String>,
    ctl_cache: HashMap<String, Option<(String, String)>>,
    ctl_refresh_gen: u64,

    out_gen: u64,
    kv_edit_gen: u64,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            tab: Tab::Encode,
            focus: [Focus::SvIn, Focus::DvIn, Focus::SealCtx],
            modal: None,
            status: Status::ready(),
            quit: false,
            effects: vec![],
            view: View::default(),
            next_tok: 0,
            latest: HashMap::new(),
            sv_in: Input::default(),
            sv_shown: false,
            file_label: "(no file)".into(),
            contexts: vec![],
            enc_ctx: String::new(),
            enc_ns: String::new(),
            enc_sec: String::new(),
            namespaces: vec![],
            secrets: vec![],
            rows: vec![],
            rows_state: TableState::default(),
            sec_name: Input::new(core::DEF_NAME),
            sec_ns: Input::new(core::DEF_NS),
            sec_type: "Opaque".into(),
            type_auto: true,
            yaml_out: String::new(),
            yaml_scroll: Scroll::default(),
            carry: Carryover::default(),
            skipped: 0,
            dv_in: Input::default(),
            dv_shown: false,
            dec_label: "(no file)".into(),
            dec_hint: None,
            dec_rows: vec![],
            dec_state: TableState::default(),
            seal_ctx: String::new(),
            scope: Scope::Strict,
            ctl_name: Input::default(),
            ctl_ns: Input::default(),
            cert: Input::default(),
            sealed_out: String::new(),
            sealed_ok: false,
            sealed_scroll: Scroll::default(),
            sealing: false,
            validating: false,
            ctl_pending: None,
            ctl_cache: HashMap::new(),
            ctl_refresh_gen: 0,
            out_gen: 0,
            kv_edit_gen: 0,
        }
    }

    /// Kick off the initial context load.
    pub fn start(&mut self) {
        let tok = self.claim("contexts");
        self.effects.push(Effect::LoadContexts { tok });
    }

    pub fn focus(&self) -> Focus {
        self.focus[self.tab.idx()]
    }

    fn set_focus(&mut self, f: Focus) {
        self.focus[self.tab.idx()] = f;
    }

    // ------------------------------------------------------------ status

    pub fn set_status(&mut self, msg: impl Into<String>, kind: Kind) {
        self.status_for(msg, kind, STATUS_DURATION);
    }

    fn status_for(&mut self, msg: impl Into<String>, kind: Kind, d: Duration) {
        self.status = Status { msg: msg.into(), kind, until: Some(Instant::now() + d) };
    }

    /// Status for an action whose result derives from the generated YAML
    /// (Generate / Save / Seal / Copy): while metadata was skipped, an
    /// unqualified green success would contradict the pending loss.
    /// `skipped` is the count frozen at dispatch for async results.
    fn status_output(&mut self, msg: &str, skipped: Option<usize>) {
        let (m, warn) = core::qualify_output(msg, skipped.unwrap_or(self.skipped));
        if warn {
            self.status_for(m, Kind::Err, WARN_DURATION);
        } else {
            self.set_status(m, Kind::Ok);
        }
    }

    /// Expire the transient status line.
    pub fn tick(&mut self, now: Instant) {
        if self.status.until.is_some_and(|u| now >= u) {
            self.status = Status::ready();
        }
    }

    // ------------------------------------------------------------ guards

    /// Claim a newest-wins token for `key`, superseding any in-flight op
    /// under the same key.
    fn claim(&mut self, key: impl Into<String>) -> Tok {
        self.next_tok += 1;
        self.latest.insert(key.into(), self.next_tok);
        self.next_tok
    }

    fn is_latest(&self, key: &str, tok: Tok) -> bool {
        self.latest.get(key) == Some(&tok)
    }

    fn discard_stale(&mut self, out_gen: u64, verb: &str, hint: &str) -> bool {
        if out_gen == self.out_gen {
            return false;
        }
        self.set_status(format!("Editor changed during {verb} — stale result discarded{hint}"), Kind::Err);
        true
    }

    fn discard_if_kv_edited(&mut self, kv_gen: u64, verb: &str) -> bool {
        if kv_gen == self.kv_edit_gen {
            return false;
        }
        self.set_status(format!("Rows changed during {verb} — discarded to avoid overwriting your edit"), Kind::Err);
        true
    }

    /// The secret in the editor changed: generated YAML and sealed output
    /// describe the previous one, so clear both and advance the generation
    /// (in-flight seal / validate / load results become stale).
    fn invalidate_outputs(&mut self) {
        self.out_gen += 1;
        self.sealed_ok = false;
        self.yaml_out.clear();
        self.sealed_out.clear();
        self.yaml_scroll = Scroll::default();
        self.sealed_scroll = Scroll::default();
    }

    /// A row was added, removed or really edited.
    fn rows_changed(&mut self) {
        self.kv_edit_gen += 1;
        if self.type_auto {
            self.sec_type = core::guess_secret_type(self.rows.iter().map(|r| r.key.trim())).to_string();
        }
        let n = self.rows.len();
        match self.rows_state.selected() {
            _ if n == 0 => self.rows_state.select(None),
            None => self.rows_state.select(Some(0)),
            Some(i) if i >= n => self.rows_state.select(Some(n - 1)),
            _ => {}
        }
    }

    /// The per-secret state's single reset owner (binary passthrough lives in
    /// the rows themselves, so replacing the rows resets it too).
    fn reset_secret_state(&mut self) {
        self.carry = Carryover::default();
        self.skipped = 0;
    }

    /// Replace every row — the choke point for every load path.
    fn set_rows(&mut self, text: Pairs, binary: Pairs) {
        self.reset_secret_state();
        self.rows = text.into_iter().map(|(key, value)| Row { key, value, binary: false, shown: false }).collect();
        self.rows.extend(binary.into_iter().map(|(key, value)| Row { key, value, binary: true, shown: false }));
        self.rows_state.select(None);
        self.rows_changed();
        self.invalidate_outputs();
    }

    /// Fill name / namespace / type from a doc, capture its carry-over
    /// metadata, and invalidate outputs (a doc-driven identity change stales
    /// them whether or not rows were replaced). Rows first, then identity.
    fn set_identity(&mut self, doc: &Value, fb_name: &str, fb_ns: &str) {
        let (name, ns, type_) = core::secret_identity(doc);
        self.sec_name.set(if name.is_empty() { fb_name } else { &name });
        self.sec_ns.set(if ns.is_empty() { fb_ns } else { &ns });
        self.sec_type = type_;
        self.type_auto = false;
        (self.carry, self.skipped) = core::secret_carryover(doc);
        self.invalidate_outputs();
    }

    fn apply_secret_doc(&mut self, doc: &Value, entries: &[Entry], fb_name: &str, fb_ns: &str) -> (usize, usize) {
        let (text, binary) = core::split_entries(entries);
        let nb = binary.len();
        self.set_rows(text, binary);
        self.set_identity(doc, fb_name, fb_ns);
        (entries.len(), nb)
    }

    /// An entry-less Secret: inherit its identity, keep editable rows, but
    /// drop binary passthrough rows — they belong to the PREVIOUS secret and
    /// re-emitting them under the new identity would leak them.
    fn apply_identity_only(&mut self, doc: &Value, fb_name: &str, fb_ns: &str) -> usize {
        let before = self.rows.len();
        self.rows.retain(|r| !r.binary);
        let dropped = before - self.rows.len();
        if dropped > 0 {
            self.rows_changed();
        }
        self.reset_secret_state();
        self.set_identity(doc, fb_name, fb_ns);
        dropped
    }

    // ------------------------------------------------------------ derived

    pub fn sv_encoded(&self) -> String {
        core::b64_encode(self.sv_in.value())
    }

    pub fn dv_decoded(&self) -> Result<String, String> {
        let s = self.dv_in.value().trim();
        if s.is_empty() {
            return Ok(String::new());
        }
        core::b64_decode(s).map_err(|e| e.to_string())
    }

    pub fn skip_warning(&self) -> Option<String> {
        core::skip_warning(self.skipped)
    }

    /// Why Seal can't run right now, if it can't.
    pub fn seal_blocked(&self) -> Option<&'static str> {
        if self.sealing {
            Some("sealing…")
        } else if self.validating {
            Some("validating…")
        } else if self.cert.value().trim().is_empty() && self.detecting() {
            Some("detecting controller…")
        } else {
            None
        }
    }

    pub fn validate_blocked(&self) -> Option<&'static str> {
        if !self.sealed_ok {
            Some("seal first")
        } else if self.detecting() {
            Some("detecting controller…")
        } else if self.sealing {
            Some("sealing…")
        } else if self.validating {
            Some("validating…")
        } else {
            None
        }
    }

    pub fn detecting(&self) -> bool {
        self.ctl_pending.as_deref().is_some_and(|c| c == self.seal_ctx)
    }

    // ------------------------------------------------------------ keys

    pub fn on_key(&mut self, k: KeyEvent) {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(k.code, KeyCode::Char('c') | KeyCode::Char('q')) {
            self.quit = true;
            return;
        }
        if let Some(modal) = self.modal.take() {
            self.modal_key(modal, k);
            return;
        }
        match k.code {
            KeyCode::F(n @ 1..=3) => self.tab = Tab::ALL[n as usize - 1],
            KeyCode::Tab => self.cycle_focus(1),
            KeyCode::BackTab => self.cycle_focus(-1),
            KeyCode::Char(c) if ctrl => match c {
                'n' => self.tab = Tab::ALL[(self.tab.idx() + 1) % 3],
                'p' => self.tab = Tab::ALL[(self.tab.idx() + 2) % 3],
                'g' => {
                    self.generate();
                }
                'o' => self.open_prompt(),
                'l' => self.load_template(),
                'y' => self.copy_focused(),
                's' => self.save_prompt(),
                'k' => self.clear_focused(),
                'r' => self.refresh_contexts(),
                'e' => self.do_seal(),
                't' => self.do_validate(),
                'x' => self.toggle_show(),
                _ => self.field_key(k),
            },
            _ => self.field_key(k),
        }
    }

    fn cycle_focus(&mut self, d: isize) {
        let order = Focus::order(self.tab);
        let i = order.iter().position(|f| *f == self.focus()).unwrap_or(0) as isize;
        let n = order.len() as isize;
        self.set_focus(order[((i + d).rem_euclid(n)) as usize]);
    }

    fn field_key(&mut self, k: KeyEvent) {
        let f = self.focus();
        if !f.is_text() && k.code == KeyCode::Char('?') {
            self.modal = Some(Modal::Help);
            return;
        }
        match f {
            Focus::SvIn => {
                self.sv_in.handle(k);
            }
            Focus::DvIn => {
                self.dv_in.handle(k);
            }
            Focus::SecName => {
                self.sec_name.handle(k);
            }
            Focus::SecNs => {
                self.sec_ns.handle(k);
            }
            Focus::Cert => {
                self.cert.handle(k);
            }
            Focus::CtlName | Focus::CtlNs => {
                let input = if f == Focus::CtlName { &mut self.ctl_name } else { &mut self.ctl_ns };
                if input.handle(k) {
                    self.controller_edited();
                }
            }
            Focus::EncCtx | Focus::EncNs | Focus::EncSecret | Focus::SecType | Focus::SealCtx | Focus::Scope => {
                match k.code {
                    KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Down => self.open_picker(f),
                    KeyCode::Left | KeyCode::Right if f == Focus::Scope => {
                        let i = Scope::ALL.iter().position(|s| *s == self.scope).unwrap_or(0);
                        let d = if k.code == KeyCode::Right { 1 } else { 2 };
                        self.scope = Scope::ALL[(i + d) % 3];
                    }
                    _ => {}
                }
            }
            Focus::Rows => self.rows_key(k),
            Focus::DecRows => self.dec_key(k),
            Focus::Yaml => scroll_key(&mut self.yaml_scroll, k, self.view.yaml_h, &self.yaml_out),
            Focus::Sealed => scroll_key(&mut self.sealed_scroll, k, self.view.sealed_h, &self.sealed_out),
            Focus::SvOut | Focus::DvOut => {}
        }
    }

    /// The user typed into a controller field: their value is now the newest,
    /// so drop any in-flight detection that would overwrite it.
    fn controller_edited(&mut self) {
        if self.ctl_pending.is_some() {
            self.claim("controller");
            self.ctl_pending = None;
        }
    }

    fn rows_key(&mut self, k: KeyEvent) {
        let n = self.rows.len();
        let sel = self.rows_state.selected();
        match k.code {
            KeyCode::Char('a') => {
                self.modal = Some(Modal::RowEdit {
                    idx: None,
                    key: Input::default(),
                    value: Input::default(),
                    on_value: false,
                    shown: false,
                })
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                if let Some(i) = sel.filter(|&i| i < n) {
                    let r = self.rows.remove(i);
                    self.rows_changed();
                    self.set_status(format!("Deleted {}", r.key), Kind::Dim);
                }
            }
            KeyCode::Enter => {
                if let Some(r) = sel.and_then(|i| self.rows.get(i)) {
                    if r.binary {
                        self.binary_row_hint();
                    } else {
                        self.modal = Some(Modal::RowEdit {
                            idx: sel,
                            key: Input::new(r.key.clone()),
                            value: Input::new(r.value.clone()),
                            on_value: true,
                            shown: r.shown,
                        });
                    }
                }
            }
            KeyCode::Char('e') => {
                if let Some(i) = sel.filter(|&i| i < n) {
                    let r = &self.rows[i];
                    if r.binary {
                        self.binary_row_hint();
                    } else {
                        let (key, value) = (r.key.clone(), r.value.clone());
                        self.effects.push(Effect::EditValue { row: i, key, value, kv_gen: self.kv_edit_gen });
                    }
                }
            }
            KeyCode::Char('v') => {
                if let Some(r) = sel.and_then(|i| self.rows.get_mut(i)) {
                    r.shown = !r.shown;
                }
            }
            KeyCode::Char('V') => self.rows_show_all(),
            _ => list_nav(&mut self.rows_state, k, n, self.view.rows_h),
        }
    }

    fn binary_row_hint(&mut self) {
        self.set_status("Binary value — kept as-is on Generate (d deletes it)", Kind::Dim);
    }

    fn rows_show_all(&mut self) {
        let show = self.rows.iter().any(|r| !r.binary && !r.shown);
        self.rows.iter_mut().for_each(|r| r.shown = show);
    }

    fn dec_key(&mut self, k: KeyEvent) {
        let sel = self.dec_state.selected();
        match k.code {
            KeyCode::Char('v') | KeyCode::Enter => {
                if let Some(r) = sel.and_then(|i| self.dec_rows.get_mut(i)) {
                    r.shown = !r.shown;
                }
            }
            KeyCode::Char('V') => self.dec_show_all(),
            _ => list_nav(&mut self.dec_state, k, self.dec_rows.len(), self.view.dec_h),
        }
    }

    fn dec_show_all(&mut self) {
        let show = self.dec_rows.iter().any(|r| r.kind == EntryKind::Text && !r.shown);
        self.dec_rows.iter_mut().for_each(|r| r.shown = show);
    }

    fn toggle_show(&mut self) {
        match self.focus() {
            Focus::SvIn | Focus::SvOut => self.sv_shown = !self.sv_shown,
            Focus::DvIn | Focus::DvOut => self.dv_shown = !self.dv_shown,
            Focus::Rows => self.rows_show_all(),
            Focus::DecRows => self.dec_show_all(),
            _ => match self.tab {
                Tab::Encode => self.rows_show_all(),
                Tab::Decode => self.dec_show_all(),
                Tab::Seal => {}
            },
        }
    }

    pub fn on_paste(&mut self, s: String) {
        // Terminals send pasted newlines as CR; values (PEM, JSON) keep them
        // as LF, single-line fields drop them.
        let value = s.replace("\r\n", "\n").replace('\r', "\n");
        let line: String = value.chars().filter(|&c| c != '\n').collect();
        match &mut self.modal {
            Some(Modal::RowEdit { key, value: v, on_value, .. }) => {
                if *on_value {
                    v.insert_str(&value)
                } else {
                    key.insert_str(&line)
                }
            }
            Some(Modal::Path { input, .. }) => input.insert_str(&line),
            Some(Modal::Picker { picker, .. }) => {
                picker.filter.insert_str(&line);
                picker.selected = 0;
            }
            Some(_) => {}
            None => match self.focus() {
                Focus::SvIn => self.sv_in.insert_str(&value),
                Focus::DvIn => self.dv_in.insert_str(&value),
                Focus::SecName => self.sec_name.insert_str(&line),
                Focus::SecNs => self.sec_ns.insert_str(&line),
                Focus::Cert => self.cert.insert_str(&line),
                Focus::CtlName => {
                    self.ctl_name.insert_str(&line);
                    self.controller_edited();
                }
                Focus::CtlNs => {
                    self.ctl_ns.insert_str(&line);
                    self.controller_edited();
                }
                _ => {}
            },
        }
    }

    // ------------------------------------------------------------ modals

    fn modal_key(&mut self, modal: Modal, k: KeyEvent) {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        match modal {
            Modal::Help => {} // any key closes
            Modal::Picker { target, mut picker } => {
                if k.code == KeyCode::Esc {
                    return;
                }
                match picker.handle(k) {
                    Some(choice) => self.picked(target, choice),
                    None => self.modal = Some(Modal::Picker { target, picker }),
                }
            }
            Modal::Path { purpose, mut input } => match k.code {
                KeyCode::Esc => {}
                KeyCode::Tab => {
                    if let Some(c) = complete_path(input.value()) {
                        input.set(c);
                    }
                    self.modal = Some(Modal::Path { purpose, input });
                }
                KeyCode::Enter => {
                    let path = input.value().trim().to_string();
                    if path.is_empty() {
                        self.modal = Some(Modal::Path { purpose, input });
                    } else {
                        self.path_chosen(purpose, path);
                    }
                }
                _ => {
                    input.handle(k);
                    self.modal = Some(Modal::Path { purpose, input });
                }
            },
            Modal::RowEdit { idx, mut key, mut value, mut on_value, mut shown } => {
                match k.code {
                    KeyCode::Esc => return,
                    KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down => on_value = !on_value,
                    KeyCode::Enter if !on_value => on_value = true,
                    KeyCode::Enter => {
                        self.row_saved(idx, key.value().to_string(), value.value().to_string(), shown);
                        return;
                    }
                    KeyCode::Char('x') if ctrl => shown = !shown,
                    _ => {
                        if on_value {
                            value.handle(k);
                        } else {
                            key.handle(k);
                        }
                    }
                }
                self.modal = Some(Modal::RowEdit { idx, key, value, on_value, shown });
            }
            Modal::Overwrite { path, content, what, skipped } => {
                if matches!(k.code, KeyCode::Char('y') | KeyCode::Char('Y')) {
                    self.effects.push(Effect::WriteFile { path, content, overwrite: true, what, skipped });
                } else {
                    self.set_status("Save cancelled", Kind::Dim);
                }
            }
        }
    }

    fn row_saved(&mut self, idx: Option<usize>, key: String, value: String, shown: bool) {
        match idx {
            None => {
                if key.trim().is_empty() && value.is_empty() {
                    return;
                }
                self.rows.push(Row { key, value, binary: false, shown });
                self.rows_state.select(Some(self.rows.len() - 1));
                self.rows_changed();
            }
            Some(i) => {
                let Some(r) = self.rows.get_mut(i) else { return };
                r.shown = shown;
                // Only a REAL edit bumps kv_edit_gen: a same-value save must not
                // discard an unrelated in-flight load.
                if r.key != key || r.value != value {
                    r.key = key;
                    r.value = value;
                    self.rows_changed();
                }
            }
        }
    }

    fn open_picker(&mut self, f: Focus) {
        let (target, title, items, current, custom) = match f {
            Focus::EncCtx => (PickTarget::EncCtx, "Context", self.contexts.clone(), &self.enc_ctx, false),
            Focus::SealCtx => (PickTarget::SealCtx, "Context", self.contexts.clone(), &self.seal_ctx, false),
            Focus::EncNs => (PickTarget::EncNs, "Namespace", self.namespaces.clone(), &self.enc_ns, false),
            Focus::EncSecret => (PickTarget::EncSecret, "Secret", self.secrets.clone(), &self.enc_sec, false),
            Focus::SecType => {
                let mut items: Vec<String> = core::SECRET_TYPES.iter().map(|s| s.to_string()).collect();
                if !items.contains(&self.sec_type) {
                    items.push(self.sec_type.clone());
                }
                (PickTarget::SecType, "Secret type (type a custom one)", items, &self.sec_type, true)
            }
            Focus::Scope => {
                let items = Scope::ALL.iter().map(|s| s.as_str().to_string()).collect();
                (PickTarget::Scope, "Scope", items, &self.scope.as_str().to_string(), false)
            }
            _ => return,
        };
        if items.is_empty() {
            let msg = match target {
                PickTarget::EncCtx | PickTarget::SealCtx => "No contexts — Ctrl+R reloads kubeconfig",
                PickTarget::EncNs => "No namespaces loaded — pick a context first",
                _ => "No secrets in this namespace (or not loaded yet)",
            };
            self.set_status(msg, Kind::Err);
            return;
        }
        let picker = Picker::new(title, items, current, custom);
        self.modal = Some(Modal::Picker { target, picker });
    }

    fn picked(&mut self, target: PickTarget, v: String) {
        match target {
            PickTarget::EncCtx => {
                self.enc_ctx = v.clone();
                self.seal_ctx = v.clone();
                self.enc_ns.clear();
                self.enc_sec.clear();
                self.namespaces.clear();
                self.secrets.clear();
                // The controller is cluster-specific — detection refills it.
                self.ctl_name.clear();
                self.ctl_ns.clear();
                self.fetch_namespaces(v.clone());
                self.detect_controller(v);
            }
            PickTarget::SealCtx => {
                self.seal_ctx = v.clone();
                self.ctl_name.clear();
                self.ctl_ns.clear();
                self.detect_controller(v);
            }
            PickTarget::EncNs => {
                self.enc_ns = v.clone();
                self.enc_sec.clear();
                self.secrets.clear();
                self.fetch_secrets(self.enc_ctx.clone(), v);
            }
            PickTarget::EncSecret => self.enc_sec = v,
            PickTarget::SecType => {
                self.sec_type = v;
                self.type_auto = false;
            }
            PickTarget::Scope => {
                self.scope = Scope::ALL.into_iter().find(|s| s.as_str() == v).unwrap_or_default();
            }
        }
    }

    fn open_prompt(&mut self) {
        let purpose = PathPurpose::Open(self.tab);
        let init = if self.tab == Tab::Seal { self.cert.value().to_string() } else { String::new() };
        self.modal = Some(Modal::Path { purpose, input: Input::new(init) });
    }

    fn save_prompt(&mut self) {
        let name = self.sec_name.value().trim();
        let name = if name.is_empty() { core::DEF_NAME } else { name };
        let (what, default) = match self.tab {
            Tab::Encode if self.yaml_out.is_empty() => {
                self.set_status("Generate YAML first (Ctrl+G)", Kind::Err);
                return;
            }
            Tab::Encode => (SaveWhat::Yaml, format!("{name}.yaml")),
            Tab::Seal if !self.sealed_ok => {
                self.set_status("Seal a secret first", Kind::Err);
                return;
            }
            Tab::Seal => (SaveWhat::Sealed, format!("sealed-{name}.yaml")),
            Tab::Decode => {
                self.set_status("Nothing to save on this tab", Kind::Dim);
                return;
            }
        };
        self.modal = Some(Modal::Path { purpose: PathPurpose::Save(what), input: Input::new(default) });
    }

    fn path_chosen(&mut self, purpose: PathPurpose, path: String) {
        match purpose {
            PathPurpose::Open(Tab::Seal) => {
                self.cert.set(path);
                self.set_status("Certificate set — sealing will use it offline", Kind::Ok);
            }
            PathPurpose::Open(tab) => {
                let (purpose, key) = if tab == Tab::Encode {
                    (ReadPurpose::Editor, "editor-read")
                } else {
                    (ReadPurpose::Decode, "decode-read")
                };
                let tok = self.claim(key);
                self.effects.push(Effect::ReadFile {
                    tok,
                    purpose,
                    path,
                    out_gen: self.out_gen,
                    kv_gen: self.kv_edit_gen,
                });
            }
            PathPurpose::Save(what) => {
                let content = if what == SaveWhat::Yaml { self.yaml_out.clone() } else { self.sealed_out.clone() };
                // Frozen now so the confirmation describes the saved payload.
                let skipped = self.skipped;
                self.effects.push(Effect::WriteFile { path, content, overwrite: false, what, skipped });
            }
        }
    }

    // ------------------------------------------------------------ actions

    /// Generate the Secret YAML from the rows. Returns whether YAML was produced.
    pub fn generate(&mut self) -> bool {
        let data =
            core::collect_pairs(self.rows.iter().filter(|r| !r.binary).map(|r| (r.key.as_str(), r.value.as_str())));
        // Binary passthrough, unless an editable row of the same key wins.
        let raw: Pairs = self
            .rows
            .iter()
            .filter(|r| r.binary && !data.iter().any(|(k, _)| k == &r.key))
            .map(|r| (r.key.clone(), r.value.clone()))
            .collect();
        if data.is_empty() && raw.is_empty() {
            self.set_status(
                "No KEY=VALUE pairs — open a .env (Ctrl+O), load from cluster (Ctrl+L) or add rows (a)",
                Kind::Err,
            );
            return false;
        }
        let name = non_empty(self.sec_name.value(), core::DEF_NAME);
        let ns = non_empty(self.sec_ns.value(), core::DEF_NS);
        if self.sec_type.trim().is_empty() {
            self.sec_type = "Opaque".into();
        }
        // The panes now describe a new generation: an in-flight seal of the
        // previous YAML must land stale.
        self.invalidate_outputs();
        self.yaml_out = core::build_secret_yaml(&name, &ns, &data, self.sec_type.trim(), &raw, &self.carry);
        let msg = core::generated_msg(data.len() + raw.len(), raw.len(), !self.carry.is_empty());
        self.status_output(&msg, None);
        true
    }

    fn clear_focused(&mut self) {
        match self.focus() {
            Focus::SvIn | Focus::SvOut => self.sv_in.clear(),
            Focus::DvIn | Focus::DvOut => self.dv_in.clear(),
            Focus::DecRows => {
                self.dec_rows.clear();
                self.dec_state.select(None);
                self.dec_label = "(no file)".into();
                self.dec_hint = None;
            }
            Focus::CtlName => {
                self.ctl_name.clear();
                self.controller_edited();
            }
            Focus::CtlNs => {
                self.ctl_ns.clear();
                self.controller_edited();
            }
            _ if self.tab == Tab::Seal => {
                self.cert.clear();
                self.set_status("Certificate cleared — sealing fetches it from the controller", Kind::Dim);
            }
            _ if self.tab == Tab::Encode => {
                self.file_label = "(no file)".into();
                self.sec_type = "Opaque".into();
                self.type_auto = true;
                self.set_rows(vec![], vec![]);
                self.set_status("Cleared", Kind::Ok);
            }
            _ => {}
        }
    }

    fn copy_focused(&mut self) {
        let (text, qualify) = match self.focus() {
            Focus::SvIn | Focus::SvOut => (self.sv_encoded(), false),
            Focus::DvIn | Focus::DvOut => match self.dv_decoded() {
                Ok(s) => (s, false),
                Err(e) => {
                    self.set_status(format!("Decode error: {e}"), Kind::Err);
                    return;
                }
            },
            Focus::Rows => match self.rows_state.selected().and_then(|i| self.rows.get(i)) {
                Some(r) => (r.value.clone(), false),
                None => (String::new(), false),
            },
            Focus::DecRows => match self.dec_state.selected().and_then(|i| self.dec_rows.get(i)) {
                Some(r) => (r.value.clone(), false),
                None => (String::new(), false),
            },
            _ if self.tab == Tab::Seal => {
                if !self.sealed_ok {
                    self.set_status("Seal a secret first", Kind::Err);
                    return;
                }
                (self.sealed_out.clone(), true)
            }
            _ if self.tab == Tab::Encode => (self.yaml_out.clone(), true),
            _ => (String::new(), false),
        };
        if text.is_empty() {
            self.set_status("Nothing to copy", Kind::Dim);
            return;
        }
        // Copied VERBATIM: a trailing newline can be part of a value (PEM).
        let skipped = qualify.then_some(self.skipped);
        self.effects.push(Effect::Copy { text, skipped });
    }

    fn refresh_contexts(&mut self) {
        // The refresh is the controller cache's invalidation point: clear and
        // bump together, so a lookup dispatched before it can't repopulate it.
        self.ctl_cache.clear();
        self.ctl_refresh_gen += 1;
        self.effects.push(Effect::ClearClients);
        let tok = self.claim("contexts");
        self.effects.push(Effect::LoadContexts { tok });
        self.set_status("Reloading kubeconfig…", Kind::Dim);
    }

    fn fetch_namespaces(&mut self, ctx: String) {
        let tok = self.claim("namespaces");
        self.effects.push(Effect::LoadNamespaces { tok, ctx });
    }

    fn fetch_secrets(&mut self, ctx: String, ns: String) {
        let tok = self.claim("secrets");
        self.effects.push(Effect::LoadSecrets { tok, ctx, ns });
    }

    fn detect_controller(&mut self, ctx: String) {
        // `get`, then match on the inner Option: a context with no controller
        // is cached as None and must count as a hit, not a miss.
        if let Some(hit) = self.ctl_cache.get(&ctx).cloned() {
            self.ctl_pending = None;
            if let Some((ns, name)) = hit {
                self.apply_controller(ns, name);
            }
            return;
        }
        self.ctl_pending = Some(ctx.clone());
        let tok = self.claim("controller");
        self.effects.push(Effect::DetectController { tok, ctx, ctl_gen: self.ctl_refresh_gen });
    }

    fn apply_controller(&mut self, ns: String, name: String) {
        self.set_status(format!("Sealed-secrets controller: {ns}/{name}"), Kind::Ok);
        self.ctl_name.set(name);
        self.ctl_ns.set(ns);
    }

    fn load_template(&mut self) {
        let (ctx, ns, sec) = (self.enc_ctx.clone(), self.enc_ns.clone(), self.enc_sec.clone());
        if ctx.is_empty() || ns.is_empty() || sec.is_empty() {
            self.set_status("Select context, namespace, and secret first", Kind::Err);
            return;
        }
        // Keyed by SELECTION: supersedes only a same-selection re-dispatch.
        let tok = self.claim(template_key(&ctx, &ns, &sec));
        self.set_status(format!("Loading {ns}/{sec}…"), Kind::Dim);
        self.effects.push(Effect::FetchTemplate { tok, ctx, ns, sec, out_gen: self.out_gen, kv_gen: self.kv_edit_gen });
    }

    fn do_seal(&mut self) {
        if let Some(why) = self.seal_blocked() {
            let msg = if why == "detecting controller…" {
                "Detecting controller… try again in a moment".to_string()
            } else {
                format!("Busy — {why}")
            };
            self.set_status(msg, Kind::Dim);
            return;
        }
        // Seals the Encode tab's YAML, generating it first if needed.
        if self.yaml_out.trim().is_empty() && !self.generate() {
            return;
        }
        let cert = self.cert.value().trim().to_string();
        let ctl = (self.ctl_ns.value().trim().to_string(), self.ctl_name.value().trim().to_string());
        if cert.is_empty() {
            if self.seal_ctx.is_empty() {
                self.set_status("No context — pick one, or set a certificate (Ctrl+O on the Seal tab)", Kind::Err);
                return;
            }
            if ctl.0.is_empty() || ctl.1.is_empty() {
                self.set_status("No controller — fill in Controller name/NS, or set a certificate", Kind::Err);
                return;
            }
        }
        self.sealing = true;
        self.set_status("Sealing…", Kind::Dim);
        self.effects.push(Effect::Seal {
            out_gen: self.out_gen,
            yaml: self.yaml_out.clone(),
            scope: self.scope,
            ctx: self.seal_ctx.clone(),
            cert: (!cert.is_empty()).then_some(cert),
            ctl,
        });
    }

    fn do_validate(&mut self) {
        if !self.sealed_ok {
            self.set_status("Seal a secret first", Kind::Err);
            return;
        }
        if let Some(why) = self.validate_blocked() {
            self.set_status(format!("Busy — {why}"), Kind::Dim);
            return;
        }
        let ctl = (self.ctl_ns.value().trim().to_string(), self.ctl_name.value().trim().to_string());
        if self.seal_ctx.is_empty() || ctl.0.is_empty() || ctl.1.is_empty() {
            self.set_status("Validate needs a context and the controller name/NS", Kind::Err);
            return;
        }
        self.validating = true;
        self.set_status("Validating…", Kind::Dim);
        self.effects.push(Effect::Validate {
            out_gen: self.out_gen,
            sealed: self.sealed_out.clone(),
            ctx: self.seal_ctx.clone(),
            ctl,
        });
    }

    // ------------------------------------------------------------ results

    pub fn on_msg(&mut self, m: Msg) {
        match m {
            Msg::Contexts { tok, res } => {
                if !self.is_latest("contexts", tok) {
                    return;
                }
                match res {
                    Err(e) => self.set_status(e, Kind::Err),
                    Ok(c) => {
                        let n = c.names.len();
                        self.contexts = c.names;
                        if self.enc_ctx.is_empty() && n > 0 {
                            let ctx = c
                                .current
                                .filter(|cur| self.contexts.contains(cur))
                                .unwrap_or_else(|| self.contexts[0].clone());
                            self.picked(PickTarget::EncCtx, ctx);
                        } else {
                            self.set_status(format!("Loaded {n} context(s)"), Kind::Ok);
                        }
                    }
                }
            }
            Msg::Namespaces { tok, ctx, res } => {
                if !self.is_latest("namespaces", tok) || ctx != self.enc_ctx {
                    return;
                }
                match res {
                    Err(e) => self.set_status(format!("Namespace fetch failed: {e}"), Kind::Err),
                    Ok(nss) => {
                        self.namespaces = nss;
                        if let Some(first) = self.namespaces.first().cloned() {
                            self.picked(PickTarget::EncNs, first);
                        }
                    }
                }
            }
            Msg::Secrets { tok, ctx, ns, res } => {
                if !self.is_latest("secrets", tok) || ctx != self.enc_ctx || ns != self.enc_ns {
                    return;
                }
                match res {
                    // Say so — an empty picker would read as "no secrets here".
                    Err(e) => self.set_status(format!("Secret list fetch failed: {e}"), Kind::Err),
                    Ok(secs) => {
                        self.secrets = secs;
                        self.enc_sec = self.secrets.first().cloned().unwrap_or_default();
                    }
                }
            }
            Msg::Controller { tok, ctx, ctl_gen, res } => self.on_controller(tok, ctx, ctl_gen, res),
            Msg::Template { tok, ctx, ns, sec, out_gen, kv_gen, res } => {
                self.on_template(tok, (ctx, ns, sec), out_gen, kv_gen, res)
            }
            Msg::FileRead { tok, purpose, path, out_gen, kv_gen, res } => {
                self.on_file_read(tok, purpose, path, out_gen, kv_gen, res)
            }
            Msg::Written { path, what, skipped, res } => match res {
                Ok(()) => self.status_output(&format!("Saved {}", basename(&path)), Some(skipped)),
                Err(WriteError::Exists(content)) => {
                    self.modal = Some(Modal::Overwrite { path, content, what, skipped });
                }
                Err(WriteError::Io(e)) => self.set_status(format!("Save failed: {e}"), Kind::Err),
            },
            Msg::Sealed { out_gen, res } => {
                self.sealing = false;
                // A stale result describes the previous secret: don't resurrect it.
                if self.discard_stale(out_gen, "sealing", "; seal again") {
                    return;
                }
                match res {
                    Err(e) => {
                        self.sealed_ok = false;
                        self.sealed_out = format!("# seal error\n{e}\n");
                        self.sealed_scroll = Scroll::default();
                        self.set_status(format!("Seal failed: {}", last_line(&e)), Kind::Err);
                    }
                    Ok(y) => {
                        self.sealed_ok = !y.trim().is_empty();
                        self.sealed_out = y;
                        self.sealed_scroll = Scroll::default();
                        if self.sealed_ok {
                            self.status_output("Sealed successfully", None);
                        } else {
                            self.set_status("Sealing produced no output", Kind::Err);
                        }
                    }
                }
            }
            Msg::Validated { out_gen, res } => {
                self.validating = false;
                if self.discard_stale(out_gen, "validation", "") {
                    return;
                }
                match res {
                    Ok(true) => self.set_status("Valid — the controller can decrypt this", Kind::Ok),
                    Ok(false) => self.set_status(
                        "Invalid seal — the controller cannot decrypt this (wrong key, scope, name or namespace)",
                        Kind::Err,
                    ),
                    Err(e) => self.set_status(format!("Validation failed: {}", last_line(&e)), Kind::Err),
                }
            }
            Msg::Copied { skipped, res } => match res {
                Ok(how) => self.copied(how, skipped),
                Err((text, _why)) => {
                    self.effects.push(Effect::Osc52 { text });
                    self.copied("terminal (OSC 52)", skipped);
                }
            },
            Msg::Edited { row, key, original, kv_gen, res } => {
                let edited = match res {
                    Ok(s) => core::editor_result(&original, s),
                    Err(e) => {
                        self.set_status(format!("Editor: {e}"), Kind::Err);
                        return;
                    }
                };
                // The row must still be the one we opened.
                if kv_gen != self.kv_edit_gen || self.rows.get(row).is_none_or(|r| r.key != key || r.binary) {
                    self.set_status("Rows changed while editing — edit discarded", Kind::Err);
                    return;
                }
                if self.rows[row].value == edited {
                    self.set_status("No change", Kind::Dim);
                } else {
                    self.rows[row].value = edited;
                    self.rows_changed();
                    self.set_status(format!("Updated {key}"), Kind::Ok);
                }
            }
        }
    }

    fn copied(&mut self, how: &str, skipped: Option<usize>) {
        let msg = format!("Copied to {how}");
        match skipped {
            Some(_) => self.status_output(&msg, skipped),
            None => self.set_status(msg, Kind::Ok),
        }
    }

    fn on_controller(&mut self, tok: Tok, ctx: String, ctl_gen: u64, res: Result<Option<(String, String)>, String>) {
        if !self.is_latest("controller", tok) || ctx != self.seal_ctx {
            return;
        }
        self.ctl_pending = None;
        let found = match res {
            // An error carries no controller data for the refresh gate to
            // protect — always report it, or an unreachable cluster would
            // retry forever with no explanation.
            Err(e) => {
                self.set_status(format!("Controller detection failed: {e}"), Kind::Err);
                return;
            }
            Ok(found) => found,
        };
        if ctl_gen != self.ctl_refresh_gen {
            // A refresh happened after dispatch: the answer may be stale.
            // Don't show or cache it — look again.
            self.set_status("Refreshed — re-checking the controller for this context…", Kind::Dim);
            self.detect_controller(ctx);
            return;
        }
        self.ctl_cache.insert(ctx.clone(), found.clone());
        match found {
            Some((ns, name)) => self.apply_controller(ns, name),
            None => self.set_status(
                format!("No sealed-secrets controller found in {ctx} — enter its name/NS, or use a certificate"),
                Kind::Dim,
            ),
        }
    }

    fn on_template(
        &mut self,
        tok: Tok,
        (ctx, ns, sec): (String, String, String),
        out_gen: u64,
        kv_gen: u64,
        res: Result<Value, String>,
    ) {
        if !self.is_latest(&template_key(&ctx, &ns, &sec), tok) {
            return; // superseded by a newer load of this SAME selection
        }
        if (&ctx, &ns, &sec) != (&self.enc_ctx, &self.enc_ns, &self.enc_sec) {
            return; // the selection moved on
        }
        if self.discard_stale(out_gen, "the cluster load", "") {
            return;
        }
        let doc = match res {
            Err(e) => {
                self.set_status(format!("Load failed: {e}"), Kind::Err);
                return;
            }
            Ok(doc) => doc,
        };
        if self.discard_if_kv_edited(kv_gen, "the cluster load") {
            return;
        }
        let entries = core::secret_entries(&doc);
        if entries.is_empty() {
            let dropped = self.apply_identity_only(&doc, &sec, &ns);
            self.file_label = format!("(cluster: {ns}/{sec})");
            let mut msg = format!("{sec} has no data/stringData — loaded name/namespace/type only");
            if dropped > 0 {
                msg.push_str(&format!("; dropped {dropped} binary value(s) from the previous secret"));
                self.status_for(msg, Kind::Err, WARN_DURATION);
            } else {
                self.set_status(msg, Kind::Ok);
            }
            return;
        }
        if let Some(err) = core::check_entries(&entries) {
            self.set_status(err, Kind::Err);
            return;
        }
        let (total, binary) = self.apply_secret_doc(&doc, &entries, &sec, &ns);
        self.file_label = format!("(cluster: {ns}/{sec})");
        self.set_status(core::applied_msg("Loaded", total, binary, &sec), Kind::Ok);
    }

    fn on_file_read(
        &mut self,
        tok: Tok,
        purpose: ReadPurpose,
        path: String,
        out_gen: u64,
        kv_gen: u64,
        res: Result<String, String>,
    ) {
        let key = if purpose == ReadPurpose::Editor { "editor-read" } else { "decode-read" };
        if !self.is_latest(key, tok) {
            return; // superseded by a newer pick
        }
        let text = match res {
            Err(e) => {
                self.set_status(format!("Could not read file: {e}"), Kind::Err);
                return;
            }
            Ok(t) => t,
        };
        if purpose == ReadPurpose::Decode {
            self.populate_decode(&path, &text);
            return;
        }
        if self.discard_stale(out_gen, "the file read", "") || self.discard_if_kv_edited(kv_gen, "the file read") {
            return;
        }
        match core::detect_file_kind(&path, &text) {
            FileKind::Env => {
                self.file_label = path.clone();
                self.sec_type = "Opaque".into();
                self.type_auto = true;
                self.set_rows(core::parse_dotenv(&text), vec![]);
                self.set_status(format!("Loaded {} key(s) from {}", self.rows.len(), basename(&path)), Kind::Ok);
            }
            FileKind::SecretYaml => {
                let Some(doc) = self.secret_doc(&text, "import") else { return };
                let entries = core::secret_entries(&doc);
                if let Some(err) = core::check_entries(&entries) {
                    self.set_status(err, Kind::Err);
                    return;
                }
                let (total, binary) = self.apply_secret_doc(&doc, &entries, core::DEF_NAME, core::DEF_NS);
                self.file_label = path.clone();
                self.set_status(core::applied_msg("Imported", total, binary, &basename(&path)), Kind::Ok);
            }
        }
    }

    /// Parse YAML and pick the Secret doc, reporting failures (with the
    /// SealedSecret hint) in the status bar.
    fn secret_doc(&mut self, text: &str, verb: &str) -> Option<Value> {
        let docs = match core::parse_yaml_docs(text) {
            Ok(d) => d,
            Err(e) => {
                self.set_status(format!("YAML parse error: {e}"), Kind::Err);
                return None;
            }
        };
        let doc = core::select_secret_doc(&docs).cloned();
        if doc.is_none() {
            if core::has_sealed_secret(&docs) {
                self.set_status(
                    format!("SealedSecret is encrypted — {verb} the plain Secret YAML it was sealed from"),
                    Kind::Err,
                );
            } else {
                self.set_status("No Secret data/stringData found in file", Kind::Err);
            }
        }
        doc
    }

    fn populate_decode(&mut self, path: &str, text: &str) {
        let sealed = core::parse_yaml_docs(text).is_ok_and(|d| core::has_sealed_secret(&d));
        // On a bail the previous rows stay, and so does the label naming them.
        let Some(doc) = self.secret_doc(text, "decode") else {
            if sealed {
                self.dec_hint = Some(format!(
                    "{} is a SealedSecret — its values only decrypt inside the cluster. Open the plain Secret it was sealed from.",
                    basename(path)
                ));
            }
            return;
        };
        self.dec_hint = None;
        let entries = core::secret_entries(&doc);
        self.dec_rows =
            entries.into_iter().map(|e| DecRow { key: e.key, value: e.value, kind: e.kind, shown: false }).collect();
        self.dec_state.select((!self.dec_rows.is_empty()).then_some(0));
        self.dec_label = path.to_string();
        self.set_status(format!("Loaded {} key(s)", self.dec_rows.len()), Kind::Ok);
    }
}

fn template_key(ctx: &str, ns: &str, sec: &str) -> String {
    format!("template\0{ctx}\0{ns}\0{sec}")
}

fn non_empty(v: &str, fallback: &str) -> String {
    let v = v.trim();
    if v.is_empty() { fallback.to_string() } else { v.to_string() }
}

pub fn basename(path: &str) -> String {
    std::path::Path::new(path).file_name().map_or_else(|| path.to_string(), |f| f.to_string_lossy().into_owned())
}

fn last_line(s: &str) -> String {
    s.trim().lines().last().unwrap_or("").chars().take(120).collect()
}

fn list_nav(state: &mut TableState, k: KeyEvent, n: usize, page: u16) {
    if n == 0 {
        state.select(None);
        return;
    }
    let cur = state.selected().unwrap_or(0);
    let page = (page as usize).max(1);
    let next = match k.code {
        KeyCode::Up | KeyCode::Char('k') => cur.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => cur + 1,
        KeyCode::PageUp => cur.saturating_sub(page),
        KeyCode::PageDown => cur + page,
        KeyCode::Home | KeyCode::Char('g') => 0,
        KeyCode::End | KeyCode::Char('G') => n - 1,
        _ => return,
    };
    state.select(Some(next.min(n - 1)));
}

fn scroll_key(s: &mut Scroll, k: KeyEvent, page: u16, text: &str) {
    let lines = text.lines().count() as u16;
    let max_y = lines.saturating_sub(page.max(1));
    let page = page.max(1);
    match k.code {
        KeyCode::Up | KeyCode::Char('k') => s.y = s.y.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => s.y = (s.y + 1).min(max_y),
        KeyCode::PageUp => s.y = s.y.saturating_sub(page),
        KeyCode::PageDown | KeyCode::Char(' ') => s.y = (s.y + page).min(max_y),
        KeyCode::Home | KeyCode::Char('g') => s.y = 0,
        KeyCode::End | KeyCode::Char('G') => s.y = max_y,
        KeyCode::Left | KeyCode::Char('h') => s.x = s.x.saturating_sub(4),
        KeyCode::Right | KeyCode::Char('l') => s.x = s.x.saturating_add(4),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }
    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }
    fn take(app: &mut App) -> Vec<Effect> {
        std::mem::take(&mut app.effects)
    }
    fn rows(app: &App) -> Vec<(&str, &str, bool)> {
        app.rows.iter().map(|r| (r.key.as_str(), r.value.as_str(), r.binary)).collect()
    }
    fn open_file(app: &mut App, path: &str, text: &str) {
        app.tab = Tab::Encode;
        app.path_chosen(PathPurpose::Open(Tab::Encode), path.into());
        let Some(Effect::ReadFile { tok, purpose, path, out_gen, kv_gen }) = take(app).pop() else { panic!() };
        app.on_msg(Msg::FileRead { tok, purpose, path, out_gen, kv_gen, res: Ok(text.into()) });
    }

    /// An app whose Encode selection is ctx/ns/db and Seal controller is known.
    fn connected() -> App {
        let mut app = App::new();
        app.start();
        let Some(Effect::LoadContexts { tok }) = take(&mut app).pop() else { panic!() };
        app.on_msg(Msg::Contexts { tok, res: Ok(Contexts { names: vec!["ctx".into()], current: None }) });
        let effects = take(&mut app);
        let mut ns_tok = 0;
        for e in effects {
            match e {
                Effect::LoadNamespaces { tok, .. } => ns_tok = tok,
                Effect::DetectController { tok, ctx, ctl_gen } => app.on_msg(Msg::Controller {
                    tok,
                    ctx,
                    ctl_gen,
                    res: Ok(Some(("kube-system".into(), "sealed-secrets-controller".into()))),
                }),
                _ => {}
            }
        }
        app.on_msg(Msg::Namespaces { tok: ns_tok, ctx: "ctx".into(), res: Ok(vec!["ns".into()]) });
        let Some(Effect::LoadSecrets { tok, .. }) = take(&mut app).pop() else { panic!() };
        app.on_msg(Msg::Secrets { tok, ctx: "ctx".into(), ns: "ns".into(), res: Ok(vec!["db".into()]) });
        assert_eq!((app.enc_ctx.as_str(), app.enc_ns.as_str(), app.enc_sec.as_str()), ("ctx", "ns", "db"));
        assert_eq!(app.ctl_name.value(), "sealed-secrets-controller");
        app
    }

    fn secret_doc() -> Value {
        json!({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "db", "namespace": "ns"},
               "type": "Opaque", "data": {"PASSWORD": "aHVudGVyMg==", "BLOB": "/w=="}})
    }

    #[test]
    fn open_auto_detects_env_and_secret_yaml() {
        let mut app = App::new();
        open_file(&mut app, "/tmp/x/prod.env", "A=1\nexport B='two'\n");
        assert_eq!(rows(&app), vec![("A", "1", false), ("B", "two", false)]);
        assert_eq!(app.file_label, "/tmp/x/prod.env");

        let yaml = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: api\n  namespace: prod\n  labels: {team: a, bad: 1}\ndata:\n  T: aGk=\n  B: /w==\n";
        open_file(&mut app, "/tmp/x/secret.yaml", yaml);
        assert_eq!(rows(&app), vec![("T", "hi", false), ("B", "/w==", true)]);
        assert_eq!((app.sec_name.value(), app.sec_ns.value()), ("api", "prod"));
        assert_eq!(app.skipped, 1);
        assert!(app.skip_warning().is_some());
        // Generate re-emits the binary value verbatim and carries the label.
        assert!(app.generate());
        assert!(app.yaml_out.contains("  B: \"/w==\"\n") && app.yaml_out.contains("team: a"));
        assert_eq!(app.status.kind, Kind::Err, "lossy carry-over must not read as plain success");

        // A SealedSecret is refused with the hint and leaves the editor alone.
        open_file(&mut app, "/tmp/x/sealed.yaml", "kind: SealedSecret\nspec: {}\n");
        assert!(app.status.msg.contains("SealedSecret is encrypted"));
        assert_eq!(app.rows.len(), 2);
    }

    #[test]
    fn env_load_auto_guesses_type_until_chosen() {
        let mut app = App::new();
        open_file(&mut app, "tls.env", "tls.crt=a\ntls.key=b\n");
        assert_eq!(app.sec_type, "kubernetes.io/tls");
        app.picked(PickTarget::SecType, "Opaque".into());
        app.rows.push(Row { key: "x".into(), value: "y".into(), binary: false, shown: false });
        app.rows_changed();
        assert_eq!(app.sec_type, "Opaque", "a hand-picked type is never overridden");
    }

    #[test]
    fn seal_result_discarded_when_outputs_changed_in_flight() {
        let mut app = connected();
        open_file(&mut app, "a.env", "A=1\n");
        app.on_key(ctrl('e')); // generates first, then seals
        assert!(!app.yaml_out.is_empty());
        let Some(Effect::Seal { out_gen, ctl, .. }) = take(&mut app).pop() else { panic!("no seal effect") };
        assert_eq!(ctl, ("kube-system".into(), "sealed-secrets-controller".into()));
        assert!(app.sealing && app.seal_blocked().is_some());
        app.generate(); // the YAML the seal was made from is gone
        app.on_msg(Msg::Sealed { out_gen, res: Ok("kind: SealedSecret\n".into()) });
        assert!(!app.sealing);
        assert!(!app.sealed_ok && app.sealed_out.is_empty());
        assert!(app.status.msg.contains("stale result discarded"));
    }

    #[test]
    fn seal_then_validate_happy_path_and_error_dump_is_not_a_manifest() {
        let mut app = connected();
        open_file(&mut app, "a.env", "A=1\n");
        app.on_key(ctrl('e'));
        let Some(Effect::Seal { out_gen, .. }) = take(&mut app).pop() else { panic!() };
        app.on_msg(Msg::Sealed { out_gen, res: Err("boom".into()) });
        assert!(!app.sealed_ok && app.sealed_out.contains("boom"));
        app.on_key(ctrl('t'));
        assert!(take(&mut app).is_empty(), "validate must refuse an error dump");

        app.on_key(ctrl('e'));
        let Some(Effect::Seal { out_gen, .. }) = take(&mut app).pop() else { panic!() };
        app.on_msg(Msg::Sealed { out_gen, res: Ok("---\nkind: SealedSecret\n".into()) });
        assert!(app.sealed_ok);
        app.on_key(ctrl('t'));
        let Some(Effect::Validate { out_gen, .. }) = take(&mut app).pop() else { panic!() };
        app.on_msg(Msg::Validated { out_gen, res: Ok(true) });
        assert!(app.status.msg.starts_with("Valid"));
    }

    #[test]
    fn template_discarded_when_rows_edited_in_flight() {
        let mut app = connected();
        open_file(&mut app, "a.env", "A=1\n");
        app.on_key(ctrl('l'));
        let Some(Effect::FetchTemplate { tok, ctx, ns, sec, out_gen, kv_gen }) = take(&mut app).pop() else { panic!() };
        // An in-place edit doesn't move out_gen — only kv_edit_gen catches it.
        app.row_saved(Some(0), "A".into(), "edited".into(), false);
        app.on_msg(Msg::Template { tok, ctx, ns, sec, out_gen, kv_gen, res: Ok(secret_doc()) });
        assert_eq!(rows(&app), vec![("A", "edited", false)]);
        assert!(app.status.msg.contains("Rows changed"));
    }

    #[test]
    fn same_value_save_is_not_an_edit() {
        let mut app = connected();
        open_file(&mut app, "a.env", "A=1\n");
        app.on_key(ctrl('l'));
        let Some(Effect::FetchTemplate { tok, ctx, ns, sec, out_gen, kv_gen }) = take(&mut app).pop() else { panic!() };
        app.row_saved(Some(0), "A".into(), "1".into(), true);
        app.on_msg(Msg::Template { tok, ctx, ns, sec, out_gen, kv_gen, res: Ok(secret_doc()) });
        assert_eq!(rows(&app), vec![("PASSWORD", "hunter2", false), ("BLOB", "/w==", true)]);
        assert_eq!(app.file_label, "(cluster: ns/db)");
    }

    #[test]
    fn template_newest_wins_for_the_same_selection() {
        let mut app = connected();
        app.on_key(ctrl('l'));
        let Some(Effect::FetchTemplate { tok: old, out_gen, kv_gen, .. }) = take(&mut app).pop() else { panic!() };
        app.on_key(ctrl('l'));
        let Some(Effect::FetchTemplate { tok: new, .. }) = take(&mut app).pop() else { panic!() };
        let mk = |tok, v: &str| Msg::Template {
            tok,
            ctx: "ctx".into(),
            ns: "ns".into(),
            sec: "db".into(),
            out_gen,
            kv_gen,
            res: Ok(json!({"kind": "Secret", "stringData": {"K": v}})),
        };
        app.on_msg(mk(new, "new"));
        app.on_msg(mk(old, "old")); // older landing last must not win
        assert_eq!(rows(&app), vec![("K", "new", false)]);
    }

    #[test]
    fn identity_only_load_drops_previous_binary_rows() {
        let mut app = connected();
        app.on_key(ctrl('l'));
        let Some(Effect::FetchTemplate { tok, ctx, ns, sec, out_gen, kv_gen }) = take(&mut app).pop() else { panic!() };
        app.on_msg(Msg::Template { tok, ctx, ns, sec, out_gen, kv_gen, res: Ok(secret_doc()) });
        app.on_key(ctrl('l'));
        let Some(Effect::FetchTemplate { tok, ctx, ns, sec, out_gen, kv_gen }) = take(&mut app).pop() else { panic!() };
        let empty = json!({"kind": "Secret", "metadata": {"name": "other"}, "type": "kubernetes.io/tls"});
        app.on_msg(Msg::Template { tok, ctx, ns, sec, out_gen, kv_gen, res: Ok(empty) });
        assert_eq!(rows(&app), vec![("PASSWORD", "hunter2", false)]);
        assert_eq!((app.sec_name.value(), app.sec_type.as_str()), ("other", "kubernetes.io/tls"));
        assert!(app.status.msg.contains("dropped 1 binary"));
    }

    #[test]
    fn controller_cache_negative_hit_and_refresh_gate() {
        let mut app = connected();
        // A second context with no controller: looked up once, then cached as None.
        app.contexts.push("dev".into());
        app.picked(PickTarget::SealCtx, "dev".into());
        let Some(Effect::DetectController { tok, ctx, ctl_gen }) = take(&mut app).pop() else { panic!() };
        assert!(app.detecting() && app.seal_blocked().is_some());
        app.on_msg(Msg::Controller { tok, ctx, ctl_gen, res: Ok(None) });
        assert!(!app.detecting());
        app.picked(PickTarget::SealCtx, "ctx".into());
        app.picked(PickTarget::SealCtx, "dev".into());
        assert!(take(&mut app).is_empty(), "cache hits (positive and negative) dispatch nothing");
        assert_eq!(app.ctl_name.value(), "");

        // A lookup in flight across a refresh is discarded and re-run.
        app.on_key(ctrl('r'));
        take(&mut app);
        app.picked(PickTarget::SealCtx, "ctx".into());
        let Some(Effect::DetectController { tok, ctx, ctl_gen }) = take(&mut app).pop() else { panic!() };
        app.on_key(ctrl('r'));
        take(&mut app);
        app.on_msg(Msg::Controller { tok, ctx, ctl_gen, res: Ok(Some(("old".into(), "old".into()))) });
        assert_eq!(app.ctl_name.value(), "", "stale answer must not reach the fields");
        assert!(app.detecting());
        assert!(matches!(take(&mut app).pop(), Some(Effect::DetectController { .. })));
    }

    #[test]
    fn controller_newest_wins_and_user_edit_supersedes_detection() {
        let mut app = connected();
        app.on_key(ctrl('r'));
        take(&mut app);
        app.picked(PickTarget::SealCtx, "ctx".into());
        let Some(Effect::DetectController { tok: t1, ctl_gen, .. }) = take(&mut app).pop() else { panic!() };
        app.tab = Tab::Seal;
        app.set_focus(Focus::CtlName);
        app.on_paste("my-ctl".into());
        assert!(!app.detecting());
        app.on_msg(Msg::Controller { tok: t1, ctx: "ctx".into(), ctl_gen, res: Ok(Some(("a".into(), "b".into()))) });
        assert_eq!(app.ctl_name.value(), "my-ctl");
    }

    #[test]
    fn editor_file_read_discarded_if_rows_edited_and_superseded_by_newer_pick() {
        let mut app = App::new();
        open_file(&mut app, "a.env", "A=1\n");
        app.path_chosen(PathPurpose::Open(Tab::Encode), "b.env".into());
        let Some(Effect::ReadFile { tok, purpose, path, out_gen, kv_gen }) = take(&mut app).pop() else { panic!() };
        app.rows_key(key(KeyCode::Char('d')));
        app.on_msg(Msg::FileRead { tok, purpose, path, out_gen, kv_gen, res: Ok("B=2".into()) });
        assert!(app.rows.is_empty());

        app.path_chosen(PathPurpose::Open(Tab::Encode), "c.env".into());
        let Some(Effect::ReadFile { tok: old, purpose, out_gen, kv_gen, .. }) = take(&mut app).pop() else { panic!() };
        app.path_chosen(PathPurpose::Open(Tab::Encode), "d.env".into());
        take(&mut app);
        app.on_msg(Msg::FileRead { tok: old, purpose, path: "c.env".into(), out_gen, kv_gen, res: Ok("C=3".into()) });
        assert!(app.rows.is_empty(), "superseded pick must not land");
    }

    #[test]
    fn decode_table_masks_and_sealed_secret_hint() {
        let mut app = App::new();
        app.tab = Tab::Decode;
        let read = |app: &mut App, path: &str, text: &str| {
            app.path_chosen(PathPurpose::Open(Tab::Decode), path.into());
            let Some(Effect::ReadFile { tok, purpose, path, out_gen, kv_gen }) = take(app).pop() else { panic!() };
            app.on_msg(Msg::FileRead { tok, purpose, path, out_gen, kv_gen, res: Ok(text.into()) });
        };
        read(&mut app, "s.yaml", "kind: Secret\ndata:\n  P: aHVudGVyMg==\n  B: /w==\n");
        assert_eq!(app.dec_rows[0].display(), "•••••••");
        assert!(app.dec_rows[1].display().contains("binary"));
        app.set_focus(Focus::DecRows);
        app.on_key(key(KeyCode::Char('v')));
        assert_eq!(app.dec_rows[0].display(), "hunter2");

        read(&mut app, "sealed.yaml", "kind: SealedSecret\nspec: {}\n");
        assert!(app.dec_hint.as_deref().unwrap().contains("SealedSecret"));
        assert_eq!(app.dec_label, "s.yaml", "a failed open keeps the previous rows and label");
        assert_eq!(app.dec_rows.len(), 2);
    }

    #[test]
    fn copy_and_save_follow_focus_and_freeze_skip_count() {
        let mut app = App::new();
        app.sv_in.set("hunter2");
        app.on_key(ctrl('y'));
        assert!(matches!(take(&mut app).pop(), Some(Effect::Copy { text, skipped: None }) if text == "aHVudGVyMg=="));

        app.on_key(ctrl('s'));
        assert!(app.modal.is_none() && app.status.msg.contains("Generate YAML first"));
        open_file(&mut app, "a.env", "A=1\n");
        app.generate();
        app.set_focus(Focus::Yaml);
        app.on_key(ctrl('y'));
        assert!(matches!(take(&mut app).pop(), Some(Effect::Copy { skipped: Some(0), .. })));
        app.on_key(ctrl('s'));
        let Some(Modal::Path { input, .. }) = &app.modal else { panic!() };
        assert_eq!(input.value(), "my-secret.yaml");
        app.on_key(key(KeyCode::Enter));
        let Some(Effect::WriteFile { path, content, overwrite: false, what, skipped }) = take(&mut app).pop() else {
            panic!()
        };
        app.on_msg(Msg::Written { path, what, skipped, res: Err(WriteError::Exists(content)) });
        app.on_key(key(KeyCode::Char('y')));
        assert!(matches!(take(&mut app).pop(), Some(Effect::WriteFile { overwrite: true, .. })));
    }

    #[test]
    fn row_editor_add_edit_delete() {
        let mut app = App::new();
        app.set_focus(Focus::Rows);
        app.on_key(key(KeyCode::Char('a')));
        for c in "K".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Enter)); // to value
        app.on_paste("line1\rline2".into());
        app.on_key(key(KeyCode::Enter)); // save
        assert_eq!(rows(&app), vec![("K", "line1\nline2", false)]);
        app.on_key(key(KeyCode::Char('e')));
        let Some(Effect::EditValue { row, key: k, value, kv_gen }) = take(&mut app).pop() else { panic!() };
        app.on_msg(Msg::Edited { row, key: k, original: value, kv_gen, res: Ok("new\n".into()) });
        assert_eq!(rows(&app), vec![("K", "new", false)]);
        app.on_key(key(KeyCode::Char('d')));
        assert!(app.rows.is_empty());
    }

    #[test]
    fn help_only_outside_text_inputs_and_quit() {
        let mut app = App::new();
        app.on_key(key(KeyCode::Char('?')));
        assert_eq!(app.sv_in.value(), "?");
        app.set_focus(Focus::Rows);
        app.on_key(key(KeyCode::Char('?')));
        assert!(matches!(app.modal, Some(Modal::Help)));
        app.on_key(key(KeyCode::Esc));
        assert!(app.modal.is_none());
        app.on_key(KeyEvent::new(KeyCode::F(3), KeyModifiers::NONE));
        assert_eq!(app.tab, Tab::Seal);
        app.on_key(ctrl('n'));
        assert_eq!(app.tab, Tab::Encode);
        app.on_key(ctrl('q'));
        assert!(app.quit);
    }
}
