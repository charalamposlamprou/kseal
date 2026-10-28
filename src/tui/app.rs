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
//! * `go_gen` — bumped whenever what the GitOps preview describes changes
//!   (its source, namespace, scope, workflow, or the Encode tab's outputs).
//!   Previews and controller checks dispatched before are discarded.
//!
//! ## Writes
//!
//! Every save goes through the same gate: the target is checked first
//! (symlink, permissions, plaintext next to a SealedSecret, Kustomize
//! namespace/name rewrites…) and anything High or worse asks first; an
//! existing file is never replaced without showing what changes.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;
use serde_json::Value;

use super::widgets::{Input, Picker, complete_path};
use crate::cluster::Contexts;
use crate::core::{self, Carryover, Entry, EntryKind, FileKind, Pairs};
use crate::diff;
use crate::gitops::{self, Workflow};
use crate::seal::Scope;
use crate::validate::{Finding, Severity};

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
    GitOps,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Encode, Tab::Decode, Tab::Seal, Tab::GitOps];
    pub fn title(self) -> &'static str {
        match self {
            Tab::Encode => "Encode",
            Tab::Decode => "Decode",
            Tab::Seal => "Seal",
            Tab::GitOps => "GitOps",
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
    // GitOps
    GoSource,
    GoNs,
    GoScope,
    GoWorkflow,
    GoRepo,
    GoOut,
    GoPreview,
    GoFindings,
}

impl Focus {
    pub fn order(tab: Tab) -> &'static [Focus] {
        use Focus::*;
        match tab {
            Tab::Encode => &[SvIn, SvOut, EncCtx, EncNs, EncSecret, Rows, SecName, SecNs, SecType, Yaml],
            Tab::Decode => &[DvIn, DvOut, DecRows],
            Tab::Seal => &[SealCtx, Scope, CtlName, CtlNs, Cert, Sealed],
            Tab::GitOps => &[GoSource, GoNs, GoScope, GoWorkflow, GoRepo, GoOut, GoPreview, GoFindings],
        }
    }
    /// The tab's fields as laid out on screen, row by row: what the arrow
    /// keys move through. Flattened, it is the Tab order.
    pub fn grid(tab: Tab) -> &'static [&'static [Focus]] {
        use Focus::*;
        match tab {
            Tab::Encode => {
                &[&[SvIn], &[SvOut], &[EncCtx, EncNs, EncSecret], &[Rows], &[SecName, SecNs, SecType], &[Yaml]]
            }
            Tab::Decode => &[&[DvIn], &[DvOut], &[DecRows]],
            Tab::Seal => &[&[SealCtx, Scope], &[CtlName, CtlNs], &[Cert], &[Sealed]],
            Tab::GitOps => {
                &[&[GoSource], &[GoNs, GoScope], &[GoWorkflow], &[GoRepo], &[GoOut], &[GoPreview, GoFindings]]
            }
        }
    }
    /// Fields that take typed text (so `?` and letters are input, not keys).
    pub fn is_text(self) -> bool {
        use Focus::*;
        matches!(self, SvIn | DvIn | SecName | SecNs | CtlName | CtlNs | Cert | GoSource | GoNs | GoRepo | GoOut)
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

/// The key a SealedSecret was sealed with: a context's controller, or a
/// certificate file (which ignores the context).
#[derive(Debug, Clone, PartialEq)]
pub enum SealedWith {
    Controller { ctx: String, ns: String, name: String },
    Cert(String),
}

impl std::fmt::Display for SealedWith {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Controller { ctx, ns, name } => write!(f, "{ns}/{name} in {ctx}"),
            Self::Cert(path) => write!(f, "the certificate {path}"),
        }
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
    Workflow,
    /// The GitOps Output: an existing manifest, or another path.
    ExportTo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathPurpose {
    /// Encode: .env or Secret YAML into the editor; Decode: Secret YAML into
    /// the table; Seal: the offline certificate; GitOps: the source Secret.
    Open(Tab),
    Save(SaveWhat),
    /// A local manifest to compare the current output with.
    Diff(SaveWhat),
    /// Where the GitOps wizard exports to (sets the Output field only).
    ExportTo,
    /// The repository folder searched for existing manifests.
    Repo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveWhat {
    Yaml,
    Sealed,
    /// The GitOps wizard's SealedSecret.
    Export,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadPurpose {
    Editor,
    Decode,
    Diff(SaveWhat),
}

/// A write waiting for the user's go-ahead (risky target, or overwrite).
#[derive(Debug, Clone, PartialEq)]
pub struct PendingWrite {
    pub path: String,
    pub content: String,
    pub what: SaveWhat,
    pub skipped: usize,
    /// The target checks were shown and accepted.
    pub confirmed: bool,
}

/// What the wizard seals with: a certificate file (if set), the controller
/// `(ns, name)`, and how to describe it.
type SealingKey = (Option<String>, (String, String), SealedWith);

/// Where the GitOps wizard's Secret comes from.
#[derive(Debug, Clone, PartialEq)]
pub enum Source {
    /// The Encode tab's generated YAML.
    Yaml(String),
    File(String),
}

/// A GitOps preview: the SealedSecret to export (absent when the
/// certificate was unusable) and everything validation found.
#[derive(Debug, Clone, PartialEq)]
pub struct GoPreview {
    pub yaml: Option<String>,
    pub findings: Vec<Finding>,
    pub name: String,
    pub namespace: String,
    /// The output path the target checks ran for.
    pub out: String,
    /// The plain Secret YAML it was sealed from, so diffs can show the new
    /// values (masked). Dropped with the preview.
    pub source_yaml: Option<String>,
    /// Local manifests already defining this SealedSecret (see
    /// [`gitops::find_manifests`]).
    pub found: Vec<String>,
}

#[derive(Debug)]
pub enum Modal {
    Picker {
        target: PickTarget,
        picker: Picker,
    },
    Path {
        purpose: PathPurpose,
        input: Input,
    },
    RowEdit {
        idx: Option<usize>,
        key: Input,
        value: Input,
        on_value: bool,
        shown: bool,
    },
    Overwrite {
        path: String,
        content: String,
        what: SaveWhat,
        skipped: usize,
    },
    /// A semantic diff; with `confirm`, `y` performs that (over)write.
    Diff {
        title: String,
        diff: diff::Diff,
        scroll: u16,
        reveal: bool,
        confirm: Option<PendingWrite>,
    },
    /// Validation findings; with `confirm`, `y` writes anyway.
    Findings {
        title: String,
        findings: Vec<Finding>,
        scroll: u16,
        confirm: Option<PendingWrite>,
    },
    Help,
    Error {
        title: String,
        detail: String,
    },
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
    /// Check the target (unless `confirmed`), then write it — exclusively
    /// unless `overwrite`.
    WriteFile {
        path: String,
        content: String,
        overwrite: bool,
        what: SaveWhat,
        skipped: usize,
        confirmed: bool,
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
        /// `Some(go_gen)`: the GitOps preview is being checked.
        go: Option<u64>,
    },
    /// Seal for the GitOps wizard and validate the result.
    /// Read one Secret from the cluster (read-only) to diff against.
    FetchLive {
        tok: Tok,
        what: SaveWhat,
        ctx: String,
        ns: String,
        name: String,
    },
    GitopsPreview {
        go_gen: u64,
        source: Source,
        opts: gitops::Options,
        ctx: String,
        cert: Option<String>,
        ctl: (String, String),
        out: String,
        /// Where to look for an existing manifest ("" = the Git repo of the cwd).
        repo: String,
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
    /// The file exists: the content to write, and what is there now (when
    /// it could be read) for the diff.
    Exists {
        content: String,
        existing: Option<String>,
    },
    /// The target checks found something High or worse.
    Risky {
        content: String,
        findings: Vec<Finding>,
    },
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
        go: Option<u64>,
        res: Result<bool, String>,
    },
    /// `Ok(None)`: no such Secret in the cluster.
    LiveFetched {
        tok: Tok,
        what: SaveWhat,
        label: String,
        res: Result<Option<String>, String>,
    },
    GitopsPreviewed {
        go_gen: u64,
        res: Result<GoPreview, String>,
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
    pub go_h: u16,
    pub findings_h: u16,
    /// Wrapped line counts of the findings pane / popup, from the last draw.
    pub findings_total: u16,
    pub modal_h: u16,
    pub modal_total: u16,
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Scroll {
    pub y: u16,
    pub x: u16,
}

pub struct App {
    pub tab: Tab,
    focus: [Focus; 4],
    /// Per tab, the column ↑/↓ aim for, so moving down through a one-field
    /// row and back up returns to where you came from.
    want_col: [usize; 4],
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
    /// What the sealed output was sealed with (shown on its pane; Validate
    /// compares it with the controller it checks against).
    pub sealed_with: Option<SealedWith>,
    /// What the in-flight seal / validate uses.
    sealing_with: Option<SealedWith>,
    validating_with: Option<SealedWith>,
    /// Seal was pressed while the context's controller was being detected:
    /// run it when the lookup lands rather than drop it (a dropped seal
    /// leaves the previous context's output in the pane).
    seal_queued: bool,
    /// Validate was pressed while a seal was running (or queued): run it
    /// when the seal lands. Dropped, the seal's green "Sealed with" that
    /// follows reads as a passed validation.
    validate_queued: bool,
    /// Ctrl+E was pressed on the Encode tab while it shows another context
    /// than the Seal tab (load from one cluster, seal for another): the
    /// status names both, so the Encode tab's context isn't taken for the
    /// one sealed with.
    sealing_from: Option<String>,
    pub sealed_scroll: Scroll,
    pub sealing: bool,
    pub validating: bool,
    /// Context whose controller lookup is in flight.
    pub ctl_pending: Option<String>,
    ctl_cache: HashMap<String, Option<(String, String)>>,
    ctl_refresh_gen: u64,

    // GitOps wizard
    /// Optional Secret YAML file; empty = the Encode tab's YAML.
    pub go_source: Input,
    /// Target namespace; empty = the Secret's own.
    pub go_ns: Input,
    pub workflow: Workflow,
    pub go_out: Input,
    /// Folder searched for an existing manifest of the export; empty = the
    /// Git repo kseal was started in (if any). Preset by `KSEAL_REPO`.
    pub go_repo: Input,
    /// The output path is kseal's default (never typed): it follows the
    /// Secret being previewed.
    go_out_auto: bool,
    pub go_preview: Option<GoPreview>,
    pub go_busy: bool,
    pub go_scroll: Scroll,
    pub go_find_scroll: u16,
    /// What the preview was sealed with (from the Seal tab's settings).
    pub go_with: Option<SealedWith>,
    /// The controller's verdict on the current preview, once asked.
    pub go_verified: Option<bool>,
    pub go_exported: Option<String>,
    go_gen: u64,

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
            focus: [Focus::SvIn, Focus::DvIn, Focus::SealCtx, Focus::GoSource],
            want_col: [0; 4],
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
            sealed_with: None,
            sealing_with: None,
            validating_with: None,
            seal_queued: false,
            validate_queued: false,
            sealing_from: None,
            sealed_scroll: Scroll::default(),
            sealing: false,
            validating: false,
            ctl_pending: None,
            ctl_cache: HashMap::new(),
            ctl_refresh_gen: 0,
            go_source: Input::default(),
            go_ns: Input::default(),
            workflow: Workflow::default(),
            go_out: Input::default(),
            go_repo: Input::new(std::env::var("KSEAL_REPO").unwrap_or_default()),
            go_out_auto: true,
            go_preview: None,
            go_busy: false,
            go_scroll: Scroll::default(),
            go_find_scroll: 0,
            go_with: None,
            go_verified: None,
            go_exported: None,
            go_gen: 0,
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
        self.want_col[self.tab.idx()] = self.grid_pos().1;
    }

    /// (row, column) of the focused field in [`Focus::grid`].
    fn grid_pos(&self) -> (usize, usize) {
        let f = self.focus();
        Focus::grid(self.tab)
            .iter()
            .enumerate()
            .find_map(|(r, row)| row.iter().position(|x| *x == f).map(|c| (r, c)))
            .unwrap_or((0, 0))
    }

    /// Move focus one row up/down (aiming for `want_col`) or one field
    /// left/right along the row. Returns false at the edge of the layout.
    fn move_focus(&mut self, dr: isize, dc: isize) -> bool {
        let grid = Focus::grid(self.tab);
        let (r, c) = self.grid_pos();
        if dr != 0 {
            let Some(row) = r.checked_add_signed(dr).and_then(|nr| grid.get(nr)) else { return false };
            let col = self.want_col[self.tab.idx()].min(row.len() - 1);
            self.focus[self.tab.idx()] = row[col];
        } else {
            let Some(&f) = c.checked_add_signed(dc).and_then(|nc| grid[r].get(nc)) else { return false };
            self.set_focus(f);
        }
        true
    }

    // ------------------------------------------------------------ status

    pub fn set_status(&mut self, msg: impl Into<String>, kind: Kind) {
        self.status_for(msg, kind, STATUS_DURATION);
    }

    /// An operation failed (cluster, file, editor, seal…): the last line of
    /// the error (the cause) goes to the status line and the whole of it to a
    /// popup, unless another dialog is open (it isn't interrupted; the first
    /// error popup stays). Hints like "Generate YAML first" stay status-only.
    fn report_error(&mut self, title: &str, detail: String) {
        self.set_status(format!("{title}: {}", last_line(&detail)), Kind::Err);
        if self.modal.is_none() {
            self.modal = Some(Modal::Error { title: title.into(), detail });
        }
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
        self.sealed_with = None;
        self.yaml_out.clear();
        self.sealed_out.clear();
        self.yaml_scroll = Scroll::default();
        self.sealed_scroll = Scroll::default();
        if self.go_source.value().trim().is_empty() {
            self.go_changed();
        }
    }

    /// What the GitOps preview describes changed: drop it (and its verdict),
    /// so in-flight previews and checks land stale.
    fn go_changed(&mut self) {
        self.go_gen += 1;
        self.go_preview = None;
        self.go_verified = None;
        self.go_exported = None;
        self.go_with = None;
        self.go_scroll = Scroll::default();
        self.go_find_scroll = 0;
    }

    /// A row was added, removed or really edited.
    fn rows_changed(&mut self) {
        self.kv_edit_gen += 1;
        self.secret_edited();
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

    /// The Secret in the editor changed (rows, name, namespace, type): the
    /// generated YAML — and everything sealed from it — is out of date.
    /// Dropped, so Seal / Preview regenerate instead of sealing the old one.
    fn secret_edited(&mut self) {
        if !self.yaml_out.is_empty() {
            self.invalidate_outputs();
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
            KeyCode::F(n @ 1..=4) => self.tab = Tab::ALL[n as usize - 1],
            KeyCode::Tab => self.cycle_focus(1),
            KeyCode::BackTab => self.cycle_focus(-1),
            KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right if !ctrl => self.arrow(k),
            KeyCode::Char(c) if ctrl => match c {
                'n' => self.tab = Tab::ALL[(self.tab.idx() + 1) % Tab::ALL.len()],
                'p' => self.tab = Tab::ALL[(self.tab.idx() + Tab::ALL.len() - 1) % Tab::ALL.len()],
                'g' => {
                    self.generate();
                }
                'o' => self.open_prompt(),
                'l' => self.load_template(),
                'y' => self.copy_focused(),
                's' => self.save_prompt(),
                'k' => self.clear_focused(),
                'r' => self.refresh_contexts(),
                'e' if self.tab == Tab::GitOps => self.gitops_preview(),
                'e' => self.do_seal(),
                't' if self.tab == Tab::GitOps => self.gitops_validate(),
                't' => self.do_validate(),
                'd' => self.diff_prompt(),
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

    /// Arrows act inside the focused field first (table rows, pane scroll,
    /// text cursor) and move to the neighbouring field at its edge.
    fn arrow(&mut self, k: KeyEvent) {
        let f = self.focus();
        let vertical = matches!(k.code, KeyCode::Up | KeyCode::Down);
        let d: isize = if matches!(k.code, KeyCode::Up | KeyCode::Left) { -1 } else { 1 };
        let moved_inside = match f {
            Focus::Rows if vertical => list_nav(&mut self.rows_state, k, self.rows.len(), self.view.rows_h),
            Focus::DecRows if vertical => list_nav(&mut self.dec_state, k, self.dec_rows.len(), self.view.dec_h),
            Focus::Yaml => scroll_key(&mut self.yaml_scroll, k, self.view.yaml_h, &self.yaml_out),
            Focus::Sealed => scroll_key(&mut self.sealed_scroll, k, self.view.sealed_h, &self.sealed_out),
            Focus::GoPreview => {
                let text = self.go_preview.as_ref().and_then(|p| p.yaml.as_deref()).unwrap_or("");
                scroll_key(&mut self.go_scroll, k, self.view.go_h, text)
            }
            Focus::GoFindings if vertical => {
                let n = self.findings_lines();
                line_scroll(&mut self.go_find_scroll, k, self.view.findings_h, n)
            }
            _ if f.is_text() && !vertical => {
                let input = self.text_input(f);
                let at_edge = if d < 0 { input.at_start() } else { input.at_end() };
                if !at_edge {
                    input.handle(k);
                }
                !at_edge
            }
            _ => false,
        };
        if !moved_inside {
            if vertical {
                self.move_focus(d, 0)
            } else {
                self.move_focus(0, d)
            };
        }
    }

    fn text_input(&mut self, f: Focus) -> &mut Input {
        match f {
            Focus::SvIn => &mut self.sv_in,
            Focus::DvIn => &mut self.dv_in,
            Focus::SecName => &mut self.sec_name,
            Focus::SecNs => &mut self.sec_ns,
            Focus::CtlName => &mut self.ctl_name,
            Focus::CtlNs => &mut self.ctl_ns,
            Focus::GoSource => &mut self.go_source,
            Focus::GoNs => &mut self.go_ns,
            Focus::GoRepo => &mut self.go_repo,
            Focus::GoOut => &mut self.go_out,
            _ => &mut self.cert,
        }
    }

    /// Lines the findings pane renders (for scrolling).
    pub fn findings_lines(&self) -> usize {
        self.view.findings_total as usize
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
            Focus::SecName | Focus::SecNs => {
                let input = if f == Focus::SecName { &mut self.sec_name } else { &mut self.sec_ns };
                if input.handle(k) {
                    self.secret_edited();
                }
            }
            Focus::Cert => {
                self.cert.handle(k);
            }
            Focus::GoSource | Focus::GoNs | Focus::GoRepo => {
                if self.text_input(f).handle(k) {
                    self.go_changed();
                }
            }
            Focus::GoOut => {
                if self.go_out.handle(k) {
                    self.go_out_edited();
                }
            }
            Focus::GoScope | Focus::GoWorkflow => {
                if matches!(k.code, KeyCode::Enter | KeyCode::Char(' ')) {
                    self.open_picker(f);
                }
            }
            Focus::GoPreview => {
                let text = self.go_preview.as_ref().and_then(|p| p.yaml.as_deref()).unwrap_or("");
                scroll_key(&mut self.go_scroll, k, self.view.go_h, text);
            }
            Focus::GoFindings => {
                let n = self.findings_lines();
                line_scroll(&mut self.go_find_scroll, k, self.view.findings_h, n);
            }
            Focus::CtlName | Focus::CtlNs => {
                let input = if f == Focus::CtlName { &mut self.ctl_name } else { &mut self.ctl_ns };
                if input.handle(k) {
                    self.controller_edited();
                }
            }
            Focus::EncCtx | Focus::EncNs | Focus::EncSecret | Focus::SecType | Focus::SealCtx | Focus::Scope => {
                if matches!(k.code, KeyCode::Enter | KeyCode::Char(' ')) {
                    self.open_picker(f);
                }
            }
            Focus::Rows => self.rows_key(k),
            Focus::DecRows => self.dec_key(k),
            Focus::Yaml => {
                scroll_key(&mut self.yaml_scroll, k, self.view.yaml_h, &self.yaml_out);
            }
            Focus::Sealed => {
                scroll_key(&mut self.sealed_scroll, k, self.view.sealed_h, &self.sealed_out);
            }
            Focus::SvOut | Focus::DvOut => {}
        }
    }

    /// The user typed into a controller field: their value is now the newest,
    /// so drop any in-flight detection that would overwrite it.
    /// A queued seal is cancelled, and so is a validation queued behind it.
    fn cancel_queued(&mut self) {
        self.seal_queued = false;
        self.validate_queued = false;
    }

    fn controller_edited(&mut self) {
        if self.ctl_pending.is_some() {
            self.claim("controller");
            self.ctl_pending = None;
            self.cancel_queued();
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
            _ => {
                list_nav(&mut self.rows_state, k, n, self.view.rows_h);
            }
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
            _ => {
                list_nav(&mut self.dec_state, k, self.dec_rows.len(), self.view.dec_h);
            }
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
                Tab::Seal | Tab::GitOps => {}
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
                Focus::SecName => {
                    self.sec_name.insert_str(&line);
                    self.secret_edited();
                }
                Focus::SecNs => {
                    self.sec_ns.insert_str(&line);
                    self.secret_edited();
                }
                Focus::Cert => self.cert.insert_str(&line),
                Focus::CtlName => {
                    self.ctl_name.insert_str(&line);
                    self.controller_edited();
                }
                Focus::CtlNs => {
                    self.ctl_ns.insert_str(&line);
                    self.controller_edited();
                }
                f @ (Focus::GoSource | Focus::GoNs | Focus::GoRepo) => {
                    self.text_input(f).insert_str(&line);
                    self.go_changed();
                }
                Focus::GoOut => {
                    self.go_out.insert_str(&line);
                    self.go_out_edited();
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
            Modal::Error { title, detail } => {
                // Ctrl+Y copies the error (e.g. for a bug report) and keeps the
                // popup open; Ctrl+R closes it and retries the same way the
                // login hint says to — reloading the kubeconfig so the
                // credential plugin runs again; any other key closes.
                if ctrl && k.code == KeyCode::Char('y') {
                    self.effects.push(Effect::Copy { text: detail.clone(), skipped: None });
                    self.modal = Some(Modal::Error { title, detail });
                } else if ctrl && k.code == KeyCode::Char('r') {
                    self.refresh_contexts();
                }
            }
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
                    if let (true, PathPurpose::Diff(what)) = (path.is_empty(), purpose) {
                        self.diff_live(what);
                    } else if path.is_empty() {
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
                    self.effects.push(Effect::WriteFile {
                        path,
                        content,
                        overwrite: true,
                        what,
                        skipped,
                        confirmed: true,
                    });
                } else {
                    self.set_status("Save cancelled", Kind::Dim);
                }
            }
            Modal::Diff { title, diff, mut scroll, mut reveal, confirm } => {
                let n = diff.lines.len();
                match k.code {
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                        if confirm.is_some() {
                            self.set_status("Save cancelled", Kind::Dim);
                        }
                        return;
                    }
                    KeyCode::Char('y') | KeyCode::Char('Y') if confirm.is_some() => {
                        let p = confirm.expect("checked");
                        self.effects.push(Effect::WriteFile {
                            path: p.path,
                            content: p.content,
                            overwrite: true,
                            what: p.what,
                            skipped: p.skipped,
                            confirmed: p.confirmed,
                        });
                        return;
                    }
                    KeyCode::Char('x') if ctrl => {
                        reveal = !reveal;
                        if reveal {
                            self.status_for("Values revealed — Ctrl+X masks them again", Kind::Err, WARN_DURATION);
                        } else {
                            self.set_status("Values masked", Kind::Dim);
                        }
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') => {
                        let changes: Vec<usize> =
                            diff.lines.iter().enumerate().filter(|(_, l)| l.tag.is_change()).map(|(i, _)| i).collect();
                        let cur = scroll as usize;
                        let next = if k.code == KeyCode::Char('n') {
                            changes.iter().find(|&&i| i > cur).or(changes.first())
                        } else {
                            changes.iter().rev().find(|&&i| i < cur).or(changes.last())
                        };
                        match next {
                            Some(&i) => scroll = i as u16,
                            None => self.set_status("No changes", Kind::Dim),
                        }
                    }
                    _ => {
                        line_scroll(&mut scroll, k, self.view.modal_h, n);
                    }
                }
                self.modal = Some(Modal::Diff { title, diff, scroll, reveal, confirm });
            }
            Modal::Findings { title, findings, mut scroll, confirm } => {
                match k.code {
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                        if confirm.is_some() {
                            self.set_status("Save cancelled", Kind::Dim);
                        }
                        return;
                    }
                    KeyCode::Char('y') | KeyCode::Char('Y') if confirm.is_some() => {
                        let p = confirm.expect("checked");
                        self.effects.push(Effect::WriteFile {
                            path: p.path,
                            content: p.content,
                            overwrite: false,
                            what: p.what,
                            skipped: p.skipped,
                            confirmed: true,
                        });
                        return;
                    }
                    _ => {
                        line_scroll(&mut scroll, k, self.view.modal_h, self.view.modal_total as usize);
                    }
                }
                self.modal = Some(Modal::Findings { title, findings, scroll, confirm });
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
            Focus::Scope | Focus::GoScope => {
                let items = Scope::ALL.iter().map(|s| s.as_str().to_string()).collect();
                (PickTarget::Scope, "Scope", items, &self.scope.as_str().to_string(), false)
            }
            Focus::GoWorkflow => {
                let items = Workflow::ALL.iter().map(|w| w.title().to_string()).collect();
                (PickTarget::Workflow, "GitOps workflow", items, &self.workflow.title().to_string(), false)
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
                self.cancel_queued();
                self.fetch_namespaces(v.clone());
                self.detect_controller(v);
            }
            PickTarget::SealCtx => {
                self.seal_ctx = v.clone();
                self.cancel_queued();
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
                if self.sec_type != v {
                    self.secret_edited();
                }
                self.sec_type = v;
                self.type_auto = false;
            }
            PickTarget::Scope => {
                self.scope = Scope::ALL.into_iter().find(|s| s.as_str() == v).unwrap_or_default();
                self.go_changed();
            }
            PickTarget::ExportTo if v == OTHER_PATH => {
                let init = self.go_out_or_default();
                self.modal = Some(Modal::Path { purpose: PathPurpose::ExportTo, input: Input::new(init) });
            }
            PickTarget::ExportTo => self.set_go_out(&v),
            PickTarget::Workflow => {
                self.workflow = Workflow::ALL.into_iter().find(|w| w.title() == v).unwrap_or_default();
                self.go_changed();
            }
        }
    }

    fn open_prompt(&mut self) {
        if self.tab == Tab::GitOps && self.focus() == Focus::GoRepo {
            let init = self.go_repo.value().to_string();
            self.modal = Some(Modal::Path { purpose: PathPurpose::Repo, input: Input::new(init) });
            return;
        }
        if self.tab == Tab::GitOps && self.focus() == Focus::GoOut {
            let found = self.go_preview.as_ref().map(|p| p.found.clone()).unwrap_or_default();
            if !found.is_empty() {
                let mut items = found;
                items.push(OTHER_PATH.into());
                let picker = Picker::new("Export to: existing manifests for it", items, self.go_out.value(), false);
                self.modal = Some(Modal::Picker { target: PickTarget::ExportTo, picker });
                return;
            }
            let init = self.go_out_or_default();
            self.modal = Some(Modal::Path { purpose: PathPurpose::ExportTo, input: Input::new(init) });
            return;
        }
        let purpose = PathPurpose::Open(self.tab);
        let init = match self.tab {
            Tab::Seal => self.cert.value().to_string(),
            Tab::GitOps => self.go_source.value().to_string(),
            _ => String::new(),
        };
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
            Tab::GitOps => {
                self.gitops_export();
                return;
            }
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
            PathPurpose::Open(Tab::GitOps) => {
                self.go_source.set(path);
                self.go_changed();
                self.set_status("Source set — Ctrl+E seals and checks it", Kind::Ok);
            }
            PathPurpose::Diff(what) => {
                let tok = self.claim("diff-read");
                self.effects.push(Effect::ReadFile {
                    tok,
                    purpose: ReadPurpose::Diff(what),
                    path,
                    out_gen: self.out_gen,
                    kv_gen: self.kv_edit_gen,
                });
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
            PathPurpose::ExportTo => self.set_go_out(&path),
            PathPurpose::Repo => {
                self.go_repo.set(path);
                self.go_changed();
                self.set_status("Repo set — Ctrl+E looks for an existing manifest there", Kind::Ok);
            }
            PathPurpose::Save(SaveWhat::Export) => {
                self.set_go_out(&path);
                let content = self.go_yaml().unwrap_or_default().to_string();
                // The Encode tab's skipped metadata only matters when it is the source.
                let skipped = if self.go_source.value().trim().is_empty() { self.skipped } else { 0 };
                self.effects.push(Effect::WriteFile {
                    path,
                    content,
                    overwrite: false,
                    what: SaveWhat::Export,
                    skipped,
                    confirmed: false,
                });
            }
            PathPurpose::Save(what) => {
                let content = match what {
                    SaveWhat::Yaml => self.yaml_out.clone(),
                    SaveWhat::Sealed => self.sealed_out.clone(),
                    SaveWhat::Export => self.go_yaml().unwrap_or_default().to_string(),
                };
                // Frozen now so the confirmation describes the saved payload.
                let skipped = self.skipped;
                self.effects.push(Effect::WriteFile {
                    path,
                    content,
                    overwrite: false,
                    what,
                    skipped,
                    confirmed: false,
                });
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
            Focus::GoSource | Focus::GoNs | Focus::GoRepo => {
                if f_input(self).value().is_empty() {
                    return;
                }
                f_input(self).clear();
                self.go_changed();
            }
            Focus::GoOut => {
                self.go_out.clear();
                self.go_out_edited();
            }
            _ if self.tab == Tab::GitOps => {}
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
                    self.report_error("Decode failed", e.to_string());
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
            _ if self.tab == Tab::GitOps => match self.go_yaml() {
                Some(y) => (y.to_string(), self.go_source.value().trim().is_empty()),
                None => {
                    self.set_status("Preview first (Ctrl+E)", Kind::Err);
                    return;
                }
            },
            _ => (String::new(), false),
        };
        if text.is_empty() {
            self.set_status("Nothing to copy", Kind::Dim);
            return;
        }
        // A trailing newline can be part of a value (PEM): kept. CRLF line
        // breaks (e.g. a PEM created on Windows) are copied as LF.
        let text = text.replace("\r\n", "\n");
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
            if why == "detecting controller…" {
                self.seal_queued = true;
                self.set_status(
                    format!("Detecting the controller for {}… sealing when found", self.seal_ctx),
                    Kind::Dim,
                );
            } else {
                self.status_for(format!("Not sealed — still {why}"), Kind::Err, WARN_DURATION);
            }
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
        self.sealing_from = (cert.is_empty() && self.tab == Tab::Encode && self.enc_ctx != self.seal_ctx)
            .then(|| self.enc_ctx.clone())
            .filter(|c| !c.is_empty());
        self.sealing_with = Some(if cert.is_empty() {
            SealedWith::Controller { ctx: self.seal_ctx.clone(), ns: ctl.0.clone(), name: ctl.1.clone() }
        } else {
            SealedWith::Cert(cert.clone())
        });
        match &self.sealing_from {
            Some(enc) => self.set_status(format!("Sealing for {} (loaded from {enc})…", self.seal_ctx), Kind::Dim),
            None => self.set_status("Sealing…", Kind::Dim),
        }
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
        if self.sealing || self.seal_queued {
            self.validate_queued = true;
            self.set_status("Validating once the seal is done…", Kind::Dim);
            return;
        }
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
        self.validating_with =
            Some(SealedWith::Controller { ctx: self.seal_ctx.clone(), ns: ctl.0.clone(), name: ctl.1.clone() });
        self.set_status("Validating…", Kind::Dim);
        self.effects.push(Effect::Validate {
            out_gen: self.out_gen,
            sealed: self.sealed_out.clone(),
            ctx: self.seal_ctx.clone(),
            ctl,
            go: None,
        });
    }

    // ------------------------------------------------------------ GitOps / diff

    /// The current preview's SealedSecret, if there is one.
    pub fn go_yaml(&self) -> Option<&str> {
        self.go_preview.as_ref().and_then(|p| p.yaml.as_deref())
    }

    /// The output path changed: the target checks in the preview were for
    /// the old one (export re-checks the new one before writing).
    fn go_out_edited(&mut self) {
        // Typed by the user: theirs from now on (cleared: kseal's again).
        self.go_out_auto = self.go_out.value().trim().is_empty();
        self.go_exported = None;
        if let Some(p) = &mut self.go_preview {
            p.findings.retain(|f| !f.rule.starts_with("target.") && !f.rule.starts_with("kustomize."));
            p.out.clear();
        }
    }

    /// The key the wizard seals with: the Seal tab's certificate, else its
    /// context's controller. `Err` says what's missing.
    fn sealing_key(&self) -> Result<SealingKey, String> {
        let cert = self.cert.value().trim().to_string();
        let ctl = (self.ctl_ns.value().trim().to_string(), self.ctl_name.value().trim().to_string());
        if !cert.is_empty() {
            return Ok((Some(cert.clone()), ctl, SealedWith::Cert(cert)));
        }
        if self.seal_ctx.is_empty() || ctl.0.is_empty() || ctl.1.is_empty() {
            return Err("No sealing certificate: pick a context whose controller is known on the Seal tab (F3), \
                        or set a certificate file there"
                .into());
        }
        let with = SealedWith::Controller { ctx: self.seal_ctx.clone(), ns: ctl.0.clone(), name: ctl.1.clone() };
        Ok((None, ctl, with))
    }

    /// Ctrl+E on the GitOps tab: seal the source for the chosen namespace,
    /// scope and workflow, and validate everything about the result.
    fn gitops_preview(&mut self) {
        if self.go_busy {
            self.set_status("Still previewing…", Kind::Dim);
            return;
        }
        if self.cert.value().trim().is_empty() && self.detecting() {
            self.set_status(
                format!("Detecting the controller for {}… try again in a moment", self.seal_ctx),
                Kind::Dim,
            );
            return;
        }
        let src = self.go_source.value().trim().to_string();
        let source = if src.is_empty() {
            if self.yaml_out.trim().is_empty() && !self.generate() {
                return;
            }
            Source::Yaml(self.yaml_out.clone())
        } else {
            Source::File(src)
        };
        let (cert, ctl, with) = match self.sealing_key() {
            Ok(k) => k,
            Err(why) => {
                // A missing certificate is a finding, not just a status line.
                let f = Finding {
                    severity: Severity::Critical,
                    rule: "cert.missing",
                    resource: "sealing certificate".into(),
                    key: None,
                    message: "no certificate to seal with".into(),
                    remediation: why.clone(),
                };
                self.go_preview = Some(GoPreview {
                    yaml: None,
                    findings: vec![f],
                    name: String::new(),
                    namespace: String::new(),
                    out: String::new(),
                    source_yaml: None,
                    found: vec![],
                });
                self.set_status(why, Kind::Err);
                return;
            }
        };
        let ns = self.go_ns.value().trim();
        let opts = gitops::Options {
            workflow: self.workflow,
            scope: self.scope,
            namespace: (!ns.is_empty()).then(|| ns.to_string()),
        };
        self.go_busy = true;
        self.go_with = Some(with);
        self.set_status("Sealing and checking…", Kind::Dim);
        self.effects.push(Effect::GitopsPreview {
            go_gen: self.go_gen,
            source,
            opts,
            ctx: self.seal_ctx.clone(),
            cert,
            ctl,
            // The default is recomputed for the Secret actually previewed.
            out: if self.go_out_auto { String::new() } else { self.go_out.value().trim().to_string() },
            repo: self.go_repo.value().trim().to_string(),
        });
    }

    fn on_gitops_preview(&mut self, go_gen: u64, res: Result<GoPreview, String>) {
        self.go_busy = false;
        if go_gen != self.go_gen {
            self.set_status("Settings changed during the preview — discarded; Ctrl+E again", Kind::Err);
            return;
        }
        let p = match res {
            Err(e) => {
                self.go_with = None;
                self.report_error("Preview failed", e);
                return;
            }
            Ok(p) => p,
        };
        if (self.go_out_auto || self.go_out.value().trim().is_empty()) && !p.out.is_empty() {
            self.go_out.set(p.out.clone());
            self.go_out_auto = true;
        }
        let summary = crate::validate::summary(&p.findings);
        let worst = crate::validate::worst(&p.findings);
        let (msg, kind) = match (&p.yaml, worst) {
            (None, _) => (format!("Not sealed — the certificate is unusable ({summary})"), Kind::Err),
            (_, Some(Severity::Critical)) => (format!("Export blocked: {summary}"), Kind::Err),
            (_, Some(Severity::High)) => (format!("Preview ready, but check the findings: {summary}"), Kind::Err),
            _ => (format!("Preview ready ({summary}) — Ctrl+S exports, Ctrl+T asks the controller"), Kind::Ok),
        };
        self.go_preview = Some(p);
        self.go_scroll = Scroll::default();
        self.go_find_scroll = 0;
        self.status_for(msg, kind, WARN_DURATION);
    }

    /// Ctrl+T on the GitOps tab: ask the controller whether it can decrypt
    /// the preview (it creates nothing).
    fn gitops_validate(&mut self) {
        let Some(yaml) = self.go_yaml().map(str::to_string) else {
            self.set_status("Preview first (Ctrl+E)", Kind::Err);
            return;
        };
        if self.validating || self.sealing {
            self.set_status("Busy — try again in a moment", Kind::Dim);
            return;
        }
        let ctl = (self.ctl_ns.value().trim().to_string(), self.ctl_name.value().trim().to_string());
        if self.seal_ctx.is_empty() || ctl.0.is_empty() || ctl.1.is_empty() {
            self.set_status("The controller check needs a context and its controller (Seal tab, F3)", Kind::Err);
            return;
        }
        self.validating = true;
        self.validating_with =
            Some(SealedWith::Controller { ctx: self.seal_ctx.clone(), ns: ctl.0.clone(), name: ctl.1.clone() });
        self.set_status("Asking the controller…", Kind::Dim);
        self.effects.push(Effect::Validate {
            out_gen: self.out_gen,
            sealed: yaml,
            ctx: self.seal_ctx.clone(),
            ctl,
            go: Some(self.go_gen),
        });
    }

    fn on_gitops_validated(&mut self, go_gen: u64, res: Result<bool, String>) {
        self.validating = false;
        let against = self.validating_with.take();
        if go_gen != self.go_gen || self.go_preview.is_none() {
            self.set_status("The preview changed during the check — discarded", Kind::Err);
            return;
        }
        if let Some(SealedWith::Controller { ctx, .. }) = &against {
            if *ctx != self.seal_ctx {
                let msg = format!("Context changed during the check (was {ctx}) — result discarded");
                self.status_for(msg, Kind::Err, WARN_DURATION);
                return;
            }
        }
        let against = against.map_or_else(|| "the controller".into(), |a| a.to_string());
        let sealed = self.go_with.as_ref().map(ToString::to_string);
        let mismatch = sealed.filter(|s| *s != against);
        let ok = match res {
            Err(e) => {
                self.report_error("Controller check failed", e);
                return;
            }
            Ok(ok) => ok,
        };
        self.go_verified = Some(ok);
        let p = self.go_preview.as_mut().expect("checked");
        p.findings.retain(|f| !f.rule.starts_with("controller."));
        let also = mismatch.as_ref().map(|s| format!(" — but it was sealed with {s}")).unwrap_or_default();
        let res = format!("SealedSecret {}/{}", p.namespace, p.name);
        let f = if ok {
            Finding {
                severity: if mismatch.is_some() { Severity::Medium } else { Severity::Info },
                rule: "controller.verified",
                resource: res,
                key: None,
                message: format!("{against} can decrypt it (asked via /v1/verify){also}"),
                remediation: String::new(),
            }
        } else {
            Finding {
                severity: Severity::High,
                rule: "controller.cannot-decrypt",
                resource: res,
                key: None,
                message: format!("{against} cannot decrypt it{also}"),
                remediation:
                    "Seal it with this controller's certificate, for the namespace/name/scope it is applied with".into(),
            }
        };
        p.findings.push(f);
        crate::validate::sort(&mut p.findings);
        if ok && mismatch.is_none() {
            self.set_status(format!("Verified — {against} can decrypt it"), Kind::Ok);
        } else if ok {
            self.status_for(format!("Valid for {against}{also}"), Kind::Err, WARN_DURATION);
        } else {
            self.report_error("Invalid seal", format!("{against} cannot decrypt this SealedSecret{also}."));
        }
    }

    /// Ctrl+S on the GitOps tab: write the preview to the output path (after
    /// the target checks; Critical findings block it).
    fn gitops_export(&mut self) {
        let Some(p) = &self.go_preview else {
            self.set_status("Preview first (Ctrl+E)", Kind::Err);
            return;
        };
        let critical: Vec<String> = p
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .map(|f| format!("{}: {}", f.resource, f.message))
            .collect();
        if !critical.is_empty() {
            self.report_error("Export blocked", format!("Critical findings:\n{}", critical.join("\n")));
            return;
        }
        if p.yaml.is_none() {
            self.set_status("Nothing to export — the preview has no SealedSecret", Kind::Err);
            return;
        }
        // Ask where (pre-filled with the Output path; Tab completes).
        let init = self.go_out_or_default();
        self.modal = Some(Modal::Path { purpose: PathPurpose::Save(SaveWhat::Export), input: Input::new(init) });
    }

    fn go_out_or_default(&self) -> String {
        match self.go_out.value().trim() {
            "" => gitops::default_file_name(self.go_preview.as_ref().map_or("", |p| p.name.as_str())),
            v => v.to_string(),
        }
    }

    /// A path chosen in a prompt becomes the Output field (the user's now).
    fn set_go_out(&mut self, path: &str) {
        if self.go_out.value().trim() != path {
            self.go_out.set(path);
            self.go_out_edited();
        }
        self.go_out_auto = false;
    }

    /// Ctrl+D: compare the tab's output with a local manifest.
    fn diff_prompt(&mut self) {
        let what = match self.tab {
            Tab::Encode => {
                if self.yaml_out.trim().is_empty() && !self.generate() {
                    return;
                }
                SaveWhat::Yaml
            }
            Tab::Seal if !self.sealed_ok => {
                self.set_status("Seal a secret first", Kind::Err);
                return;
            }
            Tab::Seal => SaveWhat::Sealed,
            Tab::GitOps => {
                if self.go_yaml().is_none() {
                    self.set_status("Preview first (Ctrl+E)", Kind::Err);
                    return;
                }
                let path = self.go_out.value().trim().to_string();
                self.modal =
                    Some(Modal::Path { purpose: PathPurpose::Diff(SaveWhat::Export), input: Input::new(path) });
                return;
            }
            Tab::Decode => {
                self.set_status("Ctrl+D compares the Encode, Seal or GitOps output with a local file", Kind::Dim);
                return;
            }
        };
        self.modal = Some(Modal::Path { purpose: PathPurpose::Diff(what), input: Input::default() });
    }

    fn current_output(&self, what: SaveWhat) -> Option<&str> {
        match what {
            SaveWhat::Yaml => Some(self.yaml_out.as_str()).filter(|y| !y.trim().is_empty()),
            SaveWhat::Sealed => self.sealed_ok.then_some(self.sealed_out.as_str()),
            SaveWhat::Export => self.go_yaml(),
        }
    }

    /// The plain Secret a sealed output was sealed from, when kseal has it.
    fn output_source(&self, what: SaveWhat) -> Option<&str> {
        match what {
            SaveWhat::Yaml => None,
            SaveWhat::Sealed => self.sealed_ok.then_some(self.yaml_out.as_str()).filter(|y| !y.trim().is_empty()),
            SaveWhat::Export => self.go_preview.as_ref().and_then(|p| p.source_yaml.as_deref()),
        }
    }

    /// Ctrl+D with no path: compare with the Secret the output becomes in
    /// the cluster — read-only. Encode: the Encode tab's context; Seal /
    /// GitOps: the context it is sealed for.
    fn diff_live(&mut self, what: SaveWhat) {
        let (ctx, ns, name) = match what {
            SaveWhat::Yaml => (
                self.enc_ctx.clone(),
                non_empty(self.sec_ns.value(), core::DEF_NS),
                non_empty(self.sec_name.value(), core::DEF_NAME),
            ),
            SaveWhat::Sealed => {
                let ctx = match &self.sealed_with {
                    Some(SealedWith::Controller { ctx, .. }) => ctx.clone(),
                    _ => self.seal_ctx.clone(),
                };
                let docs = core::parse_yaml_docs(&self.sealed_out).unwrap_or_default();
                let (name, ns, _) = docs.first().map(core::secret_identity).unwrap_or_default();
                (ctx, ns, name)
            }
            SaveWhat::Export => match &self.go_preview {
                Some(p) => (self.seal_ctx.clone(), p.namespace.clone(), p.name.clone()),
                None => return,
            },
        };
        if ctx.is_empty() || ns.is_empty() || name.is_empty() {
            self.set_status("No context / namespace / name to look the live Secret up with", Kind::Err);
            return;
        }
        let tok = self.claim("diff-read");
        self.set_status(format!("Reading {ns}/{name} from {ctx} (read-only)…"), Kind::Dim);
        self.effects.push(Effect::FetchLive { tok, what, ctx, ns, name });
    }

    fn on_live_fetched(&mut self, tok: Tok, what: SaveWhat, label: String, res: Result<Option<String>, String>) {
        if !self.is_latest("diff-read", tok) {
            return;
        }
        match res {
            Err(e) => self.report_error("Reading the live Secret failed", e),
            Ok(Some(json)) => self.show_diff(&label, what, &json),
            Ok(None) => {
                self.set_status(format!("{label} doesn't exist yet — everything would be new"), Kind::Dim);
                self.show_diff(&format!("{label} (not in the cluster)"), what, "");
            }
        }
    }

    /// `old_label` names the old side: a file (its base name) or the live Secret.
    fn show_diff(&mut self, old_label: &str, what: SaveWhat, text: &str) {
        let Some(current) = self.current_output(what).map(str::to_string) else {
            self.set_status("The output to compare is gone — generate / seal / preview again", Kind::Err);
            return;
        };
        let source = self.output_source(what).map(str::to_string);
        match diff::diff_texts_from(text, &current, source.as_deref()) {
            Ok(d) => {
                let label = match what {
                    SaveWhat::Yaml => "generated YAML",
                    SaveWhat::Sealed => "sealed output",
                    SaveWhat::Export => "export preview",
                };
                let old = if old_label.starts_with("live ") { old_label.to_string() } else { basename(old_label) };
                self.set_status(format!("{old} → {label}: {}", d.summary), Kind::Dim);
                let title = format!("{old} → {label}");
                self.modal = Some(Modal::Diff { title, diff: d, scroll: 0, reveal: false, confirm: None });
            }
            Err(e) => self.report_error("Can't compare", format!("{e:#}")),
        }
    }

    fn on_written(&mut self, path: String, what: SaveWhat, skipped: usize, res: Result<(), WriteError>) {
        match res {
            Ok(()) if what == SaveWhat::Export => {
                self.go_exported = Some(path.clone());
                let msg = format!(
                    "Exported {} — commit it with Git (kseal never commits, pushes or applies)",
                    basename(&path)
                );
                self.status_output(&msg, Some(skipped));
            }
            Ok(()) => self.status_output(&format!("Saved {}", basename(&path)), Some(skipped)),
            Err(WriteError::Exists { content, existing }) => {
                let pending = PendingWrite { path: path.clone(), content, what, skipped, confirmed: true };
                match existing.as_deref().map(|old| diff::diff_texts(old, &pending.content)) {
                    Some(Ok(d)) => {
                        let title = format!("{} exists — what overwriting it changes", basename(&path));
                        self.set_status(format!("{} exists: {} — y overwrites", basename(&path), d.summary), Kind::Dim);
                        self.modal =
                            Some(Modal::Diff { title, diff: d, scroll: 0, reveal: false, confirm: Some(pending) });
                    }
                    _ => {
                        let PendingWrite { path, content, what, skipped, .. } = pending;
                        self.modal = Some(Modal::Overwrite { path, content, what, skipped });
                    }
                }
            }
            Err(WriteError::Risky { content, findings }) => {
                let blocked = findings.iter().any(|f| f.severity == Severity::Critical);
                let summary = crate::validate::summary(&findings);
                let confirm =
                    (!blocked).then(|| PendingWrite { path: path.clone(), content, what, skipped, confirmed: true });
                let msg = if blocked {
                    format!("Not saved — {summary}")
                } else {
                    format!("Check before writing: {summary} — y writes anyway")
                };
                self.status_for(msg, Kind::Err, WARN_DURATION);
                let title = format!("Before writing {}", basename(&path));
                self.modal = Some(Modal::Findings { title, findings, scroll: 0, confirm });
            }
            Err(WriteError::Io(e)) => self.report_error("Save failed", e),
        }
    }

    // ------------------------------------------------------------ results

    pub fn on_msg(&mut self, m: Msg) {
        match m {
            Msg::Contexts { tok, res } => {
                if !self.is_latest("contexts", tok) {
                    return;
                }
                match res {
                    Err(e) => self.report_error("Loading contexts failed", e),
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
                    Err(e) => self.report_error("Namespace fetch failed", e),
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
                    Err(e) => self.report_error("Secret list fetch failed", e),
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
            Msg::Written { path, what, skipped, res } => self.on_written(path, what, skipped, res),
            Msg::GitopsPreviewed { go_gen, res } => self.on_gitops_preview(go_gen, res),
            Msg::LiveFetched { tok, what, label, res } => self.on_live_fetched(tok, what, label, res),
            Msg::Validated { go: Some(go_gen), res, .. } => self.on_gitops_validated(go_gen, res),
            Msg::Sealed { out_gen, res } => {
                self.sealing = false;
                let with = self.sealing_with.take();
                let from = self.sealing_from.take();
                let validate = std::mem::take(&mut self.validate_queued);
                // A stale result describes the previous secret: don't resurrect it.
                if self.discard_stale(out_gen, "sealing", "; seal again") {
                    return;
                }
                match res {
                    Err(e) => {
                        self.sealed_ok = false;
                        self.sealed_with = None;
                        self.sealed_out = format!("# seal error\n{e}\n");
                        self.sealed_scroll = Scroll::default();
                        self.report_error("Seal failed", e);
                    }
                    Ok(y) => {
                        self.sealed_ok = !y.trim().is_empty();
                        self.sealed_with = with.filter(|_| self.sealed_ok);
                        self.sealed_out = y;
                        self.sealed_scroll = Scroll::default();
                        let moved = matches!(&self.sealed_with, Some(SealedWith::Controller { ctx, .. }) if *ctx != self.seal_ctx);
                        if let Some(with) = self.sealed_with.clone().filter(|_| moved) {
                            // The context changed while sealing: the output is
                            // the old context's, which Validate would flag.
                            let msg = format!("Sealed with {with} — the context is now {}; seal again", self.seal_ctx);
                            self.status_for(msg, Kind::Err, WARN_DURATION);
                        } else if let Some(with) = self.sealed_with.clone() {
                            let msg = match from {
                                Some(enc) => format!("Sealed with {with} (loaded from {enc})"),
                                None => format!("Sealed with {with}"),
                            };
                            self.status_output(&msg, None);
                            if validate {
                                self.do_validate();
                            }
                        } else {
                            self.report_error("Seal failed", "Sealing produced no output".into());
                        }
                    }
                }
            }
            Msg::Validated { out_gen, go: None, res } => {
                self.validating = false;
                let against = self.validating_with.take();
                if self.discard_stale(out_gen, "validation", "") {
                    return;
                }
                // The context changed while validating: the answer is the old
                // context's, and a green "Valid" would read as the new one's.
                let moved = match &against {
                    Some(SealedWith::Controller { ctx, .. }) if *ctx != self.seal_ctx => Some(ctx.clone()),
                    _ => None,
                };
                if let Some(was) = moved {
                    let msg =
                        format!("Context changed during validation (was {was}) — result discarded; validate again");
                    self.status_for(msg, Kind::Err, WARN_DURATION);
                    return;
                }
                let against = against.map_or_else(|| "the controller".into(), |a| a.to_string());
                // Validating against another key than the one sealed with is
                // allowed (does cluster B decrypt it?) but must never pass for
                // a check of the sealing cluster: say what was compared.
                let sealed = self.sealed_with.as_ref().map(ToString::to_string);
                let mismatch = sealed.as_ref().filter(|s| **s != against);
                match res {
                    Ok(true) => match mismatch {
                        Some(s) => self.status_for(
                            format!("Valid for {against} — but it was sealed with {s}"),
                            Kind::Err,
                            WARN_DURATION,
                        ),
                        None => self.set_status(format!("Valid — {against} can decrypt this"), Kind::Ok),
                    },
                    Ok(false) => {
                        let why = match (mismatch, &self.sealed_with) {
                            (Some(s), _) => format!("It was sealed with {s}, not {against}."),
                            _ => "Check that it was sealed with this controller's key, and its scope, name and \
                                  namespace."
                                .into(),
                        };
                        self.report_error(
                            "Invalid seal",
                            format!("{against} cannot decrypt this SealedSecret.\n{why}"),
                        );
                    }
                    Err(e) => self.report_error("Validation failed", e),
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
                        self.report_error("Editor failed", e);
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
                self.cancel_queued();
                self.report_error("Controller detection failed", e);
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
        let queued = std::mem::take(&mut self.seal_queued);
        let validate = std::mem::take(&mut self.validate_queued);
        match found {
            Some((ns, name)) => {
                self.apply_controller(ns, name);
                if queued {
                    self.do_seal();
                    // Only a seal that started can be validated after.
                    self.validate_queued = validate && self.sealing;
                }
            }
            None => {
                let msg =
                    format!("No sealed-secrets controller found in {ctx} — enter its name/NS, or use a certificate");
                if queued {
                    self.status_for(format!("Not sealed: {msg}"), Kind::Err, WARN_DURATION);
                } else {
                    self.set_status(msg, Kind::Dim);
                }
            }
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
                self.report_error("Load failed", e);
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
            self.report_error("Load failed", err);
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
        let key = match purpose {
            ReadPurpose::Editor => "editor-read",
            ReadPurpose::Decode => "decode-read",
            ReadPurpose::Diff(_) => "diff-read",
        };
        if !self.is_latest(key, tok) {
            return; // superseded by a newer pick
        }
        let text = match res {
            Err(e) => {
                self.report_error("Could not read file", e);
                return;
            }
            Ok(t) => t,
        };
        if let ReadPurpose::Diff(what) = purpose {
            self.show_diff(&path, what, &text);
            return;
        }
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
                    self.report_error("Import failed", err);
                    return;
                }
                let (total, binary) = self.apply_secret_doc(&doc, &entries, core::DEF_NAME, core::DEF_NS);
                self.file_label = path.clone();
                self.set_status(core::applied_msg("Imported", total, binary, &basename(&path)), Kind::Ok);
            }
        }
    }

    /// Parse YAML and pick the Secret doc, reporting failures (with the
    /// SealedSecret hint).
    fn secret_doc(&mut self, text: &str, verb: &str) -> Option<Value> {
        let docs = match core::parse_yaml_docs(text) {
            Ok(d) => d,
            Err(e) => {
                self.report_error("YAML parse error", e.to_string());
                return None;
            }
        };
        let doc = core::select_secret_doc(&docs).cloned();
        if doc.is_none() {
            if core::has_sealed_secret(&docs) {
                self.report_error(
                    &format!("Cannot {verb} a SealedSecret"),
                    format!("SealedSecret is encrypted — {verb} the plain Secret YAML it was sealed from"),
                );
            } else {
                self.report_error(&format!("Nothing to {verb}"), "No Secret data/stringData found in file".into());
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

/// The "type a path" entry of the Output picker.
const OTHER_PATH: &str = "Other path…";

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

/// The text input behind a GitOps text field (for clear).
fn f_input(app: &mut App) -> &mut Input {
    let f = app.focus();
    app.text_input(f)
}

/// Scroll a list of `n` lines shown `page` at a time. Returns whether it moved.
fn line_scroll(y: &mut u16, k: KeyEvent, page: u16, n: usize) -> bool {
    let before = *y;
    let page = page.max(1);
    let max = (n as u16).saturating_sub(page);
    match k.code {
        KeyCode::Up | KeyCode::Char('k') => *y = y.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => *y = (*y + 1).min(max),
        KeyCode::PageUp => *y = y.saturating_sub(page),
        KeyCode::PageDown | KeyCode::Char(' ') => *y = (*y + page).min(max),
        KeyCode::Home | KeyCode::Char('g') => *y = 0,
        KeyCode::End | KeyCode::Char('G') => *y = max,
        _ => {}
    }
    *y != before
}

/// Move the table selection. Returns whether it moved.
fn list_nav(state: &mut TableState, k: KeyEvent, n: usize, page: u16) -> bool {
    if n == 0 {
        state.select(None);
        return false;
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
        _ => return false,
    };
    state.select(Some(next.min(n - 1)));
    state.selected() != Some(cur)
}

/// Scroll a pane. Returns whether it moved.
fn scroll_key(s: &mut Scroll, k: KeyEvent, page: u16, text: &str) -> bool {
    let before = *s;
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
    *s != before
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
        app.on_msg(Msg::Validated { out_gen, go: None, res: Ok(true) });
        assert!(app.status.msg.starts_with("Valid"));
    }

    /// Seal (or validate) on the current context with a controller already
    /// cached for `ctx`, answering with `res`.
    fn seal_on(app: &mut App, ctx: &str) {
        app.tab = Tab::Seal;
        app.picked(PickTarget::SealCtx, ctx.into());
        if let Some(Effect::DetectController { tok, ctx, ctl_gen }) = take(app).pop() {
            let res = Ok(Some(("kube-system".into(), "sealed-secrets-controller".into())));
            app.on_msg(Msg::Controller { tok, ctx, ctl_gen, res });
        }
    }

    #[test]
    fn validate_says_what_the_output_was_sealed_with() {
        let mut app = connected();
        open_file(&mut app, "a.env", "A=1\n");
        seal_on(&mut app, "prod-a");
        app.on_key(ctrl('e'));
        let Some(Effect::Seal { out_gen, ctx, .. }) = take(&mut app).pop() else { panic!() };
        assert_eq!(ctx, "prod-a");
        app.on_msg(Msg::Sealed { out_gen, res: Ok("kind: SealedSecret\n".into()) });
        let a = "kube-system/sealed-secrets-controller in prod-a";
        assert_eq!(app.sealed_with.as_ref().map(ToString::to_string).as_deref(), Some(a));
        assert_eq!(app.status.msg, format!("Sealed with {a}"));

        // The sealing context validates plainly.
        app.on_key(ctrl('t'));
        let Some(Effect::Validate { out_gen, ctx, .. }) = take(&mut app).pop() else { panic!() };
        assert_eq!(ctx, "prod-a");
        app.on_msg(Msg::Validated { out_gen, go: None, res: Ok(true) });
        assert_eq!((app.status.msg.as_str(), app.status.kind), (&*format!("Valid — {a} can decrypt this"), Kind::Ok));

        // Switching context keeps the output, and both answers name the mismatch.
        seal_on(&mut app, "prod-b");
        app.on_key(ctrl('t'));
        let Some(Effect::Validate { out_gen, ctx, .. }) = take(&mut app).pop() else { panic!() };
        assert_eq!(ctx, "prod-b");
        app.on_msg(Msg::Validated { out_gen, go: None, res: Ok(true) });
        assert_eq!(app.status.kind, Kind::Err, "valid for another cluster must not read as plain success");
        assert!(app.status.msg.ends_with(&format!("but it was sealed with {a}")), "{}", app.status.msg);
        app.on_key(ctrl('t'));
        let Some(Effect::Validate { out_gen, .. }) = take(&mut app).pop() else { panic!() };
        app.on_msg(Msg::Validated { out_gen, go: None, res: Ok(false) });
        let Some(Modal::Error { detail, .. }) = &app.modal else { panic!("no popup") };
        assert!(detail.contains(&format!("It was sealed with {a}, not")), "{detail}");
    }

    #[test]
    fn seal_pressed_while_detecting_runs_once_the_controller_lands() {
        let mut app = connected();
        open_file(&mut app, "a.env", "A=1\n");
        seal_on(&mut app, "prod-a");
        app.on_key(ctrl('e'));
        let Some(Effect::Seal { out_gen, .. }) = take(&mut app).pop() else { panic!() };
        app.on_msg(Msg::Sealed { out_gen, res: Ok("kind: SealedSecret\n".into()) });

        // Switch and seal at once: the seal waits for detection, not dropped.
        app.picked(PickTarget::SealCtx, "prod-b".into());
        let Some(Effect::DetectController { tok, ctx, ctl_gen }) = take(&mut app).pop() else { panic!() };
        app.on_key(ctrl('e'));
        assert!(take(&mut app).is_empty());
        let res = Ok(Some(("kube-system".into(), "sealed-secrets-controller".into())));
        app.on_msg(Msg::Controller { tok, ctx, ctl_gen, res });
        let Some(Effect::Seal { out_gen, ctx, .. }) = take(&mut app).pop() else { panic!("queued seal didn't run") };
        assert_eq!(ctx, "prod-b");
        app.on_msg(Msg::Sealed { out_gen, res: Ok("kind: SealedSecret\n".into()) });
        app.on_key(ctrl('t'));
        let Some(Effect::Validate { out_gen, .. }) = take(&mut app).pop() else { panic!() };
        app.on_msg(Msg::Validated { out_gen, go: None, res: Ok(true) });
        assert_eq!(app.status.kind, Kind::Ok, "{}", app.status.msg);

        // A queued seal is for the context it was pressed on.
        app.picked(PickTarget::SealCtx, "prod-c".into());
        take(&mut app);
        app.on_key(ctrl('e'));
        seal_on(&mut app, "prod-d");
        assert!(take(&mut app).is_empty());

        // Switching while a seal is in flight: the result says it's stale.
        app.on_key(ctrl('e'));
        let Some(Effect::Seal { out_gen, .. }) = take(&mut app).pop() else { panic!() };
        app.picked(PickTarget::SealCtx, "prod-a".into());
        app.on_msg(Msg::Sealed { out_gen, res: Ok("kind: SealedSecret\n".into()) });
        assert_eq!(app.status.kind, Kind::Err);
        assert!(app.status.msg.contains("the context is now prod-a"), "{}", app.status.msg);
    }

    #[test]
    fn validation_landing_after_a_context_switch_is_not_shown_as_valid() {
        let mut app = connected();
        open_file(&mut app, "a.env", "A=1\n");
        seal_on(&mut app, "dev");
        app.on_key(ctrl('e'));
        let Some(Effect::Seal { out_gen, .. }) = take(&mut app).pop() else { panic!() };
        app.on_msg(Msg::Sealed { out_gen, res: Ok("kind: SealedSecret\n".into()) });

        // Validate on dev, switch to prod before dev answers.
        app.on_key(ctrl('t'));
        let Some(Effect::Validate { out_gen, ctx, .. }) = take(&mut app).pop() else { panic!() };
        assert_eq!(ctx, "dev");
        seal_on(&mut app, "prod");
        app.on_msg(Msg::Validated { out_gen, go: None, res: Ok(true) });
        assert_eq!(app.status.kind, Kind::Err, "{}", app.status.msg);
        assert!(app.status.msg.contains("Context changed during validation (was dev)"), "{}", app.status.msg);

        // Validating again checks prod, and names the mismatch.
        app.on_key(ctrl('t'));
        let Some(Effect::Validate { out_gen, ctx, .. }) = take(&mut app).pop() else { panic!() };
        assert_eq!(ctx, "prod");
        app.on_msg(Msg::Validated { out_gen, go: None, res: Ok(false) });
        let Some(Modal::Error { detail, .. }) = &app.modal else { panic!("no popup") };
        assert!(detail.contains("It was sealed with kube-system/sealed-secrets-controller in dev, not"), "{detail}");
    }

    #[test]
    fn a_certificate_file_overrides_the_context_and_says_so() {
        let mut app = connected();
        open_file(&mut app, "a.env", "A=1\n");
        app.cert.set("/tmp/other-cluster.pem");
        app.on_key(ctrl('e'));
        let Some(Effect::Seal { out_gen, cert, .. }) = take(&mut app).pop() else { panic!() };
        assert_eq!(cert.as_deref(), Some("/tmp/other-cluster.pem"));
        app.on_msg(Msg::Sealed { out_gen, res: Ok("kind: SealedSecret\n".into()) });
        assert_eq!(app.status.msg, "Sealed with the certificate /tmp/other-cluster.pem");
        app.on_key(ctrl('t'));
        let Some(Effect::Validate { out_gen, .. }) = take(&mut app).pop() else { panic!() };
        app.on_msg(Msg::Validated { out_gen, go: None, res: Ok(false) });
        let Some(Modal::Error { detail, .. }) = &app.modal else { panic!("no popup") };
        assert!(detail.contains("It was sealed with the certificate /tmp/other-cluster.pem, not"), "{detail}");
    }

    #[test]
    fn copy_turns_crlf_into_lf() {
        let mut app = App::new();
        app.rows.push(Row { key: "k".into(), value: "-----BEGIN-----\r\nabc\r\n".into(), binary: false, shown: false });
        app.rows_changed();
        app.set_focus(Focus::Rows);
        app.on_key(ctrl('y'));
        assert!(matches!(take(&mut app).pop(), Some(Effect::Copy { text, .. }) if text == "-----BEGIN-----\nabc\n"));
        assert_eq!(app.rows[0].value, "-----BEGIN-----\r\nabc\r\n", "the stored value is unchanged");
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
        let Some(Effect::WriteFile { path, content, overwrite: false, what, skipped, confirmed: false }) =
            take(&mut app).pop()
        else {
            panic!()
        };
        app.on_msg(Msg::Written { path, what, skipped, res: Err(WriteError::Exists { content, existing: None }) });
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
    fn cluster_errors_open_a_popup_with_the_whole_message() {
        let mut app = App::new();
        let detail = "Cluster login failed: plugin failed:\nThe security token is expired".to_string();
        app.report_error("Namespace fetch failed", detail.clone());
        assert_eq!(app.status.msg, "Namespace fetch failed: The security token is expired");
        assert!(matches!(&app.modal, Some(Modal::Error { detail: d, .. }) if *d == detail));
        // A second failure (parallel calls) doesn't replace the popup.
        app.report_error("Controller detection failed", "other".into());
        assert!(matches!(&app.modal, Some(Modal::Error { title, .. }) if title == "Namespace fetch failed"));
        // Ctrl+Y copies and keeps it open; any other key closes it.
        app.on_key(ctrl('y'));
        assert!(matches!(take(&mut app).pop(), Some(Effect::Copy { text, .. }) if text == detail));
        assert!(app.modal.is_some());
        app.on_key(key(KeyCode::Esc));
        assert!(app.modal.is_none());
        // Ctrl+R (what the login hint tells the user to press) closes the popup
        // and retries by reloading the kubeconfig.
        app.report_error("Namespace fetch failed", detail.clone());
        app.on_key(ctrl('r'));
        assert!(app.modal.is_none());
        let effects = take(&mut app);
        assert!(effects.iter().any(|e| matches!(e, Effect::ClearClients)));
        assert!(effects.iter().any(|e| matches!(e, Effect::LoadContexts { .. })));
        assert_eq!(app.status.msg, "Reloading kubeconfig…");
        // A dialog the user is in isn't interrupted.
        app.modal = Some(Modal::Help);
        app.report_error("Load failed", "boom".into());
        assert!(matches!(app.modal, Some(Modal::Help)));
        assert_eq!(app.status.msg, "Load failed: boom");
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
        assert_eq!(app.tab, Tab::GitOps);
        app.on_key(ctrl('n'));
        assert_eq!(app.tab, Tab::Encode);
        app.on_key(ctrl('p'));
        assert_eq!(app.tab, Tab::GitOps);
        app.on_key(KeyEvent::new(KeyCode::F(4), KeyModifiers::NONE));
        assert_eq!(app.tab, Tab::GitOps);
        app.on_key(ctrl('q'));
        assert!(app.quit);
    }

    fn press(app: &mut App, codes: &[KeyCode]) {
        for c in codes {
            app.on_key(key(*c));
        }
    }

    #[test]
    fn grid_flattens_to_the_tab_order() {
        for tab in Tab::ALL {
            let flat: Vec<Focus> = Focus::grid(tab).iter().flat_map(|r| r.iter().copied()).collect();
            assert_eq!(flat, Focus::order(tab), "{tab:?}");
        }
    }

    #[test]
    fn arrows_move_through_the_layout_and_remember_the_column() {
        use KeyCode::{Down, Left, Right, Up};
        let mut app = App::new();
        press(&mut app, &[Down, Down]);
        assert_eq!(app.focus(), Focus::EncCtx);
        press(&mut app, &[Right, Right, Right]); // stops at the row's end
        assert_eq!(app.focus(), Focus::EncSecret);
        press(&mut app, &[Left]);
        assert_eq!(app.focus(), Focus::EncNs);
        press(&mut app, &[Right]);
        press(&mut app, &[Down]); // empty table: straight through it
        assert_eq!(app.focus(), Focus::Rows);
        press(&mut app, &[Down]);
        assert_eq!(app.focus(), Focus::SecType, "keeps the Secret column");
        press(&mut app, &[Up, Up]);
        assert_eq!(app.focus(), Focus::EncSecret);
        press(&mut app, &[Up, Up, Up, Up]); // stops at the top
        assert_eq!(app.focus(), Focus::SvIn);
        // Pickers open with Enter, not arrows.
        press(&mut app, &[Down, Down, Down]);
        assert!(app.modal.is_none());

        app.on_key(KeyEvent::new(KeyCode::F(3), KeyModifiers::NONE));
        press(&mut app, &[Right]);
        assert_eq!((app.focus(), app.scope), (Focus::Scope, Scope::Strict), "arrows move, they don't cycle scope");
        press(&mut app, &[Down, Down]);
        assert_eq!(app.focus(), Focus::Cert);
    }

    #[test]
    fn arrows_act_inside_tables_and_text_before_leaving() {
        use KeyCode::{Down, End, Home, Left, Right, Up};
        let mut app = App::new();
        open_file(&mut app, "a.env", "A=1\nB=2\n");
        app.set_focus(Focus::Rows);
        app.rows_state.select(Some(0));
        press(&mut app, &[Down]);
        assert_eq!((app.focus(), app.rows_state.selected()), (Focus::Rows, Some(1)));
        press(&mut app, &[Down]); // last row: on to the next field
        assert_eq!(app.focus(), Focus::SecName);
        press(&mut app, &[Up, Up]);
        assert_eq!((app.focus(), app.rows_state.selected()), (Focus::Rows, Some(0)));
        press(&mut app, &[Up]);
        assert_eq!(app.focus(), Focus::EncCtx);

        // Text: ←/→ move the cursor, and only leave the field at its ends.
        app.set_focus(Focus::SecNs); // "default", cursor at the end
        press(&mut app, &[Left]);
        assert_eq!(app.focus(), Focus::SecNs);
        press(&mut app, &[Right, Right]);
        assert_eq!(app.focus(), Focus::SecType);
        press(&mut app, &[Left]);
        assert_eq!(app.focus(), Focus::SecNs);
        press(&mut app, &[Home, Left]);
        assert_eq!(app.focus(), Focus::SecName);
        press(&mut app, &[End, Right]);
        assert_eq!(app.focus(), Focus::SecNs);
        assert_eq!((app.sec_name.value(), app.sec_ns.value()), ("my-secret", "default"), "arrows never edit");
    }

    #[test]
    fn validate_pressed_while_sealing_runs_when_the_seal_lands() {
        let mut app = connected();
        open_file(&mut app, "a.env", "A=1\n");
        seal_on(&mut app, "dev");
        app.on_key(ctrl('e'));
        let Some(Effect::Seal { out_gen, .. }) = take(&mut app).pop() else { panic!() };
        app.on_key(ctrl('t'));
        assert!(take(&mut app).is_empty());
        assert_eq!(app.status.msg, "Validating once the seal is done…");
        app.on_msg(Msg::Sealed { out_gen, res: Ok("kind: SealedSecret\n".into()) });
        let Some(Effect::Validate { out_gen, ctx, .. }) = take(&mut app).pop() else { panic!("not validated") };
        assert_eq!(ctx, "dev");
        app.on_msg(Msg::Validated { out_gen, go: None, res: Ok(true) });
        assert_eq!(app.status.kind, Kind::Ok, "{}", app.status.msg);

        // A failed seal drops the queued validation.
        app.on_key(ctrl('e'));
        let Some(Effect::Seal { out_gen, .. }) = take(&mut app).pop() else { panic!() };
        app.on_key(ctrl('t'));
        app.on_msg(Msg::Sealed { out_gen, res: Err("boom".into()) });
        assert!(take(&mut app).is_empty());
        assert!(!app.validate_queued);
    }

    #[test]
    fn validate_queued_behind_a_queued_seal_follows_it() {
        let mut app = connected();
        open_file(&mut app, "a.env", "A=1\n");
        app.tab = Tab::Seal;
        app.picked(PickTarget::SealCtx, "dev".into());
        let Some(Effect::DetectController { tok, ctx, ctl_gen }) = take(&mut app).pop() else { panic!() };
        app.on_key(ctrl('e'));
        app.on_key(ctrl('t'));
        assert!(take(&mut app).is_empty());
        let res = Ok(Some(("kube-system".into(), "sealed-secrets-controller".into())));
        app.on_msg(Msg::Controller { tok, ctx, ctl_gen, res });
        let Some(Effect::Seal { out_gen, ctx, .. }) = take(&mut app).pop() else { panic!() };
        assert_eq!(ctx, "dev");
        app.on_msg(Msg::Sealed { out_gen, res: Ok("kind: SealedSecret\n".into()) });
        assert!(matches!(take(&mut app).pop(), Some(Effect::Validate { ctx, .. }) if ctx == "dev"));

        // Switching context cancels both.
        app.picked(PickTarget::SealCtx, "prod".into());
        take(&mut app);
        app.on_key(ctrl('e'));
        app.on_key(ctrl('t'));
        app.picked(PickTarget::SealCtx, "stage".into());
        assert!(!app.seal_queued && !app.validate_queued);
    }

    #[test]
    fn load_from_one_context_and_seal_for_another() {
        let mut app = connected();
        open_file(&mut app, "a.env", "A=1\n");
        seal_on(&mut app, "prod");
        assert_eq!((app.enc_ctx.as_str(), app.seal_ctx.as_str()), ("ctx", "prod"));
        app.tab = Tab::Encode;
        app.on_key(ctrl('e'));
        assert_eq!(app.status.msg, "Sealing for prod (loaded from ctx)…");
        let Some(Effect::Seal { out_gen, ctx, .. }) = take(&mut app).pop() else { panic!() };
        assert_eq!(ctx, "prod");
        app.on_msg(Msg::Sealed { out_gen, res: Ok("kind: SealedSecret\n".into()) });
        assert_eq!(app.status.kind, Kind::Ok, "{}", app.status.msg);
        assert!(app.status.msg.ends_with("in prod (loaded from ctx)"), "{}", app.status.msg);

        // Ctrl+T right after Ctrl+E validates against the context sealed for.
        app.on_key(ctrl('e'));
        let Some(Effect::Seal { out_gen, .. }) = take(&mut app).pop() else { panic!() };
        app.on_key(ctrl('t'));
        app.on_msg(Msg::Sealed { out_gen, res: Ok("kind: SealedSecret\n".into()) });
        let Some(Effect::Validate { out_gen, ctx, .. }) = take(&mut app).pop() else { panic!("not validated") };
        assert_eq!(ctx, "prod");
        app.on_msg(Msg::Validated { out_gen, go: None, res: Ok(true) });
        assert_eq!(app.status.kind, Kind::Ok, "{}", app.status.msg);
        assert!(app.status.msg.contains("in prod can decrypt"), "{}", app.status.msg);
    }

    // --- GitOps wizard / diff / guarded writes -----------------------------

    fn finding(sev: Severity, rule: &'static str) -> Finding {
        Finding {
            severity: sev,
            rule,
            resource: "SealedSecret prod/db".into(),
            key: None,
            message: "m".into(),
            remediation: String::new(),
        }
    }

    /// GitOps tab with a preview in place (answering the dispatched effect).
    fn previewed(findings: Vec<Finding>) -> App {
        let mut app = connected();
        open_file(&mut app, "a.env", "A=1\n");
        app.tab = Tab::GitOps;
        app.on_key(ctrl('e'));
        let Some(Effect::GitopsPreview { go_gen, source, opts, ctx, cert, .. }) = take(&mut app).pop() else {
            panic!("no preview effect")
        };
        assert!(matches!(source, Source::Yaml(y) if y.contains("kind: Secret")), "generated from the Encode tab");
        assert_eq!((opts.workflow, opts.scope, opts.namespace), (Workflow::Generic, Scope::Strict, None));
        assert_eq!((ctx.as_str(), cert), ("ctx", None));
        assert!(app.go_busy);
        let p = GoPreview {
            yaml: Some("---\napiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\n".into()),
            findings,
            name: "my-secret".into(),
            namespace: "default".into(),
            out: "sealed-my-secret.yaml".into(),
            source_yaml: None,
            found: vec![],
        };
        app.on_msg(Msg::GitopsPreviewed { go_gen, res: Ok(p) });
        assert!(!app.go_busy && app.go_yaml().is_some());
        app
    }

    #[test]
    fn gitops_preview_fills_the_output_and_exports_after_checks() {
        let mut app = previewed(vec![finding(Severity::Info, "sealed.structural-only")]);
        assert_eq!(app.go_out.value(), "sealed-my-secret.yaml");
        assert_eq!(app.status.kind, Kind::Ok, "{}", app.status.msg);
        app.on_key(ctrl('s'));
        let Some(Modal::Path { purpose: PathPurpose::Save(SaveWhat::Export), input }) = &app.modal else {
            panic!("Ctrl+S asks where to export")
        };
        assert_eq!(input.value(), "sealed-my-secret.yaml", "pre-filled with the Output path");
        app.on_key(key(KeyCode::Enter));
        let Some(Effect::WriteFile {
            path,
            content,
            overwrite: false,
            what: SaveWhat::Export,
            skipped,
            confirmed: false,
        }) = take(&mut app).pop()
        else {
            panic!("no export write")
        };
        assert_eq!(path, "sealed-my-secret.yaml");
        assert!(content.contains("SealedSecret"));
        app.on_msg(Msg::Written { path, what: SaveWhat::Export, skipped, res: Ok(()) });
        assert_eq!(app.go_exported.as_deref(), Some("sealed-my-secret.yaml"));
        assert!(app.status.msg.contains("never commits, pushes or applies"), "{}", app.status.msg);
    }

    #[test]
    fn gitops_default_output_follows_the_secret_until_typed() {
        let mut app = previewed(vec![]);
        assert_eq!(app.go_out.value(), "sealed-my-secret.yaml");
        let land = |app: &mut App, name: &str| {
            app.picked(PickTarget::Workflow, "Argo CD".into());
            app.on_key(ctrl('e'));
            let Some(Effect::GitopsPreview { go_gen, out, .. }) = take(app).pop() else { panic!() };
            let p = GoPreview {
                yaml: Some("y".into()),
                findings: vec![],
                name: name.into(),
                namespace: "ns".into(),
                out: if out.is_empty() { gitops::default_file_name(name) } else { out.clone() },
                source_yaml: None,
                found: vec![],
            };
            app.on_msg(Msg::GitopsPreviewed { go_gen, res: Ok(p) });
            out
        };
        // Another Secret: the default follows it instead of keeping the old name.
        assert_eq!(land(&mut app, "api"), "", "the executor picks the default");
        assert_eq!(app.go_out.value(), "sealed-api.yaml");
        // Typed by the user: kept.
        app.tab = Tab::GitOps;
        app.set_focus(Focus::GoOut);
        app.on_key(ctrl('k'));
        app.on_paste("repo/apps/db.yaml".into());
        assert_eq!(land(&mut app, "other"), "repo/apps/db.yaml");
        assert_eq!(app.go_out.value(), "repo/apps/db.yaml");
        // Cleared: the default again.
        app.set_focus(Focus::GoOut);
        app.on_key(ctrl('k'));
        assert_eq!(land(&mut app, "third"), "");
        assert_eq!(app.go_out.value(), "sealed-third.yaml");
    }

    #[test]
    fn gitops_critical_findings_block_export_and_settings_stale_the_preview() {
        let mut app = previewed(vec![finding(Severity::Critical, "file.plaintext-secret")]);
        assert!(app.status.msg.starts_with("Export blocked"));
        app.on_key(ctrl('s'));
        assert!(take(&mut app).is_empty(), "nothing is written");
        assert!(matches!(&app.modal, Some(Modal::Error { title, .. }) if title == "Export blocked"));
        app.modal = None;

        // Changing the scope (or workflow, namespace, source) drops the preview.
        app.picked(PickTarget::Workflow, "Flux".into());
        assert_eq!(app.workflow, Workflow::Flux);
        assert!(app.go_preview.is_none());
        app.on_key(ctrl('s'));
        assert!(take(&mut app).is_empty() && app.status.msg.contains("Preview first"));

        // A preview landing after a change is discarded.
        app.on_key(ctrl('e'));
        let Some(Effect::GitopsPreview { go_gen, opts, .. }) = take(&mut app).pop() else { panic!() };
        assert_eq!(opts.workflow, Workflow::Flux);
        app.picked(PickTarget::Scope, "cluster-wide".into());
        let p = GoPreview {
            yaml: Some("x".into()),
            findings: vec![],
            name: "n".into(),
            namespace: "d".into(),
            out: "o".into(),
            source_yaml: None,
            found: vec![],
        };
        app.on_msg(Msg::GitopsPreviewed { go_gen, res: Ok(p) });
        assert!(app.go_preview.is_none() && app.status.msg.contains("discarded"));
    }

    #[test]
    fn gitops_without_a_key_reports_a_missing_certificate() {
        let mut app = App::new();
        open_file(&mut app, "a.env", "A=1\n");
        app.tab = Tab::GitOps;
        app.on_key(ctrl('e'));
        assert!(take(&mut app).is_empty());
        let p = app.go_preview.as_ref().unwrap();
        assert_eq!((p.findings[0].severity, p.findings[0].rule), (Severity::Critical, "cert.missing"));
        assert!(p.yaml.is_none());
        // A certificate file is enough, and the source can be a file.
        app.cert.set("/tmp/cert.pem");
        app.go_source.set("/tmp/secret.yaml");
        app.set_focus(Focus::GoNs);
        app.on_paste("staging".into());
        app.on_key(ctrl('e'));
        let Some(Effect::GitopsPreview { source, cert, opts, .. }) = take(&mut app).pop() else { panic!() };
        assert_eq!(source, Source::File("/tmp/secret.yaml".into()));
        assert_eq!(cert.as_deref(), Some("/tmp/cert.pem"));
        assert_eq!(opts.namespace.as_deref(), Some("staging"));
    }

    #[test]
    fn gitops_controller_check_adds_a_finding() {
        let mut app = previewed(vec![]);
        app.on_key(ctrl('t'));
        let Some(Effect::Validate { go: Some(g), sealed, ctx, .. }) = take(&mut app).pop() else { panic!() };
        assert!(sealed.contains("SealedSecret") && ctx == "ctx");
        app.on_msg(Msg::Validated { out_gen: 0, go: Some(g), res: Ok(false) });
        assert_eq!(app.go_verified, Some(false));
        let f = &app.go_preview.as_ref().unwrap().findings;
        assert_eq!((f[0].rule, f[0].severity), ("controller.cannot-decrypt", Severity::High));
        app.modal = None;
        app.on_key(ctrl('t'));
        let Some(Effect::Validate { go: Some(g), .. }) = take(&mut app).pop() else { panic!() };
        app.on_msg(Msg::Validated { out_gen: 0, go: Some(g), res: Ok(true) });
        let f = &app.go_preview.as_ref().unwrap().findings;
        assert_eq!(
            f.iter().map(|f| f.rule).collect::<Vec<_>>(),
            vec!["controller.verified"],
            "replaces the old verdict"
        );
        assert_eq!(app.status.kind, Kind::Ok);
        // The Seal tab's own validation is untouched by it.
        assert!(!app.sealed_ok);
    }

    #[test]
    fn editing_the_output_path_drops_its_target_checks() {
        let mut app =
            previewed(vec![finding(Severity::High, "kustomize.namespace"), finding(Severity::Info, "cert.info")]);
        app.set_focus(Focus::GoOut);
        app.on_key(key(KeyCode::Backspace));
        let f = &app.go_preview.as_ref().unwrap().findings;
        assert_eq!(f.iter().map(|f| f.rule).collect::<Vec<_>>(), vec!["cert.info"]);
        assert!(app.go_yaml().is_some(), "the preview itself stays");
    }

    #[test]
    fn risky_target_asks_then_overwrite_shows_the_diff() {
        let mut app = connected();
        open_file(&mut app, "a.env", "PASSWORD=dummy-old\n");
        app.generate();
        let new_yaml = app.yaml_out.clone();
        app.on_key(ctrl('s'));
        app.on_key(key(KeyCode::Enter));
        let Some(Effect::WriteFile { path, content, what, skipped, .. }) = take(&mut app).pop() else { panic!() };
        // The executor found a High risk: the user is asked first.
        let findings = vec![finding(Severity::High, "target.plaintext-in-git")];
        app.on_msg(Msg::Written {
            path: path.clone(),
            what,
            skipped,
            res: Err(WriteError::Risky { content, findings }),
        });
        assert!(matches!(&app.modal, Some(Modal::Findings { confirm: Some(_), .. })));
        app.on_key(key(KeyCode::Char('y')));
        let Some(Effect::WriteFile { overwrite: false, confirmed: true, content, .. }) = take(&mut app).pop() else {
            panic!("y must write without re-asking")
        };
        // It exists: the diff opens, values masked, and y overwrites.
        let old = new_yaml.replace(&core::b64_encode("dummy-old"), &core::b64_encode("dummy-older"));
        app.on_msg(Msg::Written { path, what, skipped, res: Err(WriteError::Exists { content, existing: Some(old) }) });
        let Some(Modal::Diff { diff, confirm: Some(_), reveal: false, .. }) = &app.modal else { panic!("no diff") };
        assert_eq!(diff.summary.changed, 1);
        assert!(app.status.msg.contains("1 key(s) modified"), "{}", app.status.msg);
        app.on_key(key(KeyCode::Char('n')));
        app.on_key(ctrl('x'));
        assert!(matches!(&app.modal, Some(Modal::Diff { reveal: true, .. })), "Ctrl+X is an explicit reveal");
        app.on_key(key(KeyCode::Char('y')));
        assert!(matches!(take(&mut app).pop(), Some(Effect::WriteFile { overwrite: true, confirmed: true, .. })));
        assert!(app.modal.is_none());

        // Critical: shown, but no way to write.
        let findings = vec![finding(Severity::Critical, "target.symlink")];
        let res = Err(WriteError::Risky { content: "x".into(), findings });
        app.on_msg(Msg::Written { path: "l.yaml".into(), what, skipped, res });
        assert!(matches!(&app.modal, Some(Modal::Findings { confirm: None, .. })));
        app.on_key(key(KeyCode::Char('y')));
        assert!(take(&mut app).is_empty());
        app.on_key(key(KeyCode::Esc));
        assert!(app.modal.is_none());
    }

    #[test]
    fn ctrl_d_diffs_the_output_against_a_file() {
        let mut app = App::new();
        open_file(&mut app, "a.env", "A=1\nB=2\n");
        app.on_key(ctrl('d')); // generates first
        assert!(!app.yaml_out.is_empty());
        let Some(Modal::Path { purpose: PathPurpose::Diff(SaveWhat::Yaml), .. }) = &app.modal else { panic!() };
        app.on_paste("old.yaml".into());
        app.on_key(key(KeyCode::Enter));
        let Some(Effect::ReadFile { tok, purpose, path, out_gen, kv_gen }) = take(&mut app).pop() else { panic!() };
        let old = "kind: Secret\nmetadata: {name: my-secret, namespace: default}\nstringData: {A: '1', C: '3'}\n";
        app.on_msg(Msg::FileRead { tok, purpose, path, out_gen, kv_gen, res: Ok(old.into()) });
        let Some(Modal::Diff { diff, confirm: None, title, .. }) = &app.modal else { panic!("no diff") };
        assert_eq!(title, "old.yaml → generated YAML");
        assert_eq!((diff.summary.added, diff.summary.removed), (1, 1));
        assert_eq!(app.rows.len(), 2, "a diff never touches the editor");
        app.on_key(key(KeyCode::Esc));
        // Malformed YAML: a clear error, no diff.
        app.on_key(ctrl('d'));
        app.on_paste("bad.yaml".into());
        app.on_key(key(KeyCode::Enter));
        let Some(Effect::ReadFile { tok, purpose, path, out_gen, kv_gen }) = take(&mut app).pop() else { panic!() };
        app.on_msg(Msg::FileRead { tok, purpose, path, out_gen, kv_gen, res: Ok("a: [".into()) });
        assert!(matches!(&app.modal, Some(Modal::Error { detail, .. }) if detail.starts_with("old: malformed YAML")));
        // Seal / GitOps need their output first.
        app.modal = None;
        app.tab = Tab::Seal;
        app.on_key(ctrl('d'));
        assert!(app.modal.is_none() && app.status.msg.contains("Seal a secret first"));
    }

    #[test]
    fn ctrl_d_with_no_path_diffs_against_the_live_secret() {
        let mut app = connected();
        open_file(&mut app, "a.env", "A=1\nB=2\n");
        app.on_key(ctrl('d'));
        app.on_key(key(KeyCode::Enter)); // empty path = live
        let Some(Effect::FetchLive { tok, what, ctx, ns, name }) = take(&mut app).pop() else {
            panic!("no live fetch")
        };
        assert_eq!((what, ctx.as_str(), ns.as_str(), name.as_str()), (SaveWhat::Yaml, "ctx", "default", "my-secret"));
        let live = json!({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "my-secret", "namespace": "default", "uid": "u"},
            "data": {"A": core::b64_encode("old"), "B": core::b64_encode("2")}});
        let label = format!("live {ns}/{name} in {ctx}");
        app.on_msg(Msg::LiveFetched { tok, what, label: label.clone(), res: Ok(Some(live.to_string())) });
        let Some(Modal::Diff { diff, title, .. }) = &app.modal else { panic!("no diff") };
        assert_eq!(title, "live default/my-secret in ctx → generated YAML");
        assert_eq!((diff.summary.changed, diff.summary.added), (1, 0));
        // Not in the cluster yet: everything is new.
        app.modal = None;
        app.on_key(ctrl('d'));
        app.on_key(key(KeyCode::Enter));
        let Some(Effect::FetchLive { tok, what, .. }) = take(&mut app).pop() else { panic!() };
        app.on_msg(Msg::LiveFetched { tok, what, label, res: Ok(None) });
        let Some(Modal::Diff { diff, .. }) = &app.modal else { panic!("no diff") };
        assert_eq!(diff.lines[0].tag, diff::Tag::Added);
    }

    #[test]
    fn sealed_output_diffs_show_the_new_values_it_was_sealed_from() {
        let mut app = connected();
        open_file(&mut app, "a.env", "PASSWORD=dummy-new\n");
        seal_on(&mut app, "prod-a");
        app.on_key(ctrl('e'));
        let Some(Effect::Seal { out_gen, yaml, scope, .. }) = take(&mut app).pop() else { panic!() };
        let sealed = crate::seal::seal_yaml(&yaml, &crate::seal::tests::test_key().to_public_key(), scope).unwrap().0;
        app.on_msg(Msg::Sealed { out_gen, res: Ok(sealed) });
        app.on_key(ctrl('d'));
        app.on_key(key(KeyCode::Enter));
        let Some(Effect::FetchLive { tok, what, ctx, ns, name }) = take(&mut app).pop() else { panic!() };
        assert_eq!(
            (ctx.as_str(), ns.as_str(), name.as_str()),
            ("prod-a", "default", "my-secret"),
            "the sealed-for context"
        );
        let live = json!({"kind": "Secret", "metadata": {"name": "my-secret", "namespace": "default"},
            "data": {"PASSWORD": core::b64_encode("dummy-old")}});
        app.on_msg(Msg::LiveFetched { tok, what, label: "live".into(), res: Ok(Some(live.to_string())) });
        let Some(Modal::Diff { diff, .. }) = &app.modal else { panic!("no diff") };
        assert_eq!((diff.summary.changed, diff.summary.unknown), (1, 0), "really compared, not 'not comparable'");
        let shown: String = diff.lines.iter().map(|l| diff::render(l, true)).collect();
        assert!(shown.contains("\"dummy-old\" → \"dummy-new\""), "{shown}");
        let masked: String = diff.lines.iter().map(|l| diff::render(l, false)).collect();
        assert!(!masked.contains("dummy-"), "masked until Ctrl+X");
    }

    #[test]
    fn editing_the_secret_drops_stale_yaml_so_previews_use_the_edit() {
        let mut app = connected();
        open_file(&mut app, "a.env", "USER=alice\n");
        app.tab = Tab::GitOps;
        app.on_key(ctrl('e'));
        let Some(Effect::GitopsPreview { go_gen, source: Source::Yaml(first), .. }) = take(&mut app).pop() else {
            panic!()
        };
        assert!(first.contains(&core::b64_encode("alice")));
        // Edit USER on the Encode tab without pressing Ctrl+G.
        app.row_saved(Some(0), "USER".into(), "bob".into(), false);
        assert!(app.yaml_out.is_empty() && !app.sealed_ok, "the old YAML (and anything sealed from it) is dropped");
        let p = GoPreview {
            yaml: Some("y".into()),
            findings: vec![],
            name: "n".into(),
            namespace: "d".into(),
            out: "o".into(),
            source_yaml: None,
            found: vec![],
        };
        app.on_msg(Msg::GitopsPreviewed { go_gen, res: Ok(p) });
        assert!(app.go_preview.is_none(), "the preview of the old YAML lands stale");
        app.on_key(ctrl('e'));
        let Some(Effect::GitopsPreview { source: Source::Yaml(second), .. }) = take(&mut app).pop() else { panic!() };
        assert!(second.contains(&core::b64_encode("bob")), "the preview seals the edited Secret");
        // Name / namespace / type edits too.
        app.generate();
        app.tab = Tab::Encode;
        app.set_focus(Focus::SecNs);
        app.on_key(key(KeyCode::Char('x')));
        assert!(app.yaml_out.is_empty());
        app.generate();
        app.picked(PickTarget::SecType, "kubernetes.io/basic-auth".into());
        assert!(app.yaml_out.is_empty());
        // A same-value save changes nothing.
        app.generate();
        app.row_saved(Some(0), "USER".into(), "bob".into(), false);
        assert!(!app.yaml_out.is_empty());
    }

    #[test]
    fn gitops_choose_where_to_export() {
        let mut app = previewed(vec![]);
        // Ctrl+O on the Output field picks the destination only.
        app.set_focus(Focus::GoOut);
        app.on_key(ctrl('o'));
        let Some(Modal::Path { purpose: PathPurpose::ExportTo, .. }) = &app.modal else {
            panic!("no destination prompt")
        };
        app.on_key(ctrl('u'));
        app.on_paste("repo/apps/db.yaml".into());
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.go_out.value(), "repo/apps/db.yaml");
        assert!(take(&mut app).is_empty(), "choosing doesn't write");
        // Ctrl+S asks, pre-filled with it; another answer is used and kept.
        app.on_key(ctrl('s'));
        let Some(Modal::Path { input, .. }) = &app.modal else { panic!() };
        assert_eq!(input.value(), "repo/apps/db.yaml");
        app.on_key(ctrl('u'));
        app.on_paste("other/db.yaml".into());
        app.on_key(key(KeyCode::Enter));
        let Some(Effect::WriteFile { path, what: SaveWhat::Export, .. }) = take(&mut app).pop() else { panic!() };
        assert_eq!(path, "other/db.yaml");
        assert_eq!(app.go_out.value(), "other/db.yaml");
        // Esc cancels without writing; Ctrl+O elsewhere still picks the source.
        app.on_key(ctrl('s'));
        app.on_key(key(KeyCode::Esc));
        assert!(take(&mut app).is_empty());
        app.set_focus(Focus::GoSource);
        app.on_key(ctrl('o'));
        assert!(matches!(&app.modal, Some(Modal::Path { purpose: PathPurpose::Open(Tab::GitOps), .. })));
    }

    #[test]
    fn found_manifests_become_the_output_and_can_be_picked() {
        let mut app = connected();
        open_file(&mut app, "a.env", "A=1\n");
        app.tab = Tab::GitOps;
        let land = |app: &mut App, found: Vec<&str>| {
            app.on_key(ctrl('e'));
            let Some(Effect::GitopsPreview { go_gen, out, .. }) = take(app).pop() else { panic!() };
            let found: Vec<String> = found.into_iter().map(String::from).collect();
            // What the executor does: one match is the output when it's kseal's to pick.
            let out = match (out.is_empty(), found.as_slice()) {
                (true, [only]) => only.clone(),
                (true, _) => "sealed-my-secret.yaml".into(),
                (false, _) => out,
            };
            let p = GoPreview {
                yaml: Some("y".into()),
                findings: vec![],
                name: "my-secret".into(),
                namespace: "default".into(),
                out,
                source_yaml: None,
                found,
            };
            app.on_msg(Msg::GitopsPreviewed { go_gen, res: Ok(p) });
        };
        land(&mut app, vec!["apps/default/my-secret.yaml"]);
        assert_eq!(app.go_out.value(), "apps/default/my-secret.yaml");
        // Several: Ctrl+O on Output lists them (and "Other path…").
        app.picked(PickTarget::Workflow, "Flux".into());
        land(&mut app, vec!["a/s.yaml", "b/s.yaml"]);
        app.set_focus(Focus::GoOut);
        app.on_key(ctrl('o'));
        let Some(Modal::Picker { target: PickTarget::ExportTo, picker }) = &app.modal else { panic!("no picker") };
        assert_eq!(picker.items, vec!["a/s.yaml", "b/s.yaml", OTHER_PATH]);
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.go_out.value(), "b/s.yaml");
        app.on_key(ctrl('o'));
        app.on_key(key(KeyCode::End));
        for _ in 0..3 {
            app.on_key(key(KeyCode::Down));
        }
        app.on_key(key(KeyCode::Enter));
        assert!(matches!(&app.modal, Some(Modal::Path { purpose: PathPurpose::ExportTo, .. })), "Other path… prompts");
        app.modal = None;
        // A path the user chose is kept on the next preview.
        land(&mut app, vec!["c/s.yaml"]);
        assert_eq!(app.go_out.value(), "b/s.yaml");
    }
}
