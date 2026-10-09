//! Rendering: a pure function of [`App`], except that it records the heights
//! of scrollable areas back into `app.view` for paging.

use std::sync::OnceLock;

use ratatui::prelude::*;
use ratatui::widgets::{Block, BorderType, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, Wrap};

use super::app::{App, Focus, Kind, Modal, PathPurpose, PickTarget, SaveWhat, Tab};
use super::widgets::{Input, centered, one_line};
use crate::core::EntryKind;

struct Theme {
    bg: Color,
    bg2: Color,
    bg3: Color,
    field: Color,
    field_focus: Color,
    fg: Color,
    dim: Color,
    accent: Color,
    blue: Color,
    ok: Color,
    err: Color,
    border: Color,
    row_a: Color,
    row_b: Color,
}

/// Terminals that don't advertise truecolor get the nearest xterm-256 colour,
/// or RGB would render as garbage (macOS Terminal.app, older tmux).
fn truecolor() -> bool {
    let colorterm = std::env::var("COLORTERM").unwrap_or_default();
    colorterm.contains("truecolor")
        || colorterm.contains("24bit")
        || std::env::var_os("WT_SESSION").is_some()
        || matches!(
            std::env::var("TERM_PROGRAM").as_deref(),
            Ok("iTerm.app" | "WezTerm" | "vscode" | "ghostty" | "Hyper" | "rio")
        )
}

fn xterm256(r: u8, g: u8, b: u8) -> u8 {
    if r == g && g == b {
        return if r < 8 {
            16
        } else if r > 238 {
            231
        } else {
            232 + (r - 8) / 10
        };
    }
    let q = |v: u8| {
        if v < 48 {
            0
        } else if v < 115 {
            1
        } else {
            (v - 35) / 40
        }
    };
    16 + 36 * q(r) + 6 * q(g) + q(b)
}

fn theme() -> &'static Theme {
    static T: OnceLock<Theme> = OnceLock::new();
    T.get_or_init(|| {
        let tc = truecolor();
        let c = |hex: u32| {
            let (r, g, b) = ((hex >> 16) as u8, (hex >> 8) as u8, hex as u8);
            if tc { Color::Rgb(r, g, b) } else { Color::Indexed(xterm256(r, g, b)) }
        };
        Theme {
            bg: c(0x1e1e1e),
            bg2: c(0x252526),
            bg3: c(0x2d2d30),
            field: c(0x333337),
            field_focus: c(0x3a3d41),
            fg: c(0xd4d4d4),
            dim: c(0x858585),
            accent: c(0x48c9b0),
            blue: c(0x569cd6),
            ok: c(0x4caf50),
            err: c(0xf44747),
            border: c(0x3c3c3c),
            row_a: c(0x232323),
            row_b: c(0x2a2a2a),
        }
    })
}

pub fn draw(f: &mut Frame, app: &mut App) {
    let t = theme();
    let area = f.area();
    f.render_widget(Block::new().style(Style::new().bg(t.bg2).fg(t.fg)), area);
    let warn = app.skip_warning();
    let [tabs, body, warn_a, status_a, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(warn.is_some() as u16),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);

    draw_tabs(f, tabs, app);
    let body = body.inner(Margin { horizontal: 1, vertical: 0 });
    let mut cur = None;
    match app.tab {
        Tab::Encode => draw_encode(f, body, app, &mut cur),
        Tab::Decode => draw_decode(f, body, app, &mut cur),
        Tab::Seal => draw_seal(f, body, app, &mut cur),
    }

    if let Some(w) = warn {
        f.render_widget(Paragraph::new(format!(" {w}")).style(Style::new().bg(t.bg).fg(t.err)), warn_a);
    }
    let color = match app.status.kind {
        Kind::Ok => t.ok,
        Kind::Err => t.err,
        Kind::Dim => t.dim,
    };
    let ver = format!("  kseal v{} ", env!("CARGO_PKG_VERSION"));
    let [st, v] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(ver.len() as u16)]).areas(status_a);
    f.render_widget(
        Paragraph::new(format!(" {}", one_line(&app.status.msg))).style(Style::new().bg(t.bg).fg(color)),
        st,
    );
    f.render_widget(Paragraph::new(ver).style(Style::new().bg(t.bg).fg(t.dim)), v);
    draw_footer(f, footer, app);

    if let Some(m) = &app.modal {
        cur = draw_modal(f, area, m);
    }
    if let Some(p) = cur {
        f.set_cursor_position(p);
    }
}

fn draw_tabs(f: &mut Frame, area: Rect, app: &App) {
    let t = theme();
    let mut spans = vec![Span::styled(" kseal ", Style::new().fg(t.accent).bold())];
    for (i, tab) in Tab::ALL.iter().enumerate() {
        let style =
            if *tab == app.tab { Style::new().bg(t.bg2).fg(t.accent).bold() } else { Style::new().bg(t.bg3).fg(t.dim) };
        spans.push(Span::raw(" "));
        spans.push(Span::styled(format!(" F{} {} ", i + 1, tab.title()), style));
    }
    f.render_widget(Paragraph::new(Line::from(spans)).style(Style::new().bg(t.bg)), area);
    if !app.enc_ctx.is_empty() {
        let ctx = format!("⎈ {} ", app.enc_ctx);
        let w = (ctx.chars().count() as u16).min(area.width / 2);
        let r = Rect { x: area.right() - w, width: w, ..area };
        f.render_widget(Paragraph::new(ctx).style(Style::new().bg(t.bg).fg(t.dim)).right_aligned(), r);
    }
}

fn heading(f: &mut Frame, area: Rect, text: &str, extra: Option<Line>) {
    let t = theme();
    let mut spans = vec![Span::styled(text.to_string(), Style::new().fg(t.accent).bold())];
    if let Some(extra) = extra {
        spans.push(Span::raw("   "));
        spans.extend(extra.spans);
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn separator(f: &mut Frame, area: Rect) {
    let t = theme();
    let line = "─".repeat(area.width as usize);
    f.render_widget(Paragraph::new(line).style(Style::new().fg(t.border)), area);
}

enum Content<'a> {
    Input { input: &'a Input, masked: bool, placeholder: &'a str },
    Text(String, Style),
    Picker(String),
}

const LABEL_W: u16 = 11;

/// A labelled one-line field. Returns the cursor position when focused.
fn field(f: &mut Frame, area: Rect, label: &str, label_w: u16, content: Content, focused: bool) -> Option<Position> {
    let t = theme();
    let [l, gap, b] =
        Layout::horizontal([Constraint::Length(label_w), Constraint::Length(1), Constraint::Fill(1)]).areas(area);
    let _ = gap;
    let lstyle = if focused { Style::new().fg(t.accent).bold() } else { Style::new().fg(t.fg) };
    f.render_widget(Paragraph::new(label.to_string()).style(lstyle), l);
    let bstyle = Style::new().bg(if focused { t.field_focus } else { t.field }).fg(t.fg);
    let inner_w = b.width.saturating_sub(2);
    let mut cursor = None;
    let line: Line = match content {
        Content::Input { input, masked, placeholder } => {
            if input.value().is_empty() && !focused {
                Line::styled(placeholder.to_string(), Style::new().fg(t.dim))
            } else {
                let (s, col) = input.view(inner_w, masked);
                if focused {
                    cursor = Some(Position { x: b.x + 1 + col, y: b.y });
                }
                Line::raw(s)
            }
        }
        Content::Text(s, style) => Line::styled(truncate(&s, inner_w as usize), style),
        Content::Picker(v) => {
            let w = inner_w.saturating_sub(2) as usize;
            let shown =
                if v.is_empty() { Span::styled("—", Style::new().fg(t.dim)) } else { Span::raw(truncate(&v, w)) };
            let pad = w.saturating_sub(shown.width());
            Line::from(vec![shown, Span::raw(" ".repeat(pad)), Span::styled(" ▾", Style::new().fg(t.dim))])
        }
    };
    f.render_widget(
        Paragraph::new(line).style(bstyle).block(Block::new().padding(ratatui::widgets::Padding::horizontal(1))),
        b,
    );
    cursor
}

const BUTTON_W: u16 = 15;

/// Split a field row so a key "button" sits at its right edge.
fn with_button(area: Rect) -> (Rect, Rect) {
    let [field, _, button] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(1), Constraint::Length(BUTTON_W)]).areas(area);
    (field, button)
}

fn show_label(shown: bool) -> &'static str {
    if shown { "Ctrl+X hide" } else { "Ctrl+X show" }
}

/// A button-looking label naming the key that does it (the TUI has no mouse).
fn key_button(f: &mut Frame, area: Rect, label: &str, active: bool) {
    let t = theme();
    let style =
        if active { Style::new().bg(t.field_focus).fg(t.accent).bold() } else { Style::new().bg(t.bg3).fg(t.dim) };
    f.render_widget(Paragraph::new(label.to_string()).style(style).centered(), area);
}

fn truncate(s: &str, w: usize) -> String {
    let s = one_line(s);
    if s.chars().count() <= w {
        return s;
    }
    let mut out: String = s.chars().take(w.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn masked(s: &str, shown: bool) -> String {
    if shown { one_line(s) } else { "•".repeat(s.chars().count().min(48)) }
}

fn pane_block<'a>(title: &'a str, hint: &'a str, focused: bool) -> Block<'a> {
    let t = theme();
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if focused { t.accent } else { t.border }))
        .title(Line::styled(format!(" {title} "), Style::new().fg(if focused { t.accent } else { t.fg }).bold()))
        .title_top(Line::styled(format!(" {hint} "), Style::new().fg(t.dim)).right_aligned())
        .style(Style::new().bg(t.bg3))
}

fn draw_encode(f: &mut Frame, area: Rect, app: &mut App, cur: &mut Option<Position>) {
    let t = theme();
    let fo = app.focus();
    let [h1, sv1, sv2, sep, h2, sel, table, ident, yaml] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area);

    heading(f, h1, "Single value encoder", None);
    let sv_in = Content::Input { input: &app.sv_in, masked: !app.sv_shown, placeholder: "type or paste a value" };
    let sv_focus = matches!(fo, Focus::SvIn | Focus::SvOut);
    let (sv1, b1) = with_button(sv1);
    let (sv2, b2) = with_button(sv2);
    *cur = field(f, sv1, "Value", LABEL_W, sv_in, fo == Focus::SvIn).or(*cur);
    key_button(f, b1, show_label(app.sv_shown), sv_focus);
    let enc = app.sv_encoded();
    let out = Content::Text(masked(&enc, app.sv_shown), Style::new().fg(t.blue));
    field(f, sv2, "Base64", LABEL_W, out, fo == Focus::SvOut);
    key_button(f, b2, "Ctrl+Y copy", sv_focus);
    separator(f, sep);

    let file = Line::from(vec![
        Span::styled("File: ", Style::new().fg(t.fg)),
        Span::styled(app.file_label.clone(), Style::new().fg(t.dim)),
    ]);
    heading(f, h2, ".env → Kubernetes Secret", Some(file));

    let [c, n, s] =
        Layout::horizontal([Constraint::Fill(5), Constraint::Fill(3), Constraint::Fill(4)]).spacing(2).areas(sel);
    field(f, c, "Context", LABEL_W, Content::Picker(app.enc_ctx.clone()), fo == Focus::EncCtx);
    field(f, n, "NS", 2, Content::Picker(app.enc_ns.clone()), fo == Focus::EncNs);
    field(f, s, "Secret", 6, Content::Picker(app.enc_sec.clone()), fo == Focus::EncSecret);

    draw_rows(f, table, app);

    let [nm, ns, ty] =
        Layout::horizontal([Constraint::Fill(5), Constraint::Fill(3), Constraint::Fill(4)]).spacing(2).areas(ident);
    let name = Content::Input { input: &app.sec_name, masked: false, placeholder: crate::core::DEF_NAME };
    *cur = field(f, nm, "Secret name", LABEL_W, name, fo == Focus::SecName).or(*cur);
    let nsv = Content::Input { input: &app.sec_ns, masked: false, placeholder: crate::core::DEF_NS };
    *cur = field(f, ns, "NS", 2, nsv, fo == Focus::SecNs).or(*cur);
    field(f, ty, "Type", 6, Content::Picker(app.sec_type.clone()), fo == Focus::SecType);

    let blk = pane_block("Secret YAML", "Ctrl+G generate · Ctrl+Y copy · Ctrl+S save", fo == Focus::Yaml);
    app.view.yaml_h = blk.inner(yaml).height;
    let text = if app.yaml_out.is_empty() {
        Text::styled("Ctrl+G generates the Secret YAML from the rows above", Style::new().fg(t.dim))
    } else {
        Text::styled(app.yaml_out.as_str(), Style::new().fg(t.blue))
    };
    f.render_widget(Paragraph::new(text).block(blk).scroll((app.yaml_scroll.y, app.yaml_scroll.x)), yaml);
}

fn draw_rows(f: &mut Frame, area: Rect, app: &mut App) {
    let t = theme();
    let focused = app.focus() == Focus::Rows;
    let blk = pane_block("Keys", "a add · d delete · Enter edit · e $EDITOR · v/V show", focused);
    let inner = blk.inner(area);
    app.view.rows_h = inner.height.saturating_sub(1);
    if app.rows.is_empty() {
        let hint = "No keys yet — Ctrl+O open a .env / Secret YAML · Ctrl+L load from cluster · a add a row";
        f.render_widget(Paragraph::new(hint).style(Style::new().fg(t.dim)).wrap(Wrap { trim: true }).block(blk), area);
        return;
    }
    let key_w = (inner.width / 3).clamp(8, 40);
    let rows = app.rows.iter().enumerate().map(|(i, r)| {
        let bg = if i % 2 == 0 { t.row_a } else { t.row_b };
        let val = if r.binary {
            Span::styled("⟨binary — kept as-is on Generate⟩", Style::new().fg(t.dim).italic())
        } else if r.value.is_empty() {
            Span::styled("(empty)", Style::new().fg(t.dim))
        } else {
            Span::styled(masked(&r.value, r.shown), Style::new().fg(t.blue))
        };
        Row::new([Cell::from(one_line(&r.key)), Cell::from(val)]).style(Style::new().bg(bg))
    });
    let hl = if focused { Style::new().bg(t.field_focus).fg(t.accent).bold() } else { Style::new().bg(t.field) };
    let table = Table::new(rows, [Constraint::Length(key_w), Constraint::Fill(1)])
        .header(Row::new(["Key", "Value"]).style(Style::new().fg(t.fg).bold()))
        .row_highlight_style(hl)
        .highlight_symbol("▌")
        .block(blk);
    f.render_stateful_widget(table, area, &mut app.rows_state);
}

fn draw_decode(f: &mut Frame, area: Rect, app: &mut App, cur: &mut Option<Position>) {
    let t = theme();
    let fo = app.focus();
    let hint_h = app.dec_hint.is_some() as u16;
    let [h1, dv1, dv2, sep, h2, hint, table] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(hint_h * 2),
        Constraint::Fill(1),
    ])
    .areas(area);

    heading(f, h1, "Single value decoder", None);
    let dv_in = Content::Input { input: &app.dv_in, masked: false, placeholder: "paste base64" };
    let dv_focus = matches!(fo, Focus::DvIn | Focus::DvOut);
    let (dv1, b1) = with_button(dv1);
    let (dv2, b2) = with_button(dv2);
    *cur = field(f, dv1, "Base64", LABEL_W, dv_in, fo == Focus::DvIn).or(*cur);
    key_button(f, b1, "Ctrl+K clear", dv_focus);
    let out = match app.dv_decoded() {
        Ok(s) => Content::Text(masked(&s, app.dv_shown), Style::new().fg(t.blue)),
        Err(e) => Content::Text(e, Style::new().fg(t.err)),
    };
    field(f, dv2, "Decoded", LABEL_W, out, fo == Focus::DvOut);
    key_button(f, b2, show_label(app.dv_shown), dv_focus);
    separator(f, sep);

    let file = Line::from(vec![
        Span::styled("File: ", Style::new().fg(t.fg)),
        Span::styled(app.dec_label.clone(), Style::new().fg(t.dim)),
    ]);
    heading(f, h2, "Secret YAML → decoded table", Some(file));
    if let Some(h) = &app.dec_hint {
        f.render_widget(Paragraph::new(format!("⚠ {h}")).style(Style::new().fg(t.err)).wrap(Wrap { trim: true }), hint);
    }

    let focused = fo == Focus::DecRows;
    let blk = pane_block("Decoded", "Ctrl+O open · v show · V all · Ctrl+Y copy value", focused);
    let inner = blk.inner(table);
    app.view.dec_h = inner.height.saturating_sub(1);
    if app.dec_rows.is_empty() {
        let msg = "Ctrl+O opens a Secret YAML (multi-doc and kind: List are fine) — values stay masked until shown";
        f.render_widget(Paragraph::new(msg).style(Style::new().fg(t.dim)).wrap(Wrap { trim: true }).block(blk), table);
        return;
    }
    let key_w = (inner.width / 3).clamp(8, 40);
    let rows = app.dec_rows.iter().enumerate().map(|(i, r)| {
        let bg = if i % 2 == 0 { t.row_a } else { t.row_b };
        let style = if r.kind == EntryKind::Text { Style::new().fg(t.blue) } else { Style::new().fg(t.dim).italic() };
        Row::new([Cell::from(one_line(&r.key)), Cell::from(Span::styled(one_line(&r.display()), style))])
            .style(Style::new().bg(bg))
    });
    let hl = if focused { Style::new().bg(t.field_focus).fg(t.accent).bold() } else { Style::new().bg(t.field) };
    let tbl = Table::new(rows, [Constraint::Length(key_w), Constraint::Fill(1)])
        .header(Row::new(["Key", "Decoded value"]).style(Style::new().fg(t.fg).bold()))
        .row_highlight_style(hl)
        .highlight_symbol("▌")
        .block(blk);
    f.render_stateful_widget(tbl, table, &mut app.dec_state);
}

fn draw_seal(f: &mut Frame, area: Rect, app: &mut App, cur: &mut Option<Position>) {
    let t = theme();
    let fo = app.focus();
    let [h1, r1, r2, r3, _gap, r4, _gap2, out] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area);
    const W: u16 = 15;

    heading(f, h1, "Seal Kubernetes Secret", None);
    let [c, s] = Layout::horizontal([Constraint::Fill(3), Constraint::Fill(2)]).spacing(2).areas(r1);
    field(f, c, "Context", W, Content::Picker(app.seal_ctx.clone()), fo == Focus::SealCtx);
    field(f, s, "Scope", 5, Content::Picker(app.scope.as_str().into()), fo == Focus::Scope);

    let [n, ns] = Layout::horizontal([Constraint::Fill(3), Constraint::Fill(2)]).spacing(2).areas(r2);
    let ph = if app.detecting() { "detecting…" } else { "auto-detected per context" };
    let name = Content::Input { input: &app.ctl_name, masked: false, placeholder: ph };
    *cur = field(f, n, "Controller", W, name, fo == Focus::CtlName).or(*cur);
    let nsv = Content::Input { input: &app.ctl_ns, masked: false, placeholder: ph };
    *cur = field(f, ns, "NS", 5, nsv, fo == Focus::CtlNs).or(*cur);

    let cert = Content::Input {
        input: &app.cert,
        masked: false,
        placeholder: "(none — fetched from the controller; Ctrl+O to pick a PEM for offline sealing)",
    };
    *cur = field(f, r3, "Cert (optional)", W, cert, fo == Focus::Cert).or(*cur);

    let button = |label: &str, blocked: Option<&str>, primary: bool| {
        let style = match (blocked, primary) {
            (Some(_), _) => Style::new().bg(t.bg3).fg(t.dim),
            (None, true) => Style::new().bg(t.accent).fg(t.bg).bold(),
            (None, false) => Style::new().bg(t.field_focus).fg(t.fg),
        };
        Span::styled(format!(" {label} "), style)
    };
    let seal_blk = app.seal_blocked();
    let val_blk = app.validate_blocked();
    let mut spans = vec![
        button("Ctrl+E  Seal →", seal_blk, true),
        Span::raw("  "),
        button("Ctrl+T  Validate", val_blk, false),
        Span::raw("   "),
    ];
    let note = match (seal_blk, val_blk) {
        (Some(why), _) => why.to_string(),
        _ => "Seals the YAML generated on the Encode tab (generating it if empty)".into(),
    };
    spans.push(Span::styled(note, Style::new().fg(t.dim)));
    f.render_widget(Paragraph::new(Line::from(spans)), r4);

    let blk = pane_block("SealedSecret", "Ctrl+Y copy · Ctrl+S save", fo == Focus::Sealed);
    app.view.sealed_h = blk.inner(out).height;
    let text = if app.sealed_out.is_empty() {
        Text::styled(
            "Sealed output appears here — nothing leaves your machine until you apply it",
            Style::new().fg(t.dim),
        )
    } else if app.sealed_ok {
        Text::styled(app.sealed_out.as_str(), Style::new().fg(t.blue))
    } else {
        Text::styled(app.sealed_out.as_str(), Style::new().fg(t.err))
    };
    f.render_widget(Paragraph::new(text).block(blk).scroll((app.sealed_scroll.y, app.sealed_scroll.x)), out);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let t = theme();
    let hints = match app.modal {
        Some(Modal::Picker { .. }) => "type to filter · ↑↓ move · Enter choose · Esc cancel",
        Some(Modal::Path { .. }) => "Tab complete · Enter OK · Esc cancel",
        Some(Modal::RowEdit { .. }) => "Tab key/value · Enter save · Ctrl+X show · Esc cancel",
        Some(Modal::Overwrite { .. }) => "y overwrite · any other key cancels",
        Some(Modal::Help) => "any key closes",
        None => match app.focus() {
            Focus::SvIn | Focus::SvOut => "Ctrl+X show/hide · Ctrl+Y copy base64 · Ctrl+K clear",
            Focus::DvIn | Focus::DvOut => "Ctrl+X show/hide · Ctrl+Y copy decoded · Ctrl+K clear",
            Focus::EncCtx | Focus::EncNs | Focus::EncSecret => {
                "Enter pick · Ctrl+L load from cluster · Ctrl+R reload contexts"
            }
            Focus::SecType => "Enter pick (or type a custom type) · Ctrl+G generate",
            Focus::SealCtx | Focus::Scope => "Enter pick · Ctrl+E seal · Ctrl+T validate",
            Focus::Rows => {
                "a add · d delete · Enter edit · e $EDITOR · v/V show · Ctrl+Y copy value · Ctrl+K clear all"
            }
            Focus::DecRows => "↑↓ move · v show · V all · Ctrl+Y copy · Ctrl+O open · Ctrl+K clear",
            Focus::Yaml | Focus::Sealed => "↑↓ PgUp PgDn scroll · ←→ pan · Ctrl+Y copy · Ctrl+S save",
            Focus::SecName | Focus::SecNs => "Ctrl+G generate · Ctrl+O open file · Ctrl+L load",
            Focus::CtlName | Focus::CtlNs => "edit to override detection · Ctrl+K clear",
            Focus::Cert => "Ctrl+O pick a cert · Ctrl+K clear",
        },
    };
    let right = "↑↓←→ move · F1-F3 tabs · ? help · Ctrl+Q quit ";
    let [l, r] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(right.chars().count() as u16)]).areas(area);
    f.render_widget(Paragraph::new(format!(" {hints}")).style(Style::new().bg(t.bg3).fg(t.dim)), l);
    f.render_widget(Paragraph::new(right).style(Style::new().bg(t.bg3).fg(t.dim)), r);
}

fn modal_block(title: &str) -> Block<'_> {
    let t = theme();
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(t.accent))
        .title(Line::styled(format!(" {title} "), Style::new().fg(t.accent).bold()))
        .style(Style::new().bg(t.bg2).fg(t.fg))
}

fn draw_modal(f: &mut Frame, area: Rect, m: &Modal) -> Option<Position> {
    let t = theme();
    match m {
        Modal::Picker { target, picker } => {
            let vis = picker.visible();
            let h = (vis.len() as u16 + 4).clamp(6, area.height.saturating_sub(4).max(6));
            let r = centered(area, 64.min(area.width.saturating_sub(4)), h);
            f.render_widget(Clear, r);
            let blk = modal_block(&picker.title);
            let inner = blk.inner(r);
            f.render_widget(blk, r);
            let [filt, list] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(inner);
            let (s, col) = picker.filter.view(filt.width.saturating_sub(8), false);
            let ph = if s.is_empty() { Span::styled("type to filter", Style::new().fg(t.dim)) } else { Span::raw(s) };
            f.render_widget(
                Paragraph::new(Line::from(vec![Span::styled("Filter: ", Style::new().fg(t.dim)), ph])),
                filt,
            );
            let mut items: Vec<ListItem> = vis.iter().map(|s| ListItem::new(one_line(s))).collect();
            if items.is_empty() {
                let msg = if picker.allow_custom && !picker.filter.value().is_empty() {
                    format!("Enter uses \"{}\"", picker.filter.value())
                } else {
                    "no match".into()
                };
                items.push(ListItem::new(Span::styled(msg, Style::new().fg(t.dim))));
            }
            let mut st = ListState::default().with_selected(Some(picker.selected));
            let list_w = List::new(items)
                .highlight_style(Style::new().bg(t.accent).fg(t.bg).bold())
                .highlight_symbol(if *target == PickTarget::Scope { "● " } else { "› " });
            f.render_stateful_widget(list_w, list, &mut st);
            Some(Position { x: filt.x + 8 + col, y: filt.y })
        }
        Modal::Path { purpose, input } => {
            let title = match purpose {
                PathPurpose::Open(Tab::Encode) => "Open .env or Secret YAML",
                PathPurpose::Open(Tab::Decode) => "Open Secret YAML",
                PathPurpose::Open(Tab::Seal) => "Sealing certificate (PEM)",
                PathPurpose::Save(SaveWhat::Yaml) => "Save Secret YAML as (written 0600)",
                PathPurpose::Save(SaveWhat::Sealed) => "Save SealedSecret as (written 0600)",
            };
            let r = centered(area, 80.min(area.width.saturating_sub(4)), 5);
            f.render_widget(Clear, r);
            let blk = modal_block(title);
            let inner = blk.inner(r);
            f.render_widget(blk, r);
            let [l, h] = Layout::vertical([Constraint::Length(1), Constraint::Length(2)]).areas(inner);
            let (s, col) = input.view(l.width.saturating_sub(1), false);
            f.render_widget(Paragraph::new(s).style(Style::new().bg(t.field_focus)), l);
            let cwd = std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default();
            let hint = format!("relative to {cwd} · ~ expands · Tab completes");
            f.render_widget(Paragraph::new(hint).style(Style::new().fg(t.dim)), h);
            Some(Position { x: l.x + col, y: l.y })
        }
        Modal::RowEdit { idx, key, value, on_value, shown } => {
            let r = centered(area, 80.min(area.width.saturating_sub(4)), 7);
            f.render_widget(Clear, r);
            let blk = modal_block(if idx.is_some() { "Edit row" } else { "Add row" });
            let inner = blk.inner(r);
            f.render_widget(blk, r);
            let [k, v, _, h] = Layout::vertical([Constraint::Length(1); 4]).areas(inner);
            let kc = field(f, k, "Key", 5, Content::Input { input: key, masked: false, placeholder: "" }, !on_value);
            let vc =
                field(f, v, "Value", 5, Content::Input { input: value, masked: !shown, placeholder: "" }, *on_value);
            let hint = "single line — multi-line values (PEM, JSON): press e on the row to use $EDITOR";
            f.render_widget(Paragraph::new(hint).style(Style::new().fg(t.dim)), h);
            kc.or(vc)
        }
        Modal::Overwrite { path, .. } => {
            let r = centered(area, 70.min(area.width.saturating_sub(4)), 4);
            f.render_widget(Clear, r);
            let blk = modal_block("File exists");
            let inner = blk.inner(r);
            f.render_widget(blk, r);
            let text = format!("{path} already exists.\nOverwrite it? (y/N)");
            f.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), inner);
            None
        }
        Modal::Help => {
            let k = |key: &'static str, what: &'static str| {
                Line::from(vec![Span::styled(format!("{key:<16}"), Style::new().fg(t.accent)), Span::raw(what)])
            };
            let h = |s: &'static str| Line::styled(s, Style::new().fg(t.fg).bold());
            let lines = vec![
                h("Anywhere"),
                k("↑ ↓ ← →", "move between fields (tables, panes and text first)"),
                k("Tab / Shift-Tab", "next / previous field"),
                k("F1 F2 F3", "Encode / Decode / Seal  (also Ctrl+N / Ctrl+P)"),
                k("Ctrl+G", "generate Secret YAML from the rows"),
                k("Ctrl+O", "open file: .env or Secret YAML (Seal tab: certificate)"),
                k("Ctrl+L", "load the selected Secret from the cluster (read-only)"),
                k("Ctrl+E / Ctrl+T", "seal / validate with the controller"),
                k("Ctrl+Y", "copy whatever is focused"),
                k("Ctrl+S", "save the YAML / SealedSecret (0600)"),
                k("Ctrl+K", "clear the focused thing"),
                k("Ctrl+R", "reload contexts (clears the controller cache)"),
                k("Ctrl+X", "show / hide masked values"),
                k("Ctrl+C / Ctrl+Q", "quit"),
                Line::raw(""),
                h("Key tables"),
                k("↑↓ PgUp PgDn", "move (↑/↓ at the edge leaves the table)"),
                k("a / d", "add / delete a row"),
                k("Enter", "edit the row"),
                k("e", "edit the value in $EDITOR (multi-line)"),
                k("v / V", "show one / all values"),
                Line::raw(""),
                h("Pickers and panes"),
                k("Enter", "open a picker (type to filter)"),
                k("↑↓ ←→", "scroll a YAML pane"),
                Line::raw(""),
                Line::styled(
                    "kseal only reads from the cluster: it never creates, patches or deletes anything.",
                    Style::new().fg(t.dim),
                ),
            ];
            let r = centered(area, 86.min(area.width.saturating_sub(2)), lines.len() as u16 + 2);
            f.render_widget(Clear, r);
            let blk = modal_block("Keys");
            let inner = blk.inner(r);
            f.render_widget(blk, r);
            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn render(app: &mut App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..h).map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect::<String>() + "\n").collect()
    }

    #[test]
    fn renders_every_tab_without_panicking_even_tiny() {
        let mut app = App::new();
        app.sv_in.set("hunter2");
        for tab in Tab::ALL {
            app.tab = tab;
            for (w, h) in [(120, 40), (60, 20), (20, 6), (1, 1)] {
                render(&mut app, w, h);
            }
        }
        app.tab = Tab::Encode;
        let s = render(&mut app, 120, 40);
        assert!(s.contains("Single value encoder") && s.contains("Secret YAML") && s.contains("Keys"));
        assert!(!s.contains("hunter2") && !s.contains("aHVudGVyMg=="), "values are masked by default");
        assert!(s.contains("Ctrl+X show"), "the reveal key is visible next to the field");
        app.sv_shown = true;
        let s = render(&mut app, 120, 40);
        assert!(s.contains("hunter2") && s.contains("aHVudGVyMg==") && s.contains("Ctrl+X hide"));
    }

    #[test]
    fn xterm256_mapping() {
        assert_eq!(xterm256(0x1e, 0x1e, 0x1e), 234);
        assert_eq!(xterm256(0x48, 0xc9, 0xb0), 79);
    }
}
