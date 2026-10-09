//! Pure, UI-independent logic: base64, `.env` parsing/rendering, Kubernetes
//! Secret YAML generation and Secret-document introspection.
//!
//! Ported 1:1 from the Python `core.py`. No I/O here except
//! [`write_secret_file`]; everything else is a pure function so it is
//! unit-tested without a terminal or a cluster.

use std::collections::{HashMap, VecDeque};
use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose};
use regex::Regex;
use serde_json::Value;

/// Ordered string→string pairs. Kept as a Vec (not a map) because order is
/// user-visible: rows in the editor and keys in the emitted YAML.
pub type Pairs = Vec<(String, String)>;

/// Insert-or-replace keeping the ORIGINAL position on a duplicate key —
/// the semantics of a Python dict (and of how Kubernetes merges stringData).
fn put_pair(out: &mut Pairs, index: &mut HashMap<String, usize>, k: String, v: String) {
    match index.get(&k) {
        Some(&i) => out[i].1 = v,
        None => {
            index.insert(k.clone(), out.len());
            out.push((k, v));
        }
    }
}

// ---------------------------------------------------------------------------
// base64
// ---------------------------------------------------------------------------

/// Go's `base64.StdEncoding` (what the API server uses): padding required,
/// non-zero trailing bits tolerated. Rust's STANDARD engine rejects those
/// trailing bits, which would flag values Kubernetes happily accepts.
const GO_STD: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

pub fn b64_encode(s: impl AsRef<[u8]>) -> String {
    general_purpose::STANDARD.encode(s)
}

/// Forgiving decode for copy-paste: drops ALL whitespace (incl. line wraps)
/// and repairs missing padding, but still rejects characters outside the
/// alphabet (never silently discards them).
pub fn b64_decode_bytes(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let mut s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let rem = s.len() % 4;
    if rem != 0 {
        s.extend(std::iter::repeat_n('=', 4 - rem));
    }
    GO_STD.decode(s)
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("decoded bytes are not UTF-8 text")]
    NotUtf8,
}

/// Forgiving decode to text; errors on invalid base64 or non-UTF-8 output.
pub fn b64_decode(s: &str) -> Result<String, DecodeError> {
    String::from_utf8(b64_decode_bytes(s)?).map_err(|_| DecodeError::NotUtf8)
}

/// Whether Kubernetes itself would accept `s` as a base64 `data` value.
///
/// Stricter than [`b64_decode`]: Go's decoder ignores only `\r` and `\n` and
/// requires correct padding, so plaintext that merely *resembles* base64
/// (e.g. "hunter2") is rejected at apply time.
pub fn b64_valid_for_k8s(s: &str) -> bool {
    let s: String = s.chars().filter(|&c| c != '\r' && c != '\n').collect();
    GO_STD.decode(s).is_ok()
}

// ---------------------------------------------------------------------------
// .env parsing / rendering
// ---------------------------------------------------------------------------

/// Python's `str.splitlines` boundaries, so a file parses identically.
fn is_line_break(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

fn dotenv_unescape(val: &str) -> String {
    let mut out = String::with_capacity(val.len());
    let mut it = val.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' {
            let mapped = match it.peek() {
                Some('\\') => Some('\\'),
                Some('n') => Some('\n'),
                Some('r') => Some('\r'),
                Some('t') => Some('\t'),
                Some('"') => Some('"'),
                _ => None,
            };
            if let Some(m) = mapped {
                it.next();
                out.push(m);
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// Parse `KEY=value` lines. Single-quoted and bare values are literal;
/// double-quoted values un-escape `\\`, `\n`, `\r`, `\t` and `\"` (the
/// inverse of [`dotenv_line`], so a template round-trips exactly).
pub fn parse_dotenv(text: &str) -> Pairs {
    let mut out = Pairs::new();
    let mut index = HashMap::new();
    for line in text.split(is_line_break) {
        let mut line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("export ") {
            line = rest.trim();
        }
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let mut val = val.trim().to_string();
        let b = val.as_bytes();
        if b.len() >= 2 && b[0] == b[b.len() - 1] && (b[0] == b'"' || b[0] == b'\'') {
            let quote = b[0];
            let inner = &val[1..val.len() - 1];
            val = if quote == b'"' { dotenv_unescape(inner) } else { inner.to_string() };
        }
        put_pair(&mut out, &mut index, key.to_string(), val);
    }
    out
}

/// Values that survive a bare (unquoted) .env line verbatim.
static BARE_ENV: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A[A-Za-z0-9_./:@+,=-]+\z").unwrap());
/// Keys parse_dotenv reads back unchanged — every Kubernetes-legal key qualifies.
static SAFE_ENV_KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A[A-Za-z0-9_.-]+\z").unwrap());

#[derive(Debug, thiserror::Error, PartialEq)]
#[error(".env cannot represent key {0:?}")]
pub struct UnrepresentableKey(pub String);

/// Render `KEY=value` so [`parse_dotenv`] reads the exact value back: bare
/// when safe, otherwise double-quoted with escaping.
///
/// Errors for a key with no .env spelling (keys can't be quoted): emitting it
/// would be silent data loss, not a round-trip.
pub fn dotenv_line(key: &str, val: &str) -> Result<String, UnrepresentableKey> {
    if !SAFE_ENV_KEY.is_match(key) {
        return Err(UnrepresentableKey(key.to_string()));
    }
    if BARE_ENV.is_match(val) {
        return Ok(format!("{key}={val}"));
    }
    let esc =
        val.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r").replace('\t', "\\t");
    Ok(format!("{key}=\"{esc}\""))
}

// ---------------------------------------------------------------------------
// Kubernetes Secret YAML
// ---------------------------------------------------------------------------

/// Built-in Kubernetes Secret types (the field accepts any string).
pub const SECRET_TYPES: &[&str] = &[
    "Opaque",
    "bootstrap.kubernetes.io/token",
    "kubernetes.io/basic-auth",
    "kubernetes.io/dockercfg",
    "kubernetes.io/dockerconfigjson",
    "kubernetes.io/service-account-token",
    "kubernetes.io/ssh-auth",
    "kubernetes.io/tls",
];

/// Infer a built-in type from the keys present (used while the type is left
/// at `Opaque`). Only unambiguous, well-known key sets qualify.
pub fn guess_secret_type<'a>(keys: impl IntoIterator<Item = &'a str>) -> &'static str {
    let keys: Vec<&str> = keys.into_iter().collect();
    let has = |k: &str| keys.contains(&k);
    if has("tls.crt") && has("tls.key") {
        "kubernetes.io/tls"
    } else if has(".dockerconfigjson") {
        "kubernetes.io/dockerconfigjson"
    } else if has(".dockercfg") {
        "kubernetes.io/dockercfg"
    } else if has("ssh-privatekey") {
        "kubernetes.io/ssh-auth"
    } else {
        "Opaque"
    }
}

/// Plain (unquoted) YAML scalars. Letter-first so nothing digit-led can hit a
/// YAML 1.1 numeric form (1234, 0x1A, 1_000, 1.5, ...). `\z` (absolute end),
/// so "abc\n" can never pass as a bare scalar.
static SAFE_YAML: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A[A-Za-z][A-Za-z0-9._-]*\z").unwrap());

/// Words a YAML 1.1 parser (kubectl) reads as booleans/null even when they
/// are meant as strings — e.g. a key "NO" or a base64 value "True".
const YAML_AMBIG: &[&str] = &[
    "y", "Y", "yes", "Yes", "YES", "n", "N", "no", "No", "NO", "true", "True", "TRUE", "false", "False", "FALSE", "on",
    "On", "ON", "off", "Off", "OFF", "null", "Null", "NULL",
];

/// Return `v` as a YAML scalar, double-quoting (with escaping) unless it is a
/// plain DNS-safe token. The empty string is quoted (bare empty reads as
/// null). Line breaks — `\n`, `\r` and YAML 1.1's NEL/LS/PS — are escaped,
/// never emitted raw: a quoted scalar spanning physical lines gets its breaks
/// FOLDED TO SPACES on reparse. Raw control characters aren't YAML-printable
/// at all, so they leave as escapes too.
pub fn yaml_scalar(v: &str) -> String {
    if SAFE_YAML.is_match(v) && !YAML_AMBIG.contains(&v) {
        return v.to_string();
    }
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x00'..='\x08' | '\x0b' | '\x0c' | '\x0e'..='\x1f' | '\x7f'..='\u{9f}' => {
                out.push_str(&format!("\\x{:02X}", c as u32))
            }
            '\u{2028}' | '\u{2029}' => out.push_str(&format!("\\u{:04X}", c as u32)),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Annotation kubectl regenerates on apply; it embeds a JSON snapshot of the
/// PREVIOUS secret (including its data), so carrying it would leak old values.
pub const LAST_APPLIED: &str = "kubectl.kubernetes.io/last-applied-configuration";

/// User-owned fields of an imported Secret that must survive an import →
/// Generate round-trip but aren't edited in the UI.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Carryover {
    pub labels: Pairs,
    pub annotations: Pairs,
    pub immutable: bool,
}

impl Carryover {
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty() && self.annotations.is_empty() && !self.immutable
    }
}

/// Extract [`Carryover`] from a Secret doc.
///
/// Returns `(carry, skipped)`; `skipped` counts candidate fields DROPPED for
/// being malformed, so callers can warn that a round-trip was lossy instead
/// of claiming full fidelity. Only string→string label/annotation pairs are
/// carried, and only a canonical `immutable: true`. A present-but-wrong-shaped
/// `metadata`/`labels`/`annotations` counts as a loss; an absent one doesn't.
/// kubectl's last-applied snapshot is stripped deliberately and not counted.
/// Server-managed metadata (uid, resourceVersion, managedFields, ...) is
/// never carried.
pub fn secret_carryover(doc: &Value) -> (Carryover, usize) {
    let mut carry = Carryover::default();
    let mut skipped = 0;
    let Value::Object(doc) = doc else {
        return (carry, 0);
    };
    let empty = serde_json::Map::new();
    let meta = match doc.get("metadata") {
        Some(Value::Object(m)) => m,
        Some(_) => {
            skipped += 1;
            &empty
        }
        None => &empty,
    };
    for (section, dest) in [("labels", &mut carry.labels), ("annotations", &mut carry.annotations)] {
        let Some(src) = meta.get(section) else { continue };
        let Value::Object(src) = src else {
            skipped += 1;
            continue;
        };
        for (k, v) in src {
            if section == "annotations" && k == LAST_APPLIED {
                continue;
            }
            match v {
                Value::String(s) => dest.push((k.clone(), s.clone())),
                _ => skipped += 1,
            }
        }
    }
    match doc.get("immutable") {
        Some(Value::Bool(true)) => carry.immutable = true,
        None | Some(Value::Null) | Some(Value::Bool(false)) => {}
        Some(_) => skipped += 1,
    }
    (carry, skipped)
}

/// Build Secret YAML. `data` holds plaintext values (base64-encoded here);
/// `raw_data` holds values that are ALREADY base64 and are emitted verbatim —
/// used for binary keys that can't survive a plaintext round-trip.
pub fn build_secret_yaml(
    name: &str,
    namespace: &str,
    data: &[(String, String)],
    type_: &str,
    raw_data: &[(String, String)],
    carry: &Carryover,
) -> String {
    let mut lines = vec![
        "apiVersion: v1".to_string(),
        "kind: Secret".to_string(),
        "metadata:".to_string(),
        format!("  name: {}", yaml_scalar(name)),
        format!("  namespace: {}", yaml_scalar(namespace)),
    ];
    for (section, pairs) in [("labels", &carry.labels), ("annotations", &carry.annotations)] {
        if !pairs.is_empty() {
            lines.push(format!("  {section}:"));
            for (k, v) in pairs {
                lines.push(format!("    {}: {}", yaml_scalar(k), yaml_scalar(v)));
            }
        }
    }
    if carry.immutable {
        lines.push("immutable: true".into());
    }
    lines.push(format!("type: {}", yaml_scalar(type_)));
    lines.push("data:".into());
    for (k, v) in data {
        lines.push(format!("  {}: {}", yaml_scalar(k), yaml_scalar(&b64_encode(v))));
    }
    for (k, v) in raw_data {
        lines.push(format!("  {}: {}", yaml_scalar(k), yaml_scalar(v)));
    }
    lines.join("\n") + "\n"
}

// ---------------------------------------------------------------------------
// Secret introspection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// Value is the decoded / plaintext string.
    Text,
    /// Valid base64 that isn't UTF-8; value is the ORIGINAL base64.
    Binary,
    /// Not base64 Kubernetes would accept (plaintext under `data`, usually);
    /// value is the original string.
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub value: String,
    pub kind: EntryKind,
}

impl Entry {
    fn new(key: impl Into<String>, value: impl Into<String>, kind: EntryKind) -> Self {
        Self { key: key.into(), value: value.into(), kind }
    }
}

/// Scalar coercion for hand-authored YAML (`K: 0` parses as a number).
fn scalar_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Flatten a Secret's `data` and `stringData` into ordered entries. `data`
/// is base64 (decoded strictly here); `stringData` is plaintext and
/// overrides `data` on a key conflict, in place — how Kubernetes merges them.
/// Returns `[]` for anything that isn't a Secret-shaped mapping.
pub fn secret_entries(doc: &Value) -> Vec<Entry> {
    let Value::Object(doc) = doc else { return vec![] };
    let mut out: Vec<Entry> = vec![];
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut put = |e: Entry| match index.get(&e.key) {
        Some(&i) => out[i] = e,
        None => {
            index.insert(e.key.clone(), out.len());
            out.push(e);
        }
    };

    if let Some(Value::Object(data)) = doc.get("data") {
        for (k, v) in data {
            if v.is_null() {
                put(Entry::new(k, "", EntryKind::Text));
                continue;
            }
            let s = scalar_string(v);
            // Check BEFORE decoding: the forgiving decoder strips all
            // whitespace, so base64 with an inner space would decode fine
            // here yet be rejected by Kubernetes at apply time.
            if !b64_valid_for_k8s(&s) {
                put(Entry::new(k, s, EntryKind::Invalid));
                continue;
            }
            match b64_decode(&s) {
                Ok(text) => put(Entry::new(k, text, EntryKind::Text)),
                Err(_) => put(Entry::new(k, s, EntryKind::Binary)),
            }
        }
    }
    if let Some(Value::Object(sdata)) = doc.get("stringData") {
        for (k, v) in sdata {
            put(Entry::new(k, scalar_string(v), EntryKind::Text));
        }
    }
    out
}

/// The first key whose value Kubernetes would reject, if any.
pub fn first_invalid_key(entries: &[Entry]) -> Option<&str> {
    entries.iter().find(|e| e.kind == EntryKind::Invalid).map(|e| e.key.as_str())
}

/// Expand `kind: List` wrappers (from `kubectl get -o yaml`, helm/argo
/// renders) into their items, however deeply nested. Iterative, so absurd
/// nesting can't overflow the stack. Non-mapping docs are dropped.
fn flatten_list_docs(docs: &[Value]) -> Vec<&Value> {
    let mut flat = vec![];
    let mut queue: VecDeque<&Value> = docs.iter().collect();
    while let Some(d) = queue.pop_front() {
        let Value::Object(m) = d else { continue };
        if m.get("kind").and_then(Value::as_str) == Some("List") {
            if let Some(Value::Array(items)) = m.get("items") {
                for it in items.iter().rev() {
                    queue.push_front(it);
                }
                continue;
            }
        }
        flat.push(d);
    }
    flat
}

fn kind_of(d: &Value) -> Option<&str> {
    d.get("kind").and_then(Value::as_str)
}

/// Pick the Secret to work on from parsed docs. An explicit `kind: Secret`
/// always wins over a kind-less fragment carrying data/stringData; other
/// kinds (ConfigMap, ...) are never picked.
pub fn select_secret_doc(docs: &[Value]) -> Option<&Value> {
    let docs = flatten_list_docs(docs);
    docs.iter().find(|d| kind_of(d) == Some("Secret")).copied().or_else(|| {
        docs.iter()
            .find(|d| {
                d.get("kind").is_none_or(Value::is_null)
                    && (d.get("data").is_some_and(Value::is_object)
                        || d.get("stringData").is_some_and(Value::is_object))
            })
            .copied()
    })
}

/// Whether any doc is a SealedSecret — nothing to decode locally.
pub fn has_sealed_secret(docs: &[Value]) -> bool {
    flatten_list_docs(docs).iter().any(|d| kind_of(d) == Some("SealedSecret"))
}

/// Parse a (multi-document) YAML string into JSON values. The parser rejects
/// anchor cycles and enforces a nesting limit, so hostile input errors out
/// instead of hanging or overflowing.
pub fn parse_yaml_docs(text: &str) -> anyhow::Result<Vec<Value>> {
    let docs: Vec<Value> = serde_saphyr::from_multiple(text)
        .map_err(|e| anyhow::anyhow!("{}", e.to_string().lines().next().unwrap_or("invalid YAML")))?;
    Ok(docs.into_iter().filter(|d| !d.is_null()).collect())
}

/// Name/namespace/type of a Secret doc, defaulting what's missing.
pub fn secret_identity(doc: &Value) -> (String, String, String) {
    let meta = doc.get("metadata");
    let get = |k| meta.and_then(|m| m.get(k)).and_then(Value::as_str).unwrap_or("").to_string();
    let type_ = doc.get("type").and_then(Value::as_str).unwrap_or("Opaque").to_string();
    (get("name"), get("namespace"), type_)
}

// ---------------------------------------------------------------------------
// Editor behaviour shared by the TUI (kept here so it is testable headless)
// ---------------------------------------------------------------------------

/// Fallback Secret identity when the fields are blank / nothing was loaded.
pub const DEF_NAME: &str = "my-secret";
pub const DEF_NS: &str = "default";

/// What a user-picked file holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Env,
    /// YAML with a Secret (or a SealedSecret, which callers reject with a hint).
    SecretYaml,
}

/// Decide whether a picked file is a `.env` or a Secret manifest: the
/// extension decides when it's conclusive, otherwise the content does (a
/// `.env` never parses to a Secret-shaped YAML doc).
pub fn detect_file_kind(path: &str, text: &str) -> FileKind {
    let lower = path.to_lowercase();
    let file = lower.rsplit(['/', '\\']).next().unwrap_or("");
    if file.ends_with(".yaml") || file.ends_with(".yml") {
        return FileKind::SecretYaml;
    }
    if file.ends_with(".env") || file.starts_with(".env") {
        return FileKind::Env;
    }
    match parse_yaml_docs(text) {
        Ok(docs) if select_secret_doc(&docs).is_some() || has_sealed_secret(&docs) => FileKind::SecretYaml,
        _ => FileKind::Env,
    }
}

/// Guards shared by Import and Load-from-cluster, run BEFORE the editor is
/// touched so a rejected secret can't destroy in-progress rows. Returns an
/// error message, or `None` if the entries are safe to apply.
pub fn check_entries(entries: &[Entry]) -> Option<String> {
    if entries.is_empty() {
        return Some("Secret has no data/stringData — nothing to import".into());
    }
    // "invalid" means Kubernetes itself would reject the value at apply time.
    // Two causes, two remedies: plaintext mistakenly under `data`, or binary
    // base64 with broken padding.
    first_invalid_key(entries).map(|bad| {
        format!("data.{bad} is not valid base64 for Kubernetes — plaintext belongs under stringData; binary needs exact '=' padding")
    })
}

/// Split entries into editable text pairs and binary passthrough pairs (key →
/// ORIGINAL base64, re-emitted verbatim on Generate). Invalid entries never
/// get here — callers run [`check_entries`] first — but are kept as binary
/// rather than silently re-encoded if they do.
pub fn split_entries(entries: &[Entry]) -> (Pairs, Pairs) {
    let mut text = Pairs::new();
    let mut binary = Pairs::new();
    for e in entries {
        let dest = if e.kind == EntryKind::Text { &mut text } else { &mut binary };
        dest.push((e.key.clone(), e.value.clone()));
    }
    (text, binary)
}

/// Status line for a secret applied to the editor ("Loaded"/"Imported").
pub fn applied_msg(verb: &str, total: usize, binary: usize, src: &str) -> String {
    let mut msg = format!("{verb} {total} key(s) from {src}");
    if binary > 0 {
        msg.push_str(&format!(" — {binary} binary value(s) kept as-is"));
    }
    msg
}

/// The persistent warning shown while a loaded secret had malformed metadata.
pub fn skip_warning(skipped: usize) -> Option<String> {
    (skipped > 0).then(|| {
        format!("⚠  {skipped} invalid metadata field(s) in the loaded secret — missing from generated / sealed YAML")
    })
}

/// Qualify an output-derived success message (Generate/Save/Seal/Copy) with
/// the pending skipped-metadata count. Returns `(message, is_warning)`.
pub fn qualify_output(msg: &str, skipped: usize) -> (String, bool) {
    if skipped > 0 {
        (format!("{msg} — {skipped} invalid metadata field(s) skipped"), true)
    } else {
        (msg.into(), false)
    }
}

/// Editable rows → the pairs Generate emits: keys trimmed, blank keys
/// skipped, a duplicate key keeps its first position with the last value.
pub fn collect_pairs<'a>(rows: impl IntoIterator<Item = (&'a str, &'a str)>) -> Pairs {
    let mut out = Pairs::new();
    let mut index = HashMap::new();
    for (k, v) in rows {
        let k = k.trim();
        if !k.is_empty() {
            put_pair(&mut out, &mut index, k.to_string(), v.to_string());
        }
    }
    out
}

/// Status line for a successful Generate.
pub fn generated_msg(keys: usize, binary: usize, carried: bool) -> String {
    let mut msg = format!("Generated YAML with {keys} key(s)");
    if binary > 0 {
        msg.push_str(&format!(" ({binary} binary kept as-is)"));
    }
    if carried {
        msg.push_str(" — labels/annotations/immutable carried over");
    }
    msg
}

/// A value round-tripped through `$EDITOR`: editors append a final newline
/// on save, so drop exactly one when the original had none. A value that
/// already ended in a newline (PEM) keeps whatever the user saved.
pub fn editor_result(original: &str, edited: String) -> String {
    if original.ends_with('\n') {
        return edited;
    }
    let mut edited = edited;
    if edited.ends_with("\r\n") {
        edited.truncate(edited.len() - 2);
    } else if edited.ends_with('\n') {
        edited.truncate(edited.len() - 1);
    }
    edited
}

// ---------------------------------------------------------------------------
// Secret-bearing file output
// ---------------------------------------------------------------------------

/// Write secret-bearing content with owner-only (0600) permissions — forced
/// even when overwriting an existing, world-readable file (the open mode only
/// applies on create). Windows has no POSIX modes; the plain write is the best
/// available there.
pub fn write_secret_file(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        opts.mode(0o600);
        let mut f = opts.open(path)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(content.as_bytes())?;
        f.sync_all()
    }
    #[cfg(not(unix))]
    {
        let mut f = opts.open(path)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()
    }
}

// ---------------------------------------------------------------------------
// Tests — ported from tests/test_core.py
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn p(pairs: &[(&str, &str)]) -> Pairs {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }
    fn yaml1(s: &str) -> Value {
        parse_yaml_docs(s).unwrap().remove(0)
    }
    fn e(k: &str, v: &str, kind: EntryKind) -> Entry {
        Entry::new(k, v, kind)
    }
    fn build(name: &str, ns: &str, data: &[(&str, &str)]) -> String {
        build_secret_yaml(name, ns, &p(data), "Opaque", &[], &Carryover::default())
    }
    const BIN: &[u8] = b"\xff\xfe\x00raw";

    // --- base64 -----------------------------------------------------------
    #[test]
    fn b64_encode_matches_stdlib() {
        assert_eq!(b64_encode("hello"), "aGVsbG8=");
    }
    #[test]
    fn b64_round_trip() {
        for t in ["", "hello", "a", "ab", "abc", "üñîçødé", "k=v\nx=y"] {
            assert_eq!(b64_decode(&b64_encode(t)).unwrap(), t);
        }
    }
    #[test]
    fn b64_decode_tolerates_missing_padding() {
        assert_eq!(b64_decode("aGVsbG8").unwrap(), "hello");
    }
    #[test]
    fn b64_decode_strips_whitespace() {
        assert_eq!(b64_decode("  aGVsbG8=\n").unwrap(), "hello");
        assert_eq!(b64_decode("aGVs\nbG8=").unwrap(), "hello");
    }
    #[test]
    fn b64_decode_raises_on_invalid_input() {
        assert!(b64_decode("!!!!aGVsbG8=").is_err());
    }
    #[test]
    fn b64_valid_for_k8s_matches_go_semantics() {
        let ok = b64_encode(BIN);
        assert!(b64_valid_for_k8s(&ok));
        assert!(b64_valid_for_k8s(&format!("{}\n{}", &ok[..4], &ok[4..])));
        assert!(!b64_valid_for_k8s("hunter2"));
        assert!(!b64_valid_for_k8s("my-password"));
        assert!(!b64_valid_for_k8s("ab cd"));
        // Go tolerates non-zero trailing bits ("aGVsbG9=" decodes in Go).
        assert!(b64_valid_for_k8s("aGVsbG9="));
    }

    // --- .env -------------------------------------------------------------
    #[test]
    fn parse_dotenv_basic_comments_export() {
        assert_eq!(parse_dotenv("FOO=bar\nBAZ=qux"), p(&[("FOO", "bar"), ("BAZ", "qux")]));
        assert_eq!(parse_dotenv("# comment\n\nFOO=bar\n   \n"), p(&[("FOO", "bar")]));
        assert_eq!(parse_dotenv("export FOO=bar"), p(&[("FOO", "bar")]));
        assert_eq!(parse_dotenv("NOEQUALS\nFOO=bar"), p(&[("FOO", "bar")]));
    }
    #[test]
    fn parse_dotenv_quotes() {
        assert_eq!(parse_dotenv(r"FOO='a\nb'"), p(&[("FOO", r"a\nb")]));
        assert_eq!(parse_dotenv(r#"FOO="a\nb\t\"c\"""#), p(&[("FOO", "a\nb\t\"c\"")]));
    }
    #[test]
    fn parse_dotenv_duplicate_keeps_first_position() {
        assert_eq!(parse_dotenv("A=1\nB=2\nA=3"), p(&[("A", "3"), ("B", "2")]));
    }
    #[test]
    fn dotenv_line_round_trips() {
        for v in [
            "simple",
            "with space",
            "has\"quote",
            "multi\nline",
            "tab\tchar",
            "trailing\\backslash",
            "",
            "a=b=c",
            "\\n literal",
        ] {
            let line = dotenv_line("KEY", v).unwrap();
            assert_eq!(parse_dotenv(&line), p(&[("KEY", v)]), "{v:?}");
        }
    }
    #[test]
    fn dotenv_line_rejects_unrepresentable_keys() {
        for k in ["#FOO", "A=B", "SP ACE", "", "K\n", " KEY"] {
            assert!(dotenv_line(k, "v").is_err(), "{k:?}");
        }
    }

    // --- YAML scalars -----------------------------------------------------
    #[test]
    fn yaml_scalar_rules() {
        assert_eq!(yaml_scalar("my-secret_1.0"), "my-secret_1.0");
        for w in ["true", "False", "NO", "yes", "null", "on"] {
            assert_eq!(yaml_scalar(w), format!("\"{w}\""));
        }
        assert_eq!(yaml_scalar(""), "\"\"");
        assert_eq!(yaml_scalar("123"), "\"123\"");
        assert_eq!(yaml_scalar(r#"a"b\c"#), r#""a\"b\\c""#);
    }
    #[test]
    fn yaml_scalar_escapes_newlines() {
        assert_eq!(yaml_scalar("a\nb"), "\"a\\nb\"");
        assert_eq!(yaml_scalar("a\r\nb"), "\"a\\r\\nb\"");
        assert_eq!(yaml_scalar("abc\n"), "\"abc\\n\"");
        assert_eq!(yaml1(&format!("v: {}", yaml_scalar("a\nb")))["v"], "a\nb");
    }
    #[test]
    fn yaml_scalar_escapes_control_chars_and_unicode_breaks() {
        assert_eq!(yaml_scalar("a\x07b"), "\"a\\x07b\"");
        assert_eq!(yaml_scalar("a\u{85}b"), "\"a\\x85b\"");
        assert_eq!(yaml_scalar("a\u{2028}b"), "\"a\\u2028b\"");
        for v in ["bell\x07", "nel\u{85}nel", "ls\u{2028}ls", "ps\u{2029}ps", "del\x7f", "emoji 🔐"] {
            assert_eq!(yaml1(&format!("v: {}", yaml_scalar(v)))["v"], v, "{v:?}");
        }
    }

    // --- Secret YAML ------------------------------------------------------
    #[test]
    fn build_secret_yaml_is_valid_and_round_trips() {
        let doc = yaml1(&build("my-secret", "default", &[("FOO", "bar")]));
        assert_eq!(doc["apiVersion"], "v1");
        assert_eq!(doc["kind"], "Secret");
        assert_eq!(doc["metadata"], json!({"name": "my-secret", "namespace": "default"}));
        assert_eq!(doc["type"], "Opaque");
        assert_eq!(b64_decode(doc["data"]["FOO"].as_str().unwrap()).unwrap(), "bar");
    }
    #[test]
    fn build_secret_yaml_honours_type_and_tricky_keys() {
        let out = build_secret_yaml("s", "ns", &[], "kubernetes.io/tls", &[], &Carryover::default());
        assert_eq!(yaml1(&out)["type"], "kubernetes.io/tls");
        let doc = yaml1(&build("name", "ns", &[("123key", "value"), ("NO", "x")]));
        assert_eq!(b64_decode(doc["data"]["123key"].as_str().unwrap()).unwrap(), "value");
        assert_eq!(b64_decode(doc["data"]["NO"].as_str().unwrap()).unwrap(), "x");
    }
    #[test]
    fn build_secret_yaml_raw_data_emitted_verbatim() {
        let already = b64_encode("\x00\x01binary");
        let out = build_secret_yaml(
            "s",
            "ns",
            &p(&[("FOO", "bar")]),
            "Opaque",
            &p(&[("CERT", &already)]),
            &Carryover::default(),
        );
        let doc = yaml1(&out);
        assert_eq!(doc["data"]["CERT"], already.as_str());
        assert_eq!(b64_decode(doc["data"]["FOO"].as_str().unwrap()).unwrap(), "bar");
    }
    #[test]
    fn multiline_binary_base64_roundtrips_intact() {
        let wrapped = "+vv8/f7/+vv8/f7/\n+vv8/f7/+vv8/f7/";
        let entries = secret_entries(&json!({"data": {"blob": wrapped}}));
        assert_eq!(entries, vec![e("blob", wrapped, EntryKind::Binary)]);
        let out = build_secret_yaml("n", "ns", &[], "Opaque", &p(&[("blob", wrapped)]), &Carryover::default());
        let rt = yaml1(&out)["data"]["blob"].as_str().unwrap().to_string();
        assert_eq!(rt, wrapped);
        assert!(b64_valid_for_k8s(&rt));
    }
    #[test]
    fn build_secret_yaml_emits_carryover() {
        let carry = Carryover { labels: p(&[("app", "web")]), annotations: p(&[("a.io/id", "x y")]), immutable: true };
        let doc = yaml1(&build_secret_yaml("s", "prod", &p(&[("K", "v")]), "Opaque", &[], &carry));
        assert_eq!(doc["metadata"]["labels"], json!({"app": "web"}));
        assert_eq!(doc["metadata"]["annotations"], json!({"a.io/id": "x y"}));
        assert_eq!(doc["immutable"], true);
        let doc = yaml1(&build("s", "prod", &[("K", "v")]));
        assert!(doc["metadata"].get("labels").is_none());
        assert!(doc.get("immutable").is_none());
    }
    #[test]
    fn guess_type() {
        assert_eq!(guess_secret_type(["tls.crt", "tls.key"]), "kubernetes.io/tls");
        assert_eq!(guess_secret_type(["tls.crt"]), "Opaque");
        assert_eq!(guess_secret_type([".dockerconfigjson"]), "kubernetes.io/dockerconfigjson");
        assert_eq!(guess_secret_type(["ssh-privatekey"]), "kubernetes.io/ssh-auth");
    }

    // --- secret_entries ---------------------------------------------------
    #[test]
    fn secret_entries_decodes_data() {
        let doc = json!({"data": {"FOO": b64_encode("bar"), "EMPTY": ""}});
        assert_eq!(secret_entries(&doc), vec![e("FOO", "bar", EntryKind::Text), e("EMPTY", "", EntryKind::Text)]);
    }
    #[test]
    fn secret_entries_flags_binary_and_keeps_base64() {
        let b64 = b64_encode(BIN);
        assert_eq!(secret_entries(&json!({"data": {"CERT": b64}})), vec![e("CERT", &b64, EntryKind::Binary)]);
    }
    #[test]
    fn secret_entries_distinguishes_missing_from_falsy() {
        assert_eq!(secret_entries(&yaml1("data:\n  K:\n")), vec![e("K", "", EntryKind::Text)]);
        let got = secret_entries(&yaml1("data:\n  K: 0\n"));
        assert_eq!((got[0].key.as_str(), got[0].value.as_str()), ("K", "0"));
    }
    #[test]
    fn secret_entries_stringdata() {
        assert_eq!(
            secret_entries(&json!({"stringData": {"USER": "alice"}})),
            vec![e("USER", "alice", EntryKind::Text)]
        );
        let doc = json!({"data": {"A": b64_encode("from-data"), "B": b64_encode("b")}, "stringData": {"A": "from-stringdata"}});
        assert_eq!(
            secret_entries(&doc),
            vec![e("A", "from-stringdata", EntryKind::Text), e("B", "b", EntryKind::Text)]
        );
    }
    #[test]
    fn secret_entries_non_secret_returns_empty() {
        for d in [Value::Null, json!("string"), json!(42), json!({}), json!({"data": "notadict"})] {
            assert!(secret_entries(&d).is_empty());
        }
    }
    #[test]
    fn secret_entries_flags_invalid() {
        for plain in ["hunter2", "my-password", "pass word", "aGVs bG8="] {
            assert_eq!(secret_entries(&json!({"data": {"P": plain}})), vec![e("P", plain, EntryKind::Invalid)]);
        }
    }
    #[test]
    fn secret_entries_coerces_non_string_keys() {
        let b64 = b64_encode(b"\xff\xfe");
        let doc = yaml1(&format!("data:\n  123: {b64}\nstringData:\n  456: x\n"));
        assert_eq!(secret_entries(&doc), vec![e("123", &b64, EntryKind::Binary), e("456", "x", EntryKind::Text)]);
    }
    #[test]
    fn first_invalid() {
        let entries = secret_entries(&json!({"data": {"OK": b64_encode("fine"), "BAD": "hunter2"}}));
        assert_eq!(first_invalid_key(&entries), Some("BAD"));
        assert_eq!(first_invalid_key(&secret_entries(&json!({"stringData": {"A": "x"}}))), None);
    }

    // --- select_secret_doc / has_sealed_secret ----------------------------
    #[test]
    fn select_prefers_explicit_kind() {
        let docs = vec![json!({"data": {"KEY": "bm90LXRoaXM="}}), json!({"kind": "Secret", "data": {"token": "cw=="}})];
        assert_eq!(select_secret_doc(&docs), Some(&docs[1]));
    }
    #[test]
    fn select_accepts_kindless_snippet_and_rejects_others() {
        let docs = vec![json!({"kind": "ConfigMap", "data": {"K": "v"}}), json!({"stringData": {"USER": "alice"}})];
        assert_eq!(select_secret_doc(&docs), Some(&docs[1]));
        assert_eq!(select_secret_doc(&[json!({"kind": "ConfigMap", "data": {"K": "v"}})]), None);
        assert_eq!(select_secret_doc(&[Value::Null, json!("text"), json!(42), json!({"spec": {}})]), None);
        assert_eq!(select_secret_doc(&[]), None);
    }
    #[test]
    fn sealed_detection() {
        let sealed = json!({"kind": "SealedSecret", "spec": {"encryptedData": {"p": "AgA="}}});
        assert!(has_sealed_secret(&[json!({"kind": "ConfigMap"}), sealed.clone()]));
        assert!(!has_sealed_secret(&[json!({"kind": "Secret"}), Value::Null, json!("junk")]));
        assert!(has_sealed_secret(&[json!({"kind": "List", "items": [sealed]})]));
    }
    #[test]
    fn select_unwraps_lists_nested_and_deep() {
        let secret = json!({"kind": "Secret", "metadata": {"name": "from-list"}, "data": {"t": "dg=="}});
        let wrapper =
            json!({"apiVersion": "v1", "kind": "List", "items": [{"kind": "ConfigMap", "data": {"K": "v"}}, secret]});
        assert_eq!(select_secret_doc(std::slice::from_ref(&wrapper)), Some(&wrapper["items"][1]));
        assert_eq!(select_secret_doc(&[json!({"kind": "List", "items": [null, "junk", 42]})]), None);
        // 5000 levels: the flattening itself is iterative, but serde_json
        // builds/drops values recursively, so give this thread a big stack.
        // (Real input never gets here: the YAML parser caps nesting depth.)
        std::thread::Builder::new()
            .stack_size(256 << 20)
            .spawn(move || {
                let mut deep = secret;
                for _ in 0..5000 {
                    deep = json!({"kind": "List", "items": [deep]});
                }
                let name = select_secret_doc(std::slice::from_ref(&deep)).map(|d| d["metadata"]["name"].clone());
                assert_eq!(name, Some(json!("from-list")));
            })
            .unwrap()
            .join()
            .unwrap();
    }
    #[test]
    fn hostile_yaml_errors_instead_of_hanging() {
        assert!(parse_yaml_docs("&a\nkind: List\nitems:\n  - *a\n").is_err());
        let deep = "[".repeat(5000) + &"]".repeat(5000);
        assert!(parse_yaml_docs(&deep).is_err());
    }
    #[test]
    fn multi_doc_and_empty_docs() {
        let docs = parse_yaml_docs("---\n---\nkind: ConfigMap\n---\nkind: Secret\n").unwrap();
        assert_eq!(docs.len(), 2);
        assert_eq!(select_secret_doc(&docs).and_then(|d| d["kind"].as_str()), Some("Secret"));
    }

    // --- carryover --------------------------------------------------------
    #[test]
    fn carryover_extracts_user_owned_fields() {
        let doc = json!({"kind": "Secret", "metadata": {"name": "s", "uid": "server-set", "resourceVersion": "42",
            "labels": {"app": "web", "team": "sre"},
            "annotations": {"argocd.argoproj.io/tracking-id": "web:Secret:prod/s", LAST_APPLIED: "{\"data\":{\"old\":\"c2VjcmV0\"}}"}},
            "immutable": true});
        let (carry, skipped) = secret_carryover(&doc);
        assert_eq!(carry.labels, p(&[("app", "web"), ("team", "sre")]));
        assert_eq!(carry.annotations, p(&[("argocd.argoproj.io/tracking-id", "web:Secret:prod/s")]));
        assert!(carry.immutable);
        assert_eq!(skipped, 0);
        assert_eq!(secret_carryover(&Value::Null), (Carryover::default(), 0));
    }
    #[test]
    fn carryover_immutable_only_true() {
        assert!(secret_carryover(&json!({"immutable": true})).0.immutable);
        assert_eq!(secret_carryover(&json!({"immutable": false})), (Carryover::default(), 0));
        assert_eq!(secret_carryover(&json!({"immutable": "true"})), (Carryover::default(), 1));
    }
    #[test]
    fn carryover_drops_and_counts_non_string_values() {
        let doc = json!({"metadata": {"labels": {"good": "web", "num": 3, "flag": true}, "annotations": {"note": null, "keep": "yes"}}});
        let (carry, skipped) = secret_carryover(&doc);
        assert_eq!(carry.labels, p(&[("good", "web")]));
        assert_eq!(carry.annotations, p(&[("keep", "yes")]));
        assert_eq!(skipped, 3);
    }
    #[test]
    fn carryover_counts_malformed_sections_and_metadata() {
        assert_eq!(secret_carryover(&json!({"metadata": {"labels": {"n": 1}}})).1, 1);
        assert_eq!(secret_carryover(&json!({"metadata": {"labels": null}})).1, 1);
        assert_eq!(secret_carryover(&json!({"metadata": {"labels": "oops"}})).1, 1);
        assert_eq!(secret_carryover(&json!({"metadata": {}})).1, 0);
        let (c, s) = secret_carryover(&json!({"metadata": {"labels": null, "annotations": {"a": "b"}}}));
        assert_eq!((c.annotations, s), (p(&[("a", "b")]), 1));
        assert_eq!(secret_carryover(&json!({"metadata": "junk"})).1, 1);
        let (c, s) = secret_carryover(&json!({"metadata": null, "immutable": true}));
        assert!(c.immutable);
        assert_eq!(s, 1);
        assert_eq!(secret_carryover(&json!({"kind": "Secret"})).1, 0);
    }

    // --- write_secret_file ------------------------------------------------
    #[cfg(unix)]
    #[test]
    fn write_secret_file_is_owner_only_and_tightens_existing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.yaml");
        write_secret_file(&path, "data: x\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "data: x\n");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_secret_file(&path, "password: café\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), "password: café\n".as_bytes());
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn detect_file_kind_by_extension_then_content() {
        assert_eq!(detect_file_kind("/x/prod.env", "apiVersion: v1"), FileKind::Env);
        assert_eq!(detect_file_kind("/x/.env.local", ""), FileKind::Env);
        assert_eq!(detect_file_kind("C:\\x\\s.YAML", "A=b"), FileKind::SecretYaml);
        let yaml = "apiVersion: v1\nkind: Secret\ndata:\n  A: YQ==\n";
        assert_eq!(detect_file_kind("/x/secret", yaml), FileKind::SecretYaml);
        assert_eq!(detect_file_kind("/x/sealed", "kind: SealedSecret\nspec: {}\n"), FileKind::SecretYaml);
        assert_eq!(detect_file_kind("/x/vars", "A=b\nB=c\n"), FileKind::Env);
        assert_eq!(detect_file_kind("/x/vars", "A: b\n"), FileKind::Env);
        assert_eq!(detect_file_kind("/x/vars", "{{{ not yaml"), FileKind::Env);
    }

    #[test]
    fn check_and_split_entries() {
        assert!(check_entries(&[]).unwrap().contains("nothing to import"));
        let doc = yaml1("kind: Secret\ndata:\n  T: aGk=\n  B: /w==\n  BAD: hunter2\n");
        let entries = secret_entries(&doc);
        assert!(check_entries(&entries).unwrap().starts_with("data.BAD is not valid base64"));
        let ok = &entries[..2];
        assert_eq!(check_entries(ok), None);
        assert_eq!(split_entries(ok), (p(&[("T", "hi")]), p(&[("B", "/w==")])));
    }

    #[test]
    fn status_messages() {
        assert_eq!(applied_msg("Loaded", 3, 0, "db"), "Loaded 3 key(s) from db");
        assert_eq!(
            applied_msg("Imported", 3, 1, "s.yaml"),
            "Imported 3 key(s) from s.yaml — 1 binary value(s) kept as-is"
        );
        assert_eq!(skip_warning(0), None);
        assert!(skip_warning(2).unwrap().contains("2 invalid metadata field(s)"));
        assert_eq!(qualify_output("Saved x", 0), ("Saved x".into(), false));
        assert_eq!(qualify_output("Saved x", 1), ("Saved x — 1 invalid metadata field(s) skipped".into(), true));
        assert_eq!(generated_msg(2, 0, false), "Generated YAML with 2 key(s)");
        assert_eq!(
            generated_msg(3, 1, true),
            "Generated YAML with 3 key(s) (1 binary kept as-is) — labels/annotations/immutable carried over"
        );
    }

    #[test]
    fn collect_pairs_trims_skips_blank_and_last_dup_wins_in_place() {
        let rows = [(" A ", "1"), ("", "x"), ("  ", "y"), ("B", "2"), ("A", "3")];
        assert_eq!(collect_pairs(rows), p(&[("A", "3"), ("B", "2")]));
    }

    #[test]
    fn editor_result_drops_only_the_editor_added_newline() {
        assert_eq!(editor_result("abc", "abcd\n".into()), "abcd");
        assert_eq!(editor_result("abc", "abcd\r\n".into()), "abcd");
        assert_eq!(editor_result("abc", "two\n\n".into()), "two\n");
        assert_eq!(editor_result("abc", "none".into()), "none");
        assert_eq!(editor_result("-----PEM-----\n", "-----PEM-----\n".into()), "-----PEM-----\n");
    }
}
