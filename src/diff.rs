//! Semantic diff of Secret / SealedSecret manifests: what a GitOps reviewer
//! cares about (keys added, removed or modified; labels, annotations, type,
//! scope), not YAML layout. Server-managed metadata and controller tracking
//! stamps are ignored, so a live Secret compares cleanly with its manifest.
//!
//! Values never leave this module unmasked unless the caller asks
//! ([`render`] with `reveal`). Encrypted values are never "compared" beyond
//! what is provable: identical ciphertext is unchanged; anything else can't
//! be decided without the controller's private key, and says so.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::core::{self, EntryKind};
use crate::seal::Scope;
use crate::validate::{self, TRACKING_ANNOTATIONS, TRACKING_LABELS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Secret,
    Sealed,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Secret => "Secret",
            Kind::Sealed => "SealedSecret",
        }
    }
}

/// One value, as far as it can be known locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Val {
    /// A Secret's decoded value.
    Plain(Vec<u8>),
    /// Not base64 Kubernetes would accept (shown masked, like plaintext).
    Invalid(String),
    /// A SealedSecret's ciphertext.
    Encrypted(String),
}

/// The parts of a Secret / SealedSecret that matter, normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logical {
    pub kind: Kind,
    pub name: String,
    pub namespace: String,
    pub type_: String,
    pub labels: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
    pub immutable: bool,
    /// SealedSecrets only.
    pub scope: Option<Scope>,
    pub values: BTreeMap<String, Val>,
}

impl Logical {
    pub fn id(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }
    pub fn label(&self) -> String {
        if self.namespace.is_empty() {
            format!("{} {}", self.kind.as_str(), self.name)
        } else {
            format!("{} {}/{}", self.kind.as_str(), self.namespace, self.name)
        }
    }
}

fn string_map(v: Option<&Value>, skip: &[&str]) -> BTreeMap<String, String> {
    let Some(Value::Object(m)) = v else { return BTreeMap::new() };
    m.iter()
        .filter(|(k, _)| !skip.contains(&k.as_str()))
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
        .collect()
}

fn s(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).unwrap_or("").to_string()
}

/// Normalize a Secret or SealedSecret doc (`None` for any other kind).
/// For a SealedSecret, labels/annotations/type are the template's — what the
/// controller creates — and the scope annotations become [`Logical::scope`].
pub fn logical(doc: &Value) -> Option<Logical> {
    let meta = doc.get("metadata");
    match core::kind_of(doc) {
        Some("Secret") => {
            let values = core::secret_entries(doc)
                .into_iter()
                .map(|e| {
                    let v = match e.kind {
                        EntryKind::Text => Val::Plain(e.value.into_bytes()),
                        EntryKind::Binary => Val::Plain(core::b64_decode_bytes(&e.value).unwrap_or_default()),
                        EntryKind::Invalid => Val::Invalid(e.value),
                    };
                    (e.key, v)
                })
                .collect();
            Some(Logical {
                kind: Kind::Secret,
                name: s(meta.and_then(|m| m.get("name"))),
                namespace: s(meta.and_then(|m| m.get("namespace"))),
                type_: doc.get("type").and_then(Value::as_str).unwrap_or("Opaque").to_string(),
                labels: string_map(meta.and_then(|m| m.get("labels")), TRACKING_LABELS),
                annotations: string_map(meta.and_then(|m| m.get("annotations")), TRACKING_ANNOTATIONS),
                immutable: doc.get("immutable") == Some(&Value::Bool(true)),
                scope: None,
                values,
            })
        }
        Some("SealedSecret") => {
            let spec = doc.get("spec");
            let tpl = spec.and_then(|s| s.get("template"));
            let tmeta = tpl.and_then(|t| t.get("metadata"));
            let scope_ann = [crate::seal::ANN_NAMESPACE_WIDE, crate::seal::ANN_CLUSTER_WIDE];
            let skip: Vec<&str> = TRACKING_ANNOTATIONS.iter().chain(scope_ann.iter()).copied().collect();
            let values = match spec.and_then(|s| s.get("encryptedData")) {
                Some(Value::Object(m)) => {
                    m.iter().map(|(k, v)| (k.clone(), Val::Encrypted(core::scalar_string(v)))).collect()
                }
                _ => BTreeMap::new(),
            };
            Some(Logical {
                kind: Kind::Sealed,
                name: s(meta.and_then(|m| m.get("name"))),
                namespace: s(meta.and_then(|m| m.get("namespace"))),
                type_: tpl.and_then(|t| t.get("type")).and_then(Value::as_str).unwrap_or("Opaque").to_string(),
                labels: string_map(tmeta.and_then(|m| m.get("labels")), TRACKING_LABELS),
                annotations: string_map(tmeta.and_then(|m| m.get("annotations")), &skip),
                immutable: tpl.and_then(|t| t.get("immutable")) == Some(&Value::Bool(true)),
                scope: Some(validate::sealed_scope(doc)),
                values,
            })
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    /// `@` the pair of resources being compared.
    Header,
    Same,
    Added,
    Removed,
    Changed,
    /// Can't be decided locally (encrypted on at least one side).
    Unknown,
    /// `#` remarks (ignored documents, …).
    Note,
}

impl Tag {
    pub fn sign(self) -> char {
        match self {
            Tag::Header => '@',
            Tag::Same => ' ',
            Tag::Added => '+',
            Tag::Removed => '-',
            Tag::Changed => '~',
            Tag::Unknown => '?',
            Tag::Note => '#',
        }
    }
    pub fn is_change(self) -> bool {
        matches!(self, Tag::Added | Tag::Removed | Tag::Changed | Tag::Unknown)
    }
}

/// What a diff line shows for one side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    /// Public metadata, shown as-is.
    Text(String),
    /// A secret value: masked unless revealed.
    Value(Val),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub tag: Tag,
    pub field: String,
    pub old: Option<Shown>,
    pub new: Option<Shown>,
    pub note: Option<&'static str>,
}

impl Line {
    fn new(tag: Tag, field: impl Into<String>, old: Option<Shown>, new: Option<Shown>) -> Self {
        Self { tag, field: field.into(), old, new, note: None }
    }
    fn note(mut self, n: &'static str) -> Self {
        self.note = Some(n);
        self
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    pub unknown: usize,
    /// Metadata lines (identity, type, scope, labels, annotations) changed.
    pub meta: usize,
}

impl Summary {
    pub fn is_identical(&self) -> bool {
        *self == Summary::default()
    }
}

impl std::fmt::Display for Summary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_identical() {
            return write!(f, "no differences");
        }
        let mut parts = vec![];
        for (n, what) in [
            (self.added, "added"),
            (self.removed, "removed"),
            (self.changed, "modified"),
            (self.unknown, "not comparable (encrypted)"),
        ] {
            if n > 0 {
                parts.push(format!("{n} key(s) {what}"));
            }
        }
        if self.meta > 0 {
            parts.push(format!("{} metadata change(s)", self.meta));
        }
        write!(f, "{}", parts.join(", "))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diff {
    pub lines: Vec<Line>,
    pub summary: Summary,
}

const NOT_COMPARABLE: &str = "plaintext vs encrypted: not comparable without the controller's private key";
const RE_ENCRYPTED: &str = "ciphertext differs — re-sealing always does, so the value may or may not have changed";

fn text(s: &str) -> Option<Shown> {
    Some(Shown::Text(s.to_string()))
}

fn meta_line(out: &mut Diff, field: &str, a: &str, b: &str) {
    if a == b {
        out.lines.push(Line::new(Tag::Same, field, text(a), None));
    } else {
        out.summary.meta += 1;
        out.lines.push(Line::new(Tag::Changed, field, text(a), text(b)));
    }
}

fn map_lines(out: &mut Diff, section: &str, a: &BTreeMap<String, String>, b: &BTreeMap<String, String>) {
    let keys: std::collections::BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    for k in keys {
        let field = format!("{section}.{k}");
        match (a.get(k), b.get(k)) {
            (Some(x), Some(y)) => meta_line(out, &field, x, y),
            (Some(x), None) => {
                out.summary.meta += 1;
                out.lines.push(Line::new(Tag::Removed, field, text(x), None));
            }
            (None, Some(y)) => {
                out.summary.meta += 1;
                out.lines.push(Line::new(Tag::Added, field, None, text(y)));
            }
            (None, None) => {}
        }
    }
}

const FROM_SOURCE: &str = "new value from the Secret it was sealed from — the old one is encrypted";
const VIA_SOURCE: &str = "compared with the Secret it was sealed from";

/// Compare two normalized resources (old → new). When `b` is a SealedSecret kseal sealed from `source`
/// kseal sealed from `source` (a plain Secret it still holds), `b`'s values
/// are known, so they're
/// shown (masked) and, against a plain old side, really compared.
fn diff_with_source(a: &Logical, b: &Logical, source: Option<&Logical>, out: &mut Diff) {
    let source = source.filter(|_| b.kind == Kind::Sealed);
    out.lines.push(Line::new(Tag::Header, format!("{}  →  {}", a.label(), b.label()), None, None));
    meta_line(out, "name", &a.name, &b.name);
    meta_line(out, "namespace", &a.namespace, &b.namespace);
    meta_line(out, "type", &a.type_, &b.type_);
    if let (Some(x), Some(y)) = (a.scope, b.scope) {
        meta_line(out, "scope", x.as_str(), y.as_str());
    }
    if a.immutable || b.immutable {
        meta_line(out, "immutable", &a.immutable.to_string(), &b.immutable.to_string());
    }
    map_lines(out, "labels", &a.labels, &b.labels);
    map_lines(out, "annotations", &a.annotations, &b.annotations);

    let keys: std::collections::BTreeSet<&String> = a.values.keys().chain(b.values.keys()).collect();
    for k in keys {
        let field = format!("data.{k}");
        let shown = |v: &Val| Some(Shown::Value(v.clone()));
        // The plaintext behind b's ciphertext, when kseal sealed it.
        let src = source.and_then(|s| s.values.get(k)).filter(|_| matches!(b.values.get(k), Some(Val::Encrypted(_))));
        let line = match (a.values.get(k), b.values.get(k)) {
            (Some(x), None) => {
                out.summary.removed += 1;
                Line::new(Tag::Removed, field, shown(x), None)
            }
            (None, Some(y)) => {
                out.summary.added += 1;
                Line::new(Tag::Added, field, None, shown(src.unwrap_or(y)))
            }
            (Some(Val::Encrypted(p)), Some(Val::Encrypted(q))) if p == q => {
                Line::new(Tag::Same, field, shown(a.values.get(k).expect("matched")), None)
            }
            (Some(x @ Val::Encrypted(_)), Some(_)) if src.is_some() => {
                out.summary.unknown += 1;
                Line::new(Tag::Unknown, field, shown(x), shown(src.expect("checked"))).note(FROM_SOURCE)
            }
            (Some(x), Some(_)) if src.is_some() => {
                let s = src.expect("checked");
                if plain_bytes(x) == plain_bytes(s) {
                    Line::new(Tag::Same, field, shown(x), None).note(VIA_SOURCE)
                } else {
                    out.summary.changed += 1;
                    Line::new(Tag::Changed, field, shown(x), shown(s)).note(VIA_SOURCE)
                }
            }
            (Some(x), Some(y)) => match (x, y) {
                (Val::Encrypted(p), Val::Encrypted(q)) if p == q => Line::new(Tag::Same, field, shown(x), None),
                (Val::Encrypted(_), Val::Encrypted(_)) => {
                    out.summary.unknown += 1;
                    Line::new(Tag::Unknown, field, shown(x), shown(y)).note(RE_ENCRYPTED)
                }
                (Val::Encrypted(_), _) | (_, Val::Encrypted(_)) => {
                    out.summary.unknown += 1;
                    Line::new(Tag::Unknown, field, shown(x), shown(y)).note(NOT_COMPARABLE)
                }
                _ if plain_bytes(x) == plain_bytes(y) => Line::new(Tag::Same, field, shown(x), None),
                _ => {
                    out.summary.changed += 1;
                    Line::new(Tag::Changed, field, shown(x), shown(y))
                }
            },
            (None, None) => continue,
        };
        out.lines.push(line);
    }
}

fn plain_bytes(v: &Val) -> &[u8] {
    match v {
        Val::Plain(b) => b,
        Val::Invalid(s) | Val::Encrypted(s) => s.as_bytes(),
    }
}

fn parse(text: &str, side: &str) -> Result<(Vec<Logical>, Vec<String>)> {
    let docs = core::parse_yaml_docs(text).with_context(|| format!("{side}: malformed YAML"))?;
    let mut res = vec![];
    let mut other = vec![];
    for d in core::flatten_docs(&docs) {
        match logical(d) {
            Some(l) => res.push(l),
            None => other.push(core::kind_of(d).unwrap_or("(no kind)").to_string()),
        }
    }
    Ok((res, other))
}

/// Diff two manifests (multi-document, `kind: List` expanded). A single
/// resource on each side is compared directly (so a rename shows as one);
/// otherwise resources pair up by namespace/name, Secret ↔ SealedSecret
/// included. Other kinds are ignored and noted.
pub fn diff_texts(old: &str, new: &str) -> Result<Diff> {
    diff_texts_from(old, new, None)
}

/// [`diff_texts`] where `new` was sealed by kseal from the plain Secret
/// manifest `source`: the new side's values come from it (see
/// [`diff_with_source`]). A source Secret pairs with a SealedSecret of the
/// same name (its namespace may have been retargeted), or is the only one.
pub fn diff_texts_from(old: &str, new: &str, source: Option<&str>) -> Result<Diff> {
    let (a, a_other) = parse(old, "old")?;
    let (b, b_other) = parse(new, "new")?;
    let sources: Vec<Logical> = match source {
        Some(t) => parse(t, "source")?.0.into_iter().filter(|l| l.kind == Kind::Secret).collect(),
        None => vec![],
    };
    let source_for = |nb: &Logical| {
        sources.iter().find(|s| s.name == nb.name).or(if sources.len() == 1 { sources.first() } else { None })
    };
    if a.is_empty() && b.is_empty() {
        anyhow::bail!("neither side holds a Secret or SealedSecret");
    }
    let mut out = Diff::default();
    if a.len() == 1 && b.len() == 1 {
        diff_with_source(&a[0], &b[0], source_for(&b[0]), &mut out);
    } else {
        let mut used = vec![false; a.len()];
        for nb in &b {
            match a.iter().enumerate().position(|(i, na)| !used[i] && na.id() == nb.id()) {
                Some(i) => {
                    used[i] = true;
                    diff_with_source(&a[i], nb, source_for(nb), &mut out);
                }
                None => {
                    out.summary.added += nb.values.len();
                    let l = Line::new(Tag::Added, nb.label(), None, None);
                    out.lines.push(l.note("whole resource added"));
                }
            }
        }
        for (na, _) in a.iter().zip(&used).filter(|(_, u)| !**u) {
            out.summary.removed += na.values.len();
            out.lines.push(Line::new(Tag::Removed, na.label(), None, None).note("whole resource removed"));
        }
    }
    // Old values are ciphertext: say where the real ones are.
    let old_encrypted =
        out.lines.iter().any(|l| l.tag == Tag::Unknown && matches!(l.old, Some(Shown::Value(Val::Encrypted(_)))));
    if old_encrypted {
        let hint = "old values are encrypted — compare with the live Secret to see them (kseal: Ctrl+D, empty path)";
        out.lines.push(Line::new(Tag::Note, hint, None, None));
    }
    for (side, other) in [("old", a_other), ("new", b_other)] {
        if !other.is_empty() {
            let field = format!("{side}: ignored {} other document(s): {}", other.len(), other.join(", "));
            out.lines.push(Line::new(Tag::Note, field, None, None));
        }
    }
    Ok(out)
}

/// A secret value as shown: masked (fixed width, so the length isn't
/// leaked) unless `reveal`. Ciphertext is never worth showing.
pub fn show_value(v: &Val, reveal: bool) -> String {
    match v {
        Val::Encrypted(_) => "‹encrypted›".into(),
        _ if !reveal => "••••••••".into(),
        Val::Plain(b) => match std::str::from_utf8(b) {
            Ok(s) => format!("{:?}", s),
            Err(_) => format!("‹binary, {} bytes›", b.len()),
        },
        Val::Invalid(s) => format!("{s:?} ‹not valid base64›"),
    }
}

fn shown(s: &Shown, reveal: bool) -> String {
    match s {
        Shown::Text(t) => t.clone(),
        Shown::Value(v) => show_value(v, reveal),
    }
}

/// One diff line as text, `sign field  old → new  (note)`.
pub fn render(l: &Line, reveal: bool) -> String {
    let mut out = format!("{} {}", l.tag.sign(), l.field);
    match (&l.old, &l.new, l.tag) {
        (Some(a), Some(b), _) => out.push_str(&format!("  {} → {}", shown(a, reveal), shown(b, reveal))),
        (Some(a), None, _) | (None, Some(a), _) => out.push_str(&format!("  {}", shown(a, reveal))),
        (None, None, _) => {}
    }
    if let Some(n) = l.note {
        out.push_str(&format!("  ({n})"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMMY: &str = "dummy-s3cret";

    fn secret(extra: &str) -> String {
        format!(
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\n  namespace: prod\n  labels:\n    app: web\n{extra}type: Opaque\nstringData:\n  USER: alice\n  PASSWORD: {DUMMY}\n"
        )
    }
    fn text_of(d: &Diff, reveal: bool) -> String {
        d.lines.iter().map(|l| render(l, reveal) + "\n").collect()
    }
    fn changes(d: &Diff) -> Vec<(char, &str)> {
        d.lines.iter().filter(|l| l.tag.is_change()).map(|l| (l.tag.sign(), l.field.as_str())).collect()
    }

    #[test]
    fn identical_secrets_and_irrelevant_metadata() {
        // data vs stringData, server metadata and tracking stamps don't count.
        let live = format!(
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\n  namespace: prod\n  uid: 1234\n  resourceVersion: \"9\"\n  creationTimestamp: \"2026-01-01T00:00:00Z\"\n  labels:\n    app: web\n    kustomize.toolkit.fluxcd.io/name: apps\n  annotations:\n    {}: '{{}}'\n    argocd.argoproj.io/tracking-id: a:/Secret:prod/db\ntype: Opaque\ndata:\n  PASSWORD: {}\n  USER: {}\n",
            core::LAST_APPLIED,
            core::b64_encode(DUMMY),
            core::b64_encode("alice")
        );
        let d = diff_texts(&secret(""), &live).unwrap();
        assert!(d.summary.is_identical(), "{}", text_of(&d, false));
        assert_eq!(d.summary.to_string(), "no differences");
    }

    #[test]
    fn added_removed_modified_keys_and_metadata() {
        let old = secret("");
        let new = old
            .replace("  USER: alice\n", "  TOKEN: t\n")
            .replace(DUMMY, "dummy-changed")
            .replace("app: web", "app: api");
        let d = diff_texts(&old, &new).unwrap();
        assert_eq!(
            changes(&d),
            vec![('~', "labels.app"), ('~', "data.PASSWORD"), ('+', "data.TOKEN"), ('-', "data.USER")]
        );
        assert_eq!(d.summary, Summary { added: 1, removed: 1, changed: 1, unknown: 0, meta: 1 });
        assert_eq!(d.summary.to_string(), "1 key(s) added, 1 key(s) removed, 1 key(s) modified, 1 metadata change(s)");
    }

    #[test]
    fn values_are_masked_unless_revealed() {
        let new = secret("").replace(DUMMY, "dummy-changed");
        let d = diff_texts(&secret(""), &new).unwrap();
        let masked = text_of(&d, false);
        assert!(!masked.contains(DUMMY) && !masked.contains("dummy-changed") && !masked.contains("alice"));
        assert!(masked.contains("~ data.PASSWORD  •••••••• → ••••••••"), "{masked}");
        assert!(masked.contains("labels.app  web"), "public metadata is shown");
        let shown = text_of(&d, true);
        assert!(shown.contains(&format!("\"{DUMMY}\" → \"dummy-changed\"")), "{shown}");
        // Fixed-width mask: the length of a value isn't leaked.
        assert_eq!(show_value(&Val::Plain(b"x".to_vec()), false), show_value(&Val::Plain(vec![b'y'; 99]), false));
        assert_eq!(show_value(&Val::Plain(vec![0xff, 0]), true), "‹binary, 2 bytes›");
    }

    fn sealed(scope: Scope, yaml: &str) -> String {
        let key = crate::seal::tests::test_key().to_public_key();
        crate::seal::seal_yaml(yaml, &key, scope).unwrap().0
    }

    #[test]
    fn secret_against_sealed_secret() {
        let s = sealed(Scope::Strict, &secret(""));
        let d = diff_texts(&secret("  annotations:\n    note: x\n"), &s).unwrap();
        let t = text_of(&d, true);
        assert!(t.starts_with("@ Secret prod/db  →  SealedSecret prod/db\n"), "{t}");
        assert_eq!(changes(&d), vec![('-', "annotations.note"), ('?', "data.PASSWORD"), ('?', "data.USER")]);
        assert!(t.contains("not comparable without the controller's private key"));
        assert!(t.contains(&format!("\"{DUMMY}\" → ‹encrypted›")), "reveal shows the plain side only: {t}");
        assert!(!text_of(&d, false).contains(DUMMY));
        assert_eq!(d.summary.unknown, 2);
    }

    #[test]
    fn sealed_against_sealed_scope_and_reencryption() {
        let a = sealed(Scope::Strict, &secret(""));
        let d = diff_texts(&a, &a).unwrap();
        assert!(d.summary.is_identical(), "the same ciphertext is unchanged");
        let b = sealed(Scope::NamespaceWide, &secret(""));
        let d = diff_texts(&a, &b).unwrap();
        assert_eq!(changes(&d), vec![('~', "scope"), ('?', "data.PASSWORD"), ('?', "data.USER")]);
        assert!(text_of(&d, false).contains("may or may not have changed"));
        assert!(text_of(&d, false).contains("# old values are encrypted"), "points at the live compare");
        assert!(!text_of(&diff_texts(&secret(""), &b).unwrap(), false).contains("old values are encrypted"));
    }

    #[test]
    fn sealed_new_side_shows_its_source_values() {
        let src = secret("")
            .replace("USER: alice", "USER: bob")
            .replace("  PASSWORD: dummy-s3cret\n", "  PASSWORD: dummy-s3cret\n  TOKEN: dummy-tok\n");
        let old_sealed = sealed(Scope::Strict, &secret(""));
        let new_sealed = sealed(Scope::Strict, &src);
        // Sealed vs sealed: the old value stays unknown, the new one is shown.
        let d = diff_texts_from(&old_sealed, &new_sealed, Some(&src)).unwrap();
        let t = text_of(&d, true);
        assert!(t.contains("? data.USER  ‹encrypted› → \"bob\"  (new value from the Secret"), "{t}");
        assert!(t.contains("+ data.TOKEN  \"dummy-tok\""), "{t}");
        assert!(!text_of(&d, false).contains("bob") && !text_of(&d, false).contains("dummy-tok"), "masked by default");
        // Plain (e.g. the live Secret) vs sealed: compared for real.
        let d = diff_texts_from(&secret(""), &new_sealed, Some(&src)).unwrap();
        assert_eq!(changes(&d), vec![("+".chars().next().unwrap(), "data.TOKEN"), ('~', "data.USER")]);
        assert_eq!((d.summary.changed, d.summary.added, d.summary.unknown), (1, 1, 0));
        assert!(
            text_of(&d, true)
                .contains("~ data.USER  \"alice\" → \"bob\"  (compared with the Secret it was sealed from)")
        );
        assert!(text_of(&d, false).contains("  data.PASSWORD  ••••••••  (compared with"), "unchanged values say how");
        // A retargeted namespace still pairs by name; no source = as before.
        let moved = sealed(Scope::Strict, &src.replace("namespace: prod", "namespace: staging"));
        let d = diff_texts_from(&secret(""), &moved, Some(&src)).unwrap();
        assert_eq!(d.summary.changed, 1);
        assert_eq!(diff_texts_from(&secret(""), &new_sealed, None).unwrap().summary.unknown, 2);
    }

    #[test]
    fn multi_document_pairing() {
        let other = secret("").replace("name: db", "name: cache");
        let third = secret("").replace("name: db", "name: queue");
        let old = format!("{}---\n{}---\nkind: ConfigMap\ndata: {{a: b}}\n", secret(""), other);
        let new = format!("{}---\n{}", third, secret("").replace("USER: alice", "USER: bob"));
        let d = diff_texts(&old, &new).unwrap();
        assert_eq!(changes(&d), vec![('+', "Secret prod/queue"), ('~', "data.USER"), ('-', "Secret prod/cache")]);
        assert_eq!(d.summary, Summary { added: 2, removed: 2, changed: 1, unknown: 0, meta: 0 });
        assert!(d.lines.last().unwrap().field.contains("old: ignored 1 other document(s): ConfigMap"));
        // kind: List wrappers are expanded too.
        let list = format!(
            "kind: List\nitems:\n  - {}\n",
            serde_json::to_string(&core::parse_yaml_docs(&secret("")).unwrap()[0]).unwrap()
        );
        assert!(diff_texts(&secret(""), &list).unwrap().summary.is_identical());
    }

    #[test]
    fn malformed_yaml_and_non_secrets() {
        let err = diff_texts(&format!("kind: Secret\nstringData: {{P: {DUMMY}\n"), &secret("")).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.starts_with("old: malformed YAML"), "{msg}");
        assert!(!msg.contains(DUMMY), "parse errors don't echo values: {msg}");
        assert!(format!("{:#}", diff_texts(&secret(""), "a: [").unwrap_err()).starts_with("new: malformed YAML"));
        assert!(diff_texts("kind: ConfigMap\n", "kind: ConfigMap\n").is_err());
        let d = diff_texts("", &secret("")).unwrap();
        assert_eq!(changes(&d), vec![('+', "Secret prod/db")]);
    }
}
