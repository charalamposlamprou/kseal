//! GitOps export: SealedSecret manifests ready to commit to a repository
//! that Argo CD or Flux reconciles.
//!
//! Everything here is LOCAL. kseal never commits, pushes, applies or syncs:
//! it writes a file, and Git plus the GitOps controller do the rest. The
//! cluster is only ever read (the sealing certificate, by the caller).
//!
//! What a workflow changes:
//! * all: canonical key order (encryptedData, labels, annotations sorted),
//!   so re-exporting the same Secret gives the same layout — only the
//!   ciphertext differs, because sealing is randomized by design;
//! * Argo CD / Flux: tracking stamps their controllers put on LIVE objects
//!   (`argocd.argoproj.io/tracking-id`, Flux's `kustomize.toolkit.fluxcd.io/*`
//!   labels, kubectl's last-applied snapshot) are dropped from the template,
//!   so a Secret loaded from a cluster doesn't carry its old owner's identity
//!   into Git. Generic keeps them and warns.

use std::path::Path;

use anyhow::{Result, bail};
use rsa::RsaPublicKey;
use serde_json::{Map, Value, json};

use crate::core;
use crate::seal::{self, Scope};
use crate::validate::{self, Finding, KeyInfo, Payload, Severity, TRACKING_ANNOTATIONS, TRACKING_LABELS, TargetScan};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Workflow {
    /// Plain SealedSecret, metadata kept as-is.
    #[default]
    Generic,
    /// Argo CD Application (plain manifests, Kustomize or Helm source).
    #[value(name = "argocd")]
    ArgoCd,
    /// Flux Kustomization.
    Flux,
}

impl Workflow {
    pub const ALL: [Workflow; 3] = [Workflow::Generic, Workflow::ArgoCd, Workflow::Flux];

    pub fn title(self) -> &'static str {
        match self {
            Workflow::Generic => "Generic",
            Workflow::ArgoCd => "Argo CD",
            Workflow::Flux => "Flux",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Options {
    pub workflow: Workflow,
    pub scope: Scope,
    /// Seal for this namespace instead of the Secret's own.
    pub namespace: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Export {
    pub yaml: String,
    pub name: String,
    pub namespace: String,
    pub findings: Vec<Finding>,
}

/// The Secret to seal: retargeted to `opts.namespace`, and for Argo CD /
/// Flux stripped of controller tracking metadata. Returns notes on what
/// changed.
pub fn prepare(doc: &Value, opts: &Options) -> (Value, Vec<Finding>) {
    let mut doc = doc.clone();
    let res = validate::resource_label(&doc);
    let mut notes = vec![];
    let Some(m) = doc.as_object_mut() else { return (doc, notes) };
    let meta = m.entry("metadata").or_insert_with(|| json!({}));
    let Some(meta) = meta.as_object_mut() else { return (doc, notes) };
    if let Some(ns) = opts.namespace.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let was = meta.get("namespace").and_then(Value::as_str).unwrap_or("").to_string();
        if was != ns {
            meta.insert("namespace".into(), json!(ns));
            let from = if was.is_empty() { "no namespace".into() } else { format!("namespace {was}") };
            notes.push(Finding {
                severity: Severity::Info,
                rule: "export.retarget",
                resource: res.clone(),
                key: None,
                message: format!("sealed for namespace {ns} (the Secret had {from})"),
                remediation: String::new(),
            });
        }
    }
    let mut tracked = vec![];
    for (section, keys) in [("annotations", TRACKING_ANNOTATIONS), ("labels", TRACKING_LABELS)] {
        let Some(Value::Object(sec)) = meta.get_mut(section) else { continue };
        let present: Vec<&str> = keys.iter().copied().filter(|k| sec.contains_key(*k)).collect();
        for k in present {
            // last-applied is always dropped by the sealer; the rest only for GitOps.
            if opts.workflow != Workflow::Generic || k == core::LAST_APPLIED {
                sec.remove(k);
            }
            tracked.push(format!("{section}.{k}"));
        }
        if sec.is_empty() {
            meta.remove(section);
        }
    }
    for t in tracked {
        let (sev, msg) = if t.ends_with(core::LAST_APPLIED) {
            (Severity::Info, "dropped kubectl's last-applied snapshot (it embeds old data)".to_string())
        } else if opts.workflow == Workflow::Generic {
            (Severity::Low, "controller tracking metadata copied from a live object".to_string())
        } else {
            (
                Severity::Info,
                format!(
                    "dropped controller tracking metadata copied from a live object ({} export)",
                    opts.workflow.title()
                ),
            )
        };
        let fix = if sev == Severity::Low { "Export with the Argo CD or Flux workflow to drop it" } else { "" };
        notes.push(Finding {
            severity: sev,
            rule: "export.tracking-metadata",
            resource: res.clone(),
            key: Some(t),
            message: msg,
            remediation: fix.into(),
        });
    }
    (doc, notes)
}

fn sort_map(v: Option<&mut Value>) {
    if let Some(Value::Object(m)) = v {
        let mut entries: Vec<(String, Value)> = std::mem::take(m).into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        *m = entries.into_iter().collect::<Map<String, Value>>();
    }
}

/// Sort the maps whose order is arbitrary, for stable output and diffs.
pub fn canonicalize(v: &mut Value) {
    sort_map(v.pointer_mut("/metadata/annotations"));
    sort_map(v.pointer_mut("/metadata/labels"));
    sort_map(v.pointer_mut("/spec/encryptedData"));
    sort_map(v.pointer_mut("/spec/template/metadata/labels"));
    sort_map(v.pointer_mut("/spec/template/metadata/annotations"));
}

/// Seal the Secret in `secret_yaml` for a GitOps repository and check the
/// result. `key_info` (from the certificate) enables the ciphertext check.
pub fn build(secret_yaml: &str, key: &RsaPublicKey, key_info: Option<KeyInfo>, opts: &Options) -> Result<Export> {
    let docs = core::parse_yaml_docs(secret_yaml)?;
    let Some(doc) = core::select_secret_doc(&docs) else {
        if core::has_sealed_secret(&docs) {
            bail!("the input is already a SealedSecret — export the plain Secret it was sealed from");
        }
        bail!("no Secret found in the input");
    };
    let mut findings: Vec<Finding> = validate::secret_findings(doc)
        .into_iter()
        // A plaintext manifest is the expected input here, not a finding.
        .filter(|f| f.rule != "secret.last-applied")
        .collect();
    let (prepared, notes) = prepare(doc, opts);
    findings.extend(notes);
    let mut sealed = seal::seal_secret(&prepared, key, opts.scope)?;
    canonicalize(&mut sealed);
    let yaml = seal::to_yaml(&sealed);

    // Defense in depth: check what is about to be written, as written.
    let written = core::parse_yaml_docs(&yaml)?;
    findings.extend(validate::file_findings(&written, key_info));
    if yaml.contains("stringData") || core::select_secret_doc(&written).is_some() {
        findings.push(Finding {
            severity: Severity::Critical,
            rule: "export.plaintext",
            resource: validate::resource_label(&sealed),
            key: None,
            message: "the export would contain plaintext Secret data".into(),
            remediation: "This is a kseal bug — please report it; nothing was written".into(),
        });
    }
    let (name, namespace, _) = core::secret_identity(&prepared);
    let res = validate::resource_label(&sealed);
    let note = |message: String| Finding {
        severity: Severity::Info,
        rule: "export.workflow",
        resource: res.clone(),
        key: None,
        message,
        remediation: String::new(),
    };
    match opts.workflow {
        Workflow::ArgoCd => findings
            .push(note("Argo CD: commit it under the Application's source path; the next sync applies it".into())),
        Workflow::Flux if opts.scope != Scope::ClusterWide => findings.push(note(format!(
            "Flux: a Kustomization with spec.targetNamespace must target {namespace:?} ({} scope)",
            opts.scope.as_str()
        ))),
        Workflow::Flux => findings.push(note("Flux: commit it under a path a Kustomization reconciles".into())),
        Workflow::Generic => {}
    }
    validate::sort(&mut findings);
    Ok(Export { yaml, name, namespace, findings })
}

/// The suggested export file name.
pub fn default_file_name(name: &str) -> String {
    let name = if name.trim().is_empty() { core::DEF_NAME } else { name.trim() };
    format!("sealed-{name}.yaml")
}

const MAX_SCAN_FILE: u64 = 1024 * 1024;
const MAX_SCAN_FILES: usize = 200;

#[cfg(unix)]
fn mode_of(m: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(m.permissions().mode())
}
#[cfg(not(unix))]
fn mode_of(_: &std::fs::Metadata) -> Option<u32> {
    None
}

fn read_capped(p: &Path) -> Option<String> {
    let m = std::fs::symlink_metadata(p).ok()?;
    if !m.is_file() || m.len() > MAX_SCAN_FILE {
        return None;
    }
    std::fs::read_to_string(p).ok()
}

/// Gather the facts [`validate::target_findings`] judges, read-only. With
/// `neighbors`, the directory's other YAML files are read too (capped), to
/// spot plain Secrets about to be committed alongside.
pub fn scan_target(path: &Path, neighbors: bool) -> TargetScan {
    let meta = std::fs::symlink_metadata(path).ok();
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => Path::new(".").to_path_buf(),
    };
    let pmeta = std::fs::metadata(&parent).ok();
    let in_git =
        std::fs::canonicalize(&parent).map(|abs| abs.ancestors().any(|a| a.join(".git").exists())).unwrap_or(false);
    let kustomization = ["kustomization.yaml", "kustomization.yml", "Kustomization"]
        .iter()
        .find_map(|n| read_capped(&parent.join(n)).map(|t| (n.to_string(), t)));
    let mut found = vec![];
    if neighbors {
        if let Ok(rd) = std::fs::read_dir(&parent) {
            let mut names: Vec<String> = rd
                .filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| (n.ends_with(".yaml") || n.ends_with(".yml")) && !n.starts_with("kustomization."))
                .collect();
            names.sort();
            for n in names.into_iter().take(MAX_SCAN_FILES) {
                if let Some(t) = read_capped(&parent.join(&n)) {
                    found.push((n, t));
                }
            }
        }
    }
    TargetScan {
        path: path.display().to_string(),
        exists: meta.is_some(),
        is_symlink: meta.as_ref().is_some_and(|m| m.file_type().is_symlink()),
        mode: meta.as_ref().filter(|m| m.is_file()).and_then(mode_of),
        parent_exists: pmeta.as_ref().is_some_and(|m| m.is_dir()),
        parent_mode: pmeta.as_ref().and_then(mode_of),
        in_git,
        kustomization,
        neighbors: found,
    }
}

/// What a write of `content` to the scanned path would be: a SealedSecret
/// (with the identity and scope its annotations select) or plaintext.
pub fn payload_of(content: &str) -> Payload {
    let docs = core::parse_yaml_docs(content).unwrap_or_default();
    let flat = core::flatten_docs(&docs);
    match flat.iter().find(|d| core::kind_of(d) == Some("SealedSecret")) {
        Some(d) if core::select_secret_doc(&docs).is_none() => {
            let (name, ns, _) = core::secret_identity(d);
            Payload::Sealed { ns, name, scope: validate::sealed_scope(d) }
        }
        _ => Payload::PlainSecret,
    }
}

/// The Git working tree `dir` is in — where [`find_manifests`] searches
/// when no repository was named. `None` outside one: kseal never crawls an
/// arbitrary directory (say, `~`) on its own.
pub fn git_root(dir: &Path) -> Option<std::path::PathBuf> {
    let abs = std::fs::canonicalize(dir).ok()?;
    abs.ancestors().find(|a| a.join(".git").exists()).map(Path::to_path_buf)
}

const SKIP_DIRS: &[&str] = &["target", "node_modules", "vendor"];
const MAX_FIND_FILES: usize = 20_000;
const MAX_FIND_DEPTH: usize = 24;

/// A local manifest defining the SealedSecret being exported.
#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    pub path: std::path::PathBuf,
    /// The matching SealedSecret, its namespace filled in when it comes
    /// from the directory's kustomization (so the controller can check it).
    pub doc: Value,
}

/// Whose a found manifest is, by asking the target cluster's controller
/// whether it can decrypt it (it creates nothing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// The controller sealed for can decrypt it: this cluster's file.
    This,
    /// It can't: sealed for another cluster (or env).
    Other,
    /// Not asked (sealing with a certificate) or the check failed.
    Unknown,
}

impl Owner {
    pub fn label(self) -> &'static str {
        match self {
            Owner::This => "this cluster",
            Owner::Other => "another cluster",
            Owner::Unknown => "cluster unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundManifest {
    /// Shown / used as the Output (relative to the cwd when under it).
    pub path: String,
    pub owner: Owner,
}

/// The namespace a directory's kustomization sets, if any.
fn dir_namespace(dir: &Path) -> Option<String> {
    ["kustomization.yaml", "kustomization.yml", "Kustomization"].iter().find_map(|n| {
        let docs = core::parse_yaml_docs(&read_capped(&dir.join(n))?).ok()?;
        docs.first()?.get("namespace")?.as_str().filter(|s| !s.is_empty()).map(str::to_string)
    })
}

/// Local manifests (under `root`) defining the SealedSecret `ns`/`name` —
/// where a re-export most likely belongs. A SealedSecret without a
/// namespace counts when its directory's kustomization sets `ns`
/// (overlays). Read-only: YAML files only, capped in size and count, hidden
/// / build directories skipped, symlinks never followed. Sorted, so the
/// result is deterministic.
pub fn find_manifests(root: &Path, ns: &str, name: &str) -> Vec<Found> {
    let mut found = vec![];
    let mut seen = 0usize;
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.filter_map(Result::ok) {
            let n = e.file_name().to_string_lossy().into_owned();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() || n.starts_with('.') {
                continue;
            }
            let p = e.path();
            if ft.is_dir() {
                if depth < MAX_FIND_DEPTH && !SKIP_DIRS.contains(&n.as_str()) {
                    stack.push((p, depth + 1));
                }
                continue;
            }
            if !(n.ends_with(".yaml") || n.ends_with(".yml")) {
                continue;
            }
            seen += 1;
            if seen > MAX_FIND_FILES {
                break;
            }
            let Some(text) = read_capped(&p) else { continue };
            // Cheap filter before parsing.
            if !text.contains("SealedSecret") || !text.contains(name) {
                continue;
            }
            let Ok(docs) = core::parse_yaml_docs(&text) else { continue };
            let kns = std::cell::OnceCell::new();
            let hit = core::flatten_docs(&docs).into_iter().find(|d| {
                let (n, s, _) = core::secret_identity(d);
                core::kind_of(d) == Some("SealedSecret")
                    && n == name
                    && (s == ns || (s.is_empty() && kns.get_or_init(|| dir_namespace(&dir)).as_deref() == Some(ns)))
            });
            if let Some(d) = hit {
                let mut doc = d.clone();
                if let Some(m) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                    m.insert("namespace".into(), json!(ns));
                }
                found.push(Found { path: p, doc });
            }
        }
    }
    found.sort_by(|a, b| a.path.cmp(&b.path));
    found
}

/// Where to export, given the manifests found and whose they are: a path
/// the user chose stays; otherwise the ONE manifest of this cluster. A file
/// of another cluster is never picked; with only a certificate (owners
/// unknown) nothing is, and the user chooses. Plus a note per manifest.
pub fn choose_output(found: &[FoundManifest], given: &str, name: &str, res: &str) -> (String, Vec<Finding>) {
    let mine: Vec<&FoundManifest> = found.iter().filter(|f| f.owner == Owner::This).collect();
    let out = match (given.is_empty(), mine.as_slice()) {
        (false, _) => given.to_string(),
        (true, [only]) => only.path.clone(),
        (true, _) => default_file_name(name),
    };
    let notes = found
        .iter()
        .map(|f| {
            let message = match f.owner {
                Owner::This => {
                    format!("existing manifest found at {} (this cluster's controller can decrypt it)", f.path)
                }
                Owner::Other => format!(
                    "{} defines it too, but for another cluster — its controller isn't this one; not picked",
                    f.path
                ),
                Owner::Unknown => {
                    format!("{} defines it — can't tell which cluster it is for; Ctrl+O on Output to choose", f.path)
                }
            };
            Finding {
                severity: Severity::Info,
                rule: "export.found",
                resource: res.to_string(),
                key: None,
                message,
                remediation: String::new(),
            }
        })
        .collect::<Vec<_>>();
    let mut notes = notes;
    // Writing elsewhere would leave two manifests for one resource (GitOps
    // tools apply both): say where this cluster's already is.
    if let [only] = mine.as_slice() {
        let canon = |p: &str| {
            let p = Path::new(p);
            std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
        };
        if !given.is_empty() && canon(given) != canon(&only.path) {
            notes.push(Finding {
                severity: Severity::Medium,
                rule: "export.not-existing-file",
                resource: res.to_string(),
                key: None,
                message: format!(
                    "Output is {given}, but this cluster's manifest for it is {} — two files would define one resource",
                    only.path
                ),
                remediation: "Ctrl+O on Output and pick it (or Ctrl+K to let kseal pick)".into(),
            });
        }
    }
    (out, notes)
}

/// HIGH when `path` is one of `foreign` (manifests known to be another
/// cluster's): overwriting it would break that cluster's next sync.
pub fn foreign_finding(path: &Path, foreign: &[String]) -> Option<Finding> {
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let target = canon(path);
    foreign.iter().any(|f| canon(Path::new(f)) == target).then(|| Finding {
        severity: Severity::High,
        rule: "target.other-cluster",
        resource: path.display().to_string(),
        key: None,
        message: "this file was sealed for another cluster — its controller can't decrypt what you're sealing now"
            .into(),
        remediation: "Export to this cluster's manifest instead (Ctrl+O on Output lists them)".into(),
    })
}

/// `p` relative to `base` when it's under it (shorter to show and type).
pub fn display_path(p: &Path, base: &Path) -> String {
    let base = std::fs::canonicalize(base).unwrap_or_else(|_| base.to_path_buf());
    let p = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    p.strip_prefix(&base).map_or_else(|_| p.display().to_string(), |r| r.display().to_string())
}

/// Pre-write checks for `content` at `path` (read-only I/O + pure rules).
pub fn check_target(path: &Path, content: &str) -> Vec<Finding> {
    let payload = payload_of(content);
    let scan = scan_target(path, matches!(payload, Payload::Sealed { .. }));
    validate::target_findings(&scan, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::tests::{hybrid_decrypt, test_key};

    const DUMMY: &str = "dummy-p4ss";

    fn live_secret() -> String {
        format!(
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\n  namespace: prod\n  uid: abc\n  labels:\n    zeta: z\n    app: web\n    kustomize.toolkit.fluxcd.io/name: apps\n  annotations:\n    argocd.argoproj.io/tracking-id: \"shop:/Secret:prod/db\"\n    team: sre\n    {}: '{{\"stringData\":{{\"P\":\"{DUMMY}\"}}}}'\ntype: Opaque\nstringData:\n  ZKEY: z\n  PASSWORD: {DUMMY}\n",
            core::LAST_APPLIED
        )
    }

    fn export(workflow: Workflow, scope: Scope, ns: Option<&str>) -> Export {
        let opts = Options { workflow, scope, namespace: ns.map(Into::into) };
        build(&live_secret(), &test_key().to_public_key(), Some(KeyInfo { rsa_bytes: 256 }), &opts).unwrap()
    }
    fn doc(e: &Export) -> Value {
        core::parse_yaml_docs(&e.yaml).unwrap().remove(0)
    }
    fn keys(v: &Value) -> Vec<String> {
        v.as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default()
    }

    #[test]
    fn argocd_export_drops_tracking_and_is_canonical() {
        let e = export(Workflow::ArgoCd, Scope::Strict, None);
        let d = doc(&e);
        assert_eq!(d["apiVersion"], "bitnami.com/v1alpha1");
        assert_eq!((d["metadata"]["name"].as_str(), d["metadata"]["namespace"].as_str()), (Some("db"), Some("prod")));
        let t = &d["spec"]["template"]["metadata"];
        assert_eq!(keys(&t["labels"]), vec!["app", "zeta"], "sorted, Flux label dropped");
        assert_eq!(keys(&t["annotations"]), vec!["team"], "tracking id and last-applied dropped");
        assert_eq!(keys(&d["spec"]["encryptedData"]), vec!["PASSWORD", "ZKEY"]);
        assert!(!e.yaml.contains("uid") && !e.yaml.contains(DUMMY) && !e.yaml.contains("stringData"));
        assert!(e.findings.iter().all(|f| f.severity >= Severity::Low), "{:?}", e.findings);
        assert!(e.findings.iter().any(|f| f.rule == "export.workflow" && f.message.starts_with("Argo CD")));
        // Decrypts with the strict label: the export is a real seal.
        let ct = core::b64_decode_bytes(d["spec"]["encryptedData"]["PASSWORD"].as_str().unwrap()).unwrap();
        assert_eq!(hybrid_decrypt(&test_key(), &ct, b"prod/db").unwrap(), DUMMY.as_bytes());
    }

    #[test]
    fn exports_are_deterministic_apart_from_ciphertext() {
        let strip = |e: &Export| {
            let mut d = doc(e);
            for v in d["spec"]["encryptedData"].as_object_mut().unwrap().values_mut() {
                *v = json!("X");
            }
            seal::to_yaml(&d)
        };
        let (a, b) = (export(Workflow::Flux, Scope::Strict, None), export(Workflow::Flux, Scope::Strict, None));
        assert_ne!(a.yaml, b.yaml, "sealing is randomized");
        assert_eq!(strip(&a), strip(&b));
        assert_eq!(a.findings, b.findings);
    }

    #[test]
    fn flux_export_with_namespace_override_and_scopes() {
        let e = export(Workflow::Flux, Scope::NamespaceWide, Some("staging"));
        let d = doc(&e);
        assert_eq!(d["metadata"]["namespace"], "staging");
        assert_eq!(d["metadata"]["annotations"][seal::ANN_NAMESPACE_WIDE], "true");
        assert_eq!((e.namespace.as_str(), e.name.as_str()), ("staging", "db"));
        assert_eq!(
            payload_of(&e.yaml),
            Payload::Sealed { ns: "staging".into(), name: "db".into(), scope: Scope::NamespaceWide }
        );
        let ct = core::b64_decode_bytes(d["spec"]["encryptedData"]["PASSWORD"].as_str().unwrap()).unwrap();
        assert_eq!(hybrid_decrypt(&test_key(), &ct, b"staging").unwrap(), DUMMY.as_bytes());
        assert!(e.findings.iter().any(|f| f.rule == "export.retarget" && f.message.contains("namespace prod")));
        assert!(e.findings.iter().any(|f| f.message.contains("targetNamespace must target \"staging\"")));
        assert!(d["spec"]["template"]["metadata"]["labels"].get("kustomize.toolkit.fluxcd.io/name").is_none());

        let cw = export(Workflow::Flux, Scope::ClusterWide, None);
        let ct = core::b64_decode_bytes(doc(&cw)["spec"]["encryptedData"]["ZKEY"].as_str().unwrap()).unwrap();
        assert_eq!(hybrid_decrypt(&test_key(), &ct, b"").unwrap(), b"z");
        assert!(cw.findings.iter().any(|f| f.rule == "sealed.cluster-wide"));
    }

    #[test]
    fn generic_export_keeps_tracking_metadata_and_warns() {
        let e = export(Workflow::Generic, Scope::Strict, None);
        let t = &doc(&e)["spec"]["template"]["metadata"];
        assert!(t["annotations"].get("argocd.argoproj.io/tracking-id").is_some());
        assert!(t["annotations"].get(core::LAST_APPLIED).is_none(), "never carried");
        let low: Vec<_> =
            e.findings.iter().filter(|f| f.severity == Severity::Low).filter_map(|f| f.key.clone()).collect();
        assert!(low.contains(&"annotations.argocd.argoproj.io/tracking-id".to_string()), "{low:?}");
        for f in &e.findings {
            assert!(!format!("{f:?}").contains(DUMMY));
        }
    }

    #[test]
    fn build_rejects_bad_input() {
        let pk = test_key().to_public_key();
        let o = Options::default();
        let sealed = export(Workflow::Generic, Scope::Strict, None).yaml;
        assert!(build(&sealed, &pk, None, &o).unwrap_err().to_string().contains("already a SealedSecret"));
        assert!(build("kind: ConfigMap\n", &pk, None, &o).is_err());
        assert!(build("kind: Secret\n  bad: [", &pk, None, &o).is_err());
        let no_ns = "kind: Secret\nmetadata: {name: a}\nstringData: {P: x}\n";
        assert!(build(no_ns, &pk, None, &o).unwrap_err().to_string().contains("namespace"));
        let o = Options { namespace: Some("prod".into()), ..o };
        assert!(build(no_ns, &pk, None, &o).is_ok(), "the target namespace fills it in");
    }

    #[test]
    fn payload_detection() {
        assert_eq!(payload_of("kind: Secret\nstringData: {a: b}\n"), Payload::PlainSecret);
        let mixed =
            format!("{}---\nkind: Secret\nstringData: {{a: b}}\n", export(Workflow::Generic, Scope::Strict, None).yaml);
        assert_eq!(payload_of(&mixed), Payload::PlainSecret, "a Secret alongside makes the file plaintext");
        assert_eq!(payload_of("{{{"), Payload::PlainSecret);
        assert_eq!(default_file_name("db"), "sealed-db.yaml");
        assert_eq!(default_file_name(" "), "sealed-my-secret.yaml");
    }

    #[test]
    fn find_manifests_locates_the_existing_sealed_secret() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let sealed = export(Workflow::Generic, Scope::Strict, None).yaml; // prod/db
        let w = |rel: &str, text: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        };
        w("apps/prod/db.yaml", &sealed);
        w("apps/all.yaml", &format!("kind: ConfigMap\n---\n{sealed}"));
        w("apps/staging/db.yaml", &sealed.replace("namespace: prod", "namespace: staging"));
        w("apps/plain.yaml", "kind: Secret\nmetadata: {name: db, namespace: prod}\n");
        w(".git/objects/db.yaml", &sealed);
        w("target/db.yaml", &sealed);
        w("apps/notes.txt", &sealed);
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("apps"), root.join("link")).unwrap();
        // An overlay without a namespace in the file, set by its kustomization.
        w(
            "overlays/prod/db.yaml",
            &sealed.replace("metadata:\n  name: db\n  namespace: prod\n", "metadata:\n  name: db\n"),
        );
        w("overlays/prod/kustomization.yaml", "namespace: prod\nresources: [db.yaml]\n");
        w(
            "overlays/dev/db.yaml",
            &sealed.replace("metadata:\n  name: db\n  namespace: prod\n", "metadata:\n  name: db\n"),
        );
        w("overlays/dev/kustomization.yaml", "namespace: dev\nresources: [db.yaml]\n");
        let hits = find_manifests(root, "prod", "db");
        let found: Vec<String> = hits.iter().map(|f| display_path(&f.path, root)).collect();
        assert_eq!(
            found,
            vec!["apps/all.yaml", "apps/prod/db.yaml", "overlays/prod/db.yaml"],
            "multi-doc and overlays too; no plain, wrong-ns, hidden, build or symlinked paths"
        );
        assert_eq!(hits[2].doc["metadata"]["namespace"], "prod", "filled in for the controller check");
        assert!(find_manifests(root, "prod", "nope").is_empty());
        // root has a .git (written above): it is the repository.
        assert_eq!(git_root(&root.join("apps/prod")), Some(std::fs::canonicalize(root).unwrap()));
        let plain = tempfile::tempdir().unwrap();
        assert_eq!(git_root(plain.path()), None, "not a repository (e.g. ~): no search root");
    }

    #[test]
    fn output_is_only_ever_this_clusters_manifest() {
        let f = |p: &str, owner| FoundManifest { path: p.into(), owner };
        let res = "SealedSecret shop/db";
        // One of this cluster's among others: picked.
        let found = [f("envs/dev/db.yaml", Owner::Other), f("envs/prod/db.yaml", Owner::This)];
        let (out, notes) = choose_output(&found, "", "db", res);
        assert_eq!(out, "envs/prod/db.yaml");
        assert!(notes[0].message.contains("for another cluster") && notes[1].message.contains("can decrypt it"));
        // Only another cluster's file: never picked.
        assert_eq!(choose_output(&found[..1], "", "db", res).0, "sealed-db.yaml");
        // Certificate mode (unknown): never picked; two of this cluster's: ambiguous.
        assert_eq!(choose_output(&[f("a.yaml", Owner::Unknown)], "", "db", res).0, "sealed-db.yaml");
        let two = [f("a.yaml", Owner::This), f("b.yaml", Owner::This)];
        assert_eq!(choose_output(&two, "", "db", res).0, "sealed-db.yaml");
        // A path the user chose stays, with a nudge to the existing file.
        let (out, notes) = choose_output(&found, "mine.yaml", "db", res);
        assert_eq!(out, "mine.yaml");
        let nudge = notes.iter().find(|n| n.rule == "export.not-existing-file").expect("nudge");
        assert_eq!(nudge.severity, Severity::Medium);
        assert!(nudge.message.contains("envs/prod/db.yaml"));
        let (_, notes) = choose_output(&found, "envs/prod/db.yaml", "db", res);
        assert!(notes.iter().all(|n| n.rule != "export.not-existing-file"), "no nudge when it is that file");

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("dev.yaml");
        std::fs::write(&p, "x").unwrap();
        let foreign = vec![p.display().to_string()];
        assert_eq!(foreign_finding(&p, &foreign).unwrap().severity, Severity::High);
        assert!(foreign_finding(&dir.path().join("prod.yaml"), &foreign).is_none());
    }

    #[test]
    fn scan_target_reads_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        std::fs::write(p.join("kustomization.yaml"), "namespace: other\nresources: [sealed-db.yaml]\n").unwrap();
        std::fs::write(p.join("plain.yaml"), "kind: Secret\nstringData: {a: b}\n").unwrap();
        std::fs::write(p.join("notes.txt"), "kind: Secret\n").unwrap();
        let target = p.join("sealed-db.yaml");
        let s = scan_target(&target, true);
        assert!(!s.exists && s.parent_exists && !s.is_symlink);
        assert_eq!(s.kustomization.as_ref().map(|k| k.0.as_str()), Some("kustomization.yaml"));
        assert_eq!(s.neighbors.iter().map(|n| n.0.as_str()).collect::<Vec<_>>(), vec!["plain.yaml"]);
        assert!(scan_target(&target, false).neighbors.is_empty());
        let content = export(Workflow::Flux, Scope::Strict, None).yaml;
        let f = check_target(&target, &content);
        let r: Vec<_> = f.iter().map(|f| f.rule).collect();
        assert_eq!(r, vec!["kustomize.namespace", "target.plaintext-neighbor"]);
        #[cfg(unix)]
        {
            std::fs::write(p.join("real.yaml"), "").unwrap();
            std::os::unix::fs::symlink(p.join("real.yaml"), p.join("link.yaml")).unwrap();
            assert!(scan_target(&p.join("link.yaml"), false).is_symlink);
            assert!(check_target(&p.join("link.yaml"), &content).iter().any(|f| f.rule == "target.symlink"));
        }
    }
}
