//! Security validation for Secrets, SealedSecrets, sealing certificates and
//! export targets. Pure: every input is passed in (parsed docs, PEM bytes,
//! the current time, a [`TargetScan`] gathered by the caller), so the rules
//! are deterministic and unit-tested without a cluster or a filesystem.
//!
//! Findings never contain secret values: messages name keys, metadata and
//! files only. SealedSecret checks are STRUCTURAL — whether the controller
//! can decrypt a manifest is only known by asking it (`kseal validate`,
//! Ctrl+T), and nothing here claims otherwise.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::core::{self, EntryKind};
use crate::seal::{ANN_CLUSTER_WIDE, ANN_NAMESPACE_WIDE, Scope};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, clap::ValueEnum)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    /// Stable rule id, e.g. `secret.invalid-base64`.
    pub rule: &'static str,
    /// What it is about: `Secret prod/db`, `certificate`, a file path.
    pub resource: String,
    pub key: Option<String>,
    pub message: String,
    pub remediation: String,
}

impl Finding {
    fn new(severity: Severity, rule: &'static str, resource: &str, message: impl Into<String>) -> Self {
        Self {
            severity,
            rule,
            resource: resource.to_string(),
            key: None,
            message: message.into(),
            remediation: String::new(),
        }
    }
    fn key(mut self, k: &str) -> Self {
        self.key = Some(k.to_string());
        self
    }
    fn fix(mut self, r: impl Into<String>) -> Self {
        self.remediation = r.into();
        self
    }
}

/// Sort for display and diffing: most severe first, then by resource, rule
/// and key — the same input always gives the same list.
pub fn sort(findings: &mut [Finding]) {
    findings.sort_by(|a, b| (a.severity, &a.resource, a.rule, &a.key).cmp(&(b.severity, &b.resource, b.rule, &b.key)));
}

pub fn worst(findings: &[Finding]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).min()
}

/// `n critical, m high, …` (non-zero levels only), or `no issues`.
pub fn summary(findings: &[Finding]) -> String {
    let parts: Vec<String> = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info]
        .iter()
        .filter_map(|s| {
            let n = findings.iter().filter(|f| f.severity == *s).count();
            (n > 0).then(|| format!("{n} {}", s.as_str().to_lowercase()))
        })
        .collect();
    if parts.is_empty() { "no issues".into() } else { parts.join(", ") }
}

/// A finding as plain text (CLI output): severity, rule, resource/key,
/// then the explanation and the fix on indented lines.
pub fn format_finding(f: &Finding) -> String {
    let what = match &f.key {
        Some(k) => format!("{} [{k}]", f.resource),
        None => f.resource.clone(),
    };
    let mut s = format!("{:<8}  {}  {what}\n          {}", f.severity.as_str(), f.rule, f.message);
    if !f.remediation.is_empty() {
        s.push_str(&format!("\n          fix: {}", f.remediation));
    }
    s
}

// ---------------------------------------------------------------------------
// Kubernetes naming
// ---------------------------------------------------------------------------

static DNS_SUBDOMAIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\z").unwrap());
static DNS_LABEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A[a-z0-9]([-a-z0-9]*[a-z0-9])?\z").unwrap());
static DATA_KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A[-._a-zA-Z0-9]+\z").unwrap());

/// metadata.name of a Secret / SealedSecret (a DNS-1123 subdomain).
pub fn valid_name(s: &str) -> bool {
    s.len() <= 253 && DNS_SUBDOMAIN.is_match(s)
}

/// A namespace (a DNS-1123 label).
pub fn valid_namespace(s: &str) -> bool {
    s.len() <= 63 && DNS_LABEL.is_match(s)
}

/// A Secret data key (Kubernetes' `IsConfigMapKey`).
pub fn valid_data_key(s: &str) -> bool {
    s.len() <= 253 && DATA_KEY.is_match(s) && s != "." && s != ".." && !s.starts_with("..")
}

/// Annotations and labels that controllers stamp onto applied objects to
/// track them. Copied from a live object into Git they are stale, and a
/// tracking id names the object's OLD owner.
pub const TRACKING_ANNOTATIONS: &[&str] = &[core::LAST_APPLIED, "argocd.argoproj.io/tracking-id"];
pub const TRACKING_LABELS: &[&str] = &["kustomize.toolkit.fluxcd.io/name", "kustomize.toolkit.fluxcd.io/namespace"];

/// Secret size limit enforced by the API server (all values together).
const MAX_SECRET_BYTES: usize = 1024 * 1024;

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(v, |v, k| v.get(k))?.as_str()
}

fn obj_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Map<String, Value>> {
    path.iter().try_fold(v, |v, k| v.get(k))?.as_object()
}

/// `Kind ns/name` for messages (missing parts shown as `?`).
pub fn resource_label(doc: &Value) -> String {
    let kind = doc.get("kind").and_then(Value::as_str).unwrap_or("Secret");
    let name = str_at(doc, &["metadata", "name"]).filter(|s| !s.is_empty()).unwrap_or("?");
    match str_at(doc, &["metadata", "namespace"]).filter(|s| !s.is_empty()) {
        Some(ns) => format!("{kind} {ns}/{name}"),
        None => format!("{kind} {name}"),
    }
}

/// The scope a SealedSecret's annotations select, as the controller reads them.
pub fn sealed_scope(doc: &Value) -> Scope {
    let ann = |k: &str| str_at(doc, &["metadata", "annotations", k]) == Some("true");
    if ann(ANN_CLUSTER_WIDE) {
        Scope::ClusterWide
    } else if ann(ANN_NAMESPACE_WIDE) {
        Scope::NamespaceWide
    } else {
        Scope::Strict
    }
}

fn identity_findings(doc: &Value, res: &str, out: &mut Vec<Finding>, name_required: bool) {
    match str_at(doc, &["metadata", "name"]) {
        None | Some("") if name_required => out.push(
            Finding::new(Severity::High, "meta.name-missing", res, "metadata.name is missing")
                .fix("Set metadata.name — Kubernetes rejects an object without one"),
        ),
        Some(n) if !n.is_empty() && !valid_name(n) => out.push(
            Finding::new(Severity::High, "meta.name-invalid", res, format!("metadata.name {n:?} is not a valid name"))
                .fix("Use lowercase letters, digits, '-' and '.', starting and ending alphanumeric (max 253)"),
        ),
        _ => {}
    }
    if let Some(ns) = str_at(doc, &["metadata", "namespace"]).filter(|s| !s.is_empty()) {
        if !valid_namespace(ns) {
            out.push(
                Finding::new(
                    Severity::High,
                    "meta.namespace-invalid",
                    res,
                    format!("metadata.namespace {ns:?} is not a valid namespace"),
                )
                .fix("Use lowercase letters, digits and '-', starting and ending alphanumeric (max 63)"),
            );
        }
    }
    if doc.get("metadata").is_some_and(|m| !m.is_object()) {
        out.push(
            Finding::new(Severity::High, "meta.malformed", res, "metadata is not a mapping")
                .fix("metadata must hold name, namespace, labels and annotations as a mapping"),
        );
    }
}

// ---------------------------------------------------------------------------
// Secret
// ---------------------------------------------------------------------------

/// Keys the API server requires for built-in Secret types (any one of the
/// alternatives for basic-auth).
fn required_keys(type_: &str) -> Option<(&'static [&'static str], bool)> {
    match type_ {
        "kubernetes.io/tls" => Some((&["tls.crt", "tls.key"], true)),
        "kubernetes.io/dockerconfigjson" => Some((&[".dockerconfigjson"], true)),
        "kubernetes.io/dockercfg" => Some((&[".dockercfg"], true)),
        "kubernetes.io/ssh-auth" => Some((&["ssh-privatekey"], true)),
        "kubernetes.io/basic-auth" => Some((&["username", "password"], false)),
        _ => None,
    }
}

/// Rules for one plain Secret document.
pub fn secret_findings(doc: &Value) -> Vec<Finding> {
    let res = resource_label(doc);
    let mut out = vec![];
    let Value::Object(m) = doc else {
        out.push(Finding::new(Severity::Critical, "secret.malformed", &res, "the document is not a mapping"));
        return out;
    };
    match m.get("apiVersion").and_then(Value::as_str) {
        Some("v1") => {}
        Some(v) => out.push(
            Finding::new(Severity::High, "secret.api-version", &res, format!("apiVersion is {v:?}, not \"v1\""))
                .fix("Secrets are apiVersion: v1"),
        ),
        None => out.push(
            Finding::new(Severity::Medium, "secret.api-version", &res, "apiVersion is missing")
                .fix("Add apiVersion: v1 — kubectl and GitOps tools reject a manifest without it"),
        ),
    }
    identity_findings(doc, &res, &mut out, true);
    for section in ["data", "stringData"] {
        if m.get(section).is_some_and(|v| !v.is_object() && !v.is_null()) {
            out.push(
                Finding::new(Severity::High, "secret.malformed", &res, format!("{section} is not a mapping"))
                    .fix(format!("{section} must map keys to values")),
            );
        }
    }

    let type_ = m.get("type").and_then(Value::as_str).unwrap_or("Opaque");
    if !core::SECRET_TYPES.contains(&type_) {
        out.push(Finding::new(
            Severity::Info,
            "secret.custom-type",
            &res,
            format!("custom type {type_:?}: Kubernetes doesn't check its keys"),
        ));
    }
    let entries = core::secret_entries(doc);
    let keys: BTreeSet<&str> = entries.iter().map(|e| e.key.as_str()).collect();
    if let Some((req, all)) = required_keys(type_) {
        let missing: Vec<&str> = req.iter().copied().filter(|k| !keys.contains(k)).collect();
        if (all && !missing.is_empty()) || (!all && missing.len() == req.len()) {
            let what = if all { missing.join(", ") } else { req.join(" or ") };
            out.push(
                Finding::new(Severity::High, "secret.type-keys", &res, format!("type {type_} needs key(s) {what}"))
                    .fix("Add the missing key(s) or change the type — the API server rejects it otherwise"),
            );
        }
    }
    if type_ == "kubernetes.io/service-account-token"
        && str_at(doc, &["metadata", "annotations", "kubernetes.io/service-account.name"]).is_none()
    {
        out.push(
            Finding::new(
                Severity::High,
                "secret.type-keys",
                &res,
                "type kubernetes.io/service-account-token needs the kubernetes.io/service-account.name annotation",
            )
            .fix("Annotate it with the ServiceAccount's name"),
        );
    }

    let both: Vec<&String> = match (obj_at(doc, &["data"]), obj_at(doc, &["stringData"])) {
        (Some(d), Some(s)) => d.keys().filter(|k| s.contains_key(*k)).collect(),
        _ => vec![],
    };
    for k in both {
        out.push(
            Finding::new(Severity::Low, "secret.duplicate-key", &res, "key is under both data and stringData")
                .key(k)
                .fix("Keep one: Kubernetes silently lets stringData win"),
        );
    }

    let mut total = 0usize;
    for e in &entries {
        if !valid_data_key(&e.key) {
            out.push(
                Finding::new(Severity::High, "secret.key-invalid", &res, "not a valid Secret key")
                    .key(&e.key)
                    .fix("Keys may only hold letters, digits, '-', '_' and '.'"),
            );
        }
        match e.kind {
            EntryKind::Invalid => out.push(
                Finding::new(Severity::High, "secret.invalid-base64", &res, "data value is not valid base64")
                    .key(&e.key)
                    .fix("Plaintext belongs under stringData; binary values need exact '=' padding"),
            ),
            EntryKind::Text => {
                total += e.value.len();
                let multiline = e.value.trim_end_matches(['\n', '\r']).contains('\n') || e.value.contains("-----BEGIN");
                if !multiline && (e.value.ends_with('\n') || e.value.ends_with('\r')) {
                    out.push(
                        Finding::new(
                            Severity::Low,
                            "secret.trailing-newline",
                            &res,
                            "single-line value ends with a newline",
                        )
                        .key(&e.key)
                        .fix("Usually an `echo` without -n: strip it unless the newline is intended"),
                    );
                }
            }
            EntryKind::Binary => total += e.value.len() * 3 / 4,
        }
    }
    if total > MAX_SECRET_BYTES {
        out.push(
            Finding::new(Severity::High, "secret.too-large", &res, format!("values total {total} bytes (limit 1 MiB)"))
                .fix("Split it into several Secrets"),
        );
    }

    for k in [".dockerconfigjson", ".dockercfg"] {
        if let Some(e) = entries.iter().find(|e| e.key == k && e.kind == EntryKind::Text) {
            if serde_json::from_str::<Value>(&e.value).is_err() {
                out.push(
                    Finding::new(Severity::High, "secret.docker-json", &res, "value is not valid JSON")
                        .key(k)
                        .fix("Regenerate it with `kubectl create secret docker-registry --dry-run=client -o yaml`"),
                );
            }
        }
    }
    if type_ == "kubernetes.io/tls" {
        if let Some(e) = entries.iter().find(|e| e.key == "tls.crt" && e.kind == EntryKind::Text) {
            tls_cert_findings(&e.value, &res, &mut out);
        }
    }

    if let Some(ann) = obj_at(doc, &["metadata", "annotations"]) {
        if ann.contains_key(core::LAST_APPLIED) {
            out.push(
                Finding::new(
                    Severity::Medium,
                    "secret.last-applied",
                    &res,
                    "carries kubectl's last-applied snapshot, which embeds an earlier version of its data",
                )
                .key(core::LAST_APPLIED)
                .fix("Drop the annotation before sharing the manifest (kseal strips it when generating)"),
            );
        }
    }
    out
}

fn tls_cert_findings(pem: &str, res: &str, out: &mut Vec<Finding>) {
    let parsed = x509_parser::pem::parse_x509_pem(pem.as_bytes());
    let Ok((_, pem)) = parsed else {
        out.push(
            Finding::new(Severity::Medium, "secret.tls-cert", res, "tls.crt is not a PEM certificate")
                .key("tls.crt")
                .fix("tls.crt must hold the PEM certificate (chain)"),
        );
        return;
    };
    match pem.parse_x509() {
        Err(_) => out.push(
            Finding::new(Severity::Medium, "secret.tls-cert", res, "tls.crt does not parse as X.509")
                .key("tls.crt")
                .fix("tls.crt must hold the PEM certificate (chain)"),
        ),
        Ok(cert) => {
            if cert.validity().not_after.timestamp() < now() {
                out.push(
                    Finding::new(
                        Severity::Medium,
                        "secret.tls-expired",
                        res,
                        format!("tls.crt expired on {}", cert.validity().not_after),
                    )
                    .key("tls.crt")
                    .fix("Renew the certificate before deploying it"),
                );
            }
        }
    }
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

// ---------------------------------------------------------------------------
// SealedSecret (structural only)
// ---------------------------------------------------------------------------

pub const SEALED_API_VERSION: &str = "bitnami.com/v1alpha1";

/// What a structural ciphertext check needs to know about the sealing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyInfo {
    /// RSA modulus size in bytes (= the wrapped session key's length).
    pub rsa_bytes: usize,
}

/// Rules for one SealedSecret. `key` (from the certificate it should have
/// been sealed with) enables the ciphertext-length check.
pub fn sealed_findings(doc: &Value, key: Option<KeyInfo>) -> Vec<Finding> {
    let res = resource_label(doc);
    let mut out = vec![];
    if !doc.is_object() {
        out.push(Finding::new(Severity::Critical, "sealed.malformed", &res, "the document is not a mapping"));
        return out;
    }
    if doc.get("apiVersion").and_then(Value::as_str) != Some(SEALED_API_VERSION) {
        out.push(
            Finding::new(Severity::High, "sealed.api-version", &res, format!("apiVersion is not {SEALED_API_VERSION}"))
                .fix(format!("SealedSecrets are apiVersion: {SEALED_API_VERSION}")),
        );
    }
    let scope = sealed_scope(doc);
    identity_findings(doc, &res, &mut out, true);
    let ns = str_at(doc, &["metadata", "namespace"]).unwrap_or("");
    if scope != Scope::ClusterWide && ns.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "sealed.namespace-missing",
                &res,
                format!("{} scope without metadata.namespace", scope.as_str()),
            )
            .fix("Set the namespace it was sealed for: applied anywhere else, the controller can't decrypt it"),
        );
    }
    let ann = |k: &str| str_at(doc, &["metadata", "annotations", k]);
    if ann(ANN_CLUSTER_WIDE) == Some("true") && ann(ANN_NAMESPACE_WIDE) == Some("true") {
        out.push(
            Finding::new(Severity::High, "sealed.scope-conflict", &res, "both namespace-wide and cluster-wide are set")
                .fix("Keep the annotation of the scope it was sealed with (the controller uses cluster-wide)"),
        );
    }
    if scope == Scope::ClusterWide {
        out.push(
            Finding::new(
                Severity::Low,
                "sealed.cluster-wide",
                &res,
                "cluster-wide scope: anyone who can create a SealedSecret in any namespace can unseal a copy",
            )
            .fix("Prefer strict (or namespace-wide) scope unless it must move between namespaces"),
        );
    }

    for (k, v) in [("name", "name"), ("namespace", "namespace")] {
        let outer = str_at(doc, &["metadata", k]).unwrap_or("");
        if let Some(inner) = str_at(doc, &["spec", "template", "metadata", v]) {
            if !inner.is_empty() && inner != outer {
                out.push(
                    Finding::new(
                        Severity::Medium,
                        "sealed.template-identity",
                        &res,
                        format!("spec.template.metadata.{k} differs from metadata.{k}"),
                    )
                    .fix("The controller uses the SealedSecret's own name/namespace — make them match"),
                );
            }
        }
    }

    // Plaintext exposure.
    for path in [&["metadata", "annotations"][..], &["spec", "template", "metadata", "annotations"][..]] {
        if obj_at(doc, path).is_some_and(|a| a.contains_key(core::LAST_APPLIED)) {
            out.push(
                Finding::new(
                    Severity::Critical,
                    "sealed.last-applied",
                    &res,
                    format!("{} carries kubectl's last-applied snapshot (plaintext data)", path.join(".")),
                )
                .key(core::LAST_APPLIED)
                .fix("Remove the annotation — it can embed the unencrypted Secret"),
            );
        }
    }
    if let Some(data) = obj_at(doc, &["spec", "template", "data"]).filter(|d| !d.is_empty()) {
        for (k, v) in data {
            let templated = v.as_str().is_some_and(|s| s.contains("{{"));
            let f = if templated {
                Finding::new(Severity::Info, "sealed.template-data", &res, "templated value in spec.template.data")
            } else {
                Finding::new(
                    Severity::High,
                    "sealed.template-data",
                    &res,
                    "spec.template.data holds an UNENCRYPTED value — it is committed as-is",
                )
                .fix("Move it into encryptedData (seal it) unless it is genuinely not secret")
            };
            out.push(f.key(k));
        }
    }

    let enc = obj_at(doc, &["spec", "encryptedData"]);
    let legacy = doc.get("spec").and_then(|s| s.get("data")).is_some();
    if enc.is_none_or(Map::is_empty) && !legacy {
        out.push(
            Finding::new(Severity::High, "sealed.empty", &res, "spec.encryptedData is missing or empty")
                .fix("Seal the Secret again: there is nothing to decrypt"),
        );
    }
    if legacy {
        out.push(
            Finding::new(Severity::Low, "sealed.legacy-data", &res, "uses the legacy spec.data format")
                .fix("Reseal with a current kubeseal / kseal to get per-key encryptedData"),
        );
    }
    for (k, v) in enc.into_iter().flatten() {
        if !valid_data_key(k) {
            out.push(
                Finding::new(Severity::High, "sealed.key-invalid", &res, "not a valid Secret key")
                    .key(k)
                    .fix("Keys may only hold letters, digits, '-', '_' and '.'"),
            );
        }
        if let Some(why) = ciphertext_problem(v.as_str().unwrap_or(""), key) {
            out.push(
                Finding::new(Severity::High, "sealed.ciphertext", &res, why)
                    .key(k)
                    .fix("Seal this key again with the controller's current certificate"),
            );
        }
    }
    out.push(Finding::new(
        Severity::Info,
        "sealed.structural-only",
        &res,
        "structural checks only — whether the controller can decrypt it is verified by `kseal validate` / Ctrl+T",
    ));
    out
}

/// Structural check of one `encryptedData` value: `u16 len || rsa_ct ||
/// aes_gcm(ct || tag)`, base64. Not decryption.
fn ciphertext_problem(v: &str, key: Option<KeyInfo>) -> Option<String> {
    let Ok(raw) = core::b64_decode_bytes(v) else {
        return Some("encrypted value is not base64".into());
    };
    if !core::b64_valid_for_k8s(v) {
        return Some("encrypted value is not canonical base64".into());
    }
    if raw.len() < 2 {
        return Some("encrypted value is too short to be sealed".into());
    }
    let n = u16::from_be_bytes([raw[0], raw[1]]) as usize;
    if !(128..=1024).contains(&n) || raw.len() < 2 + n + 16 {
        return Some("encrypted value does not have the sealed-secrets layout (was it sealed?)".into());
    }
    match key {
        Some(k) if k.rsa_bytes != n => Some(format!(
            "sealed with a {}-bit key, but the certificate's key is {}-bit — not sealed with this certificate",
            n * 8,
            k.rsa_bytes * 8
        )),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

/// Facts about a sealing certificate (all public).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub key: KeyInfo,
    pub not_after: String,
    /// SHA-256 of the certificate DER, colon-separated hex.
    pub fingerprint: String,
}

/// Sealing-certificate rules at time `now` (unix seconds). Returns the
/// findings and, when the certificate is usable, its [`CertInfo`].
pub fn cert_findings(pem: &[u8], now: i64) -> (Vec<Finding>, Option<CertInfo>) {
    let res = "sealing certificate";
    let mut out = vec![];
    let fail = |rule, msg: &str, fix: &str| Finding::new(Severity::Critical, rule, res, msg).fix(fix);
    let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(pem) else {
        let f = fail(
            "cert.invalid",
            "not a PEM certificate",
            "Fetch it again with `kseal cert` (or kubeseal --fetch-cert)",
        );
        return (vec![f], None);
    };
    let Ok(cert) = pem.parse_x509() else {
        let f = fail("cert.invalid", "not a valid X.509 certificate", "Fetch it again with `kseal cert`");
        return (vec![f], None);
    };
    let Ok(pk) = RsaPublicKey::from_public_key_der(cert.tbs_certificate.subject_pki.raw) else {
        let f = fail(
            "cert.not-rsa",
            "the certificate does not hold an RSA public key",
            "sealed-secrets seals with RSA: use the controller's certificate",
        );
        return (vec![f], None);
    };
    let v = cert.validity();
    let (nb, na) = (v.not_before.timestamp(), v.not_after.timestamp());
    if now > na {
        out.push(fail(
            "cert.expired",
            &format!("expired on {}", v.not_after),
            "Fetch the controller's current certificate (`kseal cert`) — kseal won't seal with an expired one",
        ));
    } else if now < nb {
        out.push(
            Finding::new(Severity::Medium, "cert.not-yet-valid", res, format!("not valid before {}", v.not_before))
                .fix("Check the clock here and on the controller, or fetch the certificate again"),
        );
    } else if na - now < 30 * 86400 {
        out.push(
            Finding::new(Severity::Low, "cert.expiring", res, format!("expires on {}", v.not_after))
                .fix("Fetch the renewed certificate soon (the controller rotates keys every 30 days by default)"),
        );
    }
    let bits = pk.size() * 8;
    if bits < 2048 {
        out.push(
            Finding::new(Severity::High, "cert.weak-key", res, format!("RSA key is only {bits} bits"))
                .fix("Use a controller key of at least 2048 bits (sealed-secrets defaults to 4096)"),
        );
    }
    let fingerprint =
        Sha256::digest(pem.contents.as_slice()).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
    let info = CertInfo { key: KeyInfo { rsa_bytes: pk.size() }, not_after: v.not_after.to_string(), fingerprint };
    out.push(Finding::new(
        Severity::Info,
        "cert.info",
        res,
        format!("RSA-{bits}, valid until {}, SHA-256 {}", info.not_after, short_fp(&info.fingerprint)),
    ));
    let usable = !out.iter().any(|f| f.severity == Severity::Critical);
    (out, usable.then_some(info))
}

fn short_fp(fp: &str) -> &str {
    &fp[..fp.len().min(23)]
}

// ---------------------------------------------------------------------------
// Whole files (multi-document)
// ---------------------------------------------------------------------------

/// Lint a manifest (multi-document, `kind: List` expanded): every Secret and
/// SealedSecret, plus file-level plaintext exposure.
pub fn file_findings(docs: &[Value], key: Option<KeyInfo>) -> Vec<Finding> {
    let docs = core::flatten_docs(docs);
    let mut out = vec![];
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let has_sealed = docs.iter().any(|d| core::kind_of(d) == Some("SealedSecret"));
    let mut relevant = 0;
    for d in &docs {
        let kind = core::kind_of(d);
        let f = match kind {
            Some("SealedSecret") => sealed_findings(d, key),
            Some("Secret") => {
                let mut f = secret_findings(d);
                if has_sealed {
                    f.push(
                        Finding::new(
                            Severity::Critical,
                            "file.plaintext-secret",
                            &resource_label(d),
                            "a plain Secret sits in the same file as SealedSecrets — its values are only base64",
                        )
                        .fix("Remove the Secret from the file before committing it"),
                    );
                }
                f
            }
            _ => continue,
        };
        relevant += 1;
        let id = resource_label(d);
        if !seen.insert(id.clone()) {
            out.push(
                Finding::new(Severity::Medium, "file.duplicate", &id, "defined more than once in the file")
                    .fix("Keep one definition: the last one applied wins"),
            );
        }
        out.extend(f);
    }
    if relevant == 0 {
        out.push(Finding::new(Severity::High, "file.empty", "file", "no Secret or SealedSecret found"));
    } else if !has_sealed {
        out.push(
            Finding::new(
                Severity::Info,
                "file.plaintext",
                "file",
                "plain Secret manifest: base64 is encoding, not encryption",
            )
            .fix("Don't commit it — seal it (`kseal seal` / `kseal export`) for Git"),
        );
    }
    sort(&mut out);
    out
}

// ---------------------------------------------------------------------------
// Export targets
// ---------------------------------------------------------------------------

/// What a write is about to put on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// A plain Secret (Encode tab save).
    PlainSecret,
    /// A SealedSecret bound to `ns`/`name` under `scope`.
    Sealed { ns: String, name: String, scope: Scope },
}

/// Facts about a write target, gathered by the caller (read-only I/O).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetScan {
    pub path: String,
    pub exists: bool,
    pub is_symlink: bool,
    /// Unix permission bits of the existing file / its directory.
    pub mode: Option<u32>,
    pub parent_exists: bool,
    pub parent_mode: Option<u32>,
    /// The directory is inside a Git working tree.
    pub in_git: bool,
    /// `(file name, contents)` of a kustomization in the target directory.
    pub kustomization: Option<(String, String)>,
    /// `(file name, contents)` of the other YAML files in the directory.
    pub neighbors: Vec<(String, String)>,
}

pub fn target_findings(scan: &TargetScan, payload: &Payload) -> Vec<Finding> {
    let res = scan.path.as_str();
    let mut out = vec![];
    if scan.is_symlink {
        out.push(
            Finding::new(Severity::Critical, "target.symlink", res, "the target is a symbolic link")
                .fix("Write to the real path: kseal refuses to write through a symlink"),
        );
    }
    if !scan.parent_exists {
        out.push(
            Finding::new(Severity::High, "target.no-dir", res, "the directory does not exist")
                .fix("Create the directory first (kseal doesn't create directories)"),
        );
    }
    if let Some(m) = scan.parent_mode {
        if m & 0o002 != 0 && m & 0o1000 == 0 {
            out.push(
                Finding::new(
                    Severity::High,
                    "target.dir-writable",
                    res,
                    format!("the directory is world-writable ({:o}) — others can replace the file", m & 0o7777),
                )
                .fix("Write to a directory only you can write to"),
            );
        } else if m & 0o020 != 0 && *payload == Payload::PlainSecret {
            out.push(
                Finding::new(
                    Severity::Medium,
                    "target.dir-writable",
                    res,
                    format!("the directory is group-writable ({:o})", m & 0o7777),
                )
                .fix("Write plaintext Secrets to a directory only you can write to"),
            );
        }
    }
    if let Some(m) = scan.mode.filter(|m| m & 0o077 != 0) {
        let sev = if *payload == Payload::PlainSecret { Severity::Medium } else { Severity::Info };
        out.push(
            Finding::new(
                sev,
                "target.file-mode",
                res,
                format!("the existing file is readable by others ({:o})", m & 0o777),
            )
            .fix("kseal tightens it to 0600 when it writes"),
        );
    }
    match payload {
        Payload::PlainSecret => {
            if scan.in_git {
                out.push(
                    Finding::new(
                        Severity::High,
                        "target.plaintext-in-git",
                        res,
                        "saving a plain Secret inside a Git working tree",
                    )
                    .fix("Save it outside the repository (or make sure it is gitignored); commit the SealedSecret"),
                );
            }
        }
        Payload::Sealed { ns, name, scope } => {
            let file = core::file_name(&scan.path);
            for (n, text) in &scan.neighbors {
                if *n == file {
                    continue;
                }
                let Ok(docs) = core::parse_yaml_docs(text) else { continue };
                if core::flatten_docs(&docs)
                    .iter()
                    .any(|d| core::kind_of(d) == Some("Secret") && !core::secret_entries(d).is_empty())
                {
                    out.push(
                        Finding::new(
                            Severity::High,
                            "target.plaintext-neighbor",
                            res,
                            format!("{n} in the same directory is a plain Secret with data"),
                        )
                        .fix("Delete it (or move it out of the repository) so it is never committed"),
                    );
                }
            }
            if let Some((kname, text)) = &scan.kustomization {
                kustomize_findings(kname, text, &file, ns, name, *scope, res, &mut out);
            }
        }
    }
    sort(&mut out);
    out
}

#[allow(clippy::too_many_arguments)]
fn kustomize_findings(
    kname: &str,
    text: &str,
    file: &str,
    ns: &str,
    name: &str,
    scope: Scope,
    res: &str,
    out: &mut Vec<Finding>,
) {
    let Ok(docs) = core::parse_yaml_docs(text) else {
        out.push(Finding::new(Severity::Medium, "kustomize.invalid", res, format!("{kname} is not valid YAML")));
        return;
    };
    let Some(k) = docs.first() else { return };
    if let Some(kns) = k.get("namespace").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        if kns != ns {
            let f = match scope {
                Scope::ClusterWide => Finding::new(
                    Severity::Info,
                    "kustomize.namespace",
                    res,
                    format!("{kname} moves it to namespace {kns} (fine for cluster-wide scope)"),
                ),
                _ => Finding::new(
                    Severity::High,
                    "kustomize.namespace",
                    res,
                    format!(
                        "{kname} sets namespace {kns}, but it is sealed for {ns:?} with {} scope — the controller won't decrypt it",
                        scope.as_str()
                    ),
                )
                .fix(format!("Seal it for namespace {kns}, or use cluster-wide scope")),
            };
            out.push(f);
        }
    }
    for field in ["namePrefix", "nameSuffix"] {
        if k.get(field).and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
            let f = if scope == Scope::Strict {
                Finding::new(
                    Severity::High,
                    "kustomize.rename",
                    res,
                    format!("{kname} sets {field}, which renames {name:?} — strict scope binds the name"),
                )
                .fix("Use namespace-wide scope, or exclude the SealedSecret from the prefix/suffix")
            } else {
                Finding::new(Severity::Info, "kustomize.rename", res, format!("{kname} sets {field}"))
            };
            out.push(f);
        }
    }
    let listed = k
        .get("resources")
        .and_then(Value::as_array)
        .is_some_and(|r| r.iter().filter_map(Value::as_str).any(|s| s.trim_start_matches("./") == file));
    if !listed {
        out.push(
            Finding::new(
                Severity::Low,
                "kustomize.not-listed",
                res,
                format!("{file} is not listed under resources in {kname} — it won't be applied"),
            )
            .fix(format!("Add `- {file}` to resources in {kname}")),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DUMMY: &str = "dummy-hunter2";

    fn rules(f: &[Finding]) -> Vec<&'static str> {
        f.iter().map(|f| f.rule).collect()
    }
    fn secret(extra: Value) -> Value {
        let mut d = json!({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "db", "namespace": "prod"},
            "type": "Opaque", "stringData": {"PASSWORD": DUMMY}});
        if let (Value::Object(d), Value::Object(e)) = (&mut d, extra) {
            d.extend(e);
        }
        d
    }
    fn no_values(f: &[Finding]) {
        for f in f {
            let all = format!("{} {} {} {:?}", f.resource, f.message, f.remediation, f.key);
            assert!(!all.contains(DUMMY) && !all.contains(&core::b64_encode(DUMMY)), "value leaked: {all}");
        }
    }

    #[test]
    fn clean_secret_has_no_findings() {
        assert!(secret_findings(&secret(json!({}))).is_empty());
    }

    #[test]
    fn names_and_keys_follow_kubernetes_rules() {
        assert!(valid_name("db.prod-1") && !valid_name("DB") && !valid_name("-a") && !valid_name(&"a".repeat(254)));
        assert!(valid_namespace("kube-system") && !valid_namespace("a.b") && !valid_namespace(&"a".repeat(64)));
        assert!(valid_data_key(".dockerconfigjson") && valid_data_key("tls.crt") && valid_data_key("A_B-c"));
        assert!(!valid_data_key("a b") && !valid_data_key("..x") && !valid_data_key(".") && !valid_data_key("a/b"));
        let d = secret(json!({"metadata": {"name": "Bad_Name", "namespace": "Prod"}, "stringData": {"a b": "x"}}));
        let f = secret_findings(&d);
        assert_eq!(rules(&f), vec!["meta.name-invalid", "meta.namespace-invalid", "secret.key-invalid"]);
        assert!(f.iter().all(|f| f.severity == Severity::High));
    }

    #[test]
    fn malformed_and_wrong_api_version() {
        assert_eq!(rules(&secret_findings(&json!("text"))), vec!["secret.malformed"]);
        let f = secret_findings(&secret(json!({"apiVersion": "v2", "data": "oops"})));
        assert!(rules(&f).contains(&"secret.api-version") && rules(&f).contains(&"secret.malformed"));
        let mut d = secret(json!({}));
        d.as_object_mut().unwrap().remove("apiVersion");
        d["metadata"].as_object_mut().unwrap().remove("name");
        let f = secret_findings(&d);
        assert_eq!(rules(&f), vec!["secret.api-version", "meta.name-missing"]);
    }

    #[test]
    fn base64_and_type_requirements() {
        let d = secret(json!({"data": {"P": DUMMY}, "stringData": null}));
        let f = secret_findings(&d);
        assert_eq!(rules(&f), vec!["secret.invalid-base64"]);
        assert_eq!(f[0].key.as_deref(), Some("P"));
        no_values(&f);
        let tls = secret(json!({"type": "kubernetes.io/tls", "stringData": {"tls.crt": "x"}}));
        let f = secret_findings(&tls);
        assert!(f.iter().any(|f| f.rule == "secret.type-keys" && f.message.contains("tls.key")));
        assert!(f.iter().any(|f| f.rule == "secret.tls-cert"));
        let basic = secret(json!({"type": "kubernetes.io/basic-auth", "stringData": {"username": "u"}}));
        assert!(secret_findings(&basic).is_empty(), "basic-auth needs username OR password");
        let docker =
            secret(json!({"type": "kubernetes.io/dockerconfigjson", "stringData": {".dockerconfigjson": "{"}}));
        assert_eq!(rules(&secret_findings(&docker)), vec!["secret.docker-json"]);
        let custom = secret(json!({"type": "example.com/thing"}));
        assert_eq!(secret_findings(&custom)[0].severity, Severity::Info);
        let sa = secret(json!({"type": "kubernetes.io/service-account-token"}));
        assert_eq!(rules(&secret_findings(&sa)), vec!["secret.type-keys"]);
    }

    #[test]
    fn unsafe_patterns_without_false_positives() {
        let d = secret(
            json!({"stringData": {"P": format!("{DUMMY}\n"), "PEM": "-----BEGIN X-----\nabc\n-----END X-----\n",
            "JSON": "{\n \"a\": 1\n}\n"}}),
        );
        let f = secret_findings(&d);
        assert_eq!(rules(&f), vec!["secret.trailing-newline"], "multi-line and PEM values are fine");
        no_values(&f);
        let d = secret(json!({"data": {"P": core::b64_encode("a")}, "stringData": {"P": "b"},
            "metadata": {"name": "db", "namespace": "prod", "annotations": {core::LAST_APPLIED: format!("{{\"stringData\":{{\"P\":\"{DUMMY}\"}}}}")}}}));
        let f = secret_findings(&d);
        assert_eq!(rules(&f), vec!["secret.duplicate-key", "secret.last-applied"]);
        no_values(&f);
    }

    fn sealed(scope: Scope) -> Value {
        let key = crate::seal::tests::test_key().to_public_key();
        crate::seal::seal_secret(&secret(json!({})), &key, scope).unwrap()
    }

    #[test]
    fn sealed_structural_checks() {
        let s = sealed(Scope::Strict);
        let f = sealed_findings(&s, Some(KeyInfo { rsa_bytes: 256 }));
        assert_eq!(rules(&f), vec!["sealed.structural-only"]);
        assert_eq!(f[0].severity, Severity::Info);
        // A 4096-bit certificate can't be what this was sealed with.
        let f = sealed_findings(&s, Some(KeyInfo { rsa_bytes: 512 }));
        assert!(f.iter().any(|f| f.rule == "sealed.ciphertext" && f.message.contains("2048-bit key")));

        let mut bad = s.clone();
        bad["spec"]["encryptedData"]["PASSWORD"] = json!(core::b64_encode(DUMMY));
        bad["spec"]["encryptedData"]["x y"] = json!("!!");
        bad["apiVersion"] = json!("v1");
        let f = sealed_findings(&bad, None);
        let r = rules(&f);
        assert!(r.contains(&"sealed.api-version") && r.contains(&"sealed.key-invalid"));
        assert_eq!(f.iter().filter(|f| f.rule == "sealed.ciphertext").count(), 2);
        no_values(&f);
    }

    #[test]
    fn sealed_scope_and_exposure() {
        let cw = sealed(Scope::ClusterWide);
        assert_eq!(sealed_scope(&cw), Scope::ClusterWide);
        assert!(rules(&sealed_findings(&cw, None)).contains(&"sealed.cluster-wide"));
        assert_eq!(sealed_scope(&sealed(Scope::NamespaceWide)), Scope::NamespaceWide);

        let mut s = sealed(Scope::Strict);
        s["metadata"]["annotations"] = json!({ANN_CLUSTER_WIDE: "true", ANN_NAMESPACE_WIDE: "true"});
        s["spec"]["template"]["metadata"]["annotations"] = json!({core::LAST_APPLIED: DUMMY});
        s["spec"]["template"]["data"] = json!({"plain": DUMMY, "tpl": "{{ index . \"PASSWORD\" }}"});
        s["spec"]["template"]["metadata"]["namespace"] = json!("other");
        let f = sealed_findings(&s, None);
        no_values(&f);
        let crit: Vec<_> = f.iter().filter(|f| f.severity == Severity::Critical).map(|f| f.rule).collect();
        assert_eq!(crit, vec!["sealed.last-applied"]);
        assert!(f.iter().any(|f| f.rule == "sealed.scope-conflict"));
        assert!(f.iter().any(|f| f.rule == "sealed.template-identity"));
        let td: Vec<_> = f.iter().filter(|f| f.rule == "sealed.template-data").map(|f| f.severity).collect();
        assert_eq!(td, vec![Severity::High, Severity::Info]);

        let mut nons = sealed(Scope::Strict);
        nons["metadata"].as_object_mut().unwrap().remove("namespace");
        nons["spec"]["encryptedData"] = json!({});
        let r = rules(&sealed_findings(&nons, None));
        assert!(r.contains(&"sealed.namespace-missing") && r.contains(&"sealed.empty"));
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }
    fn validity(pem: &[u8]) -> (i64, i64) {
        let (_, p) = x509_parser::pem::parse_x509_pem(pem).unwrap();
        let c = p.parse_x509().unwrap();
        (c.validity().not_before.timestamp(), c.validity().not_after.timestamp())
    }

    #[test]
    fn certificate_validity_periods() {
        let pem = fixture("rsa2048-1day.pem");
        let (nb, na) = validity(&pem);
        let (f, info) = cert_findings(&pem, nb + 60);
        assert_eq!(rules(&f), vec!["cert.expiring", "cert.info"], "a 1-day cert is close to expiry");
        let info = info.unwrap();
        assert_eq!(info.key.rsa_bytes, 256);
        assert_eq!(info.fingerprint.len(), 32 * 3 - 1);
        let (f, info) = cert_findings(&pem, na + 1);
        assert_eq!(f[0].rule, "cert.expired");
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(info.is_none(), "an expired certificate is not usable");
        let (f, info) = cert_findings(&pem, nb - 3600);
        assert_eq!(f[0].rule, "cert.not-yet-valid");
        assert!(info.is_some());
    }

    #[test]
    fn certificate_key_checks() {
        let (nb, _) = validity(&fixture("rsa1024.pem"));
        let (f, _) = cert_findings(&fixture("rsa1024.pem"), nb + 60);
        assert_eq!(rules(&f), vec!["cert.weak-key", "cert.info"]);
        let (f, info) = cert_findings(&fixture("ec-p256.pem"), nb + 60);
        assert_eq!((rules(&f), info), (vec!["cert.not-rsa"], None));
        let (f, _) = cert_findings(b"not a cert", 0);
        assert_eq!(rules(&f), vec!["cert.invalid"]);
        let pem = String::from_utf8(fixture("rsa2048-1day.pem")).unwrap().replace("MII", "MIX");
        assert_eq!(rules(&cert_findings(pem.as_bytes(), 0).0), vec!["cert.invalid"]);
    }

    #[test]
    fn file_level_exposure_duplicates_and_order() {
        let s = sealed(Scope::Strict);
        let docs = vec![s.clone(), secret(json!({})), s.clone()];
        let f = file_findings(&docs, None);
        assert_eq!(f[0].rule, "file.plaintext-secret");
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f.iter().any(|f| f.rule == "file.duplicate"));
        assert!(f.windows(2).all(|w| w[0].severity <= w[1].severity), "most severe first");
        assert_eq!(file_findings(&docs, None), f, "deterministic");
        no_values(&f);
        assert_eq!(rules(&file_findings(&[json!({"kind": "ConfigMap"})], None)), vec!["file.empty"]);
        let f = file_findings(&[json!({"kind": "List", "items": [secret(json!({}))]})], None);
        assert_eq!(rules(&f), vec!["file.plaintext"]);
        assert_eq!(summary(&f), "1 info");
        assert_eq!(summary(&[]), "no issues");
    }

    fn sealed_payload(scope: Scope) -> Payload {
        Payload::Sealed { ns: "prod".into(), name: "db".into(), scope }
    }

    #[test]
    fn target_permissions_and_symlinks() {
        let scan = TargetScan {
            path: "/repo/db.yaml".into(),
            exists: true,
            is_symlink: true,
            mode: Some(0o644),
            parent_exists: true,
            parent_mode: Some(0o777),
            ..Default::default()
        };
        let f = target_findings(&scan, &Payload::PlainSecret);
        assert_eq!(rules(&f), vec!["target.symlink", "target.dir-writable", "target.file-mode"]);
        assert_eq!(f[2].severity, Severity::Medium);
        // /tmp-style sticky directories are fine; group-writable only matters for plaintext.
        let scan = TargetScan { parent_mode: Some(0o1777), is_symlink: false, ..scan };
        assert_eq!(rules(&target_findings(&scan, &sealed_payload(Scope::Strict))), vec!["target.file-mode"]);
        let scan = TargetScan { parent_mode: Some(0o775), mode: None, in_git: true, ..scan };
        let f = target_findings(&scan, &Payload::PlainSecret);
        assert_eq!(rules(&f), vec!["target.plaintext-in-git", "target.dir-writable"]);
        assert!(target_findings(&scan, &sealed_payload(Scope::Strict)).is_empty());
        let none = TargetScan { path: "x/y.yaml".into(), parent_exists: false, ..Default::default() };
        assert_eq!(rules(&target_findings(&none, &Payload::PlainSecret)), vec!["target.no-dir"]);
    }

    #[test]
    fn target_kustomize_and_plaintext_neighbours() {
        let k = |text: &str| TargetScan {
            path: "base/db.yaml".into(),
            parent_exists: true,
            kustomization: Some(("kustomization.yaml".into(), text.into())),
            neighbors: vec![
                ("db.yaml".into(), "kind: Secret\nstringData: {a: b}\n".into()),
                ("plain.yaml".into(), format!("kind: Secret\nstringData: {{P: {DUMMY}}}\n")),
                ("cm.yaml".into(), "kind: ConfigMap\ndata: {a: b}\n".into()),
            ],
            ..Default::default()
        };
        let ok = k("resources:\n  - ./db.yaml\n");
        let f = target_findings(&ok, &sealed_payload(Scope::Strict));
        assert_eq!(rules(&f), vec!["target.plaintext-neighbor"], "the target itself is not its own neighbour");
        assert!(f[0].message.starts_with("plain.yaml"));
        no_values(&f);

        let moved = k("namespace: staging\nnamePrefix: dev-\nresources: [other.yaml]\n");
        let f = target_findings(&TargetScan { neighbors: vec![], ..moved.clone() }, &sealed_payload(Scope::Strict));
        assert_eq!(rules(&f), vec!["kustomize.namespace", "kustomize.rename", "kustomize.not-listed"]);
        assert_eq!(f[0].severity, Severity::High);
        let f = target_findings(&TargetScan { neighbors: vec![], ..moved }, &sealed_payload(Scope::ClusterWide));
        assert_eq!(
            f.iter().map(|f| f.severity).collect::<Vec<_>>(),
            vec![Severity::Low, Severity::Info, Severity::Info]
        );
        let bad = TargetScan { neighbors: vec![], ..k("{{{") };
        assert_eq!(rules(&target_findings(&bad, &sealed_payload(Scope::Strict))), vec!["kustomize.invalid"]);
    }
}
