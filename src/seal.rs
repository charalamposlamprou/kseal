//! Native, kubeseal-compatible sealing — no `kubeseal` binary required.
//!
//! Mirrors sealed-secrets' `pkg/crypto.HybridEncrypt`: per value, a fresh
//! 32-byte AES-256-GCM session key encrypts the plaintext (zero nonce — safe
//! because every key is used exactly once), and the session key is wrapped
//! with RSA-OAEP(SHA-256) under the controller's public key, using the
//! scope-derived label. Wire format (then base64):
//!
//! ```text
//! u16 BE len(rsa_ct) || rsa_ct || aes_gcm(ct || tag)
//! ```

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result, anyhow, bail};
use rand::RngCore;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use serde_json::{Map, Value, json};
use sha2::Sha256;

use crate::core::{self, EntryKind};

pub const ANN_NAMESPACE_WIDE: &str = "sealedsecrets.bitnami.com/namespace-wide";
pub const ANN_CLUSTER_WIDE: &str = "sealedsecrets.bitnami.com/cluster-wide";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Scope {
    /// Bound to this exact name + namespace.
    #[default]
    Strict,
    /// Can be renamed within its namespace.
    NamespaceWide,
    /// Can be renamed and moved to any namespace.
    ClusterWide,
}

impl Scope {
    pub const ALL: [Scope; 3] = [Scope::Strict, Scope::NamespaceWide, Scope::ClusterWide];

    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Strict => "strict",
            Scope::NamespaceWide => "namespace-wide",
            Scope::ClusterWide => "cluster-wide",
        }
    }

    /// The RSA-OAEP label (sealed-secrets `EncryptionLabel`).
    pub fn label(self, namespace: &str, name: &str) -> Vec<u8> {
        match self {
            Scope::Strict => format!("{namespace}/{name}").into_bytes(),
            Scope::NamespaceWide => namespace.as_bytes().to_vec(),
            Scope::ClusterWide => Vec::new(),
        }
    }
}

/// Parse the controller's PEM certificate (from `/v1/cert.pem` or `--cert`).
pub fn parse_cert_pem(pem: &[u8]) -> Result<RsaPublicKey> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem).map_err(|e| anyhow!("not a PEM certificate: {e}"))?;
    let cert = pem.parse_x509().map_err(|e| anyhow!("invalid X.509 certificate: {e}"))?;
    let not_after = cert.validity().not_after.to_datetime();
    if not_after < x509_parser::time::ASN1Time::now().to_datetime() {
        bail!("sealing certificate expired at {not_after}");
    }
    RsaPublicKey::from_public_key_der(cert.tbs_certificate.subject_pki.raw)
        .context("certificate does not hold an RSA public key")
}

/// sealed-secrets `HybridEncrypt`.
pub fn hybrid_encrypt(pubkey: &RsaPublicKey, plaintext: &[u8], label: &[u8]) -> Result<Vec<u8>> {
    let mut rng = rand::rngs::OsRng;
    let mut session_key = [0u8; 32];
    rng.fill_bytes(&mut session_key);

    let padding = Oaep::new_with_label::<Sha256, _>(String::from_utf8_lossy(label).into_owned());
    // Labels are always UTF-8 (namespace/name), so the lossy conversion above
    // is exact; assert it so a future change can't silently alter the label.
    debug_assert_eq!(String::from_utf8_lossy(label).as_bytes(), label);
    let rsa_ct = pubkey.encrypt(&mut rng, padding, &session_key).context("RSA-OAEP encryption failed")?;

    let aead = Aes256Gcm::new_from_slice(&session_key).expect("32-byte key");
    let aes_ct = aead
        .encrypt(Nonce::from_slice(&[0u8; 12]), plaintext)
        .map_err(|_| anyhow!("AES-GCM encryption failed"))?;

    let len = u16::try_from(rsa_ct.len()).context("RSA ciphertext too long")?;
    let mut out = Vec::with_capacity(2 + rsa_ct.len() + aes_ct.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&rsa_ct);
    out.extend_from_slice(&aes_ct);
    Ok(out)
}

/// The Secret fields sealing needs, extracted from a Secret doc.
struct SecretParts<'a> {
    name: String,
    namespace: String,
    type_: String,
    data: Vec<(String, Vec<u8>)>,
    meta: Option<&'a Map<String, Value>>,
    immutable: bool,
}

fn secret_parts(doc: &Value) -> Result<SecretParts<'_>> {
    let entries = core::secret_entries(doc);
    if let Some(k) = core::first_invalid_key(&entries) {
        bail!("key {k:?} under `data` is not valid base64 — put plaintext under `stringData` instead");
    }
    let mut data = Vec::with_capacity(entries.len());
    for e in entries {
        let bytes = match e.kind {
            EntryKind::Text => e.value.into_bytes(),
            EntryKind::Binary => core::b64_decode_bytes(&e.value)?,
            EntryKind::Invalid => unreachable!("checked above"),
        };
        data.push((e.key, bytes));
    }
    let (name, namespace, type_) = core::secret_identity(doc);
    Ok(SecretParts {
        name,
        namespace,
        type_,
        data,
        meta: doc.get("metadata").and_then(Value::as_object),
        immutable: doc.get("immutable") == Some(&Value::Bool(true)),
    })
}

/// Seal a Secret doc into a SealedSecret (as a JSON value, ready to be
/// rendered as YAML or POSTed to the controller's /v1/verify).
pub fn seal_secret(doc: &Value, pubkey: &RsaPublicKey, scope: Scope) -> Result<Value> {
    let s = secret_parts(doc)?;
    if scope != Scope::ClusterWide && s.namespace.is_empty() {
        bail!("{} scope needs metadata.namespace", scope.as_str());
    }
    if scope == Scope::Strict && s.name.is_empty() {
        bail!("strict scope needs metadata.name");
    }
    let label = scope.label(&s.namespace, &s.name);

    let mut encrypted = Map::new();
    for (k, v) in &s.data {
        let ct = hybrid_encrypt(pubkey, v, &label)?;
        encrypted.insert(k.clone(), Value::String(core::b64_encode(ct)));
    }

    // Template metadata: the Secret's own labels/annotations (minus kubectl's
    // last-applied snapshot), exactly what the controller will recreate.
    let mut tmeta = Map::new();
    let mut outer_ann = Map::new();
    match scope {
        Scope::NamespaceWide => {
            outer_ann.insert(ANN_NAMESPACE_WIDE.into(), json!("true"));
        }
        Scope::ClusterWide => {
            outer_ann.insert(ANN_CLUSTER_WIDE.into(), json!("true"));
        }
        Scope::Strict => {}
    }
    if let Some(meta) = s.meta {
        if let Some(Value::Object(ann)) = meta.get("annotations") {
            let mut ann = ann.clone();
            ann.remove(core::LAST_APPLIED);
            ann.extend(outer_ann.clone());
            if !ann.is_empty() {
                tmeta.insert("annotations".into(), Value::Object(ann));
            }
        } else if !outer_ann.is_empty() {
            tmeta.insert("annotations".into(), Value::Object(outer_ann.clone()));
        }
        if let Some(Value::Object(l)) = meta.get("labels") {
            tmeta.insert("labels".into(), Value::Object(l.clone()));
        }
    } else if !outer_ann.is_empty() {
        tmeta.insert("annotations".into(), Value::Object(outer_ann.clone()));
    }
    let mut ident = Map::new();
    if !s.name.is_empty() {
        ident.insert("name".into(), json!(s.name));
    }
    if !s.namespace.is_empty() {
        ident.insert("namespace".into(), json!(s.namespace));
    }
    tmeta.extend(ident.clone());

    let mut template = Map::new();
    template.insert("metadata".into(), Value::Object(tmeta));
    template.insert("type".into(), json!(s.type_));
    if s.immutable {
        template.insert("immutable".into(), json!(true));
    }

    let mut meta = Map::new();
    if !outer_ann.is_empty() {
        meta.insert("annotations".into(), Value::Object(outer_ann));
    }
    meta.extend(ident);

    Ok(json!({
        "apiVersion": "bitnami.com/v1alpha1",
        "kind": "SealedSecret",
        "metadata": meta,
        "spec": { "encryptedData": encrypted, "template": template },
    }))
}

/// Seal the Secret found in a YAML manifest, returning SealedSecret YAML.
pub fn seal_yaml(secret_yaml: &str, pubkey: &RsaPublicKey, scope: Scope) -> Result<(String, Value)> {
    let docs = core::parse_yaml_docs(secret_yaml)?;
    if core::has_sealed_secret(&docs) && core::select_secret_doc(&docs).is_none() {
        bail!("input is already a SealedSecret");
    }
    let doc = core::select_secret_doc(&docs).ok_or_else(|| anyhow!("no Secret found in input"))?;
    let sealed = seal_secret(doc, pubkey, scope)?;
    Ok((to_yaml(&sealed), sealed))
}

/// Minimal YAML emitter for the JSON shapes we produce (maps, strings, bools,
/// numbers). Strings go through [`core::yaml_scalar`], so quoting is safe.
pub fn to_yaml(v: &Value) -> String {
    fn emit(v: &Value, indent: usize, out: &mut String) {
        let pad = "  ".repeat(indent);
        match v {
            Value::Object(m) => {
                for (k, val) in m {
                    out.push_str(&pad);
                    out.push_str(&core::yaml_scalar(k));
                    out.push(':');
                    match val {
                        Value::Object(inner) if !inner.is_empty() => {
                            out.push('\n');
                            emit(val, indent + 1, out);
                        }
                        Value::Object(_) => out.push_str(" {}\n"),
                        _ => {
                            out.push(' ');
                            out.push_str(&scalar(val));
                            out.push('\n');
                        }
                    }
                }
            }
            other => {
                out.push_str(&pad);
                out.push_str(&scalar(other));
                out.push('\n');
            }
        }
    }
    fn scalar(v: &Value) -> String {
        match v {
            Value::String(s) => core::yaml_scalar(s),
            Value::Null => "null".into(),
            Value::Array(a) if a.is_empty() => "[]".into(),
            other => other.to_string(), // bools/numbers; arrays render as JSON flow (valid YAML)
        }
    }
    let mut out = String::from("---\n");
    emit(v, 0, &mut out);
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rsa::RsaPrivateKey;

    /// sealed-secrets `HybridDecrypt`, for round-trip tests.
    pub fn hybrid_decrypt(key: &RsaPrivateKey, ct: &[u8], label: &[u8]) -> Result<Vec<u8>> {
        let n = u16::from_be_bytes([ct[0], ct[1]]) as usize;
        let (rsa_ct, aes_ct) = ct[2..].split_at(n);
        let padding = Oaep::new_with_label::<Sha256, _>(String::from_utf8(label.to_vec())?);
        let session = key.decrypt(padding, rsa_ct)?;
        Aes256Gcm::new_from_slice(&session)?
            .decrypt(Nonce::from_slice(&[0u8; 12]), aes_ct)
            .map_err(|_| anyhow!("aes-gcm: authentication failed"))
    }

    pub fn test_key() -> RsaPrivateKey {
        use std::sync::OnceLock;
        static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap()).clone()
    }

    #[test]
    fn labels_match_sealed_secrets() {
        assert_eq!(Scope::Strict.label("ns", "n"), b"ns/n");
        assert_eq!(Scope::NamespaceWide.label("ns", "n"), b"ns");
        assert_eq!(Scope::ClusterWide.label("ns", "n"), b"");
    }

    #[test]
    fn hybrid_round_trip_and_label_binding() {
        let key = test_key();
        let ct = hybrid_encrypt(&key.to_public_key(), b"s3cr3t \xff", b"prod/db").unwrap();
        assert_eq!(u16::from_be_bytes([ct[0], ct[1]]), 256); // 2048-bit key
        assert_eq!(hybrid_decrypt(&key, &ct, b"prod/db").unwrap(), b"s3cr3t \xff");
        // A different name/namespace (= label) must fail to decrypt.
        assert!(hybrid_decrypt(&key, &ct, b"prod/other").is_err());
    }

    #[test]
    fn seal_yaml_end_to_end() {
        let key = test_key();
        let bin = core::b64_encode(b"\xff\xfe\x00");
        let secret = format!(
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\n  namespace: prod\n  labels:\n    app: web\n  annotations:\n    {}: '{{}}'\n    team: sre\nimmutable: true\ntype: Opaque\ndata:\n  PASS: {}\n  BIN: {bin}\nstringData:\n  USER: alice\n",
            core::LAST_APPLIED,
            core::b64_encode("hunter2")
        );
        for scope in Scope::ALL {
            let (yaml, _) = seal_yaml(&secret, &key.to_public_key(), scope).unwrap();
            let doc = core::parse_yaml_docs(&yaml).unwrap().remove(0);
            assert_eq!(doc["kind"], "SealedSecret");
            let enc = &doc["spec"]["encryptedData"];
            let label = scope.label("prod", "db");
            let dec = |k: &str| hybrid_decrypt(&key, &core::b64_decode_bytes(enc[k].as_str().unwrap()).unwrap(), &label).unwrap();
            assert_eq!(dec("PASS"), b"hunter2");
            assert_eq!(dec("BIN"), b"\xff\xfe\x00");
            assert_eq!(dec("USER"), b"alice");
            let t = &doc["spec"]["template"];
            assert_eq!(t["metadata"]["labels"]["app"], "web");
            assert_eq!(t["metadata"]["annotations"]["team"], "sre");
            assert!(t["metadata"]["annotations"].get(core::LAST_APPLIED).is_none());
            assert_eq!(t["immutable"], true);
            assert_eq!(t["type"], "Opaque");
            let ann = &doc["metadata"]["annotations"];
            match scope {
                Scope::Strict => assert!(ann.is_null()),
                Scope::NamespaceWide => assert_eq!(ann[ANN_NAMESPACE_WIDE], "true"),
                Scope::ClusterWide => assert_eq!(ann[ANN_CLUSTER_WIDE], "true"),
            }
        }
    }

    #[test]
    fn seal_rejects_invalid_and_missing_identity() {
        let pk = test_key().to_public_key();
        let bad = "kind: Secret\nmetadata: {name: a, namespace: b}\ndata:\n  P: hunter2\n";
        assert!(seal_yaml(bad, &pk, Scope::Strict).unwrap_err().to_string().contains("stringData"));
        let no_ns = "kind: Secret\nmetadata: {name: a}\nstringData: {P: x}\n";
        assert!(seal_yaml(no_ns, &pk, Scope::Strict).is_err());
        assert!(seal_yaml(no_ns, &pk, Scope::ClusterWide).is_ok());
        let sealed = "kind: SealedSecret\nspec: {}\n";
        assert!(seal_yaml(sealed, &pk, Scope::Strict).unwrap_err().to_string().contains("already"));
    }

    /// Cross-check against Go's crypto/rsa + crypto/cipher — the exact
    /// primitives sealed-secrets uses. Runs when `go` is on PATH.
    #[test]
    fn interop_with_go_hybrid_decrypt() {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        if std::process::Command::new("go").arg("version").output().is_err() {
            eprintln!("skipping: go not installed");
            return;
        }
        let key = test_key();
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.pem");
        std::fs::write(&key_path, key.to_pkcs1_pem(Default::default()).unwrap().as_bytes()).unwrap();
        let ct = core::b64_encode(hybrid_encrypt(&key.to_public_key(), b"from-rust \xf0\x9f\x94\x90", b"prod/db").unwrap());
        let prog = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/interop/hybrid_decrypt.go");
        let out = std::process::Command::new("go")
            .args(["run", prog, key_path.to_str().unwrap(), "prod/db", &ct])
            .env("GOFLAGS", "-mod=mod")
            .output()
            .unwrap();
        assert!(out.status.success(), "go: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(out.stdout, "from-rust 🔐".as_bytes());
    }
}
