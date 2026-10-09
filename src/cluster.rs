//! Read-only cluster access via kube-rs.
//!
//! INVARIANT: kseal never creates, patches, replaces or deletes cluster
//! objects. It only reads (contexts, namespaces, secrets, services) and talks
//! to the sealed-secrets controller's HTTP endpoints through the API-server
//! service proxy (`/v1/cert.pem`, and `/v1/verify`, which creates nothing).
//! `clippy.toml` bans the mutating `kube::Api` methods to enforce this.

use anyhow::{Context, Result, anyhow};
use k8s_openapi::api::core::v1::{Namespace, Secret, Service};
use kube::api::ListParams;
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Api, Client, Config};
use serde_json::Value;

/// Canonical controller service name (Helm chart / upstream manifests).
pub const DEFAULT_CONTROLLER: &str = "sealed-secrets-controller";

#[derive(Debug, Clone, Default)]
pub struct Contexts {
    pub names: Vec<String>,
    pub current: Option<String>,
}

/// Contexts from the merged kubeconfig (`$KUBECONFIG` or `~/.kube/config`).
pub fn list_contexts() -> Result<Contexts> {
    let kc = Kubeconfig::read().context("reading kubeconfig")?;
    let mut names: Vec<String> = kc.contexts.iter().map(|c| c.name.clone()).collect();
    names.sort();
    Ok(Contexts { names, current: kc.current_context })
}

/// A client for `context` (or the current context when `None`), plus that
/// context's default namespace.
pub async fn client_for(context: Option<&str>) -> Result<(Client, String)> {
    let opts = KubeConfigOptions { context: context.map(str::to_owned), ..Default::default() };
    let cfg = Config::from_kubeconfig(&opts)
        .await
        .with_context(|| format!("loading kubeconfig context {}", context.unwrap_or("(current)")))?;
    let ns = cfg.default_namespace.clone();
    Ok((Client::try_from(cfg)?, ns))
}

pub async fn list_namespaces(client: &Client) -> Result<Vec<String>> {
    let api: Api<Namespace> = Api::all(client.clone());
    let mut names: Vec<String> =
        api.list_metadata(&ListParams::default()).await?.items.into_iter().filter_map(|n| n.metadata.name).collect();
    names.sort();
    Ok(names)
}

pub async fn list_secrets(client: &Client, ns: &str) -> Result<Vec<String>> {
    let api: Api<Secret> = Api::namespaced(client.clone(), ns);
    // Metadata-only list: the values never leave the cluster just to fill a picker.
    let mut names: Vec<String> =
        api.list_metadata(&ListParams::default()).await?.items.into_iter().filter_map(|s| s.metadata.name).collect();
    names.sort();
    Ok(names)
}

/// One Secret as a JSON doc (`data` base64, as `kubectl get -o yaml` shows it).
pub async fn get_secret(client: &Client, ns: &str, name: &str) -> Result<Value> {
    let api: Api<Secret> = Api::namespaced(client.clone(), ns);
    let mut secret = api.get(name).await.with_context(|| format!("getting secret {ns}/{name}"))?;
    secret.metadata.managed_fields = None;
    let mut v = serde_json::to_value(&secret)?;
    if let Value::Object(m) = &mut v {
        m.insert("apiVersion".into(), "v1".into());
        m.insert("kind".into(), "Secret".into());
    }
    Ok(v)
}

/// Find the sealed-secrets controller service: `(namespace, name)`.
///
/// Lists services cluster-wide (preferring the canonical name); if that's
/// forbidden by RBAC, probes the two conventional install locations.
pub async fn detect_controller(client: &Client) -> Result<Option<(String, String)>> {
    let api: Api<Service> = Api::all(client.clone());
    match api.list_metadata(&ListParams::default()).await {
        Ok(list) => {
            let svcs: Vec<(String, String)> = list
                .items
                .into_iter()
                .filter_map(|s| Some((s.metadata.namespace?, s.metadata.name?)))
                .filter(|(_, n)| n.contains("sealed-secrets") && !n.contains("metrics"))
                .collect();
            Ok(svcs.iter().find(|(_, n)| n == DEFAULT_CONTROLLER).or(svcs.first()).cloned())
        }
        Err(kube::Error::Api(e)) if e.code == 403 => {
            for ns in ["kube-system", "sealed-secrets"] {
                let api: Api<Service> = Api::namespaced(client.clone(), ns);
                if api.get_metadata_opt(DEFAULT_CONTROLLER).await?.is_some() {
                    return Ok(Some((ns.into(), DEFAULT_CONTROLLER.into())));
                }
            }
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

fn proxy_path(ns: &str, svc: &str, suffix: &str) -> String {
    // `http:<name>:` = scheme http, first port — what kubeseal uses.
    format!("/api/v1/namespaces/{ns}/services/http:{svc}:/proxy{suffix}")
}

/// The controller's current sealing certificate (PEM).
pub async fn fetch_cert(client: &Client, ns: &str, svc: &str) -> Result<Vec<u8>> {
    let req = http::Request::get(proxy_path(ns, svc, "/v1/cert.pem")).body(Vec::new())?;
    let pem = client
        .request_text(req)
        .await
        .with_context(|| format!("fetching sealing cert from {ns}/{svc} (is the controller running?)"))?;
    Ok(pem.into_bytes())
}

/// Ask the controller whether it can decrypt `sealed`. Creates nothing.
pub async fn verify(client: &Client, ns: &str, svc: &str, sealed: &Value) -> Result<bool> {
    let req = http::Request::post(proxy_path(ns, svc, "/v1/verify"))
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(sealed)?)?;
    match client.request_text(req).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(e)) if e.code == 409 => Ok(false),
        Err(e) => Err(anyhow!(e).context(format!("verifying against {ns}/{svc}"))),
    }
}
