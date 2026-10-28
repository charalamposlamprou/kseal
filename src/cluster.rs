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
use kube::client::AuthError;
use kube::config::{ExecInteractiveMode, KubeConfigOptions, Kubeconfig};
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
///
/// `interactive: false` (the TUI) runs exec credential plugins (EKS
/// `aws eks get-token`, …) with their stderr captured: inherited, it is
/// printed straight over the TUI. It then shows up in [`describe_error`].
pub async fn client_for(context: Option<&str>, interactive: bool) -> Result<(Client, String)> {
    let opts = KubeConfigOptions { context: context.map(str::to_owned), ..Default::default() };
    let mut cfg = Config::from_kubeconfig(&opts)
        .await
        .with_context(|| format!("loading kubeconfig context {}", context.unwrap_or("(current)")))?;
    if let (false, Some(exec)) = (interactive, cfg.auth_info.exec.as_mut()) {
        exec.interactive_mode = Some(ExecInteractiveMode::Never);
    }
    // kube's default retry backs off up to 15 times on 503 — minutes for an
    // error that's permanent here (e.g. "no endpoints"). Fail fast instead.
    cfg.default_retry = false;
    let ns = cfg.default_namespace.clone();
    Ok((Client::try_from(cfg)?, ns))
}

/// Prefix of every [`describe_error`] message for a failed cluster login.
pub const LOGIN_FAILED: &str = "Cluster login failed";

/// An error from a cluster call on `context` (`None`: the current one),
/// made readable. A failed exec credential plugin is reported by its own
/// error output: kube's message is the whole command line with its
/// environment plus the raw output, which buries the cause (e.g. an expired
/// AWS token) past the edge of the screen.
pub fn describe_error(e: &anyhow::Error, context: Option<&str>) -> String {
    let auth = e.chain().find_map(|c| c.downcast_ref::<AuthError>());
    match auth {
        Some(AuthError::AuthExecRun { status, out, .. }) => {
            // stderr only: stdout is where a plugin writes credentials.
            let said = String::from_utf8_lossy(&out.stderr).trim().to_string();
            match (!said.is_empty()).then_some(said) {
                Some(said) => format!("{LOGIN_FAILED}: the kubeconfig's credential plugin failed ({status}):\n{said}"),
                None => format!("{LOGIN_FAILED}: the kubeconfig's credential plugin failed ({status})"),
            }
        }
        Some(AuthError::AuthExecStart(io)) => {
            // kube's error doesn't say which command; the kubeconfig does.
            let what = match exec_command(context) {
                Some(cmd) => format!("`{cmd}`, the kubeconfig's credential plugin"),
                None => "the kubeconfig's credential plugin".into(),
            };
            let hint = if io.kind() == std::io::ErrorKind::NotFound { " — is it installed and on PATH?" } else { "" };
            format!("{LOGIN_FAILED}: could not run {what}: {io}{hint}")
        }
        _ => chain_text(e),
    }
}

/// `{e:#}`, except a Kubernetes API error is its message and HTTP status:
/// kube's own text appends a debug dump of the whole Status object.
fn chain_text(e: &anyhow::Error) -> String {
    let mut parts = Vec::new();
    for cause in e.chain() {
        if let Some(kube::Error::Api(st)) = cause.downcast_ref::<kube::Error>() {
            parts.push(format!("{} (HTTP {} {})", st.message, st.code, st.reason));
            // The service proxy's 503: the Service exists but no pod backs it.
            if st.code == 503 && st.message.starts_with("no endpoints available") {
                return format!(
                    "{}\nThe controller has no running pod (scaled down, or its pods are Pending) — \
                     check `kubectl get pods` in its namespace.",
                    parts.join(": ")
                );
            }
            break; // its source is the same Status again
        }
        parts.push(cause.to_string());
    }
    parts.join(": ")
}

/// The exec credential plugin command `context` (`None`: the current one)
/// logs in with, if any.
fn exec_command(context: Option<&str>) -> Option<String> {
    let kc = Kubeconfig::read().ok()?;
    let name = context.map(str::to_owned).or(kc.current_context)?;
    let user = kc.contexts.iter().find(|c| c.name == name)?.context.as_ref()?.user.clone()?;
    let auth = kc.auth_infos.iter().find(|a| a.name == user)?.auth_info.as_ref()?;
    auth.exec.as_ref()?.command.clone()
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

/// [`get_secret`], or `None` when it doesn't exist (read-only).
pub async fn get_secret_opt(client: &Client, ns: &str, name: &str) -> Result<Option<Value>> {
    let api: Api<Secret> = Api::namespaced(client.clone(), ns);
    if api.get_metadata_opt(name).await.with_context(|| format!("getting secret {ns}/{name}"))?.is_none() {
        return Ok(None);
    }
    get_secret(client, ns, name).await.map(Some)
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

/// The port to proxy to, resolved like kubeseal: the service's first port,
/// by name when it has one. Helm names it `http`, and the API server matches
/// an empty port only against an UNNAMED port ("no endpoints available").
fn service_port(svc: &Service) -> String {
    let first = svc.spec.as_ref().and_then(|s| s.ports.as_ref()).and_then(|p| p.first());
    first.map_or_else(String::new, |p| p.name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| p.port.to_string()))
}

fn proxy_path_for(ns: &str, svc: &str, port: &str, suffix: &str) -> String {
    format!("/api/v1/namespaces/{ns}/services/http:{svc}:{port}/proxy{suffix}")
}

async fn proxy_path(client: &Client, ns: &str, svc: &str, suffix: &str) -> String {
    let api: Api<Service> = Api::namespaced(client.clone(), ns);
    // If the Service can't be read (RBAC), fall back to the first-port form;
    // the proxy request itself then reports the real problem.
    let port = api.get(svc).await.map(|s| service_port(&s)).unwrap_or_default();
    proxy_path_for(ns, svc, &port, suffix)
}

/// The controller's current sealing certificate (PEM).
pub async fn fetch_cert(client: &Client, ns: &str, svc: &str) -> Result<Vec<u8>> {
    let req = http::Request::get(proxy_path(client, ns, svc, "/v1/cert.pem").await).body(Vec::new())?;
    let pem = client
        .request_text(req)
        .await
        .with_context(|| format!("fetching sealing cert from {ns}/{svc} (is the controller running?)"))?;
    Ok(pem.into_bytes())
}

/// Ask the controller whether it can decrypt `sealed`. Creates nothing.
pub async fn verify(client: &Client, ns: &str, svc: &str, sealed: &Value) -> Result<bool> {
    let req = http::Request::post(proxy_path(client, ns, svc, "/v1/verify").await)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(sealed)?)?;
    match client.request_text(req).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(e)) if e.code == 409 => Ok(false),
        Err(e) => Err(anyhow!(e).context(format!("verifying against {ns}/{svc}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{ServicePort, ServiceSpec};

    fn svc(ports: Vec<(Option<&str>, i32)>) -> Service {
        let ports = ports
            .into_iter()
            .map(|(name, port)| ServicePort { name: name.map(Into::into), port, ..Default::default() })
            .collect();
        Service { spec: Some(ServiceSpec { ports: Some(ports), ..Default::default() }), ..Default::default() }
    }

    #[test]
    #[cfg(unix)] // ExitStatus::from_raw
    fn describe_error_shows_the_plugin_output_not_the_command() {
        use std::os::unix::process::ExitStatusExt;
        let out = std::process::Output {
            status: std::process::ExitStatus::from_raw(255 << 8),
            stdout: vec![],
            stderr: b"\nAn error occurred (ExpiredToken): The security token included in the request is expired\n"
                .to_vec(),
        };
        let err = kube::Error::Auth(AuthError::AuthExecRun {
            cmd: r#"AWS_PROFILE="prod" KUBERNETES_EXEC_INFO="{}" "aws" "eks" "get-token""#.into(),
            status: out.status,
            out,
        });
        let msg = describe_error(&anyhow::Error::from(err).context("listing namespaces"), None);
        assert_eq!(
            msg,
            "Cluster login failed: the kubeconfig's credential plugin failed (exit status: 255):\n\
             An error occurred (ExpiredToken): The security token included in the request is expired"
        );
        assert!(!msg.contains("AWS_PROFILE"));
        // stdout is never shown: it's where a plugin writes the token.
        let out = std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: b"{\"status\":{\"token\":\"k8s-aws-v1.secret\"}}".to_vec(),
            stderr: vec![],
        };
        let err = kube::Error::Auth(AuthError::AuthExecRun { cmd: String::new(), status: out.status, out });
        let msg = describe_error(&anyhow::Error::from(err), None);
        assert_eq!(msg, "Cluster login failed: the kubeconfig's credential plugin failed (exit status: 1)");
        // A plugin that couldn't start: missing from PATH gets a hint.
        let err = kube::Error::Auth(AuthError::AuthExecStart(std::io::ErrorKind::NotFound.into()));
        let msg = describe_error(&anyhow::Error::from(err), Some("no-such-context"));
        assert!(msg.starts_with("Cluster login failed: could not run the kubeconfig's credential plugin"), "{msg}");
        assert!(msg.ends_with("— is it installed and on PATH?"), "{msg}");
        // An API error is its message and status, without kube's debug dump.
        let st = kube::core::Status::failure(
            "no endpoints available for service \"sealed-secrets-controller\"",
            "ServiceUnavailable",
        )
        .with_code(503);
        let err = anyhow::Error::from(kube::Error::Api(st.boxed()))
            .context("fetching sealing cert from kube-system/sealed-secrets-controller");
        assert_eq!(
            describe_error(&err, None),
            "fetching sealing cert from kube-system/sealed-secrets-controller: no endpoints available for service \
             \"sealed-secrets-controller\" (HTTP 503 ServiceUnavailable)\nThe controller has no running pod (scaled \
             down, or its pods are Pending) — check `kubectl get pods` in its namespace."
        );
        // Anything else keeps the full chain.
        assert_eq!(describe_error(&anyhow!("boom").context("listing namespaces"), None), "listing namespaces: boom");
    }

    #[test]
    fn proxy_port_matches_kubeseal() {
        // Helm chart: named port — an empty port would get "no endpoints available".
        assert_eq!(service_port(&svc(vec![(Some("http"), 8080), (Some("metrics"), 8081)])), "http");
        // Upstream controller.yaml: unnamed port.
        assert_eq!(service_port(&svc(vec![(None, 8080)])), "8080");
        assert_eq!(service_port(&svc(vec![(Some(""), 8080)])), "8080");
        assert_eq!(service_port(&Service::default()), "");
        assert_eq!(
            proxy_path_for("sealed-secrets", "sealed-secrets-controller", "http", "/v1/cert.pem"),
            "/api/v1/namespaces/sealed-secrets/services/http:sealed-secrets-controller:http/proxy/v1/cert.pem"
        );
    }
}
