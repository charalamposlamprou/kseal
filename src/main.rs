//! kseal — Kubernetes Secrets in your terminal.
//!
//! `kseal` with no arguments opens the TUI; subcommands give the same
//! features scriptably (pipes, CI).

mod cluster;
mod core;
mod diff;
mod gitops;
mod seal;
mod tui;
mod validate;

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

use crate::core::EntryKind;
use crate::gitops::Workflow;
use crate::seal::Scope;
use crate::validate::Severity;

#[derive(Parser)]
#[command(name = "kseal", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Base64-encode a value (argument or stdin).
    Encode { value: Option<String> },
    /// Base64-decode a value (argument or stdin). Whitespace and missing padding are tolerated.
    Decode { value: Option<String> },
    /// Build Secret YAML from a .env file.
    Gen {
        /// .env file ("-" for stdin).
        #[arg(short = 'f', long, default_value = "-")]
        file: String,
        #[arg(long, default_value = "my-secret")]
        name: String,
        #[arg(short = 'n', long, default_value = "default")]
        namespace: String,
        /// Secret type; auto-detected from the keys when left at Opaque.
        #[arg(short = 't', long = "type", default_value = "Opaque")]
        type_: String,
        #[command(flatten)]
        out: OutArgs,
    },
    /// Show the decoded keys of a Secret manifest (values masked unless --reveal).
    Show {
        #[arg(short = 'f', long, default_value = "-")]
        file: String,
        #[arg(long)]
        reveal: bool,
    },
    /// Fetch a Secret from the cluster (read-only) as .env or regenerated YAML.
    Get {
        name: String,
        #[command(flatten)]
        kube: KubeArgs,
        #[arg(short = 'n', long)]
        namespace: Option<String>,
        #[arg(long, value_enum, default_value = "env")]
        format: GetFormat,
    },
    /// Seal a Secret manifest into a SealedSecret — natively, no kubeseal needed.
    Seal {
        #[arg(short = 'f', long, default_value = "-")]
        file: String,
        #[arg(long, value_enum, default_value = "strict")]
        scope: Scope,
        /// Seal offline with this certificate instead of fetching it from the controller.
        #[arg(long)]
        cert: Option<PathBuf>,
        #[command(flatten)]
        kube: KubeArgs,
        #[command(flatten)]
        ctl: ControllerArgs,
        #[command(flatten)]
        out: OutArgs,
    },
    /// Check that the controller can decrypt a SealedSecret (creates nothing).
    Validate {
        #[arg(short = 'f', long, default_value = "-")]
        file: String,
        #[command(flatten)]
        kube: KubeArgs,
        #[command(flatten)]
        ctl: ControllerArgs,
    },
    /// Print the controller's sealing certificate (for offline `seal --cert`).
    Cert {
        #[command(flatten)]
        kube: KubeArgs,
        #[command(flatten)]
        ctl: ControllerArgs,
    },
    /// Compare two Secret / SealedSecret manifests by meaning: keys added,
    /// removed or modified, labels, annotations, type and scope. Values are
    /// masked unless --reveal.
    Diff {
        /// The old manifest ("-" for stdin).
        old: String,
        /// The new manifest ("-" for stdin).
        new: String,
        /// Show decoded values of plain Secrets (encrypted values never are).
        #[arg(long)]
        reveal: bool,
        /// Exit with status 1 when the manifests differ.
        #[arg(long)]
        exit_code: bool,
    },
    /// Check Secret / SealedSecret manifests and sealing certificates for
    /// security problems, offline. SealedSecret checks are structural:
    /// `kseal validate` asks the controller whether it can decrypt.
    Lint {
        /// Manifest to check ("-" for stdin; multi-document files work).
        #[arg(short = 'f', long, required_unless_present = "cert")]
        file: Option<String>,
        /// Sealing certificate to check (and to check the SealedSecrets against).
        #[arg(long)]
        cert: Option<PathBuf>,
        /// Exit with status 1 when a finding is at least this severe.
        #[arg(long, value_enum, default_value = "high")]
        fail_on: Severity,
    },
    /// Seal a Secret for a GitOps repository (Argo CD, Flux) and write it to
    /// a local file after safety checks. Never commits, pushes or applies.
    Export {
        #[arg(short = 'f', long, default_value = "-")]
        file: String,
        #[arg(long, value_enum, default_value = "generic")]
        workflow: Workflow,
        #[arg(long, value_enum, default_value = "strict")]
        scope: Scope,
        /// Seal for this namespace instead of the Secret's own.
        #[arg(short = 'n', long)]
        namespace: Option<String>,
        /// Seal offline with this certificate instead of fetching it from the controller.
        #[arg(long)]
        cert: Option<PathBuf>,
        #[command(flatten)]
        kube: KubeArgs,
        #[command(flatten)]
        ctl: ControllerArgs,
        /// File to write (owner-only permissions).
        #[arg(short = 'o', long)]
        output: PathBuf,
        /// Replace the file if it exists (shows what changes first).
        #[arg(long)]
        force: bool,
        /// Write nothing when a finding is at least this severe.
        #[arg(long, value_enum, default_value = "critical")]
        fail_on: Severity,
    },
}

#[derive(Args, Clone)]
struct KubeArgs {
    /// Kubeconfig context (defaults to the current context).
    #[arg(long, env = "KSEAL_CONTEXT")]
    context: Option<String>,
}

#[derive(Args, Clone)]
struct ControllerArgs {
    /// Controller service name (auto-detected when omitted).
    #[arg(long)]
    controller_name: Option<String>,
    /// Controller namespace (auto-detected when omitted).
    #[arg(long)]
    controller_namespace: Option<String>,
}

#[derive(Args)]
struct OutArgs {
    /// Write to this file (owner-only permissions) instead of stdout.
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum GetFormat {
    Env,
    Yaml,
}

fn read_input(file: &str) -> Result<String> {
    if file == "-" {
        if std::io::stdin().is_terminal() {
            bail!("no input: pass -f FILE or pipe data on stdin");
        }
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        Ok(s)
    } else {
        std::fs::read_to_string(file).with_context(|| format!("reading {file}"))
    }
}

fn arg_or_stdin(v: Option<String>) -> Result<String> {
    match v {
        Some(v) => Ok(v),
        None => Ok(read_input("-")?.trim_end_matches(['\n', '\r']).to_string()),
    }
}

fn emit(out: &OutArgs, content: &str) -> Result<()> {
    match &out.output {
        Some(p) => {
            core::write_secret_file(p, content).with_context(|| format!("writing {}", p.display()))?;
            eprintln!("wrote {}", p.display());
        }
        None => std::io::stdout().write_all(content.as_bytes())?,
    }
    Ok(())
}

async fn controller(client: &kube::Client, ctl: &ControllerArgs) -> Result<(String, String)> {
    if let (Some(ns), Some(n)) = (&ctl.controller_namespace, &ctl.controller_name) {
        return Ok((ns.clone(), n.clone()));
    }
    let found = cluster::detect_controller(client).await?;
    match found {
        Some((ns, name)) => {
            Ok((ctl.controller_namespace.clone().unwrap_or(ns), ctl.controller_name.clone().unwrap_or(name)))
        }
        None => bail!("no sealed-secrets controller found — pass --controller-name/--controller-namespace or --cert"),
    }
}

fn print_findings(findings: &[validate::Finding]) {
    for f in findings {
        eprintln!("{}", validate::format_finding(f));
    }
}

/// The sealing certificate: `--cert`, or the controller's (read-only fetch).
async fn sealing_cert(cert: Option<PathBuf>, kube: &KubeArgs, ctl: &ControllerArgs) -> Result<Vec<u8>> {
    match cert {
        Some(p) => std::fs::read(&p).with_context(|| format!("reading {}", p.display())),
        None => {
            let (client, _) = cluster::client_for(kube.context.as_deref(), true).await?;
            let (ns, name) = controller(&client, ctl).await?;
            cluster::fetch_cert(&client, &ns, &name).await
        }
    }
}

async fn run(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Encode { value } => println!("{}", core::b64_encode(arg_or_stdin(value)?)),
        Cmd::Decode { value } => {
            let bytes = core::b64_decode_bytes(&arg_or_stdin(value)?).context("invalid base64")?;
            std::io::stdout().write_all(&bytes)?;
            if std::io::stdout().is_terminal() {
                println!();
            }
        }
        Cmd::Gen { file, name, namespace, type_, out } => {
            let pairs = core::parse_dotenv(&read_input(&file)?);
            let type_ = if type_ == "Opaque" {
                core::guess_secret_type(pairs.iter().map(|(k, _)| k.as_str())).to_string()
            } else {
                type_
            };
            let yaml = core::build_secret_yaml(&name, &namespace, &pairs, &type_, &[], &Default::default());
            emit(&out, &yaml)?;
        }
        Cmd::Show { file, reveal } => {
            let docs = core::parse_yaml_docs(&read_input(&file)?)?;
            let Some(doc) = core::select_secret_doc(&docs) else {
                if core::has_sealed_secret(&docs) {
                    bail!("this is a SealedSecret — its values only decrypt inside the cluster");
                }
                bail!("no Secret found in input");
            };
            let entries = core::secret_entries(doc);
            let w = entries.iter().map(|e| e.key.len()).max().unwrap_or(0);
            for e in entries {
                let v = match (e.kind, reveal) {
                    (EntryKind::Binary, _) => format!("<binary, {} bytes base64>", e.value.len()),
                    (EntryKind::Invalid, _) => "<invalid base64 — belongs under stringData>".into(),
                    (EntryKind::Text, true) => e.value.escape_debug().to_string(),
                    (EntryKind::Text, false) => "•".repeat(e.value.chars().count().clamp(1, 12)),
                };
                println!("{:w$}  {v}", e.key);
            }
        }
        Cmd::Get { name, kube, namespace, format } => {
            let (client, default_ns) = cluster::client_for(kube.context.as_deref(), true).await?;
            let ns = namespace.unwrap_or(default_ns);
            let doc = cluster::get_secret(&client, &ns, &name).await?;
            let entries = core::secret_entries(&doc);
            match format {
                GetFormat::Env => {
                    for e in &entries {
                        match e.kind {
                            EntryKind::Text => println!("{}", core::dotenv_line(&e.key, &e.value)?),
                            _ => eprintln!("# skipped {:?}: binary value has no .env form (use --format yaml)", e.key),
                        }
                    }
                }
                GetFormat::Yaml => {
                    let (carry, skipped) = core::secret_carryover(&doc);
                    let (n, ns, t) = core::secret_identity(&doc);
                    let text: Vec<_> = entries
                        .iter()
                        .filter(|e| e.kind == EntryKind::Text)
                        .map(|e| (e.key.clone(), e.value.clone()))
                        .collect();
                    let raw: Vec<_> = entries
                        .iter()
                        .filter(|e| e.kind != EntryKind::Text)
                        .map(|e| (e.key.clone(), e.value.clone()))
                        .collect();
                    print!("{}", core::build_secret_yaml(&n, &ns, &text, &t, &raw, &carry));
                    if skipped > 0 {
                        eprintln!("warning: {skipped} malformed metadata field(s) dropped");
                    }
                }
            }
        }
        Cmd::Seal { file, scope, cert, kube, ctl, out } => {
            let input = read_input(&file)?;
            let pem = match cert {
                Some(p) => std::fs::read(&p).with_context(|| format!("reading {}", p.display()))?,
                None => {
                    let (client, _) = cluster::client_for(kube.context.as_deref(), true).await?;
                    let (ns, name) = controller(&client, &ctl).await?;
                    cluster::fetch_cert(&client, &ns, &name).await?
                }
            };
            let key = seal::parse_cert_pem(&pem)?;
            let (yaml, _) = seal::seal_yaml(&input, &key, scope)?;
            emit(&out, &yaml)?;
        }
        Cmd::Validate { file, kube, ctl } => {
            let docs = core::parse_yaml_docs(&read_input(&file)?)?;
            let sealed = docs
                .iter()
                .find(|d| d.get("kind").and_then(|k| k.as_str()) == Some("SealedSecret"))
                .context("no SealedSecret found in input")?;
            let (client, _) = cluster::client_for(kube.context.as_deref(), true).await?;
            let (ns, name) = controller(&client, &ctl).await?;
            if cluster::verify(&client, &ns, &name, sealed).await? {
                eprintln!("✓ controller {ns}/{name} can decrypt this SealedSecret");
            } else {
                bail!(
                    "✗ controller {ns}/{name} cannot decrypt this SealedSecret (wrong key, scope, name or namespace)"
                );
            }
        }
        Cmd::Cert { kube, ctl } => {
            let (client, _) = cluster::client_for(kube.context.as_deref(), true).await?;
            let (ns, name) = controller(&client, &ctl).await?;
            std::io::stdout().write_all(&cluster::fetch_cert(&client, &ns, &name).await?)?;
        }
        Cmd::Diff { old, new, reveal, exit_code } => {
            if old == "-" && new == "-" {
                bail!("only one side can be read from stdin");
            }
            let d = diff::diff_texts(&read_input(&old)?, &read_input(&new)?)?;
            let mut out = std::io::stdout().lock();
            for l in &d.lines {
                writeln!(out, "{}", widgets_free_line(&diff::render(l, reveal)))?;
            }
            eprintln!("{}", d.summary);
            if exit_code && !d.summary.is_identical() {
                out.flush()?;
                std::process::exit(1);
            }
        }
        Cmd::Lint { file, cert, fail_on } => {
            let mut findings = vec![];
            let mut key = None;
            if let Some(p) = cert {
                let pem = std::fs::read(&p).with_context(|| format!("reading {}", p.display()))?;
                let (f, info) = validate::cert_findings(&pem, validate::now());
                findings.extend(f);
                key = info.map(|i| i.key);
            }
            if let Some(file) = file {
                let docs = core::parse_yaml_docs(&read_input(&file)?).context("malformed YAML")?;
                findings.extend(validate::file_findings(&docs, key));
            }
            validate::sort(&mut findings);
            print_findings(&findings);
            eprintln!("{}", validate::summary(&findings));
            let failing = findings.iter().filter(|f| f.severity <= fail_on).count();
            if failing > 0 {
                bail!("{failing} finding(s) at or above {}", fail_on.as_str().to_lowercase());
            }
        }
        Cmd::Export { file, workflow, scope, namespace, cert, kube, ctl, output, force, fail_on } => {
            let input = read_input(&file)?;
            let pem = sealing_cert(cert, &kube, &ctl).await?;
            let (mut findings, info) = validate::cert_findings(&pem, validate::now());
            let Some(info) = info else {
                print_findings(&findings);
                bail!("the sealing certificate can't be used — nothing written");
            };
            let key = seal::parse_cert_pem(&pem)?;
            let opts = gitops::Options { workflow, scope, namespace };
            let export = gitops::build(&input, &key, Some(info.key), &opts)?;
            findings.extend(export.findings);
            findings.extend(gitops::check_target(&output, &export.yaml));
            validate::sort(&mut findings);
            print_findings(&findings);
            let failing = findings.iter().filter(|f| f.severity <= fail_on).count();
            if failing > 0 {
                bail!("{failing} finding(s) at or above {} — nothing written", fail_on.as_str().to_lowercase());
            }
            if output.exists() && force {
                if let Ok(old) = std::fs::read_to_string(&output) {
                    if let Ok(d) = diff::diff_texts(&old, &export.yaml) {
                        eprintln!("replacing {}: {}", output.display(), d.summary);
                    }
                }
            }
            match core::save_secret_file(&output, &export.yaml, force) {
                Ok(()) => {
                    eprintln!("wrote {} ({} workflow, {} scope)", output.display(), workflow.title(), scope.as_str())
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if let Ok(d) = std::fs::read_to_string(&output)
                        .map_err(anyhow::Error::from)
                        .and_then(|old| diff::diff_texts(&old, &export.yaml))
                    {
                        for l in d.lines.iter().filter(|l| l.tag.is_change() || l.tag == diff::Tag::Header) {
                            eprintln!("{}", widgets_free_line(&diff::render(l, false)));
                        }
                        eprintln!("{}", d.summary);
                    }
                    bail!("{} exists — pass --force to replace it", output.display());
                }
                Err(e) => return Err(anyhow::Error::from(e).context(format!("writing {}", output.display()))),
            }
        }
    }
    Ok(())
}

/// Control characters made visible, so a manifest can't drive the terminal.
fn widgets_free_line(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '\u{FFFD}' } else { c }).collect()
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    match cli.cmd {
        None => tui::run(rt),
        Some(cmd) => {
            let context = match &cmd {
                Cmd::Get { kube, .. }
                | Cmd::Seal { kube, .. }
                | Cmd::Export { kube, .. }
                | Cmd::Validate { kube, .. }
                | Cmd::Cert { kube, .. } => kube.context.clone(),
                _ => None,
            };
            if let Err(e) = rt.block_on(run(cmd)) {
                eprintln!("error: {}", cluster::describe_error(&e, context.as_deref()));
                std::process::exit(1);
            }
            Ok(())
        }
    }
}
