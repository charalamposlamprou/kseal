//! kseal — Kubernetes Secrets in your terminal.
//!
//! `kseal` with no arguments opens the TUI; subcommands give the same
//! features scriptably (pipes, CI).

mod cluster;
mod core;
mod seal;
mod tui;

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

use crate::core::EntryKind;
use crate::seal::Scope;

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
        Some((ns, name)) => Ok((
            ctl.controller_namespace.clone().unwrap_or(ns),
            ctl.controller_name.clone().unwrap_or(name),
        )),
        None => bail!("no sealed-secrets controller found — pass --controller-name/--controller-namespace or --cert"),
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
            let (client, default_ns) = cluster::client_for(kube.context.as_deref()).await?;
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
                    let text: Vec<_> = entries.iter().filter(|e| e.kind == EntryKind::Text).map(|e| (e.key.clone(), e.value.clone())).collect();
                    let raw: Vec<_> = entries.iter().filter(|e| e.kind != EntryKind::Text).map(|e| (e.key.clone(), e.value.clone())).collect();
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
                    let (client, _) = cluster::client_for(kube.context.as_deref()).await?;
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
            let (client, _) = cluster::client_for(kube.context.as_deref()).await?;
            let (ns, name) = controller(&client, &ctl).await?;
            if cluster::verify(&client, &ns, &name, sealed).await? {
                eprintln!("✓ controller {ns}/{name} can decrypt this SealedSecret");
            } else {
                bail!("✗ controller {ns}/{name} cannot decrypt this SealedSecret (wrong key, scope, name or namespace)");
            }
        }
        Cmd::Cert { kube, ctl } => {
            let (client, _) = cluster::client_for(kube.context.as_deref()).await?;
            let (ns, name) = controller(&client, &ctl).await?;
            std::io::stdout().write_all(&cluster::fetch_cert(&client, &ns, &name).await?)?;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    match cli.cmd {
        None => tui::run(rt),
        Some(cmd) => {
            if let Err(e) = rt.block_on(run(cmd)) {
                eprintln!("error: {e:#}");
                std::process::exit(1);
            }
            Ok(())
        }
    }
}
