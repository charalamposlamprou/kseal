//! The interactive TUI: terminal lifecycle, and the event loop that polls
//! crossterm, runs [`app::App`]'s effects on tokio and feeds their results
//! back as messages.

mod app;
mod clipboard;
mod ui;
mod widgets;

use std::collections::HashMap;
use std::future::Future;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use crossterm::event::{self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyEventKind};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{cursor, execute};
use kube::Client;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::runtime::Runtime;
use tokio::sync::OnceCell;
use tokio::sync::mpsc::{self, UnboundedSender};

use crate::{cluster, core, locate, seal};
use app::{App, Effect, Msg, WriteError};
use widgets::expand_tilde;

const TICK: Duration = Duration::from_millis(50);
/// Bound every cluster call, so a hung API server can't leave the UI under a
/// permanent "Sealing…".
const CLUSTER_TIMEOUT: Duration = Duration::from_secs(30);
/// Ctrl+S asks the controller about found manifests: short, so a cluster
/// that is down can't hold the save prompt back for long.
const OWNER_CHECK_TIMEOUT: Duration = Duration::from_secs(4);
const OWNER_CHECKS_BUDGET: Duration = Duration::from_secs(8);

type Term = Terminal<CrosstermBackend<io::Stdout>>;

fn enter_tui() -> io::Result<()> {
    terminal::enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen, EnableBracketedPaste)
}

fn leave_tui() -> io::Result<()> {
    let r = execute!(io::stdout(), DisableBracketedPaste, LeaveAlternateScreen, cursor::Show);
    terminal::disable_raw_mode()?;
    r
}

pub fn run(rt: Runtime) -> Result<()> {
    if !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        bail!("the TUI needs a terminal — see `kseal --help` for the scriptable subcommands");
    }
    // Restore the terminal before the panic message prints, or it lands in
    // the alternate screen in raw mode and the shell is left unusable.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = leave_tui();
        prev(info);
    }));
    enter_tui()?;
    let res = Terminal::new(CrosstermBackend::new(io::stdout()))
        .map_err(anyhow::Error::from)
        .and_then(|mut term| event_loop(&mut term, &rt));
    leave_tui()?;
    // Don't wait on a hung cluster request on the way out.
    rt.shutdown_timeout(Duration::from_millis(200));
    res
}

fn event_loop(term: &mut Term, rt: &Runtime) -> Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let ex = Executor { rt, tx, kube: Kube::default() };
    let mut app = App::new();
    app.start();
    loop {
        while !app.effects.is_empty() {
            for e in std::mem::take(&mut app.effects) {
                ex.run(term, &mut app, e)?;
            }
        }
        if app.quit {
            return Ok(());
        }
        term.draw(|f| ui::draw(f, &mut app))?;
        if event::poll(TICK)? {
            // Drain everything queued (fast typing) before the next draw.
            loop {
                match event::read()? {
                    Event::Key(k) if k.kind != KeyEventKind::Release => app.on_key(k),
                    Event::Paste(s) => app.on_paste(s),
                    _ => {}
                }
                if app.quit || !app.effects.is_empty() || !event::poll(Duration::ZERO)? {
                    break;
                }
            }
        }
        while let Ok(m) = rx.try_recv() {
            app.on_msg(m);
        }
        app.tick(Instant::now());
    }
}

/// kube Clients cached per context: building one can be slow (EKS exec
/// auth), and concurrent requests for the same context share one build.
#[derive(Clone, Default)]
struct Kube {
    cells: Arc<Mutex<HashMap<String, Arc<OnceCell<Client>>>>>,
}

impl Kube {
    async fn client(&self, ctx: &str) -> Result<Client> {
        let cell = self.cells.lock().expect("client cache poisoned").entry(ctx.to_string()).or_default().clone();
        let c = cell.get_or_try_init(|| async { cluster::client_for(Some(ctx), false).await.map(|(c, _)| c) }).await?;
        Ok(c.clone())
    }
    fn clear(&self) {
        self.cells.lock().expect("client cache poisoned").clear();
    }
}

async fn timed<T>(f: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(CLUSTER_TIMEOUT, f)
        .await
        .map_err(|_| anyhow!("timed out after {}s — is the cluster reachable?", CLUSTER_TIMEOUT.as_secs()))?
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f).await?
}

fn msg_err(e: anyhow::Error) -> String {
    format!("{e:#}")
}

/// [`msg_err`] for a call on cluster context `ctx` (names its login plugin).
fn cluster_err(ctx: &str) -> impl Fn(anyhow::Error) -> String + '_ {
    move |e| cluster::describe_error(&e, Some(ctx))
}

fn read_text(path: &str) -> Result<String> {
    let p = expand_tilde(path);
    std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))
}

struct Executor<'a> {
    rt: &'a Runtime,
    tx: UnboundedSender<Msg>,
    kube: Kube,
}

impl Executor<'_> {
    fn spawn(&self, f: impl Future<Output = Msg> + Send + 'static) {
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            let _ = tx.send(f.await);
        });
    }

    fn run(&self, term: &mut Term, app: &mut App, e: Effect) -> Result<()> {
        let kube = self.kube.clone();
        match e {
            Effect::LoadContexts { tok } => self.spawn(async move {
                Msg::Contexts { tok, res: blocking(cluster::list_contexts).await.map_err(msg_err) }
            }),
            Effect::LoadNamespaces { tok, ctx } => self.spawn(async move {
                let res = timed(async { cluster::list_namespaces(&kube.client(&ctx).await?).await }).await;
                let res = res.map_err(cluster_err(&ctx));
                Msg::Namespaces { tok, ctx, res }
            }),
            Effect::LoadSecrets { tok, ctx, ns } => self.spawn(async move {
                let res = timed(async { cluster::list_secrets(&kube.client(&ctx).await?, &ns).await }).await;
                let res = res.map_err(cluster_err(&ctx));
                Msg::Secrets { tok, ctx, ns, res }
            }),
            Effect::DetectController { tok, ctx, ctl_gen } => self.spawn(async move {
                let res = timed(async { cluster::detect_controller(&kube.client(&ctx).await?).await }).await;
                let res = res.map_err(cluster_err(&ctx));
                Msg::Controller { tok, ctx, ctl_gen, res }
            }),
            Effect::FetchTemplate { tok, ctx, ns, sec, out_gen, kv_gen } => self.spawn(async move {
                let res = timed(async { cluster::get_secret(&kube.client(&ctx).await?, &ns, &sec).await }).await;
                let res = res.map_err(cluster_err(&ctx));
                Msg::Template { tok, ctx, ns, sec, out_gen, kv_gen, res }
            }),
            Effect::ReadFile { tok, purpose, path, out_gen, kv_gen } => self.spawn(async move {
                let p = path.clone();
                let res = blocking(move || read_text(&p)).await.map_err(msg_err);
                Msg::FileRead { tok, purpose, path, out_gen, kv_gen, res }
            }),
            Effect::WriteFile { path, content, overwrite, what, skipped } => self.spawn(async move {
                let p = expand_tilde(&path);
                let res = tokio::task::spawn_blocking(move || {
                    if !overwrite && p.exists() {
                        return Err(WriteError::Exists(content));
                    }
                    core::write_secret_file(&p, &content).map_err(|e| WriteError::Io(e.to_string()))
                })
                .await
                .unwrap_or_else(|e| Err(WriteError::Io(e.to_string())));
                Msg::Written { path, what, skipped, res }
            }),
            Effect::Seal { out_gen, yaml, scope, ctx, cert, ctl: (ns, name) } => self.spawn(async move {
                let res = async {
                    let pem = match cert {
                        Some(path) => blocking(move || read_text(&path).map(String::into_bytes)).await?,
                        None => {
                            timed(async { cluster::fetch_cert(&kube.client(&ctx).await?, &ns, &name).await }).await?
                        }
                    };
                    blocking(move || {
                        let key = seal::parse_cert_pem(&pem)?;
                        Ok(seal::seal_yaml(&yaml, &key, scope)?.0)
                    })
                    .await
                };
                Msg::Sealed { out_gen, res: res.await.map_err(cluster_err(&ctx)) }
            }),
            Effect::Validate { out_gen, sealed, ctx, ctl: (ns, name) } => self.spawn(async move {
                let res = async {
                    let docs = core::parse_yaml_docs(&sealed)?;
                    let doc = docs
                        .iter()
                        .find(|d| d.get("kind").and_then(|k| k.as_str()) == Some("SealedSecret"))
                        .context("no SealedSecret in the output pane")?;
                    timed(async { cluster::verify(&kube.client(&ctx).await?, &ns, &name, doc).await }).await
                };
                Msg::Validated { out_gen, res: res.await.map_err(cluster_err(&ctx)) }
            }),
            Effect::Copy { text, skipped } => {
                if clipboard::prefer_osc52() {
                    write_osc52(term, &text)?;
                    app.on_msg(Msg::Copied { skipped, res: Ok("terminal clipboard (OSC 52)") });
                } else {
                    self.spawn(async move {
                        let res = match tokio::task::spawn_blocking({
                            let text = text.clone();
                            move || clipboard::system_copy(&text)
                        })
                        .await
                        {
                            Ok(Ok(())) => Ok("clipboard"),
                            Ok(Err(e)) => Err((text, e)),
                            Err(e) => Err((text, e.to_string())),
                        };
                        Msg::Copied { skipped, res }
                    });
                }
            }
            Effect::Osc52 { text } => write_osc52(term, &text)?,
            Effect::EditValue { row, key, value, kv_gen } => {
                let res = edit_external(term, &value)?.map_err(msg_err);
                app.on_msg(Msg::Edited { row, key, original: value, kv_gen, res });
            }
            Effect::ClearClients => kube.clear(),
            Effect::LocateSave { tok, ns, name, ctl, sealed_file, last_dir } => self.spawn(async move {
                let cwd = std::env::current_dir().unwrap_or_default();
                let repo_env = std::env::var("KSEAL_REPO").ok();
                let root = locate::search_root(repo_env.as_deref(), &cwd);
                let (ns2, name2, root2) = (ns.clone(), name.clone(), root.clone());
                let hits =
                    blocking(move || Ok(root2.map(|r| locate::find_manifests(&r, &ns2, &name2)).unwrap_or_default()))
                        .await
                        .unwrap_or_default();
                // Whose each match is: can the controller sealed for decrypt it?
                // (/v1/verify — creates nothing.) With a certificate: unknown.
                // Bounded: a short timeout per check, an overall budget, and no
                // more checks after the first failure (the cluster is likely down).
                let deadline = Instant::now() + OWNER_CHECKS_BUDGET;
                let mut reachable = ctl.is_some();
                let mut found = vec![];
                for h in hits.into_iter().take(10) {
                    let owner = match &ctl {
                        Some((ctx, cns, cname)) if reachable && Instant::now() < deadline => {
                            let check = async { cluster::verify(&kube.client(ctx).await?, cns, cname, &h.doc).await };
                            match tokio::time::timeout(OWNER_CHECK_TIMEOUT, check).await {
                                Ok(Ok(true)) => locate::Owner::This,
                                Ok(Ok(false)) => locate::Owner::Other,
                                _ => {
                                    reachable = false;
                                    locate::Owner::Unknown
                                }
                            }
                        }
                        _ => locate::Owner::Unknown,
                    };
                    found.push(locate::FoundManifest { path: locate::pretty_path(&h.path), owner });
                }
                let new_file = locate::new_file_path(&sealed_file, last_dir.as_deref(), root.as_deref());
                Msg::SaveLocated { tok, new_file, found }
            }),
            Effect::FetchLive { tok, ctx, ns, name } => self.spawn(async move {
                let res = timed(async { cluster::get_secret_opt(&kube.client(&ctx).await?, &ns, &name).await }).await;
                let res = res
                    .and_then(|v| v.map(|v| serde_json::to_string(&v).map_err(anyhow::Error::from)).transpose())
                    .map_err(cluster_err(&ctx));
                Msg::LiveFetched { tok, label: format!("live {ns}/{name} in {ctx}"), res }
            }),
        }
        Ok(())
    }
}

fn write_osc52(term: &mut Term, text: &str) -> Result<()> {
    let out = term.backend_mut();
    out.write_all(clipboard::osc52(text).as_bytes())?;
    out.flush()?;
    Ok(())
}

/// Edit `value` in `$VISUAL`/`$EDITOR`: the TUI is suspended, the value
/// lives in an owner-only temp file inside an owner-only directory for the
/// duration, and both are removed afterwards. The outer error is a terminal
/// that couldn't be restored (fatal); the inner one is the editor's outcome.
fn edit_external(term: &mut Term, value: &str) -> Result<Result<String>> {
    let dir = match private_temp_dir() {
        Ok(d) => d,
        Err(e) => return Ok(Err(e)),
    };
    let path = dir.join("value.txt");
    let res = match core::write_secret_file(&path, &core::editor_text(value)) {
        Err(e) => Err(anyhow::Error::from(e).context("writing the temp file")),
        Ok(()) => {
            let mut cmd = editor_command(&path);
            leave_tui()?;
            let status = cmd.status();
            enter_tui()?;
            // A fresh Terminal forces a full redraw without Terminal::clear's
            // cursor-position query, which not every terminal answers.
            execute!(io::stdout(), terminal::Clear(terminal::ClearType::All))?;
            *term = Terminal::new(CrosstermBackend::new(io::stdout()))?;
            match status {
                Err(e) => Err(anyhow::Error::from(e).context(format!("launching {:?}", cmd.get_program()))),
                Ok(st) if !st.success() => Err(anyhow!("editor exited with {st} — value unchanged")),
                Ok(_) => std::fs::read_to_string(&path).context("reading the edited value"),
            }
        }
    };
    let _ = std::fs::remove_dir_all(&dir);
    Ok(res)
}

fn editor_command(path: &Path) -> std::process::Command {
    let default = if cfg!(windows) { "notepad" } else { "vi" };
    let editor = ["VISUAL", "EDITOR"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .find(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.into());
    // `code -w`, `subl -w`: split off the arguments.
    let mut parts = editor.split_whitespace();
    let mut cmd = std::process::Command::new(parts.next().unwrap_or(default));
    cmd.args(parts).arg(path);
    cmd
}

fn private_temp_dir() -> Result<PathBuf> {
    let base = std::env::temp_dir();
    for i in 0..16u32 {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
        let dir = base.join(format!("kseal-{}-{nanos}-{i}", std::process::id()));
        #[cfg_attr(not(unix), allow(unused_mut))] // only unix sets a mode
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        match b.create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
        }
    }
    bail!("could not create a private temp directory")
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(unix)]
    fn private_temp_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = super::private_temp_dir().unwrap();
        assert_eq!(std::fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        std::fs::remove_dir(d).unwrap();
    }
}
