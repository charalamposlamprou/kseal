//! Where a SealedSecret already lives on disk: the manifest a re-seal
//! should update. Read-only — YAML files only, capped in size, count and
//! depth, hidden / build directories skipped, symlinks never followed.

use std::path::Path;

use serde_json::{Value, json};

use crate::core;

const MAX_SCAN_FILE: u64 = 1024 * 1024;

/// Expand a leading `~` to the home directory.
fn expand_tilde(p: &str) -> std::path::PathBuf {
    match p.strip_prefix("~/").or_else(|| (p == "~").then_some("")) {
        Some(rest) => match std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            Some(home) => std::path::PathBuf::from(home).join(rest),
            None => std::path::PathBuf::from(p),
        },
        None => std::path::PathBuf::from(p),
    }
}

fn read_capped(p: &Path) -> Option<String> {
    let m = std::fs::symlink_metadata(p).ok()?;
    if !m.is_file() || m.len() > MAX_SCAN_FILE {
        return None;
    }
    std::fs::read_to_string(p).ok()
}

/// `path` absolute (its directory resolved, so a not-yet-existing file
/// works too), with the home directory shown as `~` — what findings name.
pub fn pretty_path(path: &Path) -> String {
    let abs = match (path.parent().filter(|p| !p.as_os_str().is_empty()), path.file_name()) {
        (Some(dir), Some(f)) => std::fs::canonicalize(dir).map(|d| d.join(f)).unwrap_or_else(|_| path.to_path_buf()),
        (None, Some(f)) => std::env::current_dir().map(|d| d.join(f)).unwrap_or_else(|_| path.to_path_buf()),
        _ => path.to_path_buf(),
    };
    let s = abs.display().to_string();
    match std::env::var_os("HOME").and_then(|h| std::fs::canonicalize(h).ok()) {
        Some(home) => match abs.strip_prefix(&home) {
            Ok(rest) => format!("~/{}", rest.display()),
            Err(_) => s,
        },
        None => s,
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

/// `p` relative to `base` when it's under it (shorter to show and type).
pub fn display_path(p: &Path, base: &Path) -> String {
    let base = std::fs::canonicalize(base).unwrap_or_else(|_| base.to_path_buf());
    let p = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    p.strip_prefix(&base).map_or_else(|_| p.display().to_string(), |r| r.display().to_string())
}

/// The path a NEW file is suggested at: the folder saved to last this
/// session, else the repository, else the current folder.
pub fn new_file_path(file: &str, last_dir: Option<&str>, repo: Option<&Path>) -> String {
    match (last_dir.filter(|d| !d.is_empty()), repo) {
        (Some(d), _) => pretty_path(&Path::new(d).join(file)),
        (None, Some(r)) => pretty_path(&r.join(file)),
        (None, None) => file.to_string(),
    }
}

/// Where to search: `KSEAL_REPO` if set, else the Git repo of `cwd`.
pub fn search_root(repo_env: Option<&str>, cwd: &Path) -> Option<std::path::PathBuf> {
    match repo_env.map(str::trim).filter(|s| !s.is_empty()) {
        Some(r) => Some(expand_tilde(r)),
        None => git_root(cwd),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::{self, Scope};

    #[test]
    fn find_manifests_locates_the_existing_sealed_secret() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let secret =
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\n  namespace: prod\nstringData:\n  P: dummy\n";
        let sealed = seal::seal_yaml(secret, &seal::tests::test_key().to_public_key(), Scope::Strict).unwrap().0;
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
        let no_ns = sealed.replace("metadata:\n  name: db\n  namespace: prod\n", "metadata:\n  name: db\n");
        w("overlays/prod/db.yaml", &no_ns);
        w("overlays/prod/kustomization.yaml", "namespace: prod\nresources: [db.yaml]\n");
        w("overlays/dev/db.yaml", &no_ns);
        w("overlays/dev/kustomization.yaml", "namespace: dev\nresources: [db.yaml]\n");
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("apps"), root.join("link")).unwrap();
        let hits = find_manifests(root, "prod", "db");
        let found: Vec<String> = hits.iter().map(|f| display_path(&f.path, root).replace('\\', "/")).collect();
        assert_eq!(found, vec!["apps/all.yaml", "apps/prod/db.yaml", "overlays/prod/db.yaml"]);
        assert_eq!(hits[2].doc["metadata"]["namespace"], "prod", "filled in for the controller check");
        assert!(find_manifests(root, "prod", "nope").is_empty());
        assert_eq!(git_root(&root.join("apps/prod")), Some(std::fs::canonicalize(root).unwrap()));
        assert_eq!(git_root(tempfile::tempdir().unwrap().path()), None);
    }

    #[test]
    fn new_files_go_to_the_last_folder_then_the_repo() {
        let repo = tempfile::tempdir().unwrap();
        let last = tempfile::tempdir().unwrap();
        let l = last.path().display().to_string();
        assert_eq!(
            new_file_path("sealed-db.yaml", Some(&l), Some(repo.path())),
            pretty_path(&last.path().join("sealed-db.yaml"))
        );
        assert_eq!(
            new_file_path("sealed-db.yaml", None, Some(repo.path())),
            pretty_path(&repo.path().join("sealed-db.yaml"))
        );
        assert_eq!(new_file_path("sealed-db.yaml", Some(""), None), "sealed-db.yaml");
        let shown = pretty_path(&repo.path().join("x.yaml"));
        assert!(Path::new(&shown).is_absolute() || shown.starts_with('~'), "{shown}");
    }
}
