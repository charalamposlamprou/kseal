# kseal

Kubernetes Secrets in your terminal: base64 encode/decode, `.env` → Secret YAML,
and native SealedSecret sealing and validation. You don't need the `kubeseal`
binary. kseal ships as one static binary with a TUI and scriptable subcommands.

> **Read-only against the cluster.** kseal lists contexts, namespaces and
> secrets, reads a Secret, fetches the sealed-secrets certificate and asks the
> controller to verify a SealedSecret. It never creates, patches, replaces or
> deletes anything; applying the output is up to you (or your GitOps). The
> mutating `kube::Api` methods are banned in `clippy.toml`, so CI fails if one
> sneaks in.

![kseal TUI: the Encode tab](docs/encode.png)

## Install

**Homebrew** (macOS, Linux)

```bash
brew tap charalamposlamprou/kseal https://github.com/charalamposlamprou/kseal
brew trust charalamposlamprou/kseal     # Homebrew asks once for third-party taps
brew install kseal
```

**Shell installer** (macOS, Linux)

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/charalamposlamprou/kseal/releases/latest/download/kseal-installer.sh | sh
```

**PowerShell installer** (Windows; an `.msi` is also attached to each release)

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/charalamposlamprou/kseal/releases/latest/download/kseal-installer.ps1 | iex"
```

**From source** (Rust 1.85+)

```bash
cargo install --locked --git https://github.com/charalamposlamprou/kseal
```

Prebuilt binaries cover macOS (Apple Silicon and Intel), Linux x86_64 and
arm64 (static musl, plus x86_64 glibc) and Windows x86_64.

## Usage

### TUI

Run `kseal` with no arguments. It reads your kubeconfig (`$KUBECONFIG` or
`~/.kube/config`) and picks the current context.

| Tab | What it does |
|---|---|
| **Encode** | Live single-value base64 encoder. `.env` → Secret: open a `.env` or Secret YAML, or load a Secret from the cluster, then edit the key/value table, set name / namespace / type and generate the YAML. The type is guessed from the keys (`tls.crt` + `tls.key` → `kubernetes.io/tls`, …) until you pick one. |
| **Decode** | Live single-value decoder. Open a Secret YAML (multi-document files and `kind: List` work) and get a masked table of its decoded values. |
| **Seal** | Seal the Encode tab's YAML for a context: strict, namespace-wide or cluster-wide scope. The controller is auto-detected per context (editable), or you can seal offline with a certificate. **Validate** asks the controller whether it can decrypt the result. |

Values stay masked until you reveal them. Labels, annotations and `immutable`
survive a load → generate round-trip, and binary values pass through
untouched. Malformed metadata that had to be dropped gets a persistent warning
on every tab. Saved files are written owner-only (`0600`).

#### Keys

| Key | Action |
|---|---|
| `↑` `↓` `←` `→` | Move between fields, following the layout. Inside a table, a YAML pane or a text box they move or scroll there first, and continue to the neighbouring field at the edge |
| `Tab` / `Shift-Tab` | Next / previous field |
| `F1` `F2` `F3` / `Ctrl+N` `Ctrl+P` | Switch tabs |
| `Ctrl+G` | Generate Secret YAML |
| `Ctrl+O` | Open a file: `.env` or Secret YAML, detected automatically (Seal tab: certificate) |
| `Ctrl+L` | Load the selected Secret from the cluster |
| `Ctrl+E` / `Ctrl+T` | Seal / validate |
| `Ctrl+D` | Seal tab: diff the output with a file, or (empty path) the live Secret |
| `Ctrl+Y` | Copy whatever is focused |
| `Ctrl+S` | Save the YAML / SealedSecret |
| `Ctrl+K` | Clear the focused thing |
| `Ctrl+R` | Reload contexts (also clears the controller cache) |
| `Ctrl+X` | Show / hide masked values |
| `?` | Help |
| `Ctrl+C` / `Ctrl+Q` | Quit |

In a key table: `a` add, `d` delete, `Enter` edit, `e` edit the value in
`$EDITOR` (for multi-line values such as PEM keys or JSON), `v` / `V` show one
or all. Pickers open with `Enter` and filter as you type. In the diff viewer:
`n` / `N` next / previous change, `Ctrl+X` reveal values, `Esc` close.

#### Saving (Seal tab)

`Ctrl+S` first looks for where this SealedSecret already lives, so a re-seal
updates the right file. It searches the repository (`KSEAL_REPO` if set, else
the Git repo kseal was started in) for a SealedSecret with the same namespace
and name. Overlays count too, when the folder's `kustomization.yaml` sets the
namespace. Then it asks the controller you sealed for whether it can decrypt
each match, with the same read-only check as Ctrl+T, because the same Secret
often exists once per environment.

- **Matches found:** a "Save to" list, each labelled `this cluster` or
  `another cluster`, plus a new file. This cluster's match is preselected.
  Picking another cluster's file warns you first. The choice opens the usual
  prompt, so you can still edit it.
- **No match:** the prompt suggests a full path, in this order: the folder you
  saved to last this session, `<repo>/sealed-<name>.yaml`, or the current
  folder.

```bash
export KSEAL_REPO=~/src/gitops-repo   # optional, e.g. in ~/.zshrc
```

#### Diff (Seal tab)

`Ctrl+D` compares the sealed output with a local Secret or SealedSecret
manifest. Leave the path empty to compare with the **live Secret** it would
replace, read-only, in the context it was sealed for. The comparison is
semantic, and multi-document files and `kind: List` work: keys added (`+`),
removed (`-`) or modified (`~`), plus type, scope, labels and annotations.
Server-managed metadata and controller tracking stamps are ignored.

kseal still holds the YAML it sealed, so the new values are known. Against a
plain Secret, including the live one, they're really compared. Against
another SealedSecret, the old side stays `‹encrypted›`, since only the
controller can decrypt it. Values are masked (the mask has a fixed width, so it
doesn't leak length) until `Ctrl+X`.

Over SSH, copying uses OSC 52, so the text lands in your *local* clipboard
(your terminal must allow OSC 52; in tmux, enable `set-clipboard`).

### Command line

Every feature also works in scripts:

```bash
kseal encode hunter2                          # aHVudGVyMg==
echo -n aHVudGVyMg== | kseal decode           # hunter2
kseal gen -f prod.env --name db -n prod > secret.yaml
kseal show -f secret.yaml [--reveal]          # decoded keys, masked by default
kseal get db -n prod --format env             # read a Secret as .env (or --format yaml)
kseal seal -f secret.yaml --scope strict -o sealed.yaml
kseal validate -f sealed.yaml                 # exit 1 if the controller can't decrypt it
kseal cert > cert.pem                         # then, offline: kseal seal --cert cert.pem
```

`--context` (or `KSEAL_CONTEXT`) selects a kubeconfig context. The controller
is auto-detected, or set it with `--controller-name` / `--controller-namespace`.
Run `kseal <command> --help` for every flag.

### From an AI agent

Coding agents (Claude Code, Cursor, Codex, …) can drive kseal with no MCP
server. Anything a command prints lands in the model's context, so split the
work: **the agent handles paths, contexts and git; you edit the values.**

1. **Fetch** (agent): `kseal-fetch CONTEXT NAMESPACE NAME` copies the live
   Secret to `~/.kseal-secrets/<context>/<namespace>/<name>.env`, outside any
   git repo and owner-only. It prints key names only.
2. **Edit** (you): add, change or remove `KEY=value` lines in that file.
3. **Seal** (agent): `kseal-seal CONTEXT NAMESPACE NAME path/in/gitops-repo.yaml --push`
   seals for that context's controller and validates the result. It then
   commits only that file and pushes the current branch. It never applies
   anything: Argo CD or Flux syncs it from git. It prints key names, which
   keys were added, changed or removed compared with the live Secret, and
   the commit.

**A new service** has no live Secret to fetch, so the agent starts one from
the key names instead. Those come from the service's config (its manifest,
`.env.example`, docs) and aren't secret:

```sh
kseal-fetch CONTEXT NAMESPACE NAME --new STRIPE_KEY WEBHOOK_SECRET
```

This writes the same owner-only `.env` with empty `KEY=` lines. It refuses if
the Secret already exists, or if it can't tell (unreachable cluster, no
access). You fill in the values, and the agent seals as usual. `kseal-seal`
refuses while any value is still empty, so a half-filled template is never
committed.

Both scripts are plain Bash (macOS bash 3.2 works) and need only kseal and
git. Save them on your `PATH`, e.g. in `~/.local/bin`, and `chmod +x` them.

<details>
<summary><code>kseal-fetch</code></summary>

```bash
#!/usr/bin/env bash
# kseal-fetch CONTEXT NAMESPACE NAME [FILE.env] [--force] [--new KEY...]
# Live Secret → an owner-only .env outside git, for you to edit.
# --new KEY... starts a Secret that isn't in the cluster yet: empty KEY= lines.
# Prints key names only. Won't overwrite unsealed edits without --force.
set -euo pipefail
die() { echo "kseal-fetch: $*" >&2; exit 1; }
usage="usage: kseal-fetch CONTEXT NAMESPACE NAME [FILE.env] [--force] [--new KEY...]"
force=0 new=0; args=() keys=()
for a in "$@"; do
  if [ "$a" = --force ]; then force=1
  elif [ "$a" = --new ]; then new=1
  elif [ "$new" = 1 ]; then keys+=("$a")
  else args+=("$a"); fi
done
[ ${#args[@]} -ge 3 ] || die "$usage"
if [ "$new" = 1 ]; then
  [ ${#keys[@]} -ge 1 ] || die "--new needs at least one KEY"
  for k in "${keys[@]}"; do
    case "$k" in [!A-Za-z_]*|*[!A-Za-z0-9_]*) die "'$k' isn't a valid key name (letters, digits, _)" ;; esac
  done
fi
ctx="${args[0]}" ns="${args[1]}" name="${args[2]}"
env="${args[3]:-$HOME/.kseal-secrets/${ctx//[\/:]/_}/$ns/$name.env}"

# An existing .env may hold unsealed edits. It's safe to replace only if
# kseal-seal stamped exactly this content as sealed.
if [ -e "$env" ] && [ "$force" != 1 ] &&
   [ "$(cut -d' ' -f1 "$env.sealed" 2>/dev/null)" != "$(git hash-object "$env")" ]; then
  die "$env has unsealed edits; seal or delete it, or pass --force"
fi
umask 077
mkdir -p "$(dirname "$env")"
tmp="$(mktemp "$env.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
if [ "$new" = 1 ]; then
  # Only start a new file if the Secret really doesn't exist (404), not when
  # the cluster is unreachable or access is denied.
  if kseal get "$name" -n "$ns" --context "$ctx" >/dev/null 2>"$tmp"; then
    die "$ns/$name already exists in $ctx; fetch it without --new"
  fi
  grep -q 'HTTP 404' "$tmp" || die "couldn't check whether $ns/$name exists in $ctx"
  {
    echo "# new: $ctx $ns/$name at $(date '+%F %R'). Fill in every value. Never commit this file."
    for k in "${keys[@]}"; do echo "$k="; done
  } >"$tmp"
else
  {
    echo "# fetched-from: $ctx $ns/$name at $(date '+%F %R'). Never commit this file."
    kseal get "$name" -n "$ns" --context "$ctx" 2>/dev/null
  } >"$tmp" || die "couldn't read $ns/$name from $ctx"
fi
mv "$tmp" "$env"
trap - EXIT

echo "kseal-fetch: $ctx $ns/$name → $env"
echo "  keys: $(grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' "$env" | tr -d = | tr '\n' ' ')"
```

</details>

<details>
<summary><code>kseal-seal</code></summary>

```bash
#!/usr/bin/env bash
# kseal-seal CONTEXT NAMESPACE NAME OUT.yaml [FILE.env] [--push]
# .env → SealedSecret at OUT.yaml in a GitOps repo: sealed for CONTEXT's
# controller, validated, then committed (and pushed with --push).
# Never applies anything. Prints key names and pass/fail only.
set -euo pipefail
die() { echo "kseal-seal: $*" >&2; exit 1; }
push=0; args=()
for a in "$@"; do [ "$a" = --push ] && push=1 || args+=("$a"); done
[ ${#args[@]} -ge 4 ] || die "usage: kseal-seal CONTEXT NAMESPACE NAME OUT.yaml [FILE.env] [--push]"
ctx="${args[0]}" ns="${args[1]}" name="${args[2]}" out="${args[3]}"
env="${args[4]:-$HOME/.kseal-secrets/${ctx//[\/:]/_}/$ns/$name.env}"

[ -f "$env" ] || die "$env not found; run kseal-fetch first"
# A key left empty (e.g. from `kseal-fetch --new`) is almost always unfinished.
empty="$(sed -nE 's/^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=[[:space:]]*(""|'"''"')?[[:space:]]*$/\2/p' "$env" | tr '\n' ' ')"
[ -z "$empty" ] || die "these keys have no value yet: $empty"
if git -C "$(dirname "$env")" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  die "$env is inside a git repo; keep plaintext out of git"
fi
mkdir -p "$(dirname "$out")"
out="$(cd "$(dirname "$out")" && pwd)/$(basename "$out")"
repo="$(git -C "$(dirname "$out")" rev-parse --show-toplevel 2>/dev/null)" || die "$out isn't inside a git repo"
[ -z "$(git -C "$repo" status --porcelain)" ] || die "$repo has uncommitted changes"

# A stamp next to the .env (outside git) remembers the last seal, so a re-run
# before GitOps has synced doesn't commit the same values again.
stamp="$env.sealed"
if [ -f "$stamp" ] && [ -f "$out" ] &&
   [ "$(cat "$stamp")" = "$(git hash-object "$env") $out" ]; then
  echo "kseal-seal: $env is unchanged since it was sealed to $out; nothing to seal"
  exit 0
fi

umask 077
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT   # EXIT only: an INT/TERM trap would keep running after a kill
kseal gen -f "$env" --name "$name" -n "$ns" -o "$work/plain.yaml" 2>/dev/null ||
  die "couldn't build a Secret from $env"
keys="$(kseal show -f "$work/plain.yaml" | awk 'NF {printf "%s ", $1}')"

# Key names added / changed / removed vs the live Secret. Values are compared
# in memory and never printed.
pairs() { kseal show --reveal -f "$1" 2>/dev/null | awk 'NF {k=$1; v=$0; sub(/^[^ ]+ +/, "", v); print k "\t" v}'; }
if kseal get "$name" -n "$ns" --context "$ctx" --format yaml >"$work/live.yaml" 2>/dev/null; then
  changes="$(awk -F'\t' '
    FNR == NR { old[$1] = $2; next }
    { if (!($1 in old)) a = a " " $1; else if (old[$1] != $2) c = c " " $1; seen[$1] = 1 }
    END { for (k in old) if (!(k in seen)) r = r " " k
          printf "added:%s  changed:%s  removed:%s", a ? a : " -", c ? c : " -", r ? r : " -" }
  ' <(pairs "$work/live.yaml") <(pairs "$work/plain.yaml"))"
  if [ "$changes" = "added: -  changed: -  removed: -" ] && [ -f "$out" ]; then
    echo "kseal-seal: $ns/$name in $ctx already matches $env; nothing to seal"
    exit 0
  fi
else
  changes="live Secret not readable (new, or no access)"
fi
from="$(sed -n 's/^# fetched-from: \([^ ]*\) .*/\1/p' "$env" | head -1)"

# Seal and validate in the temp dir, so a failure never leaves a file in the repo.
kseal seal -f "$work/plain.yaml" --context "$ctx" --scope strict -o "$work/sealed.yaml" 2>/dev/null ||
  die "sealing for $ctx failed"
kseal validate -f "$work/sealed.yaml" --context "$ctx" 2>"$work/validate.err" ||
  die "$(cat "$work/validate.err")"
mv "$work/sealed.yaml" "$out"

git -C "$repo" add -- "$out"
git -C "$repo" commit -q -m "seal: $ns/$name for $ctx" -m "keys: $keys"
commit="$(git -C "$repo" rev-parse --short HEAD)"
echo "$(git hash-object "$env") $out" >"$stamp"
pushed=no
if [ "$push" = 1 ]; then
  git -C "$repo" push -q -u origin HEAD 2>/dev/null || die "committed $commit, but the push failed"
  pushed="$(git -C "$repo" rev-parse --abbrev-ref HEAD)"
fi

echo "kseal-seal: $ctx $ns/$name → $out"
[ -n "$from" ] && [ "$from" != "$ctx" ] && echo "  note:      $env was fetched from $from"
echo "  keys:      $keys"
echo "  vs live:   $changes"
echo "  validated: yes (not applied; GitOps syncs it)"
echo "  commit:    $commit   pushed: $pushed"
```

</details>

How they behave:

- **Your edits are safe.** `kseal-fetch` won't overwrite a `.env` with
  unsealed edits unless you pass `--force`.
- **Re-runs don't add commits.** Every seal produces new ciphertext, so
  `kseal-seal` writes a stamp (`<name>.env.sealed`, a git hash of the `.env`)
  and does nothing if the file hasn't changed since. That holds even before
  GitOps has synced. It also does nothing when the file already matches the
  live Secret.
- **Refusals:** it won't run when the `.env` is inside a git repo, when the
  GitOps repo has uncommitted changes, or when the controller can't decrypt
  the result. A failed seal or validate never leaves a file in the repo.
- **Cross-cluster is allowed.** A file fetched from one context can be sealed
  for another; the summary adds a `note:` line saying where it came from.
- **Repo layout is yours.** For a new Secret, add the file to your
  kustomization (or whatever your GitOps tool reads) in a separate commit,
  along with the Deployment's `envFrom`/`secretKeyRef` that uses it.
- **`--push` pushes the current branch.** For a PR flow, have the agent
  create a branch first.
- **Clean up when you're done.** The plaintext stays on disk until you
  delete it: `rm ~/.kseal-secrets/<context>/<namespace>/<name>.env{,.sealed}`.

**Tell the agent.** Add this to `~/.claude/CLAUDE.md` (Claude Code) or
`AGENTS.md`:

```markdown
## Secrets

- Never read, print, search or copy `.env` files or anything under
  `~/.kseal-secrets/`: no Read tool, `cat`, `grep`, `source`, `cp` into a repo.
  Only pass their path to `kseal-fetch` / `kseal-seal`.
- Fetch with `kseal-fetch`, then stop: I edit the values. For a Secret that
  doesn't exist yet, use `kseal-fetch … --new KEY...` with the key names the
  service expects. When I say "seal",
  run `kseal-seal` with the same context, namespace and name. Report its
  summary. If a key was removed, say so.
- Don't run `kseal get`, `show`, `decode`, `encode` or `gen` yourself, and
  never `kubectl apply` a SealedSecret or `kubectl get secret -o yaml`.
- Never write a secret value in a command, commit, PR or reply. If one shows
  up in output by accident, stop and tell me.
```

**Enforce it.** Instructions alone don't stop anything. Add permission rules,
e.g. in Claude Code's `~/.claude/settings.json`:

```json
{
  "permissions": {
    "allow": ["Bash(kseal-fetch:*)", "Bash(kseal-seal:*)"],
    "deny": [
      "Bash(kseal get:*)", "Bash(kseal show:*)", "Bash(kseal decode:*)",
      "Bash(kseal encode:*)", "Bash(kseal gen:*)",
      "Read(**/.env)", "Read(**/*.env)", "Read(**/.env.*)",
      "Read(~/.kseal-secrets/**)"
    ]
  }
}
```

Rules check the command the agent types, not what a script runs inside, so
the scripts still work. The rules are a backstop, not a sandbox: they match
how a command starts, so `/opt/homebrew/bin/kseal get …`, `command kseal …`
or `cat file.env` may get past them. For real isolation, keep plaintext
where the agent's user can't read it.

If you call kseal directly instead:

- **Pass `--context` on every call.** Agents usually run each command in a
  fresh shell, so an exported `KSEAL_CONTEXT` is gone by the next call, and
  kseal falls back to the kubeconfig's current context: the wrong controller.
- **Commands that print secret values:** `get`, `decode`, `encode`, `gen`
  without `-o` (base64 is still the value), and `show`. Masked `show` prints
  one `•` per character up to 12, so it leaks the length of short values;
  `--reveal` prints them. Safe to show: `seal` and `cert` (ciphertext and the
  public certificate) and `validate` (pass/fail).
- **Read `validate`'s stderr, not just its exit code.** It exits 0 with
  `✓ … can decrypt this SealedSecret`. It exits 1 when the controller
  `cannot decrypt this SealedSecret` (reseal), but also when the input has no
  SealedSecret, no controller is found, or the API call fails (unreachable
  cluster, RBAC denied). Resealing won't fix those.
- **Write `gen`'s output to a file with `-o`, not a pipe,** so a failure
  shows its own error instead of a confusing one from `seal`.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                 # the sealing interop test also runs if `go` is on PATH
scripts/e2e-kind.sh        # opt-in: throwaway KinD cluster + real sealed-secrets controller
```

Pure logic lives in `src/core.rs` (tested). The TUI in `src/tui/` is
Elm-style: `app.rs` holds the state and update logic and never does I/O,
`mod.rs` runs its effects on tokio, and `ui.rs` renders.

## Releasing

Every PR merged into `main` cuts a release; the default bump is patch. Label
the PR `release:minor` or `release:major` to bump higher, or `release:skip`
to merge without releasing. `tag-on-merge.yml` bumps `Cargo.toml` to the new
version, commits it to `main`, pushes the `vX.Y.Z` tag and starts
`release.yml` ([dist](https://github.com/axodotdev/cargo-dist)). That builds
every target and publishes the GitHub release and installers, then
`publish-homebrew.yml` commits the updated formula to `Formula/` in this repo.

No secrets are needed: everything runs on the built-in `GITHUB_TOKEN`. If
`main` is protected, allow GitHub Actions to push to it (the version bump and
the formula are committed there).

To release by hand, push a version tag that matches `Cargo.toml`, then run
`gh workflow run release.yml --ref vX.Y.Z -f tag=vX.Y.Z`.

## License

MIT
