#!/usr/bin/env bash
# End-to-end test against a REAL sealed-secrets controller, in a throwaway
# KinD cluster that this script creates and deletes.
#
#   kseal seal  →  kubectl apply the SealedSecret  →  the controller's Secret
#   must hold exactly the values that went in — for all three scopes, plus
#   the scope semantics (namespace-wide survives a rename, cluster-wide a
#   move to another namespace). Then `kseal validate` must pass on a good
#   SealedSecret and fail on a renamed strict one.
#
# Safe by construction: it uses its own kubeconfig file (your ~/.kube/config
# is never read or written) and refuses to touch a cluster it didn't create.
#
# Needs: docker, kind, kubectl, and cargo (or KSEAL_BIN=/path/to/kseal).
#
# Env:
#   KSEAL_E2E_CLUSTER     cluster name                  (default: kseal-e2e)
#   SEALED_SECRETS_VERSION controller release to test   (default: v0.40.0)
#   KSEAL_BIN             prebuilt kseal binary          (default: cargo build)
#   KSEAL_E2E_KEEP=1      keep the cluster afterwards for debugging
set -euo pipefail

CLUSTER="${KSEAL_E2E_CLUSTER:-kseal-e2e}"
SS_VERSION="${SEALED_SECRETS_VERSION:-v0.40.0}"
CTX="kind-${CLUSTER}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

for tool in docker kind kubectl; do
  command -v "$tool" >/dev/null || { echo "e2e: $tool is required" >&2; exit 2; }
done

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "e2e: a KinD cluster named '$CLUSTER' already exists — refusing to install into it." >&2
  echo "     Delete it (kind delete cluster --name $CLUSTER) or set KSEAL_E2E_CLUSTER." >&2
  exit 2
fi

WORK="$(mktemp -d)"
export KUBECONFIG="$WORK/kubeconfig"
created=0
pass=0
fail=0

cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$created" = 1 ]; then
    echo "--- controller logs (last 40 lines) ---"
    kubectl -n kube-system logs deploy/sealed-secrets-controller --tail=40 2>/dev/null || true
  fi
  if [ "$created" = 1 ] && [ "${KSEAL_E2E_KEEP:-}" != 1 ]; then
    echo "e2e: deleting cluster $CLUSTER"
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  elif [ "$created" = 1 ]; then
    echo "e2e: keeping cluster $CLUSTER (KUBECONFIG=$KUBECONFIG)"
  fi
  [ "${KSEAL_E2E_KEEP:-}" = 1 ] || rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT

ok() { echo "  ✓ $*"; pass=$((pass + 1)); }
bad() { echo "  ✗ $*" >&2; fail=$((fail + 1)); }

if [ -n "${KSEAL_BIN:-}" ]; then
  KSEAL="$KSEAL_BIN"
else
  echo "e2e: building kseal"
  cargo build --quiet --manifest-path "$ROOT/Cargo.toml"
  KSEAL="$ROOT/target/debug/kseal"
fi

echo "e2e: creating KinD cluster $CLUSTER"
created=1
kind create cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" --wait 180s >/dev/null

echo "e2e: installing sealed-secrets $SS_VERSION"
kubectl apply -f "https://github.com/bitnami-labs/sealed-secrets/releases/download/${SS_VERSION}/controller.yaml" >/dev/null
kubectl -n kube-system rollout status deploy/sealed-secrets-controller --timeout=180s >/dev/null
kubectl create namespace e2e-a >/dev/null
kubectl create namespace e2e-b >/dev/null

# Values that would break a naive implementation: quotes, unicode, a
# multi-line PEM-ish block, YAML-ambiguous words, '=' and '#' inside values.
cat >"$WORK/app.env" <<'EOF'
DB_PASSWORD="p@ss w0rd \"quoted\" #not-a-comment"
API_TOKEN=abc=def==
GREETING="καλημέρα 🔐"
PEM="-----BEGIN KEY-----\nMIIBOgIBAAJBAKj34GkxFhD9\n-----END KEY-----"
FLAG=no
EMPTY=
EOF
# Expected values (a function, not an associative array: macOS ships bash 3.2).
KEYS="DB_PASSWORD API_TOKEN GREETING PEM FLAG EMPTY"
want() {
  case "$1" in
    DB_PASSWORD) printf '%s' 'p@ss w0rd "quoted" #not-a-comment' ;;
    API_TOKEN) printf '%s' 'abc=def==' ;;
    GREETING) printf '%s' 'καλημέρα 🔐' ;;
    PEM) printf '%s\n%s\n%s' '-----BEGIN KEY-----' 'MIIBOgIBAAJBAKj34GkxFhD9' '-----END KEY-----' ;;
    FLAG) printf '%s' 'no' ;;
    EMPTY) ;;
  esac
}
NKEYS=$(wc -w <<<"$KEYS" | tr -d " ")

# wait_secret NS NAME — the controller unseals asynchronously.
wait_secret() {
  for _ in $(seq 1 60); do
    kubectl -n "$1" get secret "$2" >/dev/null 2>&1 && return 0
    sleep 1
  done
  kubectl -n "$1" get sealedsecret "$2" -o yaml >&2 || true
  return 1
}

# check_values NS NAME — every key decodes to exactly what went in.
check_values() {
  local ns=$1 name=$2 k got exp keys
  # shellcheck disable=SC2016 # a go-template, not shell
  keys="$(kubectl -n "$ns" get secret "$name" -o go-template='{{range $k, $v := .data}}{{$k}} {{end}}')"
  for k in $KEYS; do
    # Append a sentinel so $(…) can't strip trailing newlines from the value.
    got="$(kubectl -n "$ns" get secret "$name" -o "jsonpath={.data.$k}" | base64 -d; echo x)"
    got="${got%x}"
    exp="$(want "$k"; echo x)"
    exp="${exp%x}"
    if [ "$got" == "$exp" ]; then
      ok "$ns/$name $k"
    else
      bad "$ns/$name $k: got $(printf %q "$got"), want $(printf %q "$exp")"
    fi
  done
  if [ "$(wc -w <<<"$keys" | tr -d " ")" -eq "$NKEYS" ]; then ok "$ns/$name has exactly $NKEYS keys"; else bad "$ns/$name keys: $keys"; fi
}

# seal SCOPE NAME — generate + seal with kseal (cert fetched via the controller).
seal() {
  "$KSEAL" gen -f "$WORK/app.env" --name "$2" -n e2e-a -o "$WORK/$2.yaml" >/dev/null 2>&1
  "$KSEAL" seal -f "$WORK/$2.yaml" --context "$CTX" --scope "$1" -o "$WORK/$2.sealed.yaml" >/dev/null
}

echo "e2e: strict"
seal strict e2e-strict
kubectl apply -f "$WORK/e2e-strict.sealed.yaml" >/dev/null
if wait_secret e2e-a e2e-strict; then check_values e2e-a e2e-strict; else bad "strict: no Secret produced"; fi

echo "e2e: namespace-wide (applied under a new name)"
seal namespace-wide e2e-nswide
sed 's/e2e-nswide$/e2e-nswide-renamed/' "$WORK/e2e-nswide.sealed.yaml" | kubectl apply -f - >/dev/null
if wait_secret e2e-a e2e-nswide-renamed; then check_values e2e-a e2e-nswide-renamed; else bad "namespace-wide: no Secret produced"; fi

echo "e2e: cluster-wide (applied in another namespace)"
seal cluster-wide e2e-cwide
sed 's/^\(  *namespace: \)e2e-a$/\1e2e-b/' "$WORK/e2e-cwide.sealed.yaml" | kubectl apply -f - >/dev/null
if wait_secret e2e-b e2e-cwide; then check_values e2e-b e2e-cwide; else bad "cluster-wide: no Secret produced"; fi

echo "e2e: validate"
if "$KSEAL" validate -f "$WORK/e2e-strict.sealed.yaml" --context "$CTX" 2>/dev/null; then
  ok "validate accepts the strict SealedSecret"
else
  bad "validate rejected a good SealedSecret"
fi
sed 's/e2e-strict$/e2e-strict-renamed/' "$WORK/e2e-strict.sealed.yaml" >"$WORK/renamed.yaml"
grep -q 'name: e2e-strict-renamed' "$WORK/renamed.yaml" || bad "rename didn't apply"
if "$KSEAL" validate -f "$WORK/renamed.yaml" --context "$CTX" 2>/dev/null; then
  bad "validate accepted a renamed strict SealedSecret"
else
  ok "validate rejects a renamed strict SealedSecret"
fi

# kseal itself only reads: its own fetch must agree with what kubectl sees.
if [ "$("$KSEAL" get e2e-strict -n e2e-a --context "$CTX" --format env | grep -c .)" -eq "$NKEYS" ]; then
  ok "kseal get reads the unsealed Secret"
else
  bad "kseal get output differs"
fi

echo
echo "e2e: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
