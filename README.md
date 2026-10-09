# kseal

Kubernetes Secrets in your terminal: base64 encode/decode, `.env` → Secret YAML,
and native SealedSecret sealing (no `kubeseal` binary needed). Read-only against
the cluster.

> Work in progress — Rust rewrite of `b64-k8s-secrets-tool`. TUI coming next.

```bash
kseal                                   # TUI (WIP)
kseal encode hunter2                    # aGVudGVyMg==
kseal gen -f prod.env --name db -n prod > secret.yaml
kseal show -f secret.yaml [--reveal]
kseal get db -n prod --format env       # read-only fetch
kseal seal -f secret.yaml --scope strict -o sealed.yaml
kseal validate -f sealed.yaml
kseal cert > cert.pem                   # then: kseal seal --cert cert.pem (offline)
```
