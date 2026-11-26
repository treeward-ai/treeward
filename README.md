# Treeward

Fleet control plane for [Shirudo](https://docs.shirudo.dev/) — ward of the upatch tree.

Approve → sign → canary → promote → revert. Shirudo loads BPF on the box; Treeward wards the tree across the fleet.

## Local MVP

- **Cluster:** Kind `treeward` (`kubectl --context kind-treeward`)
- **Southbound:** stub agents (fake nodes, no eBPF)
- **Signer:** local ed25519 key (GCP KMS later for SaaS)
- **Store:** SQLite on PVC (`/var/treeward/data/treeward.db`)
- **Digests:** real SHA-256 over artifact metadata
- **Components:** API, cluster connector, stub DaemonSet agent, CLI

### Tools (WSL Ubuntu)

```bash
export PATH="$HOME/bin:$HOME/go-sdk/bin:$PATH"
kind version
go version
kubectl get nodes --context kind-treeward
```

### Deploy

```bash
cd ~/src/treeward
make deploy          # build image, kind load, apply manifests
make port-forward    # in another terminal → localhost:8080
make demo            # approve → canary → promote → revert
```

### CLI

```bash
export TREEWARD_API_URL=http://127.0.0.1:8080
./bin/treeward nodes
./bin/treeward attest   # nonce → stub quotes → pass/fail posture
./bin/treeward demo     # approve → canary → promote → attest → revert
./bin/treeward bindings # status includes paused after hard fail
./bin/treeward audit    # look for action=pause
```

### Pause on hard fail

After canary, a **hard failure** sets the binding to `paused` (no auto-revert; human chooses revert or continue later). Promote is rejected while paused.

| Trigger | How to demo |
|---------|-------------|
| Attest verify fail on a canary-labeled node | Agent env `TREEWARD_ATTEST_FAIL=<node-id>` (e.g. `kind-worker-canary`), then `treeward canary …` + `treeward attest` |
| Upatch load error on canary set | Agent env `TREEWARD_LOAD_FAIL=1`, then canary a binding — stub agent reports `load error: <digest>` |

`treeward demo` keeps the happy path (no fail envs).

### Layout

```
cmd/api|connector|agent|treeward
internal/{api,store,signer,types}
deploy/k8s/treeward.yaml
```

### Shirudo runtime revert & ownership

When running the agent with `TREEWARD_RUNTIME=shirudo`:

- **Signed unload directives:** Operators build a signed UNLOAD directive alongside each upatch artifact using the convention `<SHIRUDO_UPATCH_DIR>/<name>.unload.upatch`. Treeward never holds the operator signing key; on revert, the agent invokes `shirudo-runtime upatch unload <SHIRUDO_UPATCH_DIR>/<name>.unload.upatch`. If the directive file is missing, the agent logs an error and skips the unload call.
- **Ownership tracking:** The agent persists the set of upatches that have appeared in a Treeward desired state in `<SHIRUDO_STATE_DIR>/owned.json` (default `/var/lib/treeward-agent/owned.json`). Externally loaded upatches not present in `owned.json` (such as `app-sandbox`) are never unloaded by Treeward.
