# Treeward

Fleet control plane for [Shirudo](https://docs.shirudo.dev/) — ward of the upatch tree.

Approve → sign → canary → promote → revert. Shirudo loads BPF on the box; Treeward wards the tree across the fleet.

## Quickstart

Run the full control-plane demo locally in a single command.

> **Note:** The quickstart uses **stub agents** (three simulated in-memory nodes with fixture attestation quotes and **no eBPF or kernel enforcement**). For real kernel upatch enforcement with Shirudo, see [Shirudo runtime (advanced)](#shirudo-runtime-advanced) below.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (daemon running)
- [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- `curl`

*(No local Go toolchain is required on Linux — `./bin/treeward` is extracted directly from the `treeward:quickstart` container image. On non-Linux hosts such as macOS, [Go](https://go.dev/dl/) 1.26+ is used as a fallback to build `./bin/treeward`.)*

### Run it

```bash
make quickstart
```

`make quickstart` is idempotent and handles everything from a clean checkout:

1. Checks prerequisites and Docker availability.
2. Generates distinct random `TREEWARD_ENROLL_TOKEN`, `TREEWARD_ADMIN_BOOTSTRAP_TOKEN`, and `TREEWARD_LOCAL_TOKEN` secrets into `.treeward/quickstart.env` (mode `0600`, gitignored) on first run, reusing them on subsequent runs (or honoring explicit env overrides).
3. Creates a dedicated Kind cluster named `treeward-quickstart` (skips creation if it already exists).
4. Builds the `treeward:quickstart` image, loads it into Kind, and extracts `./bin/treeward` from the image (falling back to `go build` on non-Linux hosts).
5. Applies Kubernetes Secrets and `deploy/k8s/treeward.yaml` (automatically restarting workloads if secrets changed on an existing cluster), then waits for `treeward-api`, `treeward-connector`, and `treeward-agent` rollouts.
6. Port-forwards `svc/treeward-api` to `127.0.0.1:8080` in the background (tracked via `.treeward/port-forward.pid`).
7. Mints an operator bearer token (`TREEWARD_TOKEN`) via `POST /v1/tokens` and saves it to `.treeward/quickstart.env`.
8. Runs the end-to-end demo (`scripts/demo.sh`) with pass/fail output per step.

### What the demo shows

`make demo` (run automatically at the end of `make quickstart`) authenticates with `TREEWARD_TOKEN` and verifies the full control-plane lifecycle against the stub fleet:

- **Health & inventory:** confirms the API is reachable and 3 stub nodes (`*-canary`, `*-n1`, `*-n2`) are reporting through the connector.
- **Artifact & binding:** registers a demo artifact (SHA-256 digest) and creates a `draft` binding.
- **Approve:** approves the binding (audit actor derived from the authenticated operator token).
- **Canary:** rolls out to the `treeward.ai/rollout=canary` node only and verifies non-canary nodes remain untouched.
- **Promote:** promotes the binding fleet-wide and verifies all nodes load the digest.
- **Attest:** runs an attestation campaign and verifies stub quotes pass on all nodes.
- **Revert:** reverts the binding and verifies all nodes unload the digest.
- **Audit:** verifies `approve`, `canary`, `promote`, `attest.start`, and `revert` are recorded in the audit log.

To use the CLI interactively after `make quickstart`:

```bash
set -a; source .treeward/quickstart.env; set +a
./bin/treeward nodes
./bin/treeward bindings
./bin/treeward audit
```

### Teardown

```bash
make teardown
```

Stops the background port-forward, deletes the `treeward-quickstart` Kind cluster (without touching any other Kind cluster), and removes `.treeward/`. To preserve `.treeward/quickstart.env` across rebuilds:

```bash
./scripts/teardown.sh --keep-state
```

### Troubleshooting

- **Port `8080` already in use:** Quickstart refuses to clobber another process bound to `127.0.0.1:8080`. Choose an alternate local port:
  ```bash
  TREEWARD_API_PORT=18080 make quickstart
  ```
- **Docker daemon not reachable:** Start Docker Desktop or the `dockerd` service and verify `docker info` succeeds.
- **Pods fail to start or stay Pending:** Inspect cluster state and logs:
  ```bash
  make status
  make logs
  ```
- **401 Unauthorized after changing secrets:** Re-run `make quickstart` with the new `TREEWARD_ENROLL_TOKEN` / `TREEWARD_ADMIN_BOOTSTRAP_TOKEN` / `TREEWARD_LOCAL_TOKEN`; quickstart detects the secret change, restarts the workloads automatically, and mints a fresh operator token.

## Pause on hard fail

After canary, a **hard failure** sets the binding to `paused` (no auto-revert; human chooses revert or continue later). Promote is rejected while paused.

| Trigger | How to demo |
|---------|-------------|
| Attest verify fail on a canary-labeled node | Agent env `TREEWARD_ATTEST_FAIL=<node-id>` (e.g. `treeward-quickstart-control-plane-canary`), then `treeward canary …` + `treeward attest` |
| Upatch load error on canary set | Agent env `TREEWARD_LOAD_FAIL=1`, then canary a binding — stub agent reports `load error: <digest>` |

## Layout

```
cmd/api|connector|agent|treeward
internal/{api,runtime,signer,store,types}
deploy/k8s/treeward.yaml
scripts/{quickstart,demo,teardown}.sh
```

## Shirudo runtime (advanced)

Quickstart runs with `TREEWARD_RUNTIME=stub` (no kernel enforcement). Running with real eBPF upatch enforcement via [Shirudo](https://docs.shirudo.dev/) is a separate, advanced setup on Linux hosts/VMs with `shirudo-runtime` installed and `TREEWARD_RUNTIME=shirudo`:

- **Signed unload directives:** Operators build a signed UNLOAD directive alongside each upatch artifact using the convention `<SHIRUDO_UPATCH_DIR>/<name>.unload.upatch`. Treeward never holds the operator signing key; on revert, the agent invokes `shirudo-runtime upatch unload <SHIRUDO_UPATCH_DIR>/<name>.unload.upatch`. If the directive file is missing, the agent logs an error and skips the unload call.
- **Ownership tracking:** The agent persists the set of upatches that have appeared in a Treeward desired state in `<SHIRUDO_STATE_DIR>/owned.json` (default `/var/lib/treeward-agent/owned.json`). Externally loaded upatches not present in `owned.json` (such as `app-sandbox`) are never unloaded by Treeward.

## Security & configuration

See [`SECURITY_MODEL.md`](SECURITY_MODEL.md) for the threat model, signed tree chain verification, and attestation trust boundaries.

- **Split bootstrap & local tokens:** `api` requires distinct `TREEWARD_ENROLL_TOKEN` (connector enrollment) and `TREEWARD_ADMIN_BOOTSTRAP_TOKEN` (operator token minting). `connector` protects `/v1/local/*` with `TREEWARD_LOCAL_TOKEN` and fails closed if unset; set `TREEWARD_LOCAL_AUTH=off` only for local dev.
- **TLS 1.3:** Set both `TREEWARD_TLS_CERT` and `TREEWARD_TLS_KEY` on `api` or `connector` to serve HTTPS with TLS 1.3 minimum.
