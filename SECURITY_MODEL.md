# Treeward Security Model

Treeward is a fleet control plane for [Shirudo](https://docs.shirudo.dev/) kernel micro-patches (eBPF upatches) and TPM 2.0 attestation. This document describes Treeward's trust boundaries, cryptographic primitives, and known early-preview limitations.

## Trust Boundaries

```
Operator CLI / Automation
        │  Bearer token (SHA-256 hashed at rest)
        ▼
┌───────────────────────────────────────────┐
│  Control Plane (`treeward-api`)           │
│  - Holds Ed25519 tree signing key         │
│  - Never holds Shirudo ML-DSA-87 keys     │
│  - Verifies TPM quotes (`shirudo attest`) │
└───────────────────┬───────────────────────┘
                    │  Connector token (enrolled via bootstrap token)
                    ▼
┌───────────────────────────────────────────┐
│  Cluster Connector (`treeward-connector`) │  ◄── Untrusted for policy integrity
│  - Relays desired state, inventory,       │      when agent pins TREEWARD_TREE_PUBKEY
│    reports, and attestation quotes        │
└───────────────────┬───────────────────────┘
                    │  Optional local bearer token (`TREEWARD_LOCAL_TOKEN`)
                    ▼
┌───────────────────────────────────────────┐
│  Node Agent (`treeward-agent`)            │
│  - Verifies Ed25519 hash-chained TreeOps  │
│    against pinned `TREEWARD_TREE_PUBKEY`  │
│  - Replays selectors locally              │
│  - Invokes `shirudo-runtime`              │
└───────────────────┬───────────────────────┘
                    │  Local CLI / signed `.upatch` & `.unload.upatch` files
                    ▼
┌───────────────────────────────────────────┐
│  Shirudo Kernel LSM (`shirudo-runtime`)   │
│  - Enforces ML-DSA-87 artifact & unload   │
│    directive signatures in kernel         │
│  - Produces hardware-backed TPM 2.0 quotes│
└───────────────────────────────────────────┘
```

### Boundary Summary

- **Control Plane (`treeward-api`):** Authoritative issuer of fleet rollout state (`TreeOp` log), operator token lifecycle, and attestation campaigns. Compromising the control plane's Ed25519 signing key allows issuing rollout directives for already-signed Shirudo artifacts, **not** forging new kernel eBPF code or unload directives (which require the offline operator ML-DSA-87 key).
- **Cluster Connector (`treeward-connector`):** Acts as a relay between cluster node agents and the control plane. When node agents pin `TREEWARD_TREE_PUBKEY`, a compromised connector (or MITM between control plane and agent) **cannot** tamper with digests, selectors, timestamps, op ordering, or unsigned `desired.Nodes` maps, and cannot roll back an active agent to an older tree sequence.
- **Node Agent (`treeward-agent`):** Runs on nodes to reconcile desired upatches and collect attestation evidence. For `--runtime=shirudo`, signed tree verification is **on by default** and fails closed if `TREEWARD_TREE_PUBKEY` is missing (for `stub`/`mock` runtimes it defaults to off; explicit `TREEWARD_VERIFY_TREE=1|true` enables it for any runtime and `0|false` disables it with a loud warning). With verification enabled, the agent verifies the full Ed25519 hash chain from `seq=1..N`, enforces monotonic `TreeSeq`, ignores the unsigned `desired.Nodes` map, and computes its own desired digests locally from its own node labels. If verification fails, the agent logs the failure and does not call `Runtime.Apply`.
- **Shirudo Kernel LSM (`shirudo-runtime`):** Final enforcement boundary on the host. Verifies post-quantum ML-DSA-87 signatures on `.upatch` artifacts and `.unload.upatch` directives independently of Treeward. Treeward also tracks owned upatches in `<SHIRUDO_STATE_DIR>/owned.json` so externally loaded upatches are never unloaded.

## Cryptographic Primitives

| Mechanism | Algorithm / Construction | Where Enforced |
|---|---|---|
| Kernel eBPF upatch & unload directive signing | **ML-DSA-87** (Shirudo) | Verified by Shirudo kernel LSM / `shirudo-runtime`; Treeward never holds the ML-DSA-87 private key. |
| Node platform attestation | **TPM 2.0 quotes** with fresh 128-bit campaign nonces | Generated via `shirudo-runtime attest --nonce <hex>` and verified on the control plane via `shirudo attest verify` (with AK name pinning and optional `--expect-config-root` / `--expect-config-pcr`). |
| Rollout log integrity & chaining | **Ed25519** signatures + **SHA-256** hash chain (`TreeOp.PrevHash`) | Signed by `treeward-api` over domain-separated canonical JSON (`treeward-tree-op-v1\n` covering `seq`, `prev_hash`, `op`, `digest`, sorted `selector` KV slice, `binding_id`, and UTC RFC3339Nano `at`); chained via `sha256:` over `treeward-tree-op-hash-v1\n` + canonical payload + signature. Verified end-to-end by `treeward-agent` when `TREEWARD_TREE_PUBKEY` is configured. |
| Operator API authentication | **256-bit random bearer tokens**, stored as **SHA-256** hashes | Verified in `treeward-api` using `crypto/subtle.ConstantTimeCompare`, with expiration, revocation, role-based access control (`viewer`, `operator`, `approver`, `admin`), and two-person approval separation of duties. |
| Connector & local agent auth | Shared secrets (`TREEWARD_ENROLL_TOKEN`, `TREEWARD_ADMIN_BOOTSTRAP_TOKEN`, enrolled connector tokens, fail-closed `TREEWARD_LOCAL_TOKEN`) | Constant-time comparison on enroll, admin-bootstrap, connector (SHA-256 hashed), and local agent tokens; connector tokens are cluster-scoped. |

> **Public key pinning requirement:** `DesiredState.TreePubKey` is included in `GET /v1/desired` responses strictly for observability and bootstrap discovery. Operators should obtain the control plane's Ed25519 public key from `GET /v1/desired` (`treePubKey` field) and pin it out-of-band via `TREEWARD_TREE_PUBKEY` on each agent rather than trusting `DesiredState.TreePubKey` dynamically at runtime. For `--runtime=shirudo`, verification is enabled by default and fails closed when `TREEWARD_TREE_PUBKEY` is unset.

## Operator RBAC & Separation of Duties

Operator API tokens carry an explicit role (`role` column in `api_tokens`; defaults to `admin` when omitted or migrated from pre-RBAC databases). Token minting (`POST /v1/tokens`) remains gated on the dedicated `TREEWARD_ADMIN_BOOTSTRAP_TOKEN`.

| Endpoint | `viewer` | `operator` | `approver` | `admin` |
|---|---|---|---|---|
| `GET /v1/nodes`, `/v1/artifacts`, `/v1/bindings`, `/v1/bindings/{id}`, `/v1/tree`, `/v1/audit`, `/v1/attest/campaigns`, `/v1/attest/campaigns/{id}` | Allow | Allow | Allow | Allow |
| `POST /v1/artifacts`, `POST /v1/bindings`, `POST /v1/bindings/{id}/canary`, `POST /v1/bindings/{id}/promote`, `POST /v1/attest/campaigns` | 403 | Allow | 403 | Allow |
| `POST /v1/bindings/{id}/approve` | 403 | 403 | Allow* | Allow* |
| `POST /v1/bindings/{id}/revert` | 403 | Allow | Allow | Allow |
| `GET /v1/tokens`, `DELETE /v1/tokens/{id}` | 403 | 403 | 403 | Allow |
| `POST /v1/tokens` | Admin bootstrap token only (`TREEWARD_ADMIN_BOOTSTRAP_TOKEN`) |

- **Authenticated actor binding:** `CreatedBy`, `ApprovedBy`, and all operator audit events are derived exclusively from the authenticated bearer token's principal (`token.Name`, falling back to `token.ID`). Client-supplied `actor` or `createdBy` fields in JSON request bodies are ignored when authentication is enabled.
- **Two-person separation of duties (`*`):** By default (fail-closed), `POST /v1/bindings/{id}/approve` rejects (`403 Forbidden`) any attempt by the principal who created a binding (`binding.CreatedBy`) to approve that same binding — even when using an `admin` token. Single-operator dev/demo environments may explicitly opt out via `TREEWARD_ALLOW_SELF_APPROVE=true` (logs a startup warning; must not be enabled in production).

## Upgrading Legacy Rollout Trees (Tree-Format Migration)

Agents with signed tree verification enabled (`TREEWARD_VERIFY_TREE=true`, which is the default for `--runtime=shirudo`) verify the entire Ed25519 hash chain from `seq=1..N` using the domain-separated `treeward-tree-op-v1` canonical payload and `PrevHash` links. Pre-hash-chain `TreeOp` entries written by earlier development builds lack `prevHash` and use an older signing payload, so verifying agents **fail closed** and refuse to apply desired state until the tree is migrated.

For fresh or disposable deployments, deleting `TREEWARD_DATA_DIR/treeward.db` and re-creating bindings is sufficient. For existing deployments where currently loaded Shirudo upatches must remain enforced during the upgrade, use the following zero-unload cutover procedure:

1. **Stop `treeward-agent` on managed nodes.** Stopping the agent prevents it from reconciling against an empty tree during the reset. Already-loaded Shirudo eBPF upatches remain loaded and enforced in the kernel (`shirudo-runtime status --json`).
2. **Stop `treeward-connector` and `treeward-api`, then back up the database.** Copy `TREEWARD_DATA_DIR/treeward.db` (and `-wal`/`-shm` sidecars if present) to a safe rollback location.
3. **Reset the legacy `tree` array in SQLite.** In the `kv` table (`key = 'state'`), set the JSON snapshot's `tree` array to `[]` while preserving `nodes`, `artifacts`, `bindings`, `connectors`, and `audit` (append a `tree.reset` audit event recording the backup path and reason). *(Note: SQLite `api_tokens` schema migration for the RBAC `role` column happens automatically on `treeward-api` startup.)*
4. **Start `treeward-api` and `treeward-connector`.** Confirm `/healthz` returns `ok` and `GET /v1/tree` returns `[]`.
5. **Re-issue active bindings under the signed hash-chain format.** For each active upatch binding, run `create-binding`, `approve` (with a distinct approver token), `canary`, and `promote`. Verify via `GET /v1/tree` that `seq=1` is the chain root and every subsequent op includes a `prevHash`.
6. **Upgrade and start `treeward-agent` with a pinned public key.** Deploy the updated agent binary, configure `TREEWARD_TREE_PUBKEY` out-of-band (from the `treeward-api` startup log `local signer pubkey=<hex>` or `GET /v1/desired` `treePubKey`), and start `treeward-agent`. Confirm startup logs report `verify_tree=true`, loaded upatches remain intact, and an attestation campaign passes.

## Known Early-Preview Limitations

Treeward is currently in early preview (`main`). Operators deploying beyond local evaluation should account for the following limitations:

1. **Static bearer tokens & single-cluster admin bootstrap (no OIDC/SSO yet):** While operator API tokens now enforce role-based access control (`viewer`, `operator`, `approver`, `admin`) and two-person approval separation of duties, identity is still backed by static bearer tokens minted with a single cluster-wide `TREEWARD_ADMIN_BOOTSTRAP_TOKEN` rather than federated OIDC/SSO or short-lived mTLS client certificates. (`TREEWARD_AUTH=off` and `TREEWARD_ALLOW_SELF_APPROVE=true` exist solely as local-dev escape hatches and must never be enabled in shared or production environments.)
2. **Single-node SQLite control plane & local key file:** Control-plane state is persisted in a single SQLite database (`TREEWARD_DATA_DIR/treeward.db`) without built-in HA replication. The tree-signing Ed25519 key is stored locally on disk (`TREEWARD_KEY_DIR/ed25519.priv`, mode `0600`); the `signer.Signer` interface is designed for KMS/HSM backends (e.g., GCP KMS), which are not yet wired in.
3. **Transport security (TLS termination):** `treeward-api` supports native TLS 1.3 via `TREEWARD_TLS_CERT` and `TREEWARD_TLS_KEY`, while `treeward-connector` listens on `127.0.0.1:8090` over HTTP by default. Production deployments should enable native TLS on `treeward-api` or terminate TLS / mTLS via a reverse proxy, ingress controller, or service mesh to protect bearer tokens and API traffic in transit.
4. **In-memory agent rollback high-water mark:** Agents enforce monotonic `TreeSeq >= lastVerifiedSeq` in memory to prevent mid-run truncation or rollback attacks, but `lastVerifiedSeq` is not yet persisted to disk across agent restarts.
5. **Connector token storage:** While operator API tokens are stored exclusively as SHA-256 hashes, enrolled connector tokens are currently persisted in the control-plane SQLite state snapshot.
6. **Stub runtime is non-enforcing:** The default quickstart runtime (`TREEWARD_RUNTIME=stub`) simulates nodes in memory with fixture attestation quotes and performs no eBPF loading or TPM verification. Production deployments must use `TREEWARD_RUNTIME=shirudo` and configure `SHIRUDO_BIN` on `treeward-api`.
