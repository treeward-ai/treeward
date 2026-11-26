#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/bin:$HOME/opt/go/bin:$HOME/go-sdk/bin:$HOME/sdk/go/bin:$PATH"

CLUSTER_NAME="${TREEWARD_CLUSTER_NAME:-treeward-quickstart}"
STATE_DIR="${ROOT}/.treeward"
PF_PIDFILE="${STATE_DIR}/port-forward.pid"
KEEP_STATE=0

usage() {
  cat <<EOF
Usage: $0 [--keep-state]

Stops the quickstart port-forward, deletes the Kind cluster '${CLUSTER_NAME}',
and removes local state in .treeward/ (unless --keep-state is passed).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-state)
      KEEP_STATE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf '[teardown] ERROR: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

log() { printf '[teardown] %s\n' "$*"; }

# Safety guard: never accidentally delete a cluster other than quickstart unless explicitly overridden.
if [[ -z "$CLUSTER_NAME" ]]; then
  printf '[teardown] ERROR: CLUSTER_NAME is empty\n' >&2
  exit 1
fi

# 1. Stop background port-forward if running.
if [[ -f "$PF_PIDFILE" ]]; then
  pf_pid="$(cat "$PF_PIDFILE" 2>/dev/null || true)"
  if [[ -n "$pf_pid" ]] && kill -0 "$pf_pid" 2>/dev/null; then
    # Verify the PID belongs to kubectl port-forward before sending SIGTERM.
    cmdline="$(ps -p "$pf_pid" -o args= 2>/dev/null || true)"
    if [[ "$cmdline" == *"port-forward"* ]]; then
      log "Stopping port-forward (pid ${pf_pid})..."
      kill "$pf_pid" 2>/dev/null || true
      for _ in $(seq 1 10); do
        if ! kill -0 "$pf_pid" 2>/dev/null; then
          break
        fi
        sleep 0.5
      done
      if kill -0 "$pf_pid" 2>/dev/null; then
        kill -9 "$pf_pid" 2>/dev/null || true
      fi
    else
      log "PID ${pf_pid} is no longer a kubectl port-forward; skipping kill."
    fi
  fi
  rm -f "$PF_PIDFILE"
else
  log "No port-forward pidfile found."
fi

# 2. Delete only the quickstart Kind cluster.
if command -v kind >/dev/null 2>&1; then
  if kind get clusters 2>/dev/null | grep -Fxq "$CLUSTER_NAME"; then
    log "Deleting Kind cluster '${CLUSTER_NAME}'..."
    kind delete cluster --name "$CLUSTER_NAME"
  else
    log "Kind cluster '${CLUSTER_NAME}' does not exist; skipping."
  fi
else
  log "kind not found in PATH; skipping cluster deletion."
fi

# 3. Clean up .treeward/ state unless --keep-state was requested.
if [[ "$KEEP_STATE" -eq 1 ]]; then
  log "Keeping .treeward/ state (--keep-state)."
else
  if [[ -d "$STATE_DIR" ]]; then
    log "Removing .treeward/ state..."
    rm -rf "$STATE_DIR"
  else
    log "No .treeward/ state directory found."
  fi
fi

log "Teardown complete."
