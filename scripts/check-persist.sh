#!/usr/bin/env bash
# Verify that API state survives a treeward-api pod restart (SQLite on PVC).
#
# Creates a uniquely named marker artifact, restarts the API deployment, and
# checks that the exact marker is still returned. Exits non-zero on any failure.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/bin:$HOME/opt/go/bin:$HOME/go-sdk/bin:$HOME/sdk/go/bin:$PATH"

ENV_FILE="${ROOT}/.treeward/quickstart.env"
PF_PIDFILE="${ROOT}/.treeward/port-forward.pid"
PF_LOGFILE="${ROOT}/.treeward/port-forward.log"

# Preserve caller overrides before sourcing quickstart.env.
CALLER_API_URL="${TREEWARD_API_URL:-}"
CALLER_TOKEN="${TREEWARD_TOKEN:-}"
CALLER_CONTEXT="${CONTEXT:-}"
CALLER_NAMESPACE="${TREEWARD_NAMESPACE:-}"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

TREEWARD_API_URL="${CALLER_API_URL:-${TREEWARD_API_URL:-http://127.0.0.1:8080}}"
TREEWARD_TOKEN="${CALLER_TOKEN:-${TREEWARD_TOKEN:-}}"
CONTEXT="${CALLER_CONTEXT:-kind-${TREEWARD_CLUSTER_NAME:-treeward-quickstart}}"
NAMESPACE="${CALLER_NAMESPACE:-${TREEWARD_NAMESPACE:-treeward}}"

fail() { echo "FAIL: $*" >&2; exit 1; }

[[ -n "$TREEWARD_TOKEN" ]] || fail "TREEWARD_TOKEN is not set (run 'make quickstart' first or export it)"

cd "$ROOT"

# api METHOD PATH [JSON_BODY] -- authenticated request; fails on HTTP error.
api() {
  local method="$1" path="$2" body="${3:-}"
  local -a args=(-fsS --max-time 10 -X "$method" -H "Authorization: Bearer ${TREEWARD_TOKEN}")
  if [[ -n "$body" ]]; then
    args+=(-H "Content-Type: application/json" -d "$body")
  fi
  curl "${args[@]}" "${TREEWARD_API_URL}${path}"
}

wait_healthy() {
  local i
  for i in $(seq 1 30); do
    if curl -fsS --max-time 2 "${TREEWARD_API_URL}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# A port-forward to svc/treeward-api dies when the pod it targets is replaced,
# so (re)establish it for local URLs after every rollout.
start_port_forward() {
  case "$TREEWARD_API_URL" in
    http://127.0.0.1:*|http://localhost:*) ;;
    *) return 0 ;;  # remote/ingress URL: nothing to forward
  esac
  local port="${TREEWARD_API_URL##*:}"
  if [[ -f "$PF_PIDFILE" ]]; then
    local old
    old="$(cat "$PF_PIDFILE" 2>/dev/null || true)"
    if [[ -n "$old" ]]; then
      kill "$old" 2>/dev/null || true
      sleep 1
    fi
    rm -f "$PF_PIDFILE"
  fi
  mkdir -p "$(dirname "$PF_PIDFILE")"
  nohup kubectl --context "$CONTEXT" -n "$NAMESPACE" port-forward \
    --address 127.0.0.1 svc/treeward-api "${port}:8080" \
    >"$PF_LOGFILE" 2>&1 </dev/null &
  echo "$!" >"$PF_PIDFILE"
  wait_healthy || { cat "$PF_LOGFILE" >&2 || true; fail "API not healthy at ${TREEWARD_API_URL} after port-forward"; }
}

start_port_forward
wait_healthy || fail "API not reachable at ${TREEWARD_API_URL}"

MARKER="persist-check-$(date +%s)-$RANDOM"
echo "== creating marker artifact ${MARKER}"
api POST /v1/artifacts "{\"name\":\"${MARKER}\",\"type\":\"bpf\"}" >/dev/null \
  || fail "could not create marker artifact"
api GET /v1/artifacts | grep -Fq "\"name\":\"${MARKER}\"" \
  || fail "marker artifact not visible before restart"
echo "marker present before restart"

echo "== restarting treeward-api"
kubectl --context "$CONTEXT" -n "$NAMESPACE" rollout restart deploy/treeward-api
kubectl --context "$CONTEXT" -n "$NAMESPACE" rollout status deploy/treeward-api --timeout=120s

start_port_forward
wait_healthy || fail "API not reachable after restart"

echo "== verifying marker after restart"
if api GET /v1/artifacts | grep -Fq "\"name\":\"${MARKER}\""; then
  echo "PASS: marker artifact survived pod restart (SQLite state persisted)"
else
  fail "marker artifact missing after restart -- state did not persist"
fi
