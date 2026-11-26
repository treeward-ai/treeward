#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/bin:$HOME/opt/go/bin:$HOME/go-sdk/bin:$HOME/sdk/go/bin:$PATH"

ENV_FILE="${ROOT}/.treeward/quickstart.env"

# Preserve caller overrides before sourcing quickstart.env.
CALLER_API_URL="${TREEWARD_API_URL:-}"
CALLER_TOKEN="${TREEWARD_TOKEN:-}"
CALLER_CONTEXT="${CONTEXT:-}"
CALLER_NAMESPACE="${TREEWARD_NAMESPACE:-}"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

export TREEWARD_API_URL="${CALLER_API_URL:-${TREEWARD_API_URL:-http://127.0.0.1:8080}}"
export TREEWARD_TOKEN="${CALLER_TOKEN:-${TREEWARD_TOKEN:-}}"
CONTEXT="${CALLER_CONTEXT:-kind-${TREEWARD_CLUSTER_NAME:-treeward-quickstart}}"
NAMESPACE="${CALLER_NAMESPACE:-${TREEWARD_NAMESPACE:-treeward}}"

cd "$ROOT"

api_get() {
  local path="$1"
  local -a hdrs=()
  if [[ -n "$TREEWARD_TOKEN" ]]; then
    hdrs+=(-H "Authorization: Bearer ${TREEWARD_TOKEN}")
  fi
  curl -fsS "${hdrs[@]}" "${TREEWARD_API_URL}${path}"
}

for _ in $(seq 1 20); do
  c="$(api_get /v1/nodes 2>/dev/null | grep -o '"id"' | wc -l || true)"
  echo "nodes=${c}"
  if [[ "$c" -ge 3 ]]; then
    break
  fi
  sleep 2
done

echo "BEFORE"
kubectl --context "$CONTEXT" -n "$NAMESPACE" logs deploy/treeward-api --tail=8
ART_BEFORE="$(api_get /v1/artifacts 2>/dev/null | grep -o '"digest"' | wc -l || true)"
echo "artifacts_before=${ART_BEFORE}"

kubectl --context "$CONTEXT" -n "$NAMESPACE" rollout restart deploy/treeward-api
kubectl --context "$CONTEXT" -n "$NAMESPACE" rollout status deploy/treeward-api --timeout=120s
sleep 3

echo "AFTER"
kubectl --context "$CONTEXT" -n "$NAMESPACE" logs deploy/treeward-api --tail=10
ART_AFTER="$(api_get /v1/artifacts 2>/dev/null | grep -o '"digest"' | wc -l || true)"
echo "artifacts_after=${ART_AFTER}"
