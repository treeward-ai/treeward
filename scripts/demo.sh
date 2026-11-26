#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/bin:$HOME/go-sdk/bin:$HOME/sdk/go/bin:$PATH"
export TREEWARD_API_URL="${TREEWARD_API_URL:-http://127.0.0.1:8080}"

echo "Waiting for API at $TREEWARD_API_URL ..."
for i in $(seq 1 60); do
  if curl -fsS "$TREEWARD_API_URL/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS "$TREEWARD_API_URL/healthz" >/dev/null

# Ensure CLI exists
if [[ ! -x "$ROOT/bin/treeward" ]]; then
  (cd "$ROOT" && make build-local)
fi

echo "Waiting for inventory nodes..."
for i in $(seq 1 60); do
  count="$("$ROOT/bin/treeward" nodes | grep -c '"id"' || true)"
  if [[ "$count" -ge 3 ]]; then
    break
  fi
  sleep 2
done

"$ROOT/bin/treeward" demo
