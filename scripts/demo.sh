#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/bin:$HOME/opt/go/bin:$HOME/go-sdk/bin:$HOME/sdk/go/bin:$PATH"

ENV_FILE="${ROOT}/.treeward/quickstart.env"

# Preserve explicit caller overrides before loading quickstart.env.
CALLER_API_URL="${TREEWARD_API_URL:-}"
CALLER_TOKEN="${TREEWARD_TOKEN:-}"
CALLER_APPROVER_TOKEN="${TREEWARD_APPROVER_TOKEN:-}"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

export TREEWARD_API_URL="${CALLER_API_URL:-${TREEWARD_API_URL:-http://127.0.0.1:8080}}"
export TREEWARD_TOKEN="${CALLER_TOKEN:-${TREEWARD_TOKEN:-}}"
export TREEWARD_APPROVER_TOKEN="${CALLER_APPROVER_TOKEN:-${TREEWARD_APPROVER_TOKEN:-}}"

CLI="$ROOT/bin/treeward"
PASSED=0
FAILED=0

pass() {
  PASSED=$((PASSED + 1))
  printf '[PASS] %s\n' "$*"
}

fail() {
  FAILED=$((FAILED + 1))
  printf '[FAIL] %s\n' "$*" >&2
  printf '\nDemo failed (%d passed, %d failed).\n' "$PASSED" "$FAILED" >&2
  exit 1
}

json_field() {
  local field="$1"
  sed -n "s/.*\"${field}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -n1
}

# Inspect pretty-printed /v1/nodes JSON output and check desired load state.
# mode: canary | all | none
check_nodes_loaded() {
  local nodes_json="$1"
  local digest="$2"
  local mode="$3"

  printf '%s\n' "$nodes_json" | awk -v digest="$digest" -v mode="$mode" '
    /"id":/ {
      if (in_node) {
        total++
        if (is_canary) {
          canary_total++
          if (has_digest) canary_loaded++
        } else {
          other_total++
          if (has_digest) other_loaded++
        }
      }
      in_node = 1
      is_canary = 0
      has_digest = 0
    }
    /"treeward\.ai\/rollout":[[:space:]]*"canary"/ { is_canary = 1 }
    index($0, "\"" digest "\"") > 0 { has_digest = 1 }
    END {
      if (in_node) {
        total++
        if (is_canary) {
          canary_total++
          if (has_digest) canary_loaded++
        } else {
          other_total++
          if (has_digest) other_loaded++
        }
      }
      if (total == 0) exit 1
      if (mode == "canary") {
        if (canary_total > 0 && canary_loaded == canary_total && other_loaded == 0) exit 0
        exit 1
      } else if (mode == "all") {
        if (canary_loaded + other_loaded == total) exit 0
        exit 1
      } else if (mode == "none") {
        if (canary_loaded + other_loaded == 0) exit 0
        exit 1
      }
      exit 1
    }
  '
}

wait_for_load_state() {
  local digest="$1"
  local mode="$2"
  local timeout_s="${3:-60}"
  local elapsed=0
  local nodes_json=""

  while [[ "$elapsed" -lt "$timeout_s" ]]; do
    nodes_json="$("$CLI" nodes 2>/dev/null || true)"
    if [[ -n "$nodes_json" ]] && check_nodes_loaded "$nodes_json" "$digest" "$mode"; then
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  return 1
}

if [[ -z "$TREEWARD_TOKEN" ]]; then
  fail "TREEWARD_TOKEN is not set. Run 'make quickstart' first or export TREEWARD_TOKEN."
fi

if [[ ! -x "$CLI" ]]; then
  (cd "$ROOT" && CGO_ENABLED=0 go build -o "$CLI" ./cmd/treeward) || fail "Build treeward CLI"
fi

printf 'Running Treeward stub-agent demo against %s\n\n' "$TREEWARD_API_URL"

# 1. Health check
health_ok=0
for _ in $(seq 1 30); do
  if curl -fsS --max-time 2 "${TREEWARD_API_URL}/healthz" >/dev/null 2>&1; then
    health_ok=1
    break
  fi
  sleep 1
done
if [[ "$health_ok" -eq 1 ]]; then
  pass "API health check (${TREEWARD_API_URL}/healthz)"
else
  fail "API health check (${TREEWARD_API_URL}/healthz unreachable)"
fi

# 2. Authenticated inventory check (wait for stub agent to report >= 3 nodes)
node_count=0
for _ in $(seq 1 45); do
  nodes_out="$("$CLI" nodes 2>/dev/null || true)"
  node_count="$(printf '%s\n' "$nodes_out" | grep -c '"id":' || true)"
  if [[ "$node_count" -ge 3 ]]; then
    break
  fi
  sleep 2
done
if [[ "$node_count" -ge 3 ]]; then
  pass "Authenticated inventory check (${node_count} stub nodes reporting)"
else
  fail "Authenticated inventory check (expected >=3 stub nodes, got ${node_count})"
fi

# 3. Create artifact (unique name per run so repeated demos never collide with prior bindings)
ART_NAME="java4shell-demo-$(date +%s)"
art_out="$("$CLI" create-artifact "$ART_NAME" --type java 2>&1)" || fail "Create artifact (${art_out})"
DIGEST="$(printf '%s\n' "$art_out" | json_field digest)"
if [[ -n "$DIGEST" ]]; then
  pass "Create artifact (digest=${DIGEST})"
else
  fail "Create artifact (missing digest in response)"
fi

# 4. Create binding
bind_out="$("$CLI" create-binding "$DIGEST" 2>&1)" || fail "Create binding (${bind_out})"
BINDING_ID="$(printf '%s\n' "$bind_out" | json_field id)"
BINDING_STATUS="$(printf '%s\n' "$bind_out" | json_field status)"
if [[ -n "$BINDING_ID" && "$BINDING_STATUS" == "draft" ]]; then
  pass "Create binding (id=${BINDING_ID}, status=${BINDING_STATUS})"
else
  fail "Create binding (unexpected id=${BINDING_ID} status=${BINDING_STATUS})"
fi

# 5. Approve binding (uses distinct approver token to satisfy two-person separation of duties)
approve_out="$(TREEWARD_TOKEN="${TREEWARD_APPROVER_TOKEN:-${TREEWARD_TOKEN}}" "$CLI" approve "$BINDING_ID" 2>&1)" || fail "Approve binding (${approve_out})"
APPROVE_STATUS="$(printf '%s\n' "$approve_out" | json_field status)"
APPROVED_BY="$(printf '%s\n' "$approve_out" | json_field approvedBy)"
if [[ "$APPROVE_STATUS" == "approved" ]]; then
  pass "Approve binding (status=${APPROVE_STATUS}, approvedBy=${APPROVED_BY})"
else
  fail "Approve binding (expected approved, got ${APPROVE_STATUS})"
fi

# 6. Canary rollout
canary_out="$("$CLI" canary "$BINDING_ID" 2>&1)" || fail "Canary rollout (${canary_out})"
if wait_for_load_state "$DIGEST" canary 60; then
  pass "Canary rollout (loaded on canary node only)"
else
  fail "Canary rollout (timed out waiting for canary-only load)"
fi

# 7. Promote to fleet
promote_out="$("$CLI" promote "$BINDING_ID" 2>&1)" || fail "Promote binding (${promote_out})"
if wait_for_load_state "$DIGEST" all 60; then
  pass "Promote to fleet (loaded on all ${node_count} nodes)"
else
  fail "Promote to fleet (timed out waiting for all nodes to load)"
fi

# 8. Attest (stub quotes)
camp_resp="$(curl -fsS -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TREEWARD_TOKEN}" \
  -d '{}' \
  "${TREEWARD_API_URL}/v1/attest/campaigns" 2>&1)" || fail "Start attest campaign (${camp_resp})"
CAMP_ID="$(printf '%s\n' "$camp_resp" | json_field id)"
if [[ -z "$CAMP_ID" ]]; then
  fail "Start attest campaign (missing campaign id)"
fi

attest_complete=0
camp_detail=""
for _ in $(seq 1 30); do
  camp_detail="$(curl -fsS \
    -H "Authorization: Bearer ${TREEWARD_TOKEN}" \
    "${TREEWARD_API_URL}/v1/attest/campaigns/${CAMP_ID}" 2>/dev/null || true)"
  if printf '%s\n' "$camp_detail" | grep -q '"status"[[:space:]]*:[[:space:]]*"complete"'; then
    attest_complete=1
    break
  fi
  sleep 2
done
if [[ "$attest_complete" -eq 1 ]]; then
  pass_count="$({ printf '%s\n' "$camp_detail" | grep -o '"pass"[[:space:]]*:[[:space:]]*true' || true; } | wc -l | tr -d ' ')"
  fail_count="$({ printf '%s\n' "$camp_detail" | grep -o '"pass"[[:space:]]*:[[:space:]]*false' || true; } | wc -l | tr -d ' ')"
  if [[ "$pass_count" -ge 3 && "$fail_count" -eq 0 ]]; then
    pass "Attest campaign (id=${CAMP_ID}, ${pass_count} pass, ${fail_count} fail — stub quotes)"
  else
    fail "Attest campaign (id=${CAMP_ID}, unexpected results: ${pass_count} pass, ${fail_count} fail)"
  fi
else
  fail "Attest campaign (id=${CAMP_ID}, timed out waiting for completion)"
fi

# 9. Revert binding
revert_out="$("$CLI" revert "$BINDING_ID" 2>&1)" || fail "Revert binding (${revert_out})"
if wait_for_load_state "$DIGEST" none 60; then
  pass "Revert binding (unloaded from all nodes)"
else
  fail "Revert binding (timed out waiting for unload)"
fi

# 10. Audit log check
audit_out="$("$CLI" audit 2>&1)" || fail "Read audit log (${audit_out})"
missing_actions=""
for action in approve canary promote attest.start revert; do
  if ! printf '%s\n' "$audit_out" | grep -q "\"action\"[[:space:]]*:[[:space:]]*\"${action}\""; then
    missing_actions="${missing_actions} ${action}"
  fi
done
if [[ -z "$missing_actions" ]]; then
  event_count="$(printf '%s\n' "$audit_out" | grep -c '"action":' || true)"
  pass "Audit log verified (${event_count} events; approve/canary/promote/attest.start/revert recorded)"
else
  fail "Audit log missing actions:${missing_actions}"
fi

printf '\nDemo complete: %d passed, %d failed.\n' "$PASSED" "$FAILED"
