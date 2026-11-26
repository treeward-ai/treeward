#!/bin/bash
set -euo pipefail
export PATH=$HOME/bin:$HOME/go-sdk/bin:$PATH
cd /home/damian/src/treeward
export TREEWARD_API_URL=http://127.0.0.1:8080
for i in $(seq 1 20); do
  c=$(./bin/treeward nodes 2>/dev/null | grep -c id || true)
  echo nodes=$c
  if [ "$c" -ge 3 ]; then break; fi
  sleep 2
done
echo BEFORE
kubectl --context kind-treeward -n treeward logs deploy/treeward-api --tail=8
ART=$(./bin/treeward artifacts 2>/dev/null | grep -c digest || true)
echo artifacts_before=$ART
kubectl --context kind-treeward -n treeward rollout restart deploy/treeward-api
kubectl --context kind-treeward -n treeward rollout status deploy/treeward-api --timeout=120s
sleep 3
echo AFTER
kubectl --context kind-treeward -n treeward logs deploy/treeward-api --tail=10