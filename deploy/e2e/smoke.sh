#!/usr/bin/env bash
# Build the local image, load it into kind, apply deploy/overlays/e2e, and
# send one chat completion through the inference Service. The control Service
# must show that exchange as a completed trace. Nothing is pushed to a registry.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

IMAGE="${IMAGE:-infer:local}"
CLUSTER="${KIND_CLUSTER:-infer-smoke}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
CREATED=0
PF1=""
PF2=""

on_exit() {
  status=$?
  if [[ -n "$PF1" ]]; then
    kill "$PF1" 2>/dev/null || true
  fi
  if [[ -n "$PF2" ]]; then
    kill "$PF2" 2>/dev/null || true
  fi
  if [[ "$status" -ne 0 ]]; then
    kubectl -n infer get pods -o wide || true
    kubectl -n infer describe pods || true
    kubectl -n infer logs deploy/infer --all-containers --tail=200 || true
    kubectl -n infer logs deploy/stub --tail=100 || true
    kubectl -n infer logs deploy/infer -c own-traces --tail=50 || true
  fi
  if [[ "$CREATED" == 1 && "$KEEP_CLUSTER" != 1 ]]; then
    kind delete cluster --name "$CLUSTER" || true
  fi
  exit "$status"
}
trap on_exit EXIT

if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
  docker build -t "$IMAGE" .
fi
docker image inspect "$IMAGE" --format 'image_size_bytes={{.Size}}'

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  # nftables mode avoids kube-proxy's iptables statistic match, which some
  # kernels do not provide. Service DNS still has to work for the smoke test.
  kind create cluster --name "$CLUSTER" --config deploy/e2e/kind.yaml
  CREATED=1
fi
kubectl config use-context "kind-${CLUSTER}"

load_image() {
  local image="$1"
  local node="${CLUSTER}-control-plane"
  # kind load imports with containerd's overlayfs snapshotter. Docker 29's
  # containerd image store can save an index whose referenced blob is not in
  # that import, so load the archive with ctr directly.
  docker save "$image" | docker exec -i "$node" ctr --namespace=k8s.io images import -
}

for image in "$IMAGE" busybox:1.37.0 python:3.12-alpine; do
  if [[ "$image" != "$IMAGE" ]]; then
    docker pull "$image"
  fi
  load_image "$image"
done

kubectl apply -k deploy/overlays/e2e
PROXY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
CONTROL=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
kubectl -n infer create secret generic infer-credentials \
  --from-literal=proxy-token="$PROXY" \
  --from-literal=control-token="$CONTROL" \
  --from-literal=upstream-token=smoke-upstream-token \
  --dry-run=client -o yaml | kubectl apply -f -
# The process reads tokens at startup. Recreate picks up a secret written
# after the Deployment, including a re-run that rotates the smoke tokens.
kubectl -n infer rollout restart deploy/infer

kubectl -n infer rollout status deploy/stub --timeout=180s
kubectl -n infer rollout status deploy/infer --timeout=240s

kubectl -n infer port-forward svc/infer 18080:8080 >/tmp/infer-pf-inference.log 2>&1 &
PF1=$!
kubectl -n infer port-forward svc/infer-control 18081:8081 >/tmp/infer-pf-control.log 2>&1 &
PF2=$!

ready=0
for _ in $(seq 1 50); do
  if curl -sf -o /dev/null -H "Authorization: Bearer ${CONTROL}" http://127.0.0.1:18081/health; then
    ready=1
    break
  fi
  sleep 0.2
done
if [[ "$ready" != 1 ]]; then
  echo "control health did not become ready" >&2
  cat /tmp/infer-pf-control.log >&2 || true
  exit 1
fi

headers=$(mktemp)
body=$(mktemp)
curl -sS -D "$headers" -o "$body" \
  -H "Authorization: Bearer ${PROXY}" \
  -H "Content-Type: application/json" \
  --data '{"model":"smoke-local","messages":[{"role":"user","content":"ping"}]}' \
  http://127.0.0.1:18080/v1/chat/completions
grep -q pong "$body"
trace=$(awk 'tolower($1)=="x-infer-trace-id:" {print $2}' "$headers" | tr -d '\r')
if [[ -z "$trace" ]]; then
  echo "response has no x-infer-trace-id" >&2
  cat "$headers" "$body" >&2
  exit 1
fi
meta=$(curl -sf -H "Authorization: Bearer ${CONTROL}" "http://127.0.0.1:18081/traces/${trace}")
python3 -c 'import json,sys; meta=json.loads(sys.argv[1]); assert meta["complete"] is True, meta; assert meta["status"]==200, meta' "$meta"
response_body=$(curl -sf -H "Authorization: Bearer ${CONTROL}" "http://127.0.0.1:18081/traces/${trace}/body/response")
grep -q pong <<<"$response_body"
echo "smoke ok trace=${trace}"
