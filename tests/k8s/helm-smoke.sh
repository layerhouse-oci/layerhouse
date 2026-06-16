#!/usr/bin/env bash
# Opt-in Kubernetes Helm production smoke for Layerhouse.
#
# Required env:
#   REGISTRY_ENDPOINT=registry.example.internal:32000
#
# Optional env:
#   RUN_ID, NAMESPACE, S3_NAMESPACE, SERVER_IMAGE_REPOSITORY, SERVER_IMAGE_TAG
#   NODE_TRUST_COMMAND: command invoked after cert generation to install
#     containerd trust on test nodes. It receives LAYERHOUSE_CA and
#     LAYERHOUSE_CONTAINERD_HOSTS env vars.
#   CRICTL_COMMAND: command used to pull the pushed smoke image from a node.
#   DOCKER_TRUST_COMMAND: optional command to trust LAYERHOUSE_CA in the local
#     Docker daemon before pushing the smoke image.
set -euo pipefail

RUN_ID="${RUN_ID:-$(date +%s)}"
REGISTRY_ENDPOINT="${REGISTRY_ENDPOINT:?set REGISTRY_ENDPOINT to host[:port] reachable by cluster nodes}"
REGISTRY_HOST="${REGISTRY_ENDPOINT%%:*}"
REGISTRY_PORT="${REGISTRY_ENDPOINT##*:}"
REGISTRY_PORT_EXPLICIT=1
if [ "$REGISTRY_PORT" = "$REGISTRY_ENDPOINT" ]; then
    REGISTRY_PORT=443
    REGISTRY_PORT_EXPLICIT=0
fi
NAMESPACE="${NAMESPACE:-layerhouse-smoke-$RUN_ID}"
S3_NAMESPACE="${S3_NAMESPACE:-$NAMESPACE-s3}"
RELEASE="${RELEASE:-layerhouse}"
CHART="${CHART:-deploy/kubernetes/helm}"

chart_app_version() {
    awk -F: '/^appVersion:/ { gsub(/[ "]/, "", $2); print $2; exit }' "$CHART/Chart.yaml"
}

SERVER_IMAGE_REPOSITORY="${SERVER_IMAGE_REPOSITORY:-ghcr.io/layerhouse-oci/layerhouse-server}"
SERVER_IMAGE_TAG="${SERVER_IMAGE_TAG:-$(chart_app_version)}"
if [ -z "$SERVER_IMAGE_TAG" ]; then
    echo "ERROR: unable to resolve SERVER_IMAGE_TAG from $CHART/Chart.yaml" >&2
    exit 1
fi
if [ "$REGISTRY_PORT_EXPLICIT" -eq 1 ]; then
    SERVICE_TYPE="${SERVICE_TYPE:-NodePort}"
else
    SERVICE_TYPE="${SERVICE_TYPE:-LoadBalancer}"
fi
SERVICE_NODE_PORT="${SERVICE_NODE_PORT:-$REGISTRY_PORT}"
S3_BUCKET="${S3_BUCKET:-layerhouse}"
S3_ACCESS_KEY="${S3_ACCESS_KEY:-rustfsadmin}"
S3_SECRET_KEY="${S3_SECRET_KEY:-rustfsadmin}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-/tmp}"
WORK="${WORK:-$EVIDENCE_ROOT/orb-k8s-$RUN_ID}"
SMOKE_REPO="${SMOKE_REPO:-qa/k8s-smoke-$RUN_ID}"
SMOKE_IMAGE="$REGISTRY_ENDPOINT/$SMOKE_REPO:green"
SMOKE_BASE_IMAGE="${SMOKE_BASE_IMAGE:-busybox:1.36}"
SMOKE_BASE_IMAGE_FALLBACK="${SMOKE_BASE_IMAGE_FALLBACK:-alpine:3.21}"
NODE_TRUST_COMMAND="${NODE_TRUST_COMMAND:-}"
DOCKER_TRUST_COMMAND="${DOCKER_TRUST_COMMAND:-}"
CRICTL_COMMAND="${CRICTL_COMMAND:-crictl}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=tests/k8s/lib.sh
source "$SCRIPT_DIR/lib.sh"

log() {
    printf '\n==> %s\n' "$*"
}

cleanup() {
    local status=$?
    if [ "$status" -eq 0 ]; then
        echo "PASS Kubernetes Helm smoke. Evidence: $WORK"
    else
        echo "FAIL Kubernetes Helm smoke. Evidence: $WORK" >&2
    fi
    exit "$status"
}
trap cleanup EXIT

need kubectl
need helm
need cargo
need docker
need oras
need curl
need jq

umask 077
mkdir -p "$WORK/dockerctx" "$WORK/layerhouse-airgap"
chmod -R go-rwx "$WORK"
cat > "$WORK/summary.env" <<EOF
RUN_ID=$RUN_ID
REGISTRY_ENDPOINT=$REGISTRY_ENDPOINT
NAMESPACE=$NAMESPACE
S3_NAMESPACE=$S3_NAMESPACE
SERVER_IMAGE_REPOSITORY=$SERVER_IMAGE_REPOSITORY
SERVER_IMAGE_TAG=$SERVER_IMAGE_TAG
SERVICE_TYPE=$SERVICE_TYPE
SERVICE_NODE_PORT=$SERVICE_NODE_PORT
SMOKE_IMAGE=$SMOKE_IMAGE
WORK=$WORK
EOF

log "Record tool and cluster versions"
{
    kubectl version --client=true
    helm version
    docker version --format '{{.Client.Version}} client / {{.Server.Version}} server'
    oras version
    jq --version
} | tee "$WORK/versions.txt"
kubectl get nodes -o wide | tee "$WORK/nodes.txt"

log "Install RustFS S3 fixture"
kubectl create namespace "$S3_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
cat <<YAML | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: rustfs-root
  namespace: $S3_NAMESPACE
type: Opaque
stringData:
  access_key: "$S3_ACCESS_KEY"
  secret_key: "$S3_SECRET_KEY"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rustfs
  namespace: $S3_NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: rustfs
  template:
    metadata:
      labels:
        app: rustfs
    spec:
      containers:
        - name: rustfs
          image: rustfs/rustfs:1.0.0-beta.2
          imagePullPolicy: IfNotPresent
          env:
            - name: RUSTFS_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: rustfs-root
                  key: access_key
            - name: RUSTFS_SECRET_KEY
              valueFrom:
                secretKeyRef:
                  name: rustfs-root
                  key: secret_key
            - name: RUSTFS_ADDRESS
              value: "0.0.0.0:9000"
            - name: RUSTFS_CONSOLE_ADDRESS
              value: "0.0.0.0:9001"
            - name: RUSTFS_VOLUMES
              value: /data
          ports:
            - name: api
              containerPort: 9000
          readinessProbe:
            httpGet:
              path: /health
              port: api
            initialDelaySeconds: 5
            periodSeconds: 5
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: rustfs
  namespace: $S3_NAMESPACE
spec:
  selector:
    app: rustfs
  ports:
    - name: api
      port: 9000
      targetPort: api
YAML
record kubectl -n "$S3_NAMESPACE" rollout status deploy/rustfs --timeout=180s
cat <<YAML | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: rustfs-init-$RUN_ID
  namespace: $S3_NAMESPACE
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: rc
          image: rustfs/rc:latest
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-ec"]
          args:
            - |
              RUSTFS_IP=\$(getent hosts rustfs.$S3_NAMESPACE.svc.cluster.local | awk '{print \$1}')
              rc alias set local http://\${RUSTFS_IP}:9000 "$S3_ACCESS_KEY" "$S3_SECRET_KEY"
              rc bucket create local/$S3_BUCKET -p
  backoffLimit: 3
YAML
record kubectl -n "$S3_NAMESPACE" wait --for=condition=complete "job/rustfs-init-$RUN_ID" --timeout=120s

log "Generate air-gapped certs and Helm values"
record cargo run -q -p layerhouse-ctl -- air-gapped cert init \
    --registry-host "$REGISTRY_HOST" \
    --san "$RELEASE.$NAMESPACE.svc" \
    --san "$RELEASE.$NAMESPACE.svc.cluster.local" \
    --namespace "$NAMESPACE" \
    --statefulset-name "$RELEASE" \
    --headless-service "$RELEASE-headless" \
    --replicas 3 \
    --out "$WORK/layerhouse-airgap" \
    --overwrite
record cargo run -q -p layerhouse-ctl -- air-gapped k8s bundle-generate \
    --registry-endpoint "$REGISTRY_ENDPOINT" \
    --cert-dir "$WORK/layerhouse-airgap/certs" \
    --namespace "$NAMESPACE" \
    --image-repository "$SERVER_IMAGE_REPOSITORY" \
    --image-tag "$SERVER_IMAGE_TAG" \
    --out "$WORK/layerhouse-airgap" \
    --overwrite

log "Install node trust"
export LAYERHOUSE_CA="$WORK/layerhouse-airgap/containerd/ca.crt"
export LAYERHOUSE_CONTAINERD_HOSTS="$WORK/layerhouse-airgap/containerd/hosts.toml"
if [ -z "$NODE_TRUST_COMMAND" ]; then
    echo "ERROR: set NODE_TRUST_COMMAND to install LAYERHOUSE_CA and LAYERHOUSE_CONTAINERD_HOSTS on test nodes" >&2
    exit 2
fi
record bash -ec "$NODE_TRUST_COMMAND"

log "Install Layerhouse Helm chart"
HELM_SERVICE_ARGS=(--set "service.type=$SERVICE_TYPE")
if [ "$SERVICE_TYPE" = "NodePort" ]; then
    if ! [[ "$SERVICE_NODE_PORT" =~ ^[0-9]+$ ]]; then
        echo "ERROR: SERVICE_NODE_PORT must be numeric" >&2
        exit 2
    fi
    if [ "$SERVICE_NODE_PORT" -lt 30000 ] || [ "$SERVICE_NODE_PORT" -gt 32767 ]; then
        echo "ERROR: SERVICE_NODE_PORT must be in the Kubernetes NodePort range" >&2
        exit 2
    fi
    HELM_SERVICE_ARGS+=(--set "service.nodePort=$SERVICE_NODE_PORT")
fi
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NAMESPACE" create secret generic layerhouse-s3 \
    --from-literal=access_key="$S3_ACCESS_KEY" \
    --from-literal=secret_key="$S3_SECRET_KEY" \
    --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "$WORK/layerhouse-airgap/k8s/server-tls-secret.yaml"
kubectl apply -f "$WORK/layerhouse-airgap/k8s/raft-mtls-secret.yaml"
record helm upgrade --install "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --create-namespace \
    -f "$WORK/layerhouse-airgap/helm/values-air-gapped.yaml" \
    "${HELM_SERVICE_ARGS[@]}" \
    --set "image.repository=$SERVER_IMAGE_REPOSITORY" \
    --set "image.tag=$SERVER_IMAGE_TAG" \
    --set "storage.s3.endpoint=http://rustfs.$S3_NAMESPACE.svc.cluster.local:9000" \
    --set "storage.s3.bucket=$S3_BUCKET"
record kubectl -n "$NAMESPACE" rollout status "statefulset/$RELEASE" --timeout=300s
kubectl -n "$NAMESPACE" get pods -o wide | tee "$WORK/layerhouse-pods.txt"

log "Verify public readiness and cluster status"
curl --cacert "$LAYERHOUSE_CA" -fsS "https://$REGISTRY_ENDPOINT/readyz" | tee "$WORK/readyz.txt"
curl --cacert "$LAYERHOUSE_CA" -fsS "https://$REGISTRY_ENDPOINT/api/v1/admin/cluster/status" \
    | tee "$WORK/cluster-status.json" \
    | jq '{leader_id, quorum, healthy_voters}'
jq -e '.leader_id != null and .healthy_voters >= .quorum' "$WORK/cluster-status.json" >/dev/null

log "Push smoke image"
if [ -n "$DOCKER_TRUST_COMMAND" ]; then
    record bash -ec "$DOCKER_TRUST_COMMAND"
fi
BASE_IMAGE="$(resolve_smoke_base_image)"
printf 'hello from layerhouse k8s smoke %s\n' "$RUN_ID" > "$WORK/dockerctx/hello.txt"
printf 'FROM %s\nCOPY hello.txt /hello.txt\n' "$BASE_IMAGE" > "$WORK/dockerctx/Dockerfile"
record docker build -t "$SMOKE_IMAGE" "$WORK/dockerctx"
record docker push "$SMOKE_IMAGE"

log "Pull smoke image from a Kubernetes node with crictl"
record bash -ec "$CRICTL_COMMAND pull '$SMOKE_IMAGE'"

log "Run smoke image from Layerhouse source"
record kubectl -n "$NAMESPACE" run "orb-smoke-$RUN_ID" \
    --image="$SMOKE_IMAGE" \
    --restart=Never \
    --command -- /bin/sh -c 'cat /hello.txt; sleep 30'
record kubectl -n "$NAMESPACE" wait --for=condition=Ready "pod/orb-smoke-$RUN_ID" --timeout=120s
kubectl -n "$NAMESPACE" logs "pod/orb-smoke-$RUN_ID" | tee "$WORK/kubectl-run.log"
