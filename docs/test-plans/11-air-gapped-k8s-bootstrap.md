# Air-Gapped Kubernetes Bootstrap Test Plan

**Scope**: Native HTTPS registry listener, Raft mTLS, CLI-generated air-gapped
certificate bundle, Helm values, containerd trust snippets, and dashboard setup
instructions.

## Coverage

| Area | Priority |
|------|----------|
| CLI cert generation rejects malformed hosts and refuses overwrite by default | P0 |
| CLI cert generation covers StatefulSet pod DNS SANs for Raft mTLS | P0 |
| CLI bundle generation renders server TLS Secret, Raft mTLS Secret, Helm values, and containerd `hosts.toml` | P0 |
| Server parses `[server.tls]` and serves the public registry listener over HTTPS | P0 |
| Server parses `[raft.tls]` with `server_ca_path` and `client_ca_path` and rejects missing peer client certs | P0 |
| Dashboard Setup page renders copyable Kubernetes/containerd snippets | P1 |
| Kubernetes node can pull from an internally trusted Layerhouse endpoint | P2 |

## Coverage Status

| Scenario | Mode | Command/Plan ID | Priority | Current Status | Evidence Path |
|----------|------|-----------------|----------|----------------|---------------|
| CLI cert and bundle generation unit coverage | Automated | `just check` | P0 | Implemented | command log |
| Helm chart render matrix including air-gapped values | Automated | `just helm-check` | P0 | Implemented | command log |
| Production-like cert-manager Helm install with RustFS and Kanidm | Automated | `just tilt-ci` | P0 | Implemented | `target/tilt/evidence/<run_id>` |
| Host Docker daemon trust setup for local HTTPS NodePort push | Automated | `just tilt-ci-host-docker` | P1 | Implemented, opt-in because it may restart Docker; latest local pass `target/tilt/evidence/20260601-143738` | `target/tilt/evidence/<run_id>` |
| CLI-generated Kubernetes Helm smoke with manual node trust injection | Automated | `tests/k8s/helm-smoke.sh` | P1 | Implemented scripted harness; requires cluster-specific `NODE_TRUST_COMMAND`, external endpoint, and S3 fixture | `/tmp/orb-k8s-<run_id>` |
| Node trust removal and missing imagePullSecret failure checks | Automated | `just tilt-failure-smoke` | P1 | Implemented, opt-in destructive local smoke | `target/tilt/evidence/<run_id>-failure` |
| CLI-generated certs, Secrets, Helm values, and node trust install | Agent-executable manual | `K8S-MANUAL-AIRGAP-01` | P0 | Full operator plan remains manual; scripted harness covers the reusable path when node trust injection is supplied | `/tmp/orb-airgap-<run_id>` |
| cert-manager renewal and post-rotation health | Agent-executable manual | `K8S-MANUAL-CERTROT-01` | P1 | Manual plan only; not automated because rotation is environment/RBAC dependent | `/tmp/orb-certrot-<run_id>` |
| External S3-compatible bucket install | Agent-executable manual | `K8S-MANUAL-EXTS3-01` | P0 | Manual plan only; not automated because it requires operator-provided external S3 credentials | `/tmp/orb-exts3-<run_id>` |
| Node trust removal/failure verification on real worker nodes | Agent-executable manual | `K8S-MANUAL-NODETRUST-01` | P1 | Manual plan only; not automated because it makes destructive host-level node trust changes | `/tmp/orb-nodetrust-<run_id>` |

## Unit And Build Checks

Run from the Rust workspace:

```bash
just check
just helm-check
```

For local host Docker trust validation, run:

```bash
KANIDM_HOST_PORT=28443 just tilt-ci-host-docker
```

This validates the same class of trust distribution that operators must solve
for developer workstations or CI runners outside the cluster: install the
registry CA into the host Docker daemon trust path, restart/reload Docker if
needed, wait for Kubernetes API recovery, and require host `docker push` to
work over the HTTPS NodePort.

Expected:

- Cargo unit tests pass for CLI cert/bundle helpers.
- Config parsing accepts valid `[server.tls]` and rejects empty cert/key paths.
- Raft mTLS tests cover valid peer certs, missing client certs, and wrong CA.
- Dashboard build succeeds with the Setup route.
- Helm chart renders default, auth-enabled, cert-manager, and air-gapped values.

## K8S-MANUAL-AIRGAP-01: CLI-Generated Air-Gapped Install

**Mode**: Agent-executable manual
**Priority**: P0

### Preconditions And Environment

- Kubernetes cluster with `kubectl` access.
- Helm 3.
- External S3-compatible bucket and credentials already available.
- A registry endpoint reachable from cluster nodes, for example
  `registry.internal.example.com:32000`.
- Node-management access to install containerd trust files on at least one test
  node.

```bash
export RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
export WORK="/tmp/orb-airgap-$RUN_ID"
export NAMESPACE="layerhouse"
export REGISTRY_HOST="registry.internal.example.com"
export REGISTRY_ENDPOINT="$REGISTRY_HOST:32000"
export S3_ENDPOINT="https://s3.internal.example.com"
export S3_BUCKET="layerhouse"
export S3_REGION="us-east-1"
export S3_ACCESS_KEY="replace-me"
export S3_SECRET_KEY="replace-me"
export IMAGE_TAG="replace-with-mirrored-layerhouse-server-tag"
umask 077
mkdir -p "$WORK"
chmod 0700 "$WORK"
```

### Commands

1. Generate certs:

   ```bash
   layerhouse-ctl air-gapped cert init \
     --registry-host "$REGISTRY_HOST" \
     --namespace "$NAMESPACE" \
     --statefulset-name layerhouse \
     --headless-service layerhouse-headless \
     --replicas 3 \
     --out "$WORK"
   ```

2. Generate bundle:

   ```bash
   layerhouse-ctl air-gapped k8s bundle-generate \
     --registry-endpoint "$REGISTRY_ENDPOINT" \
     --cert-dir "$WORK/certs" \
     --namespace "$NAMESPACE" \
     --server-tls-secret layerhouse-server-tls \
     --raft-tls-secret layerhouse-raft-mtls \
     --image-repository "$REGISTRY_ENDPOINT/layerhouse-server" \
     --image-tag "$IMAGE_TAG" \
     --out "$WORK"
   ```

3. Create the external S3 Secret and apply generated Secrets:

   ```bash
   kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
   kubectl -n "$NAMESPACE" create secret generic layerhouse-s3 \
     --from-literal=access_key="$S3_ACCESS_KEY" \
     --from-literal=secret_key="$S3_SECRET_KEY" \
     --dry-run=client -o yaml | tee "$WORK/s3-secret.yaml" | kubectl apply -f -

   kubectl apply -f "$WORK/k8s/server-tls-secret.yaml"
   kubectl apply -f "$WORK/k8s/raft-mtls-secret.yaml"
   ```

4. Install the Helm chart with generated values and external S3 overrides:

   ```bash
   helm upgrade --install layerhouse ./deploy/kubernetes/helm \
     --namespace "$NAMESPACE" \
     --create-namespace \
     -f "$WORK/helm/values-air-gapped.yaml" \
     --set storage.s3.endpoint="$S3_ENDPOINT" \
     --set storage.s3.bucket="$S3_BUCKET" \
     --set storage.s3.region="$S3_REGION" \
     --set storage.s3.existingSecret=layerhouse-s3
   ```

5. Confirm readiness:

   ```bash
   kubectl -n "$NAMESPACE" rollout status statefulset/layerhouse --timeout=5m
   curl --cacert "$WORK/certs/ca.crt" \
     "https://$REGISTRY_ENDPOINT/readyz" | tee "$WORK/readyz.txt"
   ```

6. Verify the public registry and dashboard cluster status:

   ```bash
   curl --cacert "$WORK/certs/ca.crt" \
     "https://$REGISTRY_ENDPOINT/v2/" | tee "$WORK/v2.txt"

   curl --cacert "$WORK/certs/ca.crt" \
     "https://$REGISTRY_ENDPOINT/api/v1/admin/cluster/status" \
     | tee "$WORK/cluster-status.json" \
     | jq '{leader_id, quorum, healthy_voters}'
   ```

7. Install generated `containerd/ca.crt` and `containerd/hosts.toml` on a test
   node under `/etc/containerd/certs.d/registry.internal.example.com:32000/`.
8. Restart or reload containerd.
9. Push a disposable image to `$REGISTRY_ENDPOINT/qa/airgap:$RUN_ID`.
10. Verify node pull:

   ```bash
   crictl pull "$REGISTRY_ENDPOINT/qa/airgap:$RUN_ID" | tee "$WORK/crictl-pull.txt"
   ```

11. Verify Kubernetes pull:

   ```bash
   kubectl -n "$NAMESPACE" run "layerhouse-pull-test-$RUN_ID" \
     --image="$REGISTRY_ENDPOINT/qa/airgap:$RUN_ID" \
     --restart=Never

   kubectl -n "$NAMESPACE" wait --for=condition=Ready \
     "pod/layerhouse-pull-test-$RUN_ID" --timeout=3m
   kubectl -n "$NAMESPACE" describe pod "layerhouse-pull-test-$RUN_ID" \
     > "$WORK/pull-test-pod.txt"
   ```

The same scenario can be driven by the opt-in smoke script when a cluster-specific
node trust command is available:

```bash
REGISTRY_ENDPOINT=registry.internal.example.com:32000 \
NODE_TRUST_COMMAND='./install-node-trust.sh' \
tests/k8s/helm-smoke.sh
```

The script writes evidence to `/tmp/orb-k8s-<run_id>`.

Expected:

- `/v2/` responds over HTTPS with the generated CA.
- `crictl pull` succeeds without insecure registry settings.
- Kubernetes schedules the pull-test pod and image pull does not fail with an
  unknown authority error.
- The Raft cluster forms a leader with three voters over mTLS.
- Kubernetes Secrets do not include CA private keys.
- No privileged node-trust DaemonSet is required.

### Evidence

- `$WORK/summary.env` with cluster, endpoint, and chart version.
- `$WORK/k8s/*.yaml`, `$WORK/helm/*.yaml`, with directory permissions `0700`
  and sensitive files `0600`.
- `$WORK/cluster-status.json` showing `leader_id != null` and
  `healthy_voters >= quorum`.
- `kubectl -n "$NAMESPACE" get pods -o wide > "$WORK/pods.txt"`.
- `crictl pull` log and pull-test pod description.

### Cleanup And Rollback

```bash
helm -n "$NAMESPACE" uninstall layerhouse || true
kubectl -n "$NAMESPACE" delete pod "layerhouse-pull-test-$RUN_ID" --ignore-not-found
kubectl -n "$NAMESPACE" delete secret layerhouse-s3 layerhouse-server-tls layerhouse-raft-mtls --ignore-not-found
```

Remove containerd trust files only from test nodes where they were installed:

```bash
sudo rm -rf "/etc/containerd/certs.d/$REGISTRY_ENDPOINT"
sudo systemctl restart containerd
```

### Known Hazards

- Node trust changes are host-level changes. Do not run on shared production
  workers unless the cluster owner has approved the rollback window.
- Do not publish real CA private keys in evidence. Generated Kubernetes Secret
  manifests are sensitive and must remain private.

## K8S-MANUAL-CERTROT-01: cert-manager Renewal And Post-Rotation Health

**Mode**: Agent-executable manual
**Priority**: P1

### Preconditions And Environment

- Helm install uses `certManager.server.enabled=true` and
  `certManager.raft.enabled=true`.
- cert-manager is installed, the public server issuer is Ready, and the private
  Raft issuer is Ready.
- The test cluster can tolerate pod restarts if projected Secrets need reload.

```bash
export RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
export WORK="/tmp/orb-certrot-$RUN_ID"
export NAMESPACE="layerhouse"
export REGISTRY_ENDPOINT="registry.internal.example.com:32000"
umask 077
mkdir -p "$WORK"
chmod 0700 "$WORK"
```

### Commands

```bash
kubectl -n "$NAMESPACE" get certificate,secret > "$WORK/certs-before.txt"
kubectl -n "$NAMESPACE" get secret layerhouse-server-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > "$WORK/ca-before.crt"
kubectl -n "$NAMESPACE" get secret layerhouse-server-tls -o jsonpath='{.data.tls\.crt}' | base64 -d > "$WORK/server-before.crt"
kubectl -n "$NAMESPACE" get secret layerhouse-raft-mtls -o jsonpath='{.data.tls\.crt}' | base64 -d > "$WORK/raft-before.crt"

cmctl renew -n "$NAMESPACE" layerhouse-server-tls
cmctl renew -n "$NAMESPACE" layerhouse-raft
kubectl -n "$NAMESPACE" wait --for=condition=Ready certificate/layerhouse-server-tls --timeout=3m
kubectl -n "$NAMESPACE" wait --for=condition=Ready certificate/layerhouse-raft --timeout=3m

kubectl -n "$NAMESPACE" rollout restart statefulset/layerhouse
kubectl -n "$NAMESPACE" rollout status statefulset/layerhouse --timeout=5m

kubectl -n "$NAMESPACE" get secret layerhouse-server-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > "$WORK/ca-after.crt"
kubectl -n "$NAMESPACE" get secret layerhouse-server-tls -o jsonpath='{.data.tls\.crt}' | base64 -d > "$WORK/server-after.crt"
kubectl -n "$NAMESPACE" get secret layerhouse-raft-mtls -o jsonpath='{.data.tls\.crt}' | base64 -d > "$WORK/raft-after.crt"

curl --cacert "$WORK/ca-after.crt" "https://$REGISTRY_ENDPOINT/readyz" | tee "$WORK/readyz-after.txt"
curl --cacert "$WORK/ca-after.crt" "https://$REGISTRY_ENDPOINT/api/v1/admin/cluster/status" \
  | tee "$WORK/cluster-status-after.json" \
  | jq '{leader_id, quorum, healthy_voters}'
```

### Expected Checks

- `server-before.crt` and `server-after.crt` differ.
- `raft-before.crt` and `raft-after.crt` differ.
- `/readyz` succeeds with the post-rotation CA.
- Cluster status reports `leader_id != null` and `healthy_voters >= quorum`.
- Existing node trust remains valid if the CA is unchanged; if the CA changed,
  node trust must be reinstalled before `crictl pull`.

### Evidence

- Certificate and Secret listings before and after renewal.
- Before/after decoded public certificates.
- Rollout status log, `/readyz` output, and cluster status JSON.
- Node pull log if CA rotation also required node trust update.

### Cleanup And Rollback

If rotation breaks the registry, restore the previous known-good Helm values or
issuer, then force a new certificate and restart:

```bash
helm -n "$NAMESPACE" rollback layerhouse
kubectl -n "$NAMESPACE" rollout restart statefulset/layerhouse
kubectl -n "$NAMESPACE" rollout status statefulset/layerhouse --timeout=5m
```

### Known Hazards

- CA rotation can invalidate every node's containerd trust. Schedule a test
  maintenance window and keep the old CA until node trust has been updated.
- `cmctl renew` requires cert-manager RBAC and may not be available on minimal
  operator hosts.

## K8S-MANUAL-EXTS3-01: External S3-Compatible Bucket Install

**Mode**: Agent-executable manual
**Priority**: P0

### Preconditions And Environment

- External S3-compatible bucket exists and is dedicated to this test.
- Bucket credentials allow object put/get/list/delete.
- The endpoint is reachable from every Layerhouse pod.

```bash
export RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
export WORK="/tmp/orb-exts3-$RUN_ID"
export NAMESPACE="layerhouse"
export S3_ENDPOINT="https://s3.example.internal"
export S3_BUCKET="layerhouse-$RUN_ID"
export S3_REGION="us-east-1"
export S3_ACCESS_KEY="replace-me"
export S3_SECRET_KEY="replace-me"
umask 077
mkdir -p "$WORK"
chmod 0700 "$WORK"
```

### Commands

```bash
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NAMESPACE" create secret generic layerhouse-s3 \
  --from-literal=access_key="$S3_ACCESS_KEY" \
  --from-literal=secret_key="$S3_SECRET_KEY" \
  --dry-run=client -o yaml | tee "$WORK/s3-secret.yaml" | kubectl apply -f -

helm upgrade --install layerhouse ./deploy/kubernetes/helm \
  --namespace "$NAMESPACE" \
  --create-namespace \
  -f deploy/kubernetes/helm/test-values/cert-manager.yaml \
  --set storage.s3.endpoint="$S3_ENDPOINT" \
  --set storage.s3.bucket="$S3_BUCKET" \
  --set storage.s3.region="$S3_REGION" \
  --set storage.s3.existingSecret=layerhouse-s3

kubectl -n "$NAMESPACE" rollout status statefulset/layerhouse --timeout=5m
kubectl -n "$NAMESPACE" get pods -o wide | tee "$WORK/pods.txt"
```

Push a disposable image, then record S3 object evidence with the platform's S3
client:

```bash
aws --endpoint-url "$S3_ENDPOINT" s3 ls "s3://$S3_BUCKET/blobs/" --recursive | tee "$WORK/s3-blobs.txt"
aws --endpoint-url "$S3_ENDPOINT" s3 ls "s3://$S3_BUCKET/raft-snapshots/" --recursive | tee "$WORK/s3-snapshots.txt"
```

### Expected Checks

- Pods become Ready without bundled RustFS.
- OCI push/pull succeeds against Layerhouse.
- External S3 contains `blobs/` objects after push.
- S3 snapshot objects appear after graceful pod restart or snapshot policy.

### Evidence

- Helm values used, with Secrets redacted or stored privately.
- Pod listing and cluster status JSON.
- OCI push/pull logs.
- S3 object listings for `blobs/` and `raft-snapshots/`.

### Cleanup And Rollback

```bash
helm -n "$NAMESPACE" uninstall layerhouse || true
kubectl -n "$NAMESPACE" delete secret layerhouse-s3 --ignore-not-found
aws --endpoint-url "$S3_ENDPOINT" s3 rm "s3://$S3_BUCKET/" --recursive
```

### Known Hazards

- This plan deletes the configured S3 test bucket prefix during cleanup. Never
  point it at a shared or production bucket.
- S3 credentials in evidence are sensitive.

## K8S-MANUAL-NODETRUST-01: Node Trust Removal/Failure Verification

**Mode**: Agent-executable manual
**Priority**: P1

### Preconditions And Environment

- A test node already trusts the Layerhouse registry CA and can pull a
  disposable image.
- You have approval to edit that node's containerd trust directory.
- A disposable image exists at `$REGISTRY_ENDPOINT/qa/nodetrust:$RUN_ID`.

```bash
export RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
export WORK="/tmp/orb-nodetrust-$RUN_ID"
export REMOTE_WORK="/tmp/orb-nodetrust-$RUN_ID-node"
export REGISTRY_ENDPOINT="registry.internal.example.com:32000"
export IMAGE="$REGISTRY_ENDPOINT/qa/nodetrust:$RUN_ID"
export NODE="worker-node-name"
export TRUST_SOURCE_DIR="$WORK/containerd"
umask 077
mkdir -p "$WORK"
chmod 0700 "$WORK"
```

### Commands

```bash
ssh "$NODE" "sudo crictl pull '$IMAGE'" | tee "$WORK/pull-before.txt"
ssh "$NODE" "mkdir -p '$REMOTE_WORK' && sudo cp -a '/etc/containerd/certs.d/$REGISTRY_ENDPOINT' '$REMOTE_WORK/containerd-trust-backup' 2>/dev/null || true"
ssh "$NODE" "sudo rm -rf '/etc/containerd/certs.d/$REGISTRY_ENDPOINT' && sudo systemctl restart containerd"

set +e
ssh "$NODE" "sudo crictl pull '$IMAGE'" > "$WORK/pull-after-removal.txt" 2>&1
STATUS=$?
set -e
test "$STATUS" -ne 0

ssh "$NODE" "sudo mkdir -p '/etc/containerd/certs.d/$REGISTRY_ENDPOINT'"
scp "$TRUST_SOURCE_DIR/ca.crt" "$NODE:/tmp/layerhouse-ca.crt"
scp "$TRUST_SOURCE_DIR/hosts.toml" "$NODE:/tmp/layerhouse-hosts.toml"
ssh "$NODE" "sudo mv /tmp/layerhouse-ca.crt '/etc/containerd/certs.d/$REGISTRY_ENDPOINT/ca.crt' && sudo mv /tmp/layerhouse-hosts.toml '/etc/containerd/certs.d/$REGISTRY_ENDPOINT/hosts.toml' && sudo systemctl restart containerd"
ssh "$NODE" "sudo crictl pull '$IMAGE'" | tee "$WORK/pull-after-restore.txt"
```

### Expected Checks

- Pull succeeds before trust removal.
- Pull fails after trust removal with an x509 or certificate authority error,
  not an auth-only error.
- Pull succeeds after trust restore.

### Evidence

- Pull logs before removal, after removal, and after restore.
- Node name and trust directory listing before and after.
- Containerd restart/reload output.

### Cleanup And Rollback

Restore the node's original trust directory from the backup if the test restore
does not match the original platform-managed trust:

```bash
ssh "$NODE" "sudo rm -rf '/etc/containerd/certs.d/$REGISTRY_ENDPOINT' && sudo cp -a '$REMOTE_WORK/containerd-trust-backup' '/etc/containerd/certs.d/$REGISTRY_ENDPOINT' && sudo systemctl restart containerd"
```

### Known Hazards

- This is a destructive node-level test. Run only on disposable nodes or during
  an approved maintenance window.
- On managed Kubernetes, direct SSH changes may be reverted by node management;
  record the platform mechanism that owns containerd trust.
