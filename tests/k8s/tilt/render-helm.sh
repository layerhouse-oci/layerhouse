#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${ORB_NAMESPACE:-layerhouse-tilt}"
S3_NAMESPACE="${RUSTFS_NAMESPACE:-layerhouse-tilt-s3}"
RELEASE="${RELEASE:-layerhouse}"
CHART="${CHART:-deploy/kubernetes/helm}"
REGISTRY_ENDPOINT="${REGISTRY_ENDPOINT:-localhost:32050}"
KANIDM_HOST_PORT="${KANIDM_HOST_PORT:-8443}"
S3_BUCKET="${S3_BUCKET:-layerhouse}"
S3_ACCESS_KEY="${S3_ACCESS_KEY:-rustfsadmin}"
S3_SECRET_KEY="${S3_SECRET_KEY:-rustfsadmin}"
WORK="${WORK:-target/tilt/helm}"

mkdir -p "$WORK"
VALUES="$WORK/values.yaml"
cat > "$VALUES" <<YAML
replicaCount: 3

image:
  repository: layerhouse-server
  tag: tilt
  pullPolicy: IfNotPresent

service:
  type: NodePort
  nodePort: 32050

storage:
  s3:
    endpoint: http://rustfs.$S3_NAMESPACE.svc.cluster.local:9000
    bucket: $S3_BUCKET
    region: us-east-1
    pathStyle: true
    existingSecret: layerhouse-s3

server:
  tls:
    existingSecret: layerhouse-server-tls
    dnsNames:
      - localhost

raft:
  tls:
    existingSecret: layerhouse-raft-mtls

auth:
  enabled: true
  issuerUrl: https://localhost:$KANIDM_HOST_PORT/oauth2/openid/layerhouse
  issuerInternalUrl: https://kanidm.kanidm.svc.cluster.local:8443/oauth2/openid/layerhouse
  issuerInternalUrls:
    - https://kanidm.kanidm.svc.cluster.local:8443/oauth2/openid/layerhouse
  clientId: layerhouse
  tokenEndpointUrl: https://$REGISTRY_ENDPOINT/v2/token
  redirectUri: https://$REGISTRY_ENDPOINT/oauth2/callback
  tlsInsecureSkipVerify: true
  existingSecret: layerhouse-auth
  permissions:
    - name: admin-full-access
      groups: ["registry_admins"]
      scopes: ["repository:*:*"]
    - name: developer-access
      groups: ["registry_developers"]
      scopes: ["repository:dev/*:push", "repository:dev/*:pull"]

certManager:
  server:
    enabled: true
    issuerRef:
      name: layerhouse-ca
      kind: ClusterIssuer
      group: cert-manager.io
  raft:
    enabled: true
    issuerRef:
      name: layerhouse-ca
      kind: ClusterIssuer
      group: cert-manager.io
YAML

cat <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: $NAMESPACE
---
apiVersion: v1
kind: Secret
metadata:
  name: layerhouse-s3
  namespace: $NAMESPACE
type: Opaque
stringData:
  access_key: "$S3_ACCESS_KEY"
  secret_key: "$S3_SECRET_KEY"
---
YAML

helm template "$RELEASE" "$CHART" --namespace "$NAMESPACE" -f "$VALUES"
