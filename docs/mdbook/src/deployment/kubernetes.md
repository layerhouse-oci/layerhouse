# Kubernetes

layerhouse runs as a StatefulSet with automatic Raft membership management.
The Helm chart is at `deploy/kubernetes/helm/`.

## Architecture

```
┌──────────────────────────────────────────────────┐
│                   Kubernetes                      │
│                                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ orb-0    │  │ orb-1    │  │ orb-2    │        │
│  │ leader   │  │ follower │  │ follower │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       │             │             │               │
│       └─────────────┼─────────────┘               │
│                     │                              │
│            ┌────────┴────────┐                    │
│            │  S3 (external)  │                    │
│            └─────────────────┘                    │
└──────────────────────────────────────────────────┘
```

- Each pod gets a stable hostname: `layerhouse-0`, `layerhouse-1`, ...
- Ordinal 0 bootstraps the Raft cluster if no cluster exists
- DNS discovery (`discovery_dns = "layerhouse"`) finds peers automatically
- StatefulSet reconciler adjusts Raft voters when replicas change
- Ephemeral redb log — no PVC needed. State recovers from S3 snapshots

## Prerequisites

- Kubernetes cluster with a StorageClass for temporary pod files
- External S3-compatible bucket for blobs and Raft snapshots
- Kubernetes Secret with S3 credentials
- TLS Secret for the public registry listener (optional but recommended)
- Raft mTLS Secret (optional but recommended)
- Use separate certificate issuers for public registry TLS and internal Raft
  mTLS. Public ACME issuers should only issue public DNS names; Raft `.svc`
  names should be issued by a private CA.

## Install

```bash
helm install layerhouse ./deploy/kubernetes/helm \
  --namespace layerhouse \
  --create-namespace \
  --set storage.s3.endpoint=https://s3.example.internal \
  --set storage.s3.bucket=layerhouse \
  --set storage.s3.region=us-east-1
```

### With existing Secrets

```bash
kubectl -n layerhouse create secret generic layerhouse-s3 \
  --from-literal=access_key=ACCESS_KEY \
  --from-literal=secret_key=SECRET_KEY

helm install layerhouse ./deploy/kubernetes/helm \
  --namespace layerhouse \
  --set storage.s3.existingSecret=layerhouse-s3 \
  --set storage.s3.endpoint=https://s3.example.internal \
  --set storage.s3.bucket=layerhouse
```

### With cert-manager

```yaml
server:
  tls:
    existingSecret: layerhouse-server-tls
    dnsNames:
      - registry.example.com

raft:
  tls:
    existingSecret: layerhouse-raft-mtls

certManager:
  server:
    enabled: true
    issuerRef:
      name: letsencrypt-prod
      kind: ClusterIssuer
      group: cert-manager.io
  raft:
    enabled: true
    issuerRef:
      name: layerhouse-raft-ca
      kind: Issuer
      group: cert-manager.io
```

`layerhouse-raft-mtls` is the active Raft mTLS Secret name. A manually generated
`Opaque` Secret with `server-ca.crt` and `client-ca.crt` is still supported for
air-gapped installs, but normal Kubernetes installs should let cert-manager own
the Secret and mount `ca.crt` for both trust paths.

## Defaults

| Parameter | Default |
|---|---|
| `replicaCount` | 3 |
| Public port | 5050 |
| Raft port | 5051 |
| Raft mTLS | enabled |
| Authentication | disabled |
| External S3 | required |
| Image | `ghcr.io/adamcavendish/layerhouse-server:<version>` |

## Sidecars

The Helm chart deploys only layerhouse. You deploy RustFS and an OIDC provider separately:

- **RustFS** — Run as a separate StatefulSet or use an external S3 endpoint
- **OIDC Provider** — Run as a separate Deployment for OIDC authentication (Kanidm recommended)

See [Authentication](../authentication/kanidm.md) for Kanidm integration.

## Scaling

```bash
# Scale up — new pod auto-joins the Raft cluster
kubectl scale statefulset layerhouse --replicas=5

# Scale down — pod gracefully leaves before termination
kubectl scale statefulset layerhouse --replicas=3
```

The Kubernetes reconciler (`raft.kubernetes.enabled: true`) handles Raft
membership changes automatically when replicas change.
