# Kubernetes

orb-chrysa runs as a StatefulSet with automatic Raft membership management.
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

- Each pod gets a stable hostname: `orb-chrysa-0`, `orb-chrysa-1`, ...
- Ordinal 0 bootstraps the Raft cluster if no cluster exists
- DNS discovery (`discovery_dns = "orb-chrysa"`) finds peers automatically
- StatefulSet reconciler adjusts Raft voters when replicas change
- Ephemeral redb log — no PVC needed. State recovers from S3 snapshots

## Prerequisites

- Kubernetes cluster with a StorageClass for temporary pod files
- External S3-compatible bucket for blobs and Raft snapshots
- Kubernetes Secret with S3 credentials
- TLS Secret for the public registry listener (optional but recommended)
- Raft mTLS Secret (optional but recommended)

## Install

```bash
helm install orb-chrysa ./deploy/kubernetes/helm \
  --namespace orb-chrysa \
  --create-namespace \
  --set storage.s3.endpoint=https://s3.example.internal \
  --set storage.s3.bucket=orb-chrysa \
  --set storage.s3.region=us-east-1
```

### With existing Secrets

```bash
kubectl -n orb-chrysa create secret generic orb-chrysa-s3 \
  --from-literal=access_key=ACCESS_KEY \
  --from-literal=secret_key=SECRET_KEY

helm install orb-chrysa ./deploy/kubernetes/helm \
  --namespace orb-chrysa \
  --set storage.s3.existingSecret=orb-chrysa-s3 \
  --set storage.s3.endpoint=https://s3.example.internal \
  --set storage.s3.bucket=orb-chrysa
```

## Defaults

| Parameter | Default |
|---|---|
| `replicaCount` | 3 |
| Public port | 5050 |
| Raft port | 5051 |
| Raft mTLS | enabled |
| Authentication | disabled |
| External S3 | required |
| Image | `ghcr.io/adamcavendish/orb-chrysa-server:<version>` |

## Sidecars

The Helm chart deploys only orb-chrysa. You deploy RustFS and an OIDC provider separately:

- **RustFS** — Run as a separate StatefulSet or use an external S3 endpoint
- **OIDC Provider** — Run as a separate Deployment for OIDC authentication (Kanidm recommended)

See [Authentication](../authentication/kanidm.md) for Kanidm integration.

## Scaling

```bash
# Scale up — new pod auto-joins the Raft cluster
kubectl scale statefulset orb-chrysa --replicas=5

# Scale down — pod gracefully leaves before termination
kubectl scale statefulset orb-chrysa --replicas=3
```

The Kubernetes reconciler (`raft.kubernetes.enabled: true`) handles Raft
membership changes automatically when replicas change.
