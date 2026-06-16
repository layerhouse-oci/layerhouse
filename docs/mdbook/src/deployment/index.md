# Deployment

layerhouse is a single-binary OCI registry. It can be deployed in three ways:

| Mode | Orchestrator | Scaling | Best for |
|---|---|---|---|
| [Kubernetes](kubernetes.md) | Helm + StatefulSet | Automatic via `replicas` | Production clusters |
| [Docker Compose](docker-compose.md) | Compose + named services | Manual rolling updates | Multi-host without k8s |
| [Binary](binary.md) | systemd or oxmgr | Manual | Single-host, edge, air-gapped |

All modes use the same configuration schema and the same OCI Distribution
Spec-compliant API. The Raft consensus layer handles leader election and
metadata replication identically in all three modes.

## What you need for any deployment

1. **layerhouse binary** — from [releases](https://github.com/layerhouse-oci/layerhouse/releases) or built from source
2. **S3-compatible storage** — RustFS, MinIO, AWS S3, or any S3 API-compatible store
3. **Configuration** — a TOML file with server, storage, and raft sections

## Choosing a mode

- **Kubernetes**: You have a k8s cluster and want automatic scaling, rolling updates, and StatefulSet-managed pod identities.
- **Docker Compose**: You run on VMs or bare metal without k8s. Compose handles service naming, restarts, and networking.
- **Binary**: Minimal dependencies — just the binary and a process manager. Good for edge deployments, air-gapped environments, or development.

## Directory reference

Deployment artifacts live under `deploy/`:

```
deploy/
  kubernetes/   # Helm chart
  compose/      # Production compose files + configs
  binary/       # Configs, systemd units, oxmgr config
```

Test fixtures live under `tests/compose/`.
