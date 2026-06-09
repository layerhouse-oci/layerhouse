# Health Checks

## Endpoints

| Endpoint | Auth Required | Purpose |
|----------|---------------|---------|
| `GET /healthz` | No | Liveness probe — returns 200 OK |
| `GET /readyz` | No | Readiness probe — verifies S3 access and a known Raft leader |
| `GET /metrics` | No | Prometheus metrics |
| `GET /v2/` | Conditional | OCI API version check |
| `GET /api/v1/admin/cluster/status` | Yes (when auth enabled) | Raft cluster health |

## `/healthz`

Returns `200 OK` when the process is running.

```bash
curl -v http://localhost:5050/healthz
# HTTP/1.1 200 OK
```

## `/readyz`

Returns `200 OK` only when the node can reach S3 and has a known Raft leader.
Returns `503` while the node is still joining, cannot reach S3, or cannot observe
cluster leadership.

```bash
curl -v http://localhost:5050/readyz
# HTTP/1.1 200 OK
```

## Cluster Status

```bash
curl http://localhost:5050/api/v1/admin/cluster/status | jq
```

Response:

```json
{
  "cluster_id": "layerhouse-1",
  "leader_id": 1,
  "term": 7,
  "quorum": 2,
  "healthy_voters": 3,
  "updated_at": 1770000000,
  "voters": [
    {
      "node_id": 1,
      "address": "layerhouse-0.layerhouse-headless.layerhouse.svc:5051",
      "role": "leader",
      "status": "healthy",
      "commit_index": 42,
      "replication_lag_ms": 0
    },
    {
      "node_id": 2,
      "address": "layerhouse-1.layerhouse-headless.layerhouse.svc:5051",
      "role": "voter",
      "status": "healthy",
      "commit_index": 42,
      "replication_lag_ms": 0
    },
    {
      "node_id": 3,
      "address": "layerhouse-2.layerhouse-headless.layerhouse.svc:5051",
      "role": "voter",
      "status": "healthy",
      "commit_index": 42,
      "replication_lag_ms": 0
    }
  ],
  "learners": []
}
```

## Docker Health Checks

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://127.0.0.1:5050/healthz"]
  interval: 5s
  timeout: 5s
  retries: 5
  start_period: 10s
```

## Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 5050
    scheme: HTTPS
  initialDelaySeconds: 10
  periodSeconds: 5

readinessProbe:
  httpGet:
    path: /readyz
    port: 5050
    scheme: HTTPS
  initialDelaySeconds: 5
  periodSeconds: 3
```
