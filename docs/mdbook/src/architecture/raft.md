# Raft Clustering

layerhouse uses [OpenRaft](https://github.com/datafuselabs/openraft) (v0.9) for
distributed consensus over metadata.

## Raft Integration

The Raft integration lives in the `raft/` module:

- **`state_machine.rs`** — In-memory `BTreeMap` via `Arc<RwLock<StateMachineData>>`.
  Applies commands: put/delete manifest, mirror rules, sync jobs, PATs. Shared between
  `StateMachine` (writes via Raft apply) and `RaftRouter` (reads).
- **`log_store.rs`** — Ephemeral redb persistence via a dedicated actor thread. All
  redb I/O runs on one background thread. Lost on pod restart; state recovers from
  S3 snapshot.
- **`network.rs`** — HTTP-based Raft RPC (bincode over POST). Routes: `/raft/append`,
  `/raft/vote`, `/raft/snapshot`, `/raft/join`, `/raft/leave`, `/raft/status`.
- **`membership.rs`** — Dynamic cluster membership. DNS-based peer discovery,
  join/leave handlers, exponential backoff join loop.
- **`snapshot_s3.rs`** — S3 snapshot persistence. Upload after each snapshot build,
  download on cold start.
- **`router.rs`** — Write/read routing. Writes go to leader, reads use local state.

## Raft Configuration

```toml
[raft]
listen = "0.0.0.0:5051"
data_dir = "/tmp/raft"
discovery_dns = "layerhouse"
```

Raft uses a separate listener from the public registry/API listener. Production
Helm deployments enable mutual TLS on this listener by default.

Internal Raft timeouts:

| Parameter | Value | Description |
|-----------|-------|-------------|
| `heartbeat_interval` | 500ms | Leader heartbeat frequency |
| `election_timeout_min` | 1,500ms | Minimum election timeout |
| `election_timeout_max` | 3,000ms | Maximum election timeout |
| `snapshot_policy` | LogsSinceLast(1000) | Build snapshot every 1000 log entries |
| `max_in_snapshot_log_to_keep` | 100 | Log entries to retain after snapshot |

## State Machine Data

The state machine stores all metadata in memory using `BTreeMap` keyed by strings:

- `manifests` — repository → (digest → manifest entry)
- `tags` — repository → (tag → digest)
- `blob_ref_counts` — digest → reference count
- `mirror_rules` — rule ID → mirror rule
- `proxy_caches` — cache ID → proxy cache
- `proxy_cache_tag_validations` — cache ID → repository → tag → upstream digest
  and last validation time
- `personal_access_tokens` — token ID → PAT
- `helm_charts` — chart name → chart metadata

All data is serialized to S3 snapshots for recovery.
