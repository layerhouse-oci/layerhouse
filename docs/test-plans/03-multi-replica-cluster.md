# Multi-Replica Test Plan — layerhouse

**Date**: 2026-05-21
**Type**: Test Plan (not a run — enumerates tests to execute)
**Branch**: master
**Scope**: Multi-replica cluster capabilities
**Framework**: docker-compose 3-node cluster (`deploy/compose/cluster.yml`)

---

## Architecture Summary (for test planning)

- **3 named services**: `layerhouse-0` (node_id=1), `layerhouse-1` (node_id=2), `layerhouse-2` (node_id=3)
- **DNS Discovery**: All nodes resolve `layerhouse` → all peer IPs. No static peer list.
- **Bootstrap**: Node 0 self-bootstraps if no cluster exists. Other nodes discover and join.
- **Raft**: openraft with ephemeral redb log + S3 snapshots. No PVC.
- **Reads**: All nodes serve reads from their local state machine (follower reads). Writes forwarded to leader.
- **GC**: Leader-only mark-and-sweep. Followers skip GC ticks.
- **Graceful shutdown**: Upload snapshot → leave cluster → exit.

### Key Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/v2/` | OCI registry API |
| `/raft/status` | Cluster status (state, leader, voters) |
| `/raft/join` | Add node to cluster |
| `/raft/leave` | Remove node from cluster |

### Node Identity

- `layerhouse-0` → node_id=1 (hostname ordinal 0 + 1)
- `layerhouse-1` → node_id=2
- `layerhouse-2` → node_id=3

---

## Features Tested

| Feature | Tests | Priority |
|---------|-------|----------|
| Cluster formation (cold start, DNS discovery, self-bootstrap) | 1.1–1.3 | P0 |
| Leader election (crash, lone survivor, write recovery) | 2.1–2.3 | P0 |
| Data replication (write to leader, redirect, blob serving) | 3.1–3.4 | P0 |
| Follower reads (zero-lag, lag warning, leader read) | 4.1–4.3 | P2 |
| Snapshot persistence (upload, cold start restore, stale catch-up, divergent recovery, schema-compatible restore) | 5.1–5.6 | P1 |
| Dynamic membership (join, leave, last-voter, non-member, redirect, already-member) | 6.1–6.6 | P1 |
| Leader-only operations (GC gating, leader change, metadata-aware deletion, mirror scheduler) | 7.1–7.4 | P2 |
| Graceful shutdown (SIGTERM snapshot upload, orchestrator-driven scale-down, leader shutdown, SIGKILL recovery) | 8.1–8.3 | P1 |
| DNS discovery (peer resolution, partial DNS, self-skip) | 9.1–9.3 | P3 |
| Fault tolerance (network partition, flaps, simultaneous restart, concurrent writes) | 10.1–10.4 | P3 |
| TLS/mTLS (cluster communication encryption) | 11.1 | P3 |

## Coverage Status

| Scenario | Mode | Command/Plan ID | Priority | Current Status | Evidence Path |
|----------|------|-----------------|----------|----------------|---------------|
| Compose 3-node cluster formation and leader gate | Automated | `just compose-up` then `just cluster-status` | P0 | Implemented | command log |
| Production-like Kubernetes 3-node Helm cluster with Raft mTLS | Automated | `just tilt-ci` | P0 | Implemented | `target/tilt/evidence/<run_id>` |
| Kubernetes StatefulSet scale `3 -> 1 -> 3 -> 2 -> 1` with data preserved and converged voter membership | Automated | `just tilt-scale-smoke` | P0 | Implemented, opt-in local smoke | `target/tilt/evidence/<run_id>-scale` |
| One-pod loss and two-pod quorum-loss behavior on Tilt kind | Automated | `just tilt-failure-smoke` | P1 | Implemented, opt-in destructive local smoke | `target/tilt/evidence/<run_id>-failure` |
| Pod restart, StatefulSet restart, S3 snapshot restore log evidence, membership rejoin | Automated | `just tilt-recovery-smoke` | P1 | Implemented, opt-in local smoke | `target/tilt/evidence/<run_id>-recovery` |
| Deep network partition and flap behavior | Agent-executable manual | `K8S-MANUAL-PARTITION-01` | P3 | Manual plan only; not automated because it requires cluster-specific CNI or firewall manipulation | `/tmp/orb-partition-<run_id>` |
| High-volume snapshot compaction and divergent stale-node recovery | Agent-executable manual | `K8S-MANUAL-SNAPSHOT-01` | P2 | Manual plan only; not automated because it needs long write load or temporary snapshot threshold changes | `/tmp/orb-snapshot-<run_id>` |

## Remaining Manual Scenarios

For Kubernetes scale-down, Helm installs use a StatefulSet desired-replica
reconciler instead of relying on every terminating pod to issue an independent
leave. The test evidence must show the voter set converging to the requested
replica count with no dead voters left behind.

| Feature | Reason | Manual/Automation Status |
|---------|--------|--------------------------|
| OCI Distribution Spec conformance | Separate conformance test suite | Automated separately by `just conformance` |
| S3 blob storage correctness | Unit-tested in `store/s3.rs`; shared backend, not Raft-replicated | Automated at unit/integration level, not a cluster manual scenario |
| Performance/throughput benchmarks | Requires dedicated perf environment | Backlog/non-contract until production SLOs and benchmark hardware are defined |
| Upgrade/migration paths | No prior deployed version exists | Not applicable until there is a prior production contract |
| Cross-region replication | Not yet implemented | Backlog/non-contract until cross-region replication exists |
| Deep network partition/flap behavior | Requires CNI or node-level network manipulation that is too environment-dependent for the default Tilt smoke | Manual plan only: `K8S-MANUAL-PARTITION-01` |
| High-volume snapshot compaction and divergent stale-node recovery | Requires many committed writes or targeted snapshot hooks; keep as manual until the runtime exposes a safe admin trigger | Manual plan only: `K8S-MANUAL-SNAPSHOT-01` |

---

## Test Plan

### 1. Cluster Formation & Bootstrap

#### 1.1 Cold start — 3 nodes form cluster

**Precondition**: Fresh RustFS, no S3 data, all 3 nodes starting simultaneously.

**Steps**:
1. `docker compose -f deploy/compose/cluster.yml up -d`
2. Wait for all 3 to be healthy
3. Check `/raft/status` on each node
4. Run a leader gate that requires all three host ports to be reachable and exactly one node to report `state: leader` within 60 seconds

**Expected**:
- Node 0 self-bootstraps (logs: `ordinal-0: self-bootstrapped`)
- Nodes 1 & 2 discover node 0 and join (logs: `successfully joined cluster`)
- All 3 nodes agree on leader
- `/raft/status` reports same `leader_id` on all nodes
- The leader gate fails loudly if a port is down, a host process owns port 5050, or a single reachable node is carrying a 3-voter membership without quorum

**Edge cases**:
- Node 0 starts last — nodes 1 & 2 retry with exponential backoff until node 0 bootstraps
- DNS returns peers in random order
- A stale local debug process started outside compose can expose `/raft/status` on `localhost:5050` while compose registry services are stopped; this is not a healthy compose cluster

#### 1.1a Compose startup leader gate

**Precondition**: Cluster compose is expected to be the only owner of host ports 5050-5052.

**Steps**:
1. Confirm ports 5050-5052 are free before startup, or owned by the expected compose containers after startup.
2. `docker compose -f deploy/compose/cluster.yml up -d --build`
3. Poll `/raft/status` on ports 5050, 5051, and 5052 for up to 60 seconds.
4. Count reachable nodes and leaders on every poll.

**Expected**:
- All three ports become reachable.
- Exactly one node reports `state: leader`.
- The three status responses show distinct node IDs 1, 2, and 3.
- If only one node is reachable and it reports `voters` length 3 with `leader_id: null`, the test reports lost quorum rather than a generic election failure.
- If `localhost:5050` responds while compose shows the registry containers stopped, the test reports host-process contamination and asks the operator to stop the stray debug binary before judging compose health.

**Reference check**:

```bash
wait_for_cluster_leader() {
  local max=${1:-60}
  local states=""
  for i in $(seq 1 "$max"); do
    local reachable=0 leaders=0
    states=""
    for p in 5050 5051 5052; do
      STATUS=$(curl -sf --max-time 2 "http://localhost:$p/raft/status" 2>/dev/null || true)
      if [ -n "$STATUS" ]; then
        reachable=$((reachable + 1))
        STATE=$(echo "$STATUS" | jq -r '.state')
        NODE_ID=$(echo "$STATUS" | jq -r '.node_id')
        VOTERS=$(echo "$STATUS" | jq -r '.voters | length')
        states="$states :$p=node:$NODE_ID,state:$STATE,voters:$VOTERS"
        [ "$STATE" = "leader" ] && leaders=$((leaders + 1))
      else
        states="$states :$p=down"
      fi
    done

    [ "$reachable" -eq 3 ] && [ "$leaders" -eq 1 ] && {
      echo "healthy cluster:$states"
      return 0
    }
    sleep 1
  done

  echo "FAIL: expected 3 reachable nodes and exactly 1 leader; got:$states" >&2
  echo "If one reachable node reports voters=3 with no leader, diagnose lost quorum: check docker compose ps -a, host port owners, and stale local Raft/S3 state." >&2
  return 1
}
```

#### 1.2 Single node cluster (only node 0)

**Precondition**: Modify cluster compose to comment out nodes 1 & 2.

**Steps**:
1. Start only node 0
2. Check `/raft/status`

**Expected**:
- Node 0 self-bootstraps as single-node cluster
- `state: leader`, `voters: [{id:1}]`

#### 1.3 Node 0 is down — others cannot bootstrap

**Precondition**: Start nodes 1 & 2 without node 0.

**Steps**:
1. Start nodes 1 & 2
2. Wait 30 seconds
3. Check `/raft/status`

**Expected**:
- Neither becomes leader
- Both keep retrying DNS discovery with backoff
- No panic, no crash

---

### 2. Leader Election

#### 2.1 Leader election after leader crash

**Precondition**: 3-node cluster running, identify current leader.

**Steps**:
1. `docker compose stop layerhouse-<leader-ordinal>`
2. Wait 5 seconds
3. Check `/raft/status` on remaining nodes

**Expected**:
- Remaining nodes elect new leader within Raft election timeout (~heartbeat interval × 2)
- New `leader_id` matches one of the survivors
- All survivors agree on new leader
- No writes lost (committed entries replicated before leader crash)

#### 2.2 Leader and one follower crash — lone survivor

**Precondition**: 3-node cluster, stop 2 nodes.

**Steps**:
1. Stop leader + one follower
2. Check `/raft/status` on lone survivor

**Expected**:
- Lone survivor does NOT become leader (no quorum)
- `/raft/status`: `state: candidate` or `state: follower`, `leader_id: null`
- Writes fail with consensus error (not timeout)
- Reads from local state still succeed (follower reads)

#### 2.3 Leader crash — writes fail on follower

**Precondition**: 3-node cluster, kill leader.

**Steps**:
1. `docker compose stop layerhouse-0` (if node 0 is leader)
2. Immediately try `docker push` to a surviving node
3. Wait for new leader election
4. Try `docker push` again

**Expected**:
- Push during leaderless window → 503 or redirect to (old) leader
- Push after election → succeeds on new leader
- Followers auto-redirect writes (307 to leader via `LayerhouseError::NotLeader`)

---

### 3. Data Replication

#### 3.1 Write to leader → replicate to followers

**Precondition**: 3-node cluster, push image to leader (or any node that redirects to leader).

**Steps**:
1. Push manifest: `curl -X PUT .../manifests/latest` to leader port
2. Check manifest on follower: `curl .../manifests/latest` on follower port

**Expected**:
- Manifest visible on all nodes within replication time (typically <1s)
- Digest, content-type, body identical across all nodes

#### 3.2 Write to follower → redirect to leader

**Steps**:
1. Push manifest to follower port (not leader)
2. Check response headers

**Expected**:
- Follower returns 307 or error directing to leader
- Manifest eventually committed by Raft and readable on all nodes

#### 3.3 Blob upload → all nodes can serve

**Precondition**: Blobs stored in shared S3 (RustFS), not in Raft.

**Steps**:
1. Upload blob via leader port
2. Download blob via follower port

**Expected**:
- Both can serve blob (S3 is shared backend)
- No replication delay for blobs (direct S3 read)

#### 3.4 Large manifest body — replication integrity

**Steps**:
1. Push manifest with large body (e.g., 10MB annotations)
2. Verify digest on all nodes

**Expected**:
- Digest identical across all nodes
- No truncation or corruption

---

### 4. Follower Reads

#### 4.1 Follower serves read with zero lag

**Precondition**: 3-node cluster, no writes in last 5 seconds.

**Steps**:
1. `curl .../manifests/latest` on follower
2. Check `last_applied` from tracing logs (`follower read` event)

**Expected**:
- Read succeeds on follower
- `last_log_index` equals `last_applied` (lag=0)
- `is_leader: false` in debug log

#### 4.2 Follower lag warning on high-throughput writes

**Precondition**: Rapid manifest pushes (scripted loop).

**Steps**:
1. Push 200+ manifests rapidly to leader
2. Read on follower during push storm
3. Check logs for `follower read lag exceeds threshold`

**Expected**:
- Reads still succeed (eventually consistent)
- If lag > FOLLOWER_READ_LAG_THRESHOLD (100), `warn!` emitted
- Reads never fail, just serve slightly stale data

#### 4.3 Leader serves read

**Steps**:
1. Read manifest on leader
2. Check tracing log

**Expected**:
- `is_leader: true` in debug log
- No lag warning (leader is always up to date)

---

### 5. Snapshot Persistence & Cold Start

#### 5.1 Snapshot uploaded on Raft snapshot trigger

**Precondition**: 3-node cluster, push enough data to trigger snapshot (1000 log entries since last snapshot by default).

**Steps**:
1. Push 1000+ unique manifests
2. Check S3 for `raft-snapshots/<node-id>/latest.bin`

**Expected**:
- Snapshot file exists in S3 for each node
- Snapshot contains full `StateMachineData` (all manifests, tags, mirror rules)
- Subsequent snapshots overwrite previous ones

#### 5.2 Cold start — restore from S3 snapshot

**Precondition**: Cluster running, snapshots exist in S3. Full cluster restart.

**Steps**:
1. `docker compose down`
2. `docker compose -f deploy/compose/cluster.yml up -d --build`
3. Check data integrity
4. Poll `/raft/status` on ports 5050, 5051, and 5052

**Expected**:
- All nodes download snapshot from S3 on startup
- Logs: `restoring state from S3 snapshot`
- All manifests, tags, mirror rules restored
- `verify_or_rejoin` confirms membership or re-joins
- All three nodes remain running after restore
- Exactly one node reports `state: leader`

#### 5.3 New node joins with snapshot restore

**Precondition**: 2-node cluster with data. Add a new node that was previously not part of cluster.

**Steps**:
1. Start new node (ordinal 2, node_id=3) while cluster has data
2. Check join flow

**Expected**:
- New node joins as learner, promoted to voter
- New node receives Raft replication (catches up from leader's log)
- After catch-up, new node has full state

#### 5.4 Node restarts with stale snapshot

**Precondition**: Take node 1 offline, push new data, restart node 1.

**Steps**:
1. Stop node 1
2. Push 50 manifests
3. Restart node 1
4. Check node 1's state

**Expected**:
- Node 1 restores from its last snapshot (stale)
- Raft replication catches it up to current state
- All 50 new manifests appear on node 1 within replication window

#### 5.5 Divergent snapshot recovery (quorum rejection path)

**Precondition**: 3-node cluster with data, graceful stop, all snapshots in S3.

**Steps**:
1. Manually corrupt node 1's S3 snapshot: upload a `StateMachineData` with
   `voters=[1]` and `last_applied_log.index=5` (stale, outdated membership)
2. Restart all 3 nodes simultaneously
3. Check node 1's logs and `/raft/status`

**Expected**:
- Node 1 downloads the corrupt snapshot, restores stale state
- `verify_or_rejoin` queries ALL peers concurrently
- Peers report `last_applied_log` higher than 5 → filter to authoritative peers
- Authoritative peers do NOT confirm node 1's membership (stale `voters=[1]` view)
  or — if they do include node 1 — strict majority check passes and node 1 catches up
- Node 1 either re-joins (logs: `"membership not confirmed by quorum, re-joining"`)
  or catches up via Raft replication
- Final state: `voters=[1,2,3]` on all nodes, consistent `last_applied_log`
- No manual intervention required

**Key verification**: The quorum logic must activate. Look for either:
- `"quorum of authoritative peers confirms cluster membership"` with `in_membership` and `total_auth` counts, OR
- `"membership not confirmed by quorum, re-joining cluster"` with counts,
  followed by `"successfully joined cluster"`

#### 5.6 Snapshot schema compatibility

**Precondition**: RustFS contains an older `raft-snapshots/<node-id>/latest.bin`
whose manifest entries are missing newer metadata fields such as
`stored_size_bytes`, `manifest_size_bytes`, `created_at`, `last_modified`, or
`config_summary`.

**Steps**:
1. Start the existing RustFS volume without deleting S3 data.
2. Rebuild and restart the cluster:
   `docker compose -f deploy/compose/cluster.yml up -d --build layerhouse-0 layerhouse-1 layerhouse-2`
3. Inspect logs for all three registry containers.
4. Call:
   `curl -s http://localhost:5050/api/v1/repositories/{name}/manifests?n=50 | jq .`
5. Check leader health on all three ports.

**Expected**:
- Nodes do not crash with JSON errors such as `missing field stored_size_bytes`
  or `missing field manifest_size_bytes`.
- Restore normalizes missing manifest metadata with safe defaults.
- Manifest list APIs return explicit `stored_size_bytes`,
  `manifest_size_bytes`, `created_at`, and `last_modified` when the manifest
  body is available.
- The compose cluster still reaches three running nodes and exactly one leader.
- Operators are not required to wipe the RustFS volume for local schema changes.

---

### 6. Dynamic Membership

#### 6.1 Join — follower adds itself

**Steps**:
1. Add a new named service `layerhouse-3` to cluster compose
2. Start it
3. Check `/raft/status` on any node

**Expected**:
- New node appears in `voters` list
- `leader_id` unchanged
- No disruption to existing nodes

#### 6.2 Leave — node gracefully removes itself

**Steps**:
1. `curl -X POST http://localhost:5051/raft/leave -d '{"node_id":2}'`
2. Check `/raft/status`

**Expected**:
- Node 2 removed from voters
- Node 2's `leave` response: `result: ok`
- Cluster continues with remaining nodes

#### 6.3 Leave — last voter

**Steps**:
1. In 1-node cluster, try `curl .../raft/leave -d '{"node_id":1}'`

**Expected**:
- Response: `result: last_voter`
- Node NOT removed

#### 6.4 Leave — non-member

**Steps**:
1. Try to remove node_id=99 from cluster

**Expected**:
- Response: `result: not_member`

#### 6.5 Join — redirect to leader

**Steps**:
1. `curl -X POST http://localhost:5051/raft/join ...` (to follower)
2. Check response

**Expected**:
- Response: `result: not_leader`, `leader_addr` populated
- Client should re-send to leader_addr

#### 6.6 Join — already member

**Steps**:
1. Try to re-join an existing member

**Expected**:
- Response: `result: already_member`

---

### 7. Leader-Only Operations

#### 7.1 GC only runs on leader

**Precondition**: 3-node cluster, GC interval set to 10s for testing.

**Steps**:
1. Check GC logs on each node.
2. Query `GET /api/v1/admin/gc/status` on the leader.
3. Confirm the GC status record includes last run time, duration, scanned
   objects, candidates, deleted objects, skipped referenced objects, skipped
   young objects, delete errors, dry-run flag, leadership-loss flag, and last
   error.

**Expected**:
- Leader: `GC sweep completed` events
- Followers: No GC sweep logs (skip at leader gate)
- Leader stats are monotonic within a run and distinguish skipped referenced
  blobs from skipped young blobs.

#### 7.2 GC continues after leader change

**Precondition**: GC running on leader. Kill leader.

**Steps**:
1. Stop leader node
2. Wait for new leader election + GC interval
3. Check GC logs on new leader

**Expected**:
- New leader starts running GC sweeps
- Old leader (if restarted as follower) stops GC
- No double-GC (only one leader at a time)
- A node that loses leadership before a delete batch aborts the batch and
  reports leadership loss rather than continuing S3 deletes.

#### 7.3 Metadata-aware GC deletion safety

**Precondition**: 3-node cluster with short GC interval and short test grace
period. Push at least two blobs: one referenced by a committed manifest and one
old unreferenced blob.

**Steps**:
1. Verify manifest PUT records referenced blob digests in the Raft state
   machine and increments derived blob ref counts once per manifest digest.
2. Delete a tag and confirm blob ref counts do not change.
3. Delete the manifest digest or repository and confirm only then the relevant
   ref counts decrement.
4. Send blob `DELETE` for a referenced blob and confirm the route returns
   `202 Accepted`, the blob remains readable while referenced, and no S3 delete
   is issued.
5. Trigger or wait for GC.
6. During a GC candidate window, push a manifest that references one candidate
   blob and confirm the final metadata re-check observes the new reference.
7. Restart a node from S3 snapshot and verify ref counts rebuild from manifests
   before GC can delete.

**Expected**:
- Referenced blobs are never physically deleted.
- Explicit blob-delete requests hide only unreferenced blobs from registry
  reads; referenced blobs stay readable until their manifest references are
  removed.
- Young blobs inside the configured grace period are skipped.
- Old unreferenced blobs are batch-deleted from S3 only by the current leader.
- Snapshot restore rebuilds `blob_ref_counts` deterministically from manifest
  metadata and manifest bodies.

#### 7.4 Mirror scheduler — only one instance

**Steps**:
1. Check mirror/scheduler logs on each node

**Expected**:
- Mirror scheduler also leader-gated (check code)
- Only leader schedules and executes mirror jobs

---

### 8. Graceful Shutdown

#### 8.1 SIGTERM triggers snapshot + leave

**Precondition**: 3-node cluster.

**Steps**:
1. `docker compose stop layerhouse-1`
2. Check logs
3. Check S3 for updated snapshot

**Expected**:
- Logs: `uploaded raft snapshot to S3` before exit
- Logs: `node left cluster` (if leader processed the leave)
- Node cleanly removed from voters
- No data loss (snapshot uploaded)

#### 8.2 SIGTERM on leader

**Steps**:
1. Stop current leader
2. Check remaining nodes

**Expected**:
- Leader uploads snapshot before exit
- Leader does NOT need to "leave" itself — cluster can elect new leader
- New leader elected within election timeout

#### 8.3 SIGKILL (unclean shutdown)

**Steps**:
1. `docker kill --signal=KILL layerhouse-0`
2. Check remaining nodes

**Expected**:
- Cluster continues (has quorum)
- Killed node restarts from S3 snapshot
- Killed node re-joins cluster automatically

---

### 9. DNS Discovery

#### 9.1 Discovery resolves all peers

**Steps**:
1. Check DNS resolution inside any container: `getent hosts layerhouse`

**Expected**:
- Returns IPs of all 3 nodes
- docker-compose aliases provide this via embedded DNS

#### 9.2 Discovery with partial DNS — graceful retry

**Precondition**: Temporarily remove DNS aliases.

**Steps**:
1. Modify compose to remove `aliases: [layerhouse]` from one node
2. Restart
3. Check join behavior

**Expected**:
- Node discovers fewer peers but still joins if leader is reachable
- Exponential backoff on discovery failure (500ms → 10s max)

#### 9.3 DNS returns self — skip

**Steps**:
1. Check join loop logs when DNS includes own address

**Expected**:
- `status.node_id == node_id` → `continue` (skip self)

---

### 10. Fault Tolerance & Edge Cases

#### 10.1 Network partition — split brain prevention

**Precondition**: 3-node cluster. Isolate leader from followers (iptables or docker network).

**Steps**:
1. Block leader's port on follower networks
2. Check cluster state

**Expected**:
- Followers cannot reach leader → election timeout → new leader elected
- Old leader steps down (cannot reach quorum)
- When partition heals, ex-leader rejoins as follower
- No two leaders simultaneously (Raft guarantees)

#### 10.2 Intermittent network flaps

**Steps**:
1. Introduce 2s packet loss to leader
2. Push manifests during flaps

**Expected**:
- Some writes timeout → retry on new leader
- No duplicate entries (Raft log deduplication)
- Cluster stabilizes after network heals

#### 10.3 All nodes restart simultaneously

**Steps**:
1. `docker compose down`
2. `docker compose up -d`
3. Check cluster formation

**Expected**:
- Node 0 bootstraps (or restores from snapshot)
- Other nodes discover and join
- Full data recovery from S3 snapshots
- <30s to full cluster health

#### 10.4 Concurrent writes from different clients

**Steps**:
1. Two clients push different manifests simultaneously
2. Verify both committed

**Expected**:
- Both writes committed (Raft linearizability)
- If conflicting tag → last writer wins
- Both manifests accessible on all nodes

---

### 11. TLS / mTLS (if enabled)

#### 11.1 Cluster with TLS

**Precondition**: `[raft.tls]` configured with valid certs.

**Steps**:
1. Start cluster with TLS
2. Check `/raft/status` over HTTPS
3. Verify inter-node communication is encrypted

**Expected**:
- Nodes connect over HTTPS
- Join/leave work over TLS
- Self-signed certs work if CA configured

---

## Test Execution Priority

| Priority | Test | Why |
|----------|------|-----|
| P0 | 1.1 Cold start 3-node | Basic cluster formation |
| P0 | 2.1 Leader election after crash | Core Raft correctness |
| P0 | 3.1 Write replication | Data integrity |
| P1 | 5.2 Cold start restore | Snapshot integrity |
| P1 | 5.6 Snapshot schema compatibility | Local/dev upgrade safety |
| P1 | 2.2 Lone survivor no quorum | Correct quorum behavior |
| P1 | 6.2 Graceful leave | Membership safety |
| P2 | 4.1/4.2 Follower reads | Observability |
| P2 | 7.1 GC leader-only | Correct GC gating |
| P2 | 7.3 GC metadata-aware deletion safety | Blob lifecycle correctness |
| P3 | TLS tests | Optional feature |
| P3 | Network partition tests | Hard to orchestrate in docker |

---

## Traceability Matrix

### Tests → Design Decisions

| Test | Validates | Design Doc Reference |
|------|-----------|---------------------|
| 1.1 Cold start 3-node | DNS-based peer discovery, ordinal-0 bootstrap | Design: clustering model |
| 5.2 Cold start restore | S3 snapshot as source of truth, ephemeral redb | Design: Raft integration |
| 5.5 Divergent snapshot recovery | Quorum-based `verify_or_rejoin`, authoritative peer comparison | Fix `2566404` |
| 5.6 Snapshot schema compatibility | Raft snapshot restore is tolerant of additive metadata fields | Dashboard repository metadata |
| 8.1 SIGTERM snapshot+leave | Graceful shutdown: snapshot → leave → exit | Design: clustering model |
| 10.3 Simultaneous restart | Full recovery from S3 without split-brain | Fix `2566404` |

### Tests → Bugs Caught

| Test | Bug | Severity | Fixed |
|------|-----|----------|-------|
| 5.2, 10.3 | Bug 1: Snapshot Membership Inconsistency | High | `2566404` |
| 6.2, 6.3 | Bug 2: Stale Configuration Change | Medium | `2566404` `44357c6` |
| 1.1, 8.3 | Bug 3: Learner Stuck After Re-join | Medium | `44357c6` |
| 6.3, 8.1 | Bug 4: LastVoter Guard Off-by-One | Low | `44357c6` |
| 5.6 | Bug 5: Additive manifest metadata crashed restore from older S3 snapshots | High | current implementation |

---

## Prerequisites

- `docker compose` v2
- RustFS images available (pulled from Docker Hub)
- layerhouse Docker image built
- Ports 5050-5052 free on host
- `curl` and `jq` for CLI verification

## Running the Tests

```bash
# Start cluster
docker compose -f deploy/compose/cluster.yml up -d --build

# Wait for health
for p in 5050 5051 5052; do
  while ! curl -sf http://localhost:$p/v2/ >/dev/null; do sleep 1; done
  echo "port $p ready"
done

# Check cluster status
curl -s http://localhost:5050/raft/status | jq .
curl -s http://localhost:5051/raft/status | jq .
curl -s http://localhost:5052/raft/status | jq .

# Gate cluster readiness on election, not only HTTP readiness
wait_for_cluster_leader 60

# Test write → read replication
# (use ORAS, Docker, or direct curl)
```

---

## Agent-Executable Manual Plans

### K8S-MANUAL-PARTITION-01: Network Partition And Flap Behavior

**Preconditions**: Disposable Kubernetes cluster with a CNI or node firewall
mechanism that can block traffic between selected Layerhouse pods without
deleting the pods.

**Commands**:

```bash
export RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
export WORK="/tmp/orb-partition-$RUN_ID"
export NAMESPACE="layerhouse"
mkdir -p "$WORK"
kubectl -n "$NAMESPACE" get pods -o wide | tee "$WORK/pods-before.txt"

# Apply the platform-specific partition here. Record the exact command.
# Example categories: CNI policy, node firewall rule, or test harness network cut.

curl -fsS "$REGISTRY_STATUS_URL" | tee "$WORK/status-during-partition.json"

# Remove the partition and verify recovery.
kubectl -n "$NAMESPACE" rollout status statefulset/layerhouse --timeout=5m
curl -fsS "$REGISTRY_STATUS_URL" | tee "$WORK/status-after-heal.json"
```

**Expected**: Majority side keeps or elects a leader; minority side cannot
commit writes; after healing, `healthy_voters >= quorum` and disposable pushed
metadata is consistent on all nodes.

**Evidence**: partition command transcript, before/during/after cluster status
JSON, pod state, and server logs around election changes.

**Cleanup/Rollback**: remove all partition/firewall/CNI test rules and confirm
normal pod-to-pod connectivity before ending the run.

**Hazards**: network manipulation is cluster-specific and can affect unrelated
workloads. Use disposable nodes or a dedicated namespace with explicit approval.

### K8S-MANUAL-SNAPSHOT-01: High-Volume Snapshot And Stale-Node Recovery

**Preconditions**: Dedicated cluster and S3 bucket. The operator can generate
enough committed writes to trigger snapshot policy or can run a build with a
temporary low snapshot threshold.

**Commands**:

```bash
export RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
export WORK="/tmp/orb-snapshot-$RUN_ID"
export NAMESPACE="layerhouse"
mkdir -p "$WORK"

for i in $(seq 1 1200); do
  # Push or create a disposable manifest/tag so Raft commits exceed snapshot threshold.
  # Record the exact client command used for this environment.
  :
done

kubectl -n "$NAMESPACE" logs statefulset/layerhouse --all-containers=true \
  | tee "$WORK/logs-after-snapshot-load.txt"
kubectl -n "$NAMESPACE" rollout restart statefulset/layerhouse
kubectl -n "$NAMESPACE" rollout status statefulset/layerhouse --timeout=5m
curl -fsS "$REGISTRY_STATUS_URL" | tee "$WORK/status-after-restore.json"
```

**Expected**: logs show snapshot upload and restore; after restart the cluster
has a leader, `healthy_voters >= quorum`, and previously pushed disposable tags
remain readable.

**Evidence**: write workload transcript, snapshot log excerpts, S3
`raft-snapshots/` listing, cluster status JSON, and post-restore read checks.

**Cleanup/Rollback**: delete disposable repositories and remove only the test
bucket/prefix created for this run.

## Notes

- **Browser testing covered separately** — this plan is API/runtime focused. Dashboard browser coverage lives in the product contract plans.
- **S3 is shared** — blobs are not replicated via Raft, only metadata. Tests should verify blob availability from any node but not expect per-node blob state.
- **redb is ephemeral** — local Raft log is lost on container restart. Snapshot in S3 is the source of truth.
- **GC grace period** — 1 hour default. Tests should use short intervals for observability but normal intervals for production validation.
