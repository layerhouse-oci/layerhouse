# Production OCI Workflow Test Plan

**Date**: 2026-05-26
**Type**: Runtime product test plan
**Source**: OCI Distribution behavior, repository browser runtime behavior,
and local compose production workflow QA
**Scope**: Real OCI client workflows against an layerhouse registry: push,
pull, tag listing, manifest/blob reads, range reads, dashboard/API delete
flows, follower reads, and cleanup.

---

## Product Contract Summary

layerhouse must behave like a production OCI registry for ordinary clients.
Metadata changes are committed through Raft; blob bytes are stored in S3. Real
clients such as Docker and ORAS should be able to push and pull through the
`/v2/*` Distribution API, while dashboard `/api/v1/*` endpoints expose enriched
repository, digest, tag, copy, and delete workflows for operators.

## Safety Boundary

Run these tests only against repositories under a disposable prefix such as
`qa/oci-*`. Destructive cleanup must delete only repositories created by this
test pass. Existing fixture repositories such as `platform/layerhouse-api`,
`mirror/*`, and `cache/*` must not be deleted by this plan.

## Tooling

The preferred local tools are:

- `oras` for generic OCI artifacts and digest-focused copy/pull checks.
- `docker` for container image push/pull compatibility.
- `curl` and `jq` for Distribution and dashboard API assertions.
- `crane` or `skopeo` as optional cross-client confirmation.

Use `--plain-http` or equivalent for local compose because TLS is not enabled
on `localhost:5050` in the development cluster.

The executable local regression script is:

```bash
tests/production/oci-workflow.sh
```

It assumes a running registry at `localhost:5050`, writes evidence to
`/tmp/orb-oci-{RUN_ID}`, and deletes only disposable `qa/oci-*` repositories.
Override `REGISTRY`, `SCHEME`, `NODE_PORTS`, `RUN_ID`, or `EVIDENCE_ROOT` when
testing a different environment.

## Local Execution Notes

- ORAS rejects absolute file paths by default. Run `oras push` from the scratch
  directory with relative file paths, or intentionally pass
  `--disable-path-validation` when testing absolute-path handling.
- Docker treats `localhost` registries as local/insecure for development, so no
  daemon insecure-registry change is required for `localhost:5050`.
- Dashboard delete responses return `deleted_manifests` and `deleted_tags`.
- For automated browser copy checks, grant clipboard permissions for
  `http://localhost:5050` before reading `navigator.clipboard`.
- A follower-write smoke test should choose any exposed node port that is not
  the current leader and then verify tag visibility from ports 5050, 5051, and
  5052.

## Features Tested

| Feature | Tests | Priority |
|---------|-------|----------|
| Registry liveness and client compatibility | OCI1 | P0 |
| ORAS artifact push and pull | OCI2 | P0 |
| Docker image push and pull | OCI3 | P0 |
| Tags, manifests, blobs, and range reads | OCI4 | P0 |
| Dashboard repository/detail consistency | OCI5 | P0 |
| Tag delete and untagged digest behavior | OCI6 | P0 |
| Digest delete and cascading tag removal | OCI7 | P0 |
| Repository delete and cleanup | OCI8 | P0 |
| Follower reads and leader-routed writes | OCI9 | P1 |
| Copy-value invariants | OCI10 | P1 |
| Negative and edge cases | OCI11 | P1 |
| Blob redirect mode with private/public S3 endpoints | OCI12 | P1 |
| Host Docker daemon trust and strict HTTPS push through NodePort | OCI13 | P1 |

## Coverage Status

| Scenario | Mode | Command/Plan ID | Priority | Current Status | Evidence Path |
|----------|------|-----------------|----------|----------------|---------------|
| Compose OCI push/pull/delete/range workflow | Automated | `just production-oci` | P0 | Implemented, opt-in local smoke | `/tmp/orb-oci-<run_id>` |
| Compose OCI plus mirror/proxy production smoke | Automated | `just production-smoke` | P1 | Implemented, opt-in local smoke | child workflow evidence dirs |
| Redirect-mode blob workflow | Automated | `EXPECT_BLOB_REDIRECT=1 tests/production/oci-workflow.sh` | P1 | Implemented, requires redirect compose config | `/tmp/orb-oci-<run_id>` |
| Tilt Helm happy path authenticated image push and Kubernetes pull | Automated | `just tilt-ci` | P0 | Implemented | `target/tilt/evidence/<run_id>` |
| Tilt Helm host Docker trust restart and mandatory host `docker push` | Automated | `just tilt-ci-host-docker` | P1 | Implemented, opt-in because it may restart Docker; latest local pass `target/tilt/evidence/20260601-143738` | `target/tilt/evidence/<run_id>` |
| OCI Distribution conformance | Automated | `just conformance` | P1 | Implemented, opt-in conformance runner | `tests/conformance/results` |
| Release chart/image packaging dry run | Automated | `just release-dry-run` | P0 | Implemented, runs local gates | `target/release-dry-run/<version>` |
| Tagged GitHub release, GHCR image, Helm chart archive, CLI binaries | Agent-executable manual | `REL-MANUAL-GHCR-01` | P0 | Manual plan only; not automated because it publishes public release artifacts | `/tmp/orb-release-<run_id>` |

## Tests

### OCI1. Registry Liveness And Cluster Health

**Steps**:
1. Start the compose cluster.
2. Call `GET /v2/` on `localhost:5050`.
3. Call `GET /api/v1/admin/cluster/status`.
4. Confirm all three exposed node ports are reachable when running a cluster.

**Expected**:
- `/v2/` returns HTTP 200 without requiring auth when auth is not configured.
- Cluster status reports a non-null leader, quorum, and healthy voters.
- All node ports used for the test are reachable before client workflows start.

### OCI2. ORAS Artifact Push And Pull

**Steps**:
1. Create a small local test file.
2. Push it with `oras push --plain-http localhost:5050/qa/oci-oras:{tag}`.
3. Capture the pushed manifest digest from ORAS output or the registry API.
4. Pull by tag into a clean directory.
5. Pull by digest into another clean directory.
6. Compare pulled file bytes to the original.

**Expected**:
- Push succeeds and returns a manifest digest.
- Pull by tag and pull by digest both succeed.
- Pulled bytes exactly match the original.
- Dashboard manifest list contains one digest row with the pushed tag.

### OCI3. Docker Image Push And Pull

**Steps**:
1. Build or retag a tiny local image.
2. Push it to `localhost:5050/qa/oci-docker:{tag}`.
3. Remove the local tag/image reference.
4. Pull it back from layerhouse.
5. Inspect the pulled image ID and manifest digest.

**Expected**:
- Docker push succeeds using the standard blob upload and manifest PUT flow.
- Docker pull succeeds from layerhouse.
- The pulled image is runnable or inspectable locally.
- Dashboard repository APIs show the pushed repository, tag, and digest.

### OCI4. Tags, Manifests, Blobs, And Range Reads

**Steps**:
1. Call `/v2/{name}/tags/list` for ORAS and Docker repositories.
2. `HEAD` and `GET` the manifest by tag.
3. `HEAD` and `GET` the manifest by digest.
4. Extract at least one referenced blob digest from the manifest.
5. `HEAD` and `GET` that blob.
6. Send `Range: bytes=0-9` for the blob.

**Expected**:
- Tag list includes pushed tags.
- Manifest responses include `Docker-Content-Digest` and correct media type.
- Blob responses include `Docker-Content-Digest`, `Content-Length`, and
  `Accept-Ranges`.
- Range read returns HTTP 206 and the expected byte count.

### OCI5. Dashboard Repository And Detail Consistency

**Steps**:
1. Call `GET /api/v1/repositories?q=qa/oci`.
2. Call `GET /api/v1/repositories/{name}/manifests` for each test repo.
3. Call `GET /api/v1/repositories/{name}/manifests/{digest}`.
4. Call `GET /api/v1/repositories/{name}/manifests/{digest}/raw`.

**Expected**:
- Repository summaries include tag count, manifest count,
  `stored_size_bytes`, `manifest_size_bytes`, and last modified data.
- Detail APIs are digest-first: each row is one manifest digest, with tags
  attached to the row, plus `stored_size_bytes` and `manifest_size_bytes`.
- Raw manifest bytes parse as valid JSON.
- Type/media metadata is stable enough for the dashboard to classify or show as
  unknown.

### OCI12. Blob Redirect Mode

**Precondition**: Start the compose cluster with redirect enabled while keeping
server-side S3 I/O private and client redirects public:

```bash
LAYERHOUSE_CONFIG="$PWD/tests/fixtures/configs/compose/cluster-redirect.toml" \
  docker compose -f deploy/compose/cluster.yml up -d --build
EXPECT_BLOB_REDIRECT=1 tests/production/oci-workflow.sh
```

The redirect config uses private `storage.s3.endpoint = "http://rustfs:9000"`
and public `storage.s3.redirect.public_endpoint = "http://localhost:9000"`.

**Steps**:
1. Push an ORAS artifact.
2. `HEAD` the blob and verify the registry still responds directly.
3. Full `GET` the blob without `Range`.
4. Confirm the response is HTTP 307 with `Location`,
   `Docker-Content-Digest`, and `Accept-Ranges`.
5. Verify the `Location` begins with the configured public S3 endpoint.
6. Follow the redirect URL and compare downloaded bytes to the pushed payload.
7. Send `Range: bytes=0-9` to the registry blob URL.

**Expected**:
- Normal blob storage access continues to use the private compose DNS endpoint.
- Full blob GET redirects to the public S3/RustFS endpoint.
- Redirect-followed bytes exactly match the original payload.
- `HEAD` and `Range` GET remain proxied by the registry for v1 redirect mode.
- Missing blobs still return OCI `BLOB_UNKNOWN`; redirect mode must not mask
  registry error semantics.

> Note: the redirect response body is empty, so its HTTP `Content-Length`
> describes the redirect response framing rather than the blob size. The
> followed S3 response carries the blob body length.

### OCI13. Host Docker Trust Restart And Strict HTTPS Push

**Precondition**: Tilt kind cluster is available, `localhost:32050` is the
public NodePort endpoint, and cert-manager has issued `layerhouse-server-tls`.

**Steps**:
1. Run `KANIDM_HOST_PORT=28443 just tilt-ci-host-docker`.
2. Confirm the `host-docker-trust` phase installs the registry CA and verifies
   host Docker reaches the registry without an x509 error.
3. Confirm the full smoke runs with `REQUIRE_HOST_DOCKER_PUSH=1`.
4. Confirm host `docker push` succeeds with the Kanidm service token.
5. Confirm host `docker push` succeeds with a generated PAT.
6. Confirm every kind node can `crictl pull` the pushed image.
7. Confirm `kubectl run` pulls the image through the Kubernetes image pull path.

**Expected**:
- Docker backend restart/reload, if needed, completes before smoke assertions.
- Kubernetes API recovers after the Docker trust phase.
- The smoke does not use the kind containerd push fallback.
- Evidence under `target/tilt/evidence/<run_id>` includes `commands.log`,
  `cluster-status.json`, Docker push logs, PAT response, node pull output, and
  `kubectl-run.log`.

### OCI6. Tag Delete And Untagged Digest Behavior

**Steps**:
1. Push or retag a second tag pointing at the same ORAS digest.
2. Delete one tag through
   `DELETE /api/v1/repositories/{name}/manifests/{digest}/tags/{tag}`.
3. Verify `/v2/{name}/tags/list` no longer includes that tag.
4. Delete the last tag on the digest.
5. Reload dashboard manifest list.

**Expected**:
- Deleting one tag does not delete the manifest digest when another tag remains.
- Deleting the last tag makes the digest untagged, not immediately absent.
- Dashboard detail still returns the digest with an empty `tags` array.

### OCI7. Digest Delete And Cascading Tag Removal

**Steps**:
1. Push a digest with at least one tag.
2. Delete it through `DELETE /api/v1/repositories/{name}/manifests/{digest}`.
3. Verify the API response includes deleted manifest and tag counts.
4. Verify manifest `GET` by digest and tag now returns not found.

**Expected**:
- Digest delete removes the manifest row and all tags pointing to it.
- Delete responses use `deleted_manifests` and `deleted_tags` count fields.
- Blob bytes are left for normal GC; immediate S3 blob deletion is not required.
- Dashboard and `/v2/*` reads agree after deletion.

### OCI8. Repository Delete And Cleanup

**Steps**:
1. Delete test repositories through `DELETE /api/v1/repositories/{name}`.
2. Verify repository list no longer includes them.
3. Verify `/v2/{name}/tags/list` returns an empty or not-found result according
   to the registry error contract.

**Expected**:
- Repository delete removes all manifests and tags for that repository.
- Response includes `deleted_manifests` and `deleted_tags` counts.
- Cleanup touches only `qa/oci-*` repositories.

### OCI9. Follower Reads And Leader-Routed Writes

**Steps**:
1. Discover leader from `/api/v1/admin/cluster/status`.
2. Read tags/manifests from all exposed ports.
3. Push through a follower port when practical.
4. Re-read through the leader and followers.

**Expected**:
- Reads work from followers.
- Writes sent to a follower are redirected or forwarded to the leader according
  to the Raft routing contract.
- All nodes converge on the same repository metadata.

### OCI10. Copy-Value Invariants

**Steps**:
1. Grant clipboard read/write permission to the dashboard origin when running
   this as browser automation.
2. Copy repository name, manifest digest, config digest, subject digest, and
   Helm/ORAS command snippets from dashboard controls where present.
3. Paste each value into a local scratch file or shell variable.
4. Use copied values in `curl`, `oras pull`, or dashboard API requests.

**Expected**:
- Copied values are complete, even when UI text is visually shortened.
- Copied digest strings are valid `sha256:*` values.
- Copied repository names preserve slashes and can be used directly in API
  paths after URL encoding.

### OCI11. Negative And Edge Cases

**Steps**:
1. Push a manifest referencing a missing blob.
2. Delete a nonexistent tag and digest.
3. Request a malformed digest.
4. Pull a deleted tag.

**Expected**:
- Missing blob manifests are rejected with OCI `BLOB_UNKNOWN` semantics.
- Nonexistent deletes return structured errors and do not mutate other tags.
- Malformed digests return structured validation errors.
- Pulling deleted tags does not resurrect metadata from stale state.

## Runtime Evidence To Record

For every run, record:

- Commit SHA and cluster image build date.
- Exact client versions for Docker, ORAS, and any optional client.
- Test repository names and tags.
- Manifest digest(s) produced by push.
- Commands run and pass/fail status per test ID.
- Cluster leader and healthy voter count before and after the workflow.
- Any cleanup repositories deleted at the end.

## Reference Smoke Sequence

Prefer the checked-in script:

```bash
tests/production/oci-workflow.sh
```

For redirect-mode coverage, start compose with
`LAYERHOUSE_CONFIG="$PWD/tests/fixtures/configs/compose/cluster-redirect.toml"` and run:

```bash
EXPECT_BLOB_REDIRECT=1 tests/production/oci-workflow.sh
```

This is the minimum command shape behind that local production workflow run:

```bash
RUN_ID="$(date +%s)"
REG=localhost:5050
WORK="/tmp/orb-oci-${RUN_ID}"
mkdir -p "$WORK"

curl -fsS "http://$REG/v2/" >/dev/null
curl -fsS "http://$REG/api/v1/admin/cluster/status" \
  | jq '{leader_id, quorum, healthy_voters}'

cd "$WORK"
printf 'payload %s\n' "$RUN_ID" > payload.txt
oras push --plain-http --no-tty --format json \
  --artifact-type application/vnd.layerhouse.qa.v1 \
  "$REG/qa/oci-oras-${RUN_ID}:alpha,beta" \
  "payload.txt:application/vnd.layerhouse.qa.payload.v1+txt"

oras pull --plain-http --no-tty \
  "$REG/qa/oci-oras-${RUN_ID}:alpha"

docker build -t "$REG/qa/oci-docker-${RUN_ID}:blue" ./dockerctx
docker push "$REG/qa/oci-docker-${RUN_ID}:blue"
docker pull "$REG/qa/oci-docker-${RUN_ID}:blue"

curl -fsS "http://$REG/api/v1/repositories?q=qa/oci" | jq .

curl -fsS -X DELETE \
  "http://$REG/api/v1/repositories/qa/oci-docker-${RUN_ID}" | jq .
curl -fsS -X DELETE \
  "http://$REG/api/v1/repositories/qa/oci-oras-${RUN_ID}" | jq .
```

## REL-MANUAL-GHCR-01: Tagged Release And Published Artifacts

**Mode**: Agent-executable manual
**Priority**: P0

### Preconditions And Environment

- GitHub Actions release workflow is enabled on the target repository.
- Operator has permission to push tags and read GitHub Releases.
- GHCR package visibility and permissions are configured for
  `ghcr.io/layerhouse-oci/layerhouse-server`.
- Local dry run has passed:

```bash
just release-dry-run
```

```bash
export RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
export VERSION="0.0.3"
export TAG="$VERSION"
export WORK="/tmp/orb-release-$RUN_ID"
umask 077
mkdir -p "$WORK"
chmod 0700 "$WORK"
```

### Commands

```bash
git status --short | tee "$WORK/git-status-before.txt"
git tag -a "$TAG" -m "$TAG"
git push origin "$TAG"

gh run list --workflow release.yml --limit 5 | tee "$WORK/release-runs.txt"
gh run watch --exit-status
gh release view "$TAG" --json tagName,name,assets,url \
  | tee "$WORK/release.json"

docker pull "ghcr.io/layerhouse-oci/layerhouse-server:$VERSION" \
  | tee "$WORK/docker-pull-version-tag.txt"
docker pull "ghcr.io/layerhouse-oci/layerhouse-server:latest" \
  | tee "$WORK/docker-pull-latest-tag.txt"

gh release download "$TAG" --dir "$WORK/assets"
tar -xOf "$WORK/assets/layerhouse-$VERSION.tgz" layerhouse/Chart.yaml \
  | tee "$WORK/chart-yaml.txt"
grep -q "^version: $VERSION$" "$WORK/chart-yaml.txt"
grep -q "^appVersion: $VERSION$" "$WORK/chart-yaml.txt"
```

### Expected Checks

- Release workflow completes successfully.
- GHCR image exists with `$VERSION` and `latest` tags.
- GitHub Release contains CLI binaries and `layerhouse-$VERSION.tgz`.
- Chart archive metadata has `version: $VERSION` and `appVersion: $VERSION`.
- Rendering the chart without `image.tag` uses `$VERSION`; explicit
  `image.tag` override still works.

### Evidence

- Git status before tag.
- GitHub Actions run URL and conclusion.
- GitHub Release JSON.
- Docker pull logs for version and latest tags.
- Downloaded asset listing and chart metadata.

### Cleanup And Rollback

If the release was accidental and no users should consume it:

```bash
gh release delete "$TAG" --yes
git push origin ":refs/tags/$TAG"
git tag -d "$TAG"
```

Delete GHCR tags only through the repository/package owner-approved process.
Record any deleted package versions in `$WORK/rollback.txt`.

### Known Hazards

- This publishes public artifacts. Do not run against throwaway commits unless
  the release owner explicitly approves.
- Removing GHCR package versions can affect users who pulled the release during
  the rollback window.
