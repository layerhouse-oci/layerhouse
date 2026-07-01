# layerhouse Test Plans

**Date**: 2026-05-31
**Type**: Test Plan Index

This directory is the canonical source for automated test coverage and
agent-executable manual production evidence plans. It has two layers of test
plans:

1. Product and dashboard contract plans.
2. Runtime plans for Raft, S3 snapshot, docker-compose, and failure recovery.

Product contract plans should be updated whenever dashboard behavior, API
contracts, mockups, or operator workflows change.
Runtime plans should be updated whenever deployment, clustering, persistence,
or failure behavior changes.

## Execution Modes

| Mode | Definition | Evidence Expectation |
|------|------------|----------------------|
| Automated | Invoked by `just`, CI, or a checked-in script. These plans should be repeatable without design choices once prerequisites are present. | Script logs, command output, status JSON, generated artifacts, and pass/fail result under the script's evidence path. |
| Agent-executable manual | Step-by-step plans for scenarios that need real clusters, destructive node changes, external S3, release credentials, browser auth, or long-running waits. These are first-class production evidence plans even when they are not scripts. | Command transcript, cluster status JSON, pod state, relevant logs, screenshots when browser-based, cleanup result, and a note stating what remains unverified if the plan is skipped. |

Manual plans must include deterministic IDs, preconditions, exact commands,
expected pass/fail checks, evidence files or screenshots to collect, cleanup or
rollback, and known hazards.

Do not silently hide tests that cannot be automatically executed. Every
non-automated production scenario must appear in a coverage-status table with
`Mode = Agent-executable manual`, a deterministic plan ID, a clear current
status that says it is not automated, and an evidence path. If a scenario is
listed under "Features NOT Tested" or "Remaining Manual Scenarios", it must also
point to a manual plan ID or explicitly mark the scenario as non-contract or
backlog so it is not a hidden production gap.

## Plan Map

| Plan | Source | Scope |
|------|--------|-------|
| `01-standalone-mode.md` | Runtime architecture | Single-node Raft/S3 behavior |
| `02-scale-up.md` | Runtime architecture | Standalone to multi-node expansion |
| `03-multi-replica-cluster.md` | Runtime architecture and cluster dashboard support | Multi-node Raft, snapshots, failure recovery |
| `04-dashboard-contract.md` | Dashboard product contract | Shared dashboard UI/API contract |
| `05-repositories-artifact-browser.md` | Repository browser product contract | Repositories and digest-first artifact browser |
| `06-mirror-proxy-cache.md` | Mirror/proxy cache product contract | Mirror rules/jobs and proxy cache |
| `07-cluster-dashboard.md` | Cluster dashboard product contract | Cluster dashboard UI/API safety behavior |
| `08-production-oci-workflows.md` | OCI Distribution runtime | Real OCI client push, pull, delete, copy, and cleanup workflows |
| `09-mirror-proxy-production-workflow.md` | Mirror/proxy cache runtime | Local upstream mirror, proxy-cache pull-through, warm-up, push mirror, proxy validation |
| `10-auth-workflows.md` | Auth runtime | Kanidm token auth, PAT lifecycle, OIDC dashboard login, and permission enforcement |
| `11-air-gapped-k8s-bootstrap.md` | Kubernetes operator workflow | Air-gapped cert generation, native HTTPS, and containerd node trust |
| `12-wasm-kanidm-directory-connector.md` | Directory connector runtime and Admin UX | WASM Kanidm connector build/package, compose, Docker, binary/VM, Helm wiring, Admin search/resolve, fail-fast startup, and runtime fallback |

## Coverage Status

| Scenario | Mode | Command/Plan ID | Priority | Current Status | Evidence Path |
|----------|------|-----------------|----------|----------------|---------------|
| Local build, lint, unit tests, dashboard build | Automated | `just check` | P0 | Implemented | command log |
| Helm lint/template matrix | Automated | `just helm-check` | P0 | Implemented | command log |
| Documentation book build | Automated | `just docs-check` | P1 | Implemented | command log |
| Tilt production-like Helm happy path with RustFS, cert-manager, and Kanidm | Automated | `just tilt-ci` | P0 | Implemented | `target/tilt/evidence/<run_id>` |
| Tilt happy path with host Docker daemon trust restart and mandatory host `docker push` | Automated | `just tilt-ci-host-docker` | P1 | Implemented, opt-in because it may restart Docker; latest local pass `target/tilt/evidence/20260601-143738` | `target/tilt/evidence/<run_id>` |
| Opt-in Kubernetes Helm smoke with CLI-generated certs and manual node trust injection | Automated | `tests/k8s/helm-smoke.sh` | P1 | Implemented scripted harness; requires cluster-specific `NODE_TRUST_COMMAND`, S3 fixture, and endpoint setup | `/tmp/orb-k8s-<run_id>` |
| Tilt StatefulSet scale `3 -> 1 -> 3 -> 2 -> 1` with data preserved and no dead voters | Automated | `just tilt-scale-smoke` | P0 | Implemented, opt-in local smoke | `target/tilt/evidence/<run_id>-scale` |
| Tilt failure scenarios: node trust removal, missing imagePullSecret, one-pod loss, two-pod quorum loss | Automated | `just tilt-failure-smoke` | P1 | Implemented, opt-in destructive local smoke | `target/tilt/evidence/<run_id>-failure` |
| Tilt recovery scenarios: pod restart, StatefulSet restart, snapshot restore log evidence, membership rejoin | Automated | `just tilt-recovery-smoke` | P1 | Implemented, opt-in local smoke | `target/tilt/evidence/<run_id>-recovery` |
| JWKS last-good cache trust window | Automated | `cargo test -p layerhouse-server auth::` | P1 | Implemented at unit level; live IdP outage remains manual | command log |
| Release packaging dry run | Automated | `just release-dry-run` | P0 | Implemented, opt-in because it runs `just check` | `target/release-dry-run/<version>` |
| OCI Distribution conformance | Automated | `just conformance` | P1 | Implemented, opt-in external conformance runner | `tests/conformance/results` |
| CLI-generated air-gapped Kubernetes install | Agent-executable manual | `K8S-MANUAL-AIRGAP-01` | P0 | Full operator plan remains manual; `tests/k8s/helm-smoke.sh` covers the scripted harness when node trust injection is supplied | `/tmp/orb-airgap-<run_id>` |
| cert-manager certificate rotation on Kubernetes | Agent-executable manual | `K8S-MANUAL-CERTROT-01` | P1 | Manual plan only; not automated because rotation is environment/RBAC dependent | `/tmp/orb-certrot-<run_id>` |
| external S3-compatible bucket install | Agent-executable manual | `K8S-MANUAL-EXTS3-01` | P0 | Manual plan only; not automated because it requires operator-provided external S3 credentials | `/tmp/orb-exts3-<run_id>` |
| Browser OIDC dashboard login/session cookie flow | Agent-executable manual | `AUTH-MANUAL-OIDC-01` | P1 | Manual plan only; not automated because it requires interactive browser identity flow | `/tmp/orb-auth-oidc-<run_id>` |
| Live JWKS restart resilience with IdP outage | Agent-executable manual | `AUTH-MANUAL-JWKS-RESUME-01` | P1 | Manual plan only; not automated because it intentionally stops the IdP during pod restart | `/tmp/orb-auth-jwks-resume-<run_id>` |
| Cross-region JWKS failover endpoints | Agent-executable manual | `AUTH-MANUAL-JWKS-XREGION-01` | P2 | Manual plan only; not automated because it needs multiple reachable IdP/JWKS origins | `/tmp/orb-auth-jwks-xregion-<run_id>` |
| Tagged GitHub release, GHCR image, chart archive, CLI binaries | Agent-executable manual | `REL-MANUAL-GHCR-01` | P0 | Manual plan only; not automated because it publishes release artifacts | `/tmp/orb-release-<run_id>` |
| WASM Kanidm connector build/package and compose search/resolve smoke | Automated | `just connector-kanidm-build && just connector-kanidm-package && just compose-auth-directory-up` | P0 | Planned in `12-wasm-kanidm-directory-connector.md`; not implemented yet | `target/directory-smoke/<run_id>` |
| Docker image with Kanidm directory connector artifact and checksum | Automated | `just connector-docker-check` | P0 | Planned in `12-wasm-kanidm-directory-connector.md`; not implemented yet | image inspection log |
| VM package with Kanidm directory connector artifact and checksum | Automated | `just pack-binary` or release dry run | P0 | Planned in `12-wasm-kanidm-directory-connector.md`; not implemented yet | `dist/` package contents |
| Helm install with Kanidm directory connector secret and artifact mount | Agent-executable manual | `DIR-MANUAL-KANIDM-HELM-01` | P1 | Manual plan only; implementation planned in `12-wasm-kanidm-directory-connector.md` | `/tmp/orb-dir-kanidm-<run_id>` |
| VM install with Kanidm directory connector token and artifact | Agent-executable manual | `DIR-MANUAL-KANIDM-VM-01` | P1 | Manual plan only; implementation planned in `12-wasm-kanidm-directory-connector.md` | `/tmp/orb-dir-kanidm-vm-<run_id>` |
| Connector digest rotation and fail-fast startup | Agent-executable manual | `DIR-MANUAL-DIGEST-ROTATE-01` | P2 | Manual plan only; implementation planned in `12-wasm-kanidm-directory-connector.md` | `/tmp/orb-dir-digest-<run_id>` |

## Non-Automated Coverage Registry

These are intentionally visible gaps in automation. They are not skipped or
considered automated unless an agent runs the named plan and records evidence.

| Plan ID | Scenario | Why Not Automated | Owning Plan |
|---------|----------|-------------------|-------------|
| `K8S-MANUAL-AIRGAP-01` | CLI-generated air-gapped certs, Secrets, Helm values, and node trust | Needs real cluster endpoint, platform-specific node trust installation, and operator-provided S3 | `11-air-gapped-k8s-bootstrap.md` |
| `K8S-MANUAL-CERTROT-01` | cert-manager certificate renewal and post-rotation health | Depends on cert-manager RBAC, issuer behavior, and node trust policy | `11-air-gapped-k8s-bootstrap.md` |
| `K8S-MANUAL-EXTS3-01` | install with an external S3-compatible bucket | Requires real external storage credentials and cleanup authority | `11-air-gapped-k8s-bootstrap.md` |
| `K8S-MANUAL-NODETRUST-01` | node trust removal/failure verification on real worker nodes | Destructive host-level node change | `11-air-gapped-k8s-bootstrap.md` |
| `K8S-MANUAL-PARTITION-01` | network partition and flap behavior | Requires CNI or node firewall manipulation that is cluster-specific | `03-multi-replica-cluster.md` |
| `K8S-MANUAL-SNAPSHOT-01` | high-volume snapshot compaction and stale-node recovery | Requires long write load or temporary snapshot threshold changes | `03-multi-replica-cluster.md` |
| `AUTH-MANUAL-OIDC-01` | browser OIDC login and session cookie flow | Requires an interactive browser and identity-provider session | `10-auth-workflows.md` |
| `AUTH-MANUAL-JWKS-RESUME-01` | restart from S3 last-good JWKS while IdP is down | Intentionally disrupts IdP availability during Kubernetes restart | `10-auth-workflows.md` |
| `AUTH-MANUAL-JWKS-XREGION-01` | ordered internal issuer/JWKS endpoint failover | Requires multiple IdP/JWKS endpoints or a controlled proxy fixture | `10-auth-workflows.md` |
| `AUTH-MANUAL-JWKS-01` | JWKS rotation and token expiry | Requires Kanidm key rotation flow and long token lifetime waits | `10-auth-workflows.md` |
| `DIR-MANUAL-KANIDM-HELM-01` | Kubernetes install with Kanidm directory connector enabled | Needs a real cluster, connector artifact distribution path, and operator-provided Kanidm service token | `12-wasm-kanidm-directory-connector.md` |
| `DIR-MANUAL-KANIDM-VM-01` | Virtual-machine install with Kanidm directory connector enabled | Needs a VM/systemd environment, connector artifact installation, and operator-provided Kanidm service token | `12-wasm-kanidm-directory-connector.md` |
| `DIR-MANUAL-DIGEST-ROTATE-01` | Connector artifact digest rotation and fail-fast startup behavior | Requires pod restarts and intentionally mismatched connector artifacts | `12-wasm-kanidm-directory-connector.md` |
| `REL-MANUAL-GHCR-01` | tagged GitHub release, GHCR image, chart archive, CLI binaries | Publishes public release artifacts and needs release credentials | `08-production-oci-workflows.md` |

## Execution Tiers

| Tier | When | Examples |
|------|------|----------|
| P0 | Every implementation pass touching the area | Unit/API tests, dashboard build, route smoke tests, compose leader gate |
| P1 | Before merge | CRUD flows, destructive confirmations, browser flows, restart checks |
| P2 | Scheduled or pre-release | Large data sets, batch deletes, proxy/warm-up against real upstreams, partitions |

## Required Evidence

Each test execution should record:

- Commit SHA
- Date and operator
- Commands run
- Pass/fail result per test ID
- Browser URL or API endpoint used
- Relevant logs/screenshots for failures
- Follow-up issue or commit for any failure

## Automated Runners

Use these from the Rust workspace:

```bash
just check
just helm-check
just docs-check
KANIDM_HOST_PORT=28443 HTTP_PROXY=http://127.0.0.1:1081 HTTPS_PROXY=http://127.0.0.1:1081 just tilt-ci
KANIDM_HOST_PORT=28443 HTTP_PROXY=http://127.0.0.1:1081 HTTPS_PROXY=http://127.0.0.1:1081 just tilt-ci-host-docker
KANIDM_HOST_PORT=28443 just tilt-scale-smoke
KANIDM_HOST_PORT=28443 just tilt-failure-smoke
KANIDM_HOST_PORT=28443 just tilt-recovery-smoke
just release-dry-run
just conformance
```

The Tilt runners use a local kind cluster and are production-like, not
production-bundled: RustFS, Kanidm, and cert-manager are platform/test
dependencies outside the production Helm chart.

`just tilt-ci-host-docker` is intentionally separate from default `just
tilt-ci`. It runs a host Docker trust phase before the smoke: install the
cert-manager-generated registry CA into host Docker trust, restart/reload the
Docker backend if the daemon still reports an x509 error, wait for Docker and
the kind Kubernetes API to recover, then run the full smoke with host
`docker push` required. It fails instead of falling back to kind containerd
push if host Docker still cannot push.

## Production Workflow Runner

For a live local compose cluster, run the production-style OCI and mirror/proxy
workflows together with:

```bash
just production-smoke
```

The runner preserves each child workflow's disposable cleanup behavior and
evidence directory. Override `REGISTRY`, `SCHEME`, `NODE_PORTS`, `RUN_ID`, or
`EVIDENCE_ROOT` when testing a non-default environment.
For redirect-mode coverage, start the cluster with
`LAYERHOUSE_CONFIG="$PWD/tests/compose/config/cluster-redirect.toml"` and set
`EXPECT_BLOB_REDIRECT=1` for `tests/production/oci-workflow.sh`.

This runner is intentionally an opt-in local or self-hosted pre-release gate,
not a default GitHub Actions requirement. It needs Docker daemon access,
Docker network control, a running multi-node compose cluster, ORAS, curl, jq,
and enough time to build and exercise real OCI pushes/pulls. Hosted CI can run
the unit/API/dashboard build checks from `just check`; production smoke belongs
in an environment that can safely start containers and preserve evidence.
