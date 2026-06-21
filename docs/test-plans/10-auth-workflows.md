# Authentication & Authorization Test Plan

**Date**: 2026-05-28
**Type**: Runtime product test plan
**Source**: Auth implementation (kanidm + layerhouse internal token system)
**Scope**: OCI client auth, PAT lifecycle, dashboard OIDC, permission enforcement,
multi-replica auth consistency
**Branch**: HEAD

---

## Product Contract Summary

layerhouse supports authentication via kanidm as the identity provider. When `[auth]`
is configured in the registry config:

- `/v2/` returns HTTP 401 with `Www-Authenticate: Bearer` challenge
- `/v2/token` exchanges Basic auth credentials (PAT or kanidm token) for OCI bearer tokens
- All `/v2/*` endpoints require a valid `Authorization: Bearer` token
- Dashboard OIDC login flow through kanidm
- PATs are managed via `/api/v1/tokens` (create/list/delete)
- Permissions are enforced via group→scope mappings in config
- When `[auth]` is not configured, all endpoints remain open (current behavior)

## Safety Boundary

Run these tests only against repositories under the disposable prefix `qa/auth-*`.
Destructive cleanup must delete only repositories created by this test pass.
Do not delete `qa/oci-*` repositories created by the OCI workflow test plan.

## Tooling

- `docker` for container image push/pull
- `curl` and `jq` for API assertions
- `oras` for generic OCI artifact tests
- Use `--plain-http` for local compose (no TLS on localhost:5050)

## Features Tested

| Feature | Tests | Priority |
|---------|-------|----------|
| Auth-disabled /v2/ returns 200 | AUTH1 | P0 |
| Auth-enabled /v2/ returns 401 with challenge | AUTH2 | P0 |
| PAT creation and listing | AUTH3 | P0 |
| docker login with PAT | AUTH4 | P0 |
| docker push with PAT (authorized) | AUTH5 | P0 |
| docker push with PAT (denied — wrong scope) | AUTH6 | P0 |
| docker pull without auth (denied) | AUTH7 | P0 |
| OIDC login flow to dashboard | AUTH8 | P1 |
| kanidm service account token | AUTH9 | P1 |
| Token reuse across requests | AUTH10 | P1 |
| PAT revocation | AUTH11 | P1 |
| Permission wildcard matching | AUTH12 | P1 |
| Follower node auth enforcement | AUTH13 | P2 |
| Multi-replica PAT consistency | AUTH14 | P2 |
| Auth middleware public path skip | AUTH15 | P2 |
| Kanidm OAuth2 redirect_uri / landing mapping | AUTH16 | P0 |
| Host Docker push with Kanidm token and PAT over trusted HTTPS | AUTH17 | P1 |
| Namespace grant owner CRUD and enforcement | AUTH18 | P0 |
| Admin namespace grant audit controls | AUTH19 | P1 |
| Namespace public pull for anonymous clients | AUTH20 | P0 |

## Coverage Status

| Scenario | Mode | Command/Plan ID | Priority | Current Status | Evidence Path |
|----------|------|-----------------|----------|----------------|---------------|
| Auth-disabled `/v2/` behavior | Automated | `just production-oci` against unauthenticated compose | P0 | Implemented by OCI smoke | `/tmp/orb-oci-<run_id>` |
| Auth-enabled `/v2/` challenge, Kanidm token push, PAT create, PAT push | Automated | `just tilt-ci` | P0 | Implemented with Kanidm fixture | `target/tilt/evidence/<run_id>` |
| Auth-enabled host Docker push with Kanidm token and generated PAT over trusted HTTPS | Automated | `just tilt-ci-host-docker` | P1 | Implemented, opt-in because it may restart Docker; latest local pass `target/tilt/evidence/20260601-143738` | `target/tilt/evidence/<run_id>` |
| Missing imagePullSecret failure for auth-enabled Kubernetes pulls | Automated | `just tilt-failure-smoke` | P1 | Implemented, opt-in local smoke | `target/tilt/evidence/<run_id>-failure` |
| Compose auth smoke | Automated | `just auth-smoke` | P0 | Implemented, opt-in local smoke | `/tmp/orb-auth-<run_id>` |
| Kanidm OAuth2 client redirect/landing mapping | Automated | `AUTH16` via `just compose-auth-up` setup assertion | P0 | Implemented — `kanidm-setup.sh` fails if `oauth2_rs_origin` != the callback URL | compose `kanidm-setup` logs |
| Browser OIDC login, session cookie, and dashboard API access | Agent-executable manual | `AUTH-MANUAL-OIDC-01` | P1 | Manual plan only; not automated because it requires an interactive browser identity flow | `/tmp/orb-auth-oidc-<run_id>` |
| JWKS last-good cache trust window | Automated | `cargo test -p layerhouse-server auth::` | P1 | Implemented at unit level | command log |
| Namespace owner grants, user/group/public enforcement, admin audit, snapshot roundtrip | Automated | `cargo test -p layerhouse-server namespace_`; focused audit and snapshot tests | P0 | Implemented at unit/API/state-machine level | command log |
| Live JWKS restart resilience with IdP outage | Agent-executable manual | `AUTH-MANUAL-JWKS-RESUME-01` | P1 | Manual plan only; not automated because it intentionally stops Kanidm during pod restart | `/tmp/orb-auth-jwks-resume-<run_id>` |
| Cross-region ordered issuer/JWKS failover | Agent-executable manual | `AUTH-MANUAL-JWKS-XREGION-01` | P2 | Manual plan only; not automated because it needs multiple reachable IdP/JWKS origins | `/tmp/orb-auth-jwks-xregion-<run_id>` |
| JWKS rotation and token expiry | Agent-executable manual | `AUTH-MANUAL-JWKS-01` | P2 | Manual plan only; not automated because it needs Kanidm key rotation and long token lifetime waits | `/tmp/orb-auth-jwks-<run_id>` |

## Features NOT Tested

| Feature | Reason | Manual/Automation Status |
|---------|--------|--------------------------|
| JWKS restart from S3 last-good cache under live IdP outage | Requires intentionally stopping Kanidm during pod restart | Manual plan only: `AUTH-MANUAL-JWKS-RESUME-01` |
| JWKS key rotation | Requires manual kanidm key rotation trigger | Manual plan only: `AUTH-MANUAL-JWKS-01` |
| Token expiry | Token lifetime is 1hr; tests don't wait that long | Manual plan only: `AUTH-MANUAL-JWKS-01` |
| OIDC refresh token flow | Requires interactive browser session | Manual plan only: `AUTH-MANUAL-OIDC-01` |
| mTLS client certificates | P2 hardening feature, not required for beta production | Backlog/non-contract until public client certificate auth is implemented |
| Cross-region JWKS sync | Needs multiple reachable IdP/JWKS origins | Manual plan only: `AUTH-MANUAL-JWKS-XREGION-01` |

## Tests

### AUTH1. Auth-Disabled /v2/ Returns 200

**Precondition**: Cluster started without `[auth]` section in config.

**Steps**:
1. Start `docker compose -f deploy/compose/cluster.yml up -d`
2. `curl -s -o /dev/null -w "%{http_code}" http://localhost:5050/v2/`

**Expected**:
- HTTP 200
- Response header includes `Docker-Distribution-API-Version: registry/2.0`
- No `Www-Authenticate` header

### AUTH2. Auth-Enabled /v2/ Returns 401 With Challenge

**Precondition**: Cluster started with `[auth]` section, kanidm healthy.

**Steps**:
1. Start `docker compose -f deploy/compose/auth-cluster.yml up -d`
2. `curl -v http://localhost:5050/v2/ 2>&1`
3. Verify the response status and headers

**Expected**:
- HTTP 401
- `Www-Authenticate: Bearer realm="http://localhost:5050/v2/token",service="layerhouse"`
- JSON body with `errors[0].code = "UNAUTHORIZED"`

### AUTH3. PAT Creation And Listing

**Precondition**: Auth-enabled cluster running, admin user has a PAT.

**Steps**:
1. Create a PAT via the API (requires dashboard session cookie — use direct API with admin PAT for now):
   ```
   POST /api/v1/tokens
   {"name": "test-token", "scopes": ["repository:qa/auth-test/*:pull,create,update"]}
   ```
2. List PATs: `GET /api/v1/tokens`
3. Verify PAT appears in list with prefix visible but not full token

**Expected**:
- POST returns 201 with `token` field (full token visible once)
- GET returns PAT list with `prefix`, `name`, `scopes`, `created_at` — no `token` field
- PAT `prefix` starts with `layerhouse-`

### AUTH4. Docker Login With PAT

**Precondition**: PAT created in AUTH3 (or create fresh PAT).

**Steps**:
1. `echo "<PAT>" | docker login localhost:5050 --username developer --password-stdin`

**Expected**:
- Login succeeds (`Login Succeeded` message)
- Docker stores credential for `localhost:5050`

### AUTH5. Docker Push With PAT (Authorized)

**Precondition**: PAT with `repository:qa/auth-test/*:pull,create,update` scope.

**Steps**:
1. `docker login localhost:5050 -u developer -p <PAT>`
2. Create a small test image: `docker pull alpine:latest && docker tag alpine:latest localhost:5050/qa/auth-test/alpine:v1`
3. `docker push localhost:5050/qa/auth-test/alpine:v1`

**Expected**:
- Push succeeds (layers upload, manifest accepted)
- `GET /v2/qa/auth-test/alpine/tags/list` returns `["v1"]`

### AUTH6. Docker Push With PAT (Denied — Wrong Scope)

**Precondition**: PAT has scopes only for `qa/auth-test/*`, not `qa/auth-admin/*`.

**Steps**:
1. `docker login localhost:5050 -u developer -p <PAT>`
2. Try to push: `docker tag alpine:latest localhost:5050/qa/auth-admin/alpine:v1 && docker push localhost:5050/qa/auth-admin/alpine:v1`

**Expected**:
- Push is rejected with HTTP 403
- Error message indicates `DENIED` for repository `qa/auth-admin/alpine`
- Image is NOT visible in repository listing

### AUTH7. Docker Pull Without Auth (Denied)

**Precondition**: Auth-enabled cluster running.

**Steps**:
1. Push an image first (as authenticated user)
2. `docker logout localhost:5050`
3. `docker pull localhost:5050/qa/auth-test/alpine:v1`

**Expected**:
- Pull is rejected with authentication error
- Docker prompts for login or fails with "unauthorized"

### AUTH8. OIDC Login Flow To Dashboard

**Precondition**: Auth-enabled cluster, kanidm healthy.

**Steps**:
1. Open browser to `http://localhost:5050/oauth2/start`
2. Verify redirect to kanidm login page
3. Complete login with `developer` credentials
4. Verify redirect back to dashboard with session cookie set

**Expected**:
- `/oauth2/start` redirects to kanidm (HTTP 302)
- After login, redirected to dashboard root `/`
- `layerhouse_session` cookie is set (HttpOnly, SameSite=Lax)
- Dashboard APIs become accessible with session cookie

### AUTH9. Kanidm Service Account Token

**Precondition**: `ci-bot` service account created with API token.

**Steps**:
1. `echo "<ci-bot-token>" | docker login localhost:5050 --username ci-bot --password-stdin`
2. Verify login succeeds
3. Push/pull test

**Expected**:
- Service account token works for `docker login`
- Token is a valid kanidm JWS that layerhouse validates via JWKS

### AUTH10. Token Reuse Across Requests

**Precondition**: Authenticated `docker login` session.

**Steps**:
1. `docker login localhost:5050 -u developer -p <PAT>`
2. Push image A: `docker push localhost:5050/qa/auth-test/img-a:v1`
3. Push image B: `docker push localhost:5050/qa/auth-test/img-b:v1`
4. Pull image A: `docker pull localhost:5050/qa/auth-test/img-a:v1`

**Expected**:
- Same bearer token works across multiple push/pull operations
- Docker does not re-authenticate between operations

### AUTH11. PAT Revocation

**Precondition**: Active PAT.

**Steps**:
1. Create a PAT
2. Use it once — verify it works (push succeeds)
3. `DELETE /api/v1/tokens/{id}`
4. Try using the PAT again — should be rejected

**Expected**:
- DELETE returns 204 No Content
- Subsequent use of revoked PAT returns 401
- PAT no longer appears in token list

### AUTH12. Permission Wildcard Matching

**Precondition**: Admin user with `repository:*:*` scope.

**Steps**:
1. Create PAT for admin user with wildcard scope
2. Push to arbitrary repositories: `qa/auth-test/repo1`, `qa/auth-test/sub/repo2`
3. Verify all succeed

**Expected**:
- Wildcard `repository:*:*` grants access to any repository
- Prefix wildcard `repository:qa/auth-test/*:pull,create,update` grants push to `qa/auth-test/any-sub`

### AUTH13. Follower Node Auth Enforcement

**Precondition**: 3-node auth cluster running.

**Steps**:
1. Identify follower nodes via `/api/v1/admin/cluster/status`
2. Push an image to the leader
3. Pull from a follower: `docker pull localhost:5051/qa/auth-test/alpine:v1`
4. Verify auth is required on follower too (no token = 401)

**Expected**:
- All nodes enforce auth, not just the leader
- Follower returns 401 without token, 200 with valid token
- Image pullable from any node with valid auth

### AUTH14. Multi-Replica PAT Consistency

**Precondition**: 3-node auth cluster, PAT created on node-0.

**Steps**:
1. Create PAT via node-0 (port 5050)
2. List PATs via node-1 (port 5051): `GET /api/v1/tokens`
3. Try `docker login` with that PAT to node-2 (port 5052)

**Expected**:
- PAT visible on all nodes (Raft-replicated)
- PAT works for authentication on any node
- PAT revocation propagates to all nodes

### AUTH15. Auth Middleware Public Path Skip

**Precondition**: Auth-enabled cluster running.

**Steps**:
1. `curl http://localhost:5050/healthz` — should return 200
2. `curl http://localhost:5050/metrics` — should return 200
3. `curl -X POST http://localhost:5050/oauth2/start` — should redirect, not 401
4. `curl http://localhost:5050/v2/token` — should return 401 with challenge (valid behavior for token endpoint without credentials)

**Expected**:
- `/healthz` and `/metrics` accessible without auth
- OAuth2 flow endpoints not blocked by auth middleware
- All other `/api/*` and `/v2/*` endpoints require auth

### AUTH16. Kanidm OAuth2 redirect_uri / Landing Mapping

Regression guard for the live-login `redirect_uri` mismatch: Layerhouse sends
`redirect_uri = http://localhost:5050/oauth2/callback` during the authorization-code
exchange, which Kanidm validates against the client's `oauth2_rs_origin` (the allowed
redirect set). `oauth2_rs_origin_landing` is only the app-portal landing page. These two
must not be swapped.

**Precondition**: Auth-enabled cluster bootstrapped via `just compose-auth-up` (runs
`kanidm-setup.sh`), kanidm healthy, admin bearer available.

**Steps**:
1. Inspect the `kanidm-setup` container logs — the `=== Verifying OAuth2 redirect/landing
   mapping ===` step must print the stored attributes and not abort the script.
2. Independently query the client: `GET $KANIDM_URL/v1/oauth2/layerhouse` (with admin
   bearer) and read `attrs.oauth2_rs_origin` and `attrs.oauth2_rs_origin_landing`.

**Expected**:
- `oauth2_rs_origin` contains `http://localhost:5050/oauth2/callback` (matches the server's
  configured `redirect_uri`).
- `oauth2_rs_origin_landing` is `http://localhost:5050` (registry root).
- The setup script exits non-zero if `oauth2_rs_origin` does not contain the callback URL
  (the assertion added to `kanidm-setup.sh` / `bootstrap-kanidm.sh`).

### AUTH17. Host Docker Push With Kanidm Token And PAT Over Trusted HTTPS

**Precondition**: Tilt kind cluster is available, auth is enabled through the
Kanidm fixture, and the public registry endpoint is `https://localhost:32050`.

**Steps**:
1. Run `KANIDM_HOST_PORT=28443 just tilt-ci-host-docker`.
2. Confirm `host-docker-trust` verifies host Docker daemon trust before the
   full smoke starts.
3. Confirm `docker login localhost:32050 --username ci-bot` succeeds with the
   Kanidm service token.
4. Confirm host `docker push` succeeds with the Kanidm service token.
5. Create a PAT through `POST /api/v1/tokens` using the Kanidm bearer token.
6. Confirm `docker login` and host `docker push` succeed with the generated PAT.

**Expected**:
- `/v2/token` is reachable from the host Docker daemon without TLS trust errors.
- Both the Kanidm service token path and PAT path mint OCI bearer tokens.
- The smoke fails rather than falling back to kind containerd push when
  `REQUIRE_HOST_DOCKER_PUSH=1`.
- Evidence includes Docker login/push output and `pat-response.json` under
  `target/tilt/evidence/<run_id>`.

## Test Execution Priority

| Priority | Tests | Rationale |
|----------|-------|-----------|
| P0 | AUTH1-AUTH7, AUTH16 | Core auth on/off, PAT login, push/pull, denial, OAuth2 client mapping |
| P0 | AUTH18, AUTH20 | Namespace grant enforcement and anonymous public pull |
| P1 | AUTH8-AUTH12, AUTH17, AUTH19 | Dashboard OIDC, CI tokens, revocation, wildcards, host Docker auth over trusted HTTPS, admin audit |
| P2 | AUTH13-AUTH15 | Multi-replica consistency, edge cases |

## Traceability Matrix

| Test | Design Decision | Verifies |
|------|----------------|----------|
| AUTH1 | Auth opt-in via `[auth]` section | Backward compatibility |
| AUTH2 | OCI spec 401 challenge | `Www-Authenticate` header format |
| AUTH3 | PAT CRUD in Raft | Token creation, storage, listing |
| AUTH4-AUTH5 | OCI token bridge | `/v2/token` + bearer token flow |
| AUTH6 | Permission enforcement | Scope-to-action mapping |
| AUTH7 | Auth required for all operations | Unauthenticated rejection |
| AUTH8 | OIDC dashboard login | kanidm integration |
| AUTH9 | kanidm service accounts | JWKS-based JWT validation |
| AUTH13-AUTH14 | Multi-replica Raft | Auth state replication |
| AUTH16 | redirect_uri must be in `oauth2_rs_origin` | Kanidm client origin/landing mapping |
| AUTH17 | Host Docker token fetch requires daemon TLS trust | End-to-end Docker auth with Kanidm token and PAT over HTTPS |
| AUTH18 | Namespace grants are Raft metadata | Owner CRUD, user/group matching, action ladder |
| AUTH19 | Admin grant changes are audited | Required reason and audit event visibility |
| AUTH20 | Namespace-level Public Pull | Anonymous manifest/blob pull without write access |

## Prerequisites

- `docker` CLI (with `docker login`, `docker push`, `docker pull`)
- `oras` CLI
- `curl` and `jq`
- Running auth cluster via `just compose-auth-up`
- `admin` user password in `admin-pw` file (generated by kanidm-setup)
- `developer` user password in `developer-pw` file

## Running the Tests

```bash
# Start the auth cluster
just compose-auth-up

# Run the auth smoke test
just auth-smoke

# Manual testing
curl -v http://localhost:5050/v2/
docker login localhost:5050 -u developer -p <PAT>

# Cleanup
just compose-auth-down
```

## Agent-Executable Manual Plans

### AUTH-MANUAL-OIDC-01: Browser OIDC Login And Session Cookie Flow

**Mode**: Agent-executable manual
**Priority**: P1

#### Preconditions And Environment

- Auth-enabled Layerhouse deployment is running with Kanidm.
- Browser can reach both Layerhouse and Kanidm public origins.
- Test user is a member of the configured registry admin group.
- Browser automation can preserve screenshots and network logs.

```bash
export RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
export WORK="/tmp/orb-auth-oidc-$RUN_ID"
export ORB_URL="https://localhost:32050"
export KANIDM_URL="https://localhost:8443"
export USERNAME="admin"
export PASSWORD_FILE="$WORK/admin-password.txt"
umask 077
mkdir -p "$WORK"
chmod 0700 "$WORK"
```

#### Commands And Browser Steps

1. Record starting health:

   ```bash
   curl -sk "$ORB_URL/readyz" | tee "$WORK/readyz-before.txt"
   curl -sk "$ORB_URL/api/v1/admin/cluster/status" \
     | tee "$WORK/cluster-status-before.json" \
     | jq '{leader_id, quorum, healthy_voters}'
   ```

2. Open `$ORB_URL/oauth2/start` in a browser.
3. Expect a redirect to the Kanidm login page under `$KANIDM_URL`.
4. Log in with `$USERNAME` and the password from `$PASSWORD_FILE`.
5. Approve the Kanidm consent screen, then expect to land on
   `$ORB_URL/oauth2/callback` and for Layerhouse to exchange the authorization code
   successfully (no `redirect_uri`/`invalid_grant` error) before redirecting to the
   dashboard.
6. In browser devtools or automation output, verify:
   - `layerhouse_session` cookie exists.
   - cookie is `HttpOnly`.
   - cookie has `SameSite=Lax`.
   - dashboard API calls include the cookie and return 200.
7. Capture the authenticated session identity and cluster view:

   ```bash
   curl -sk --cookie "$WORK/browser-cookies.txt" \
     "$ORB_URL/api/v1/session" \
     | tee "$WORK/session.json" \
     | jq '{auth_enabled, subject, username, groups, scopes, token_type}'
   curl -sk --cookie "$WORK/browser-cookies.txt" \
     "$ORB_URL/api/v1/admin/cluster/status" \
     | tee "$WORK/cluster-status-with-session.json" \
     | jq '{leader_id, quorum, healthy_voters}'
   ```

#### Expected Checks

- `/oauth2/start` redirects to Kanidm.
- After consent, the browser lands on `$ORB_URL/oauth2/callback` and the authorization-code
  exchange succeeds — confirming the sent `redirect_uri` matches the client's
  `oauth2_rs_origin` (see AUTH16).
- Successful login redirects back to Layerhouse, not to a stale or internal
  cluster URL.
- `GET /api/v1/session` returns `auth_enabled: true` with a populated `subject`/`username`
  for the expected admin or developer user and the expected `groups`/`scopes`.
- Session cookie exists and is not readable from JavaScript.
- Dashboard API calls succeed with the session cookie and fail after cookie
  removal.

#### Evidence

- Screenshot of Kanidm login page.
- Screenshot of authenticated Layerhouse dashboard.
- Network log or HAR showing redirect chain.
- Cookie metadata screenshot or browser automation dump.
- Cluster status JSON before and after login.

#### Cleanup And Rollback

```bash
# Browser cleanup: clear cookies for $ORB_URL and $KANIDM_URL.
curl -sk "$ORB_URL/oauth2/logout" | tee "$WORK/logout.txt" || true
```

Remove the test user or reset its password only if this plan created it.

#### Known Hazards

- Browser screenshots and HAR files may contain cookies or tokens. Store them
  under a private evidence directory.
- If running through Tilt, use the configured public origins
  `https://localhost:32050` and `https://localhost:8443`; internal service DNS
  issuers are not valid browser origins.

### AUTH-MANUAL-JWKS-01: JWKS Rotation And Token Expiry

**Mode**: Agent-executable manual
**Priority**: P2

Run this only when Kanidm exposes an operator-approved key rotation flow for the
test deployment. Record the pre-rotation JWKS, create a token before rotation,
rotate keys, verify new tokens work, verify old tokens remain valid until their
configured lifetime or fail according to the configured rotation policy, then
record the post-rotation JWKS and Layerhouse auth logs.

### AUTH-MANUAL-JWKS-RESUME-01: Restart From Last-Good JWKS While IdP Is Down

**Mode**: Agent-executable manual
**Priority**: P1

#### Preconditions And Environment

- Tilt cluster is running with auth enabled and at least one successful JWKS fetch.
- RustFS is healthy; Kanidm can be intentionally stopped and restarted.
- The Layerhouse config uses `jwks_cache_s3_key = "auth/jwks/last-good.json"` and
  `jwks_max_stale_seconds = 86400`.

```bash
export RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
export WORK="/tmp/orb-auth-jwks-resume-$RUN_ID"
export ORB_NAMESPACE="${ORB_NAMESPACE:-layerhouse-tilt}"
export KANIDM_NAMESPACE="${KANIDM_NAMESPACE:-kanidm}"
export REGISTRY_ENDPOINT="${REGISTRY_ENDPOINT:-localhost:32050}"
umask 077
mkdir -p "$WORK"
chmod 0700 "$WORK"
```

#### Commands

1. Record baseline health and metrics:

   ```bash
   kubectl -n "$ORB_NAMESPACE" get pods -o wide | tee "$WORK/pods-before.txt"
   curl -sk "https://$REGISTRY_ENDPOINT/metrics" | tee "$WORK/metrics-before.txt"
   curl -sk "https://$REGISTRY_ENDPOINT/readyz" | tee "$WORK/readyz-before.txt"
   ```

2. Confirm the last-good JWKS object exists in RustFS/S3 using the cluster's S3
   client or RustFS console/`rc` tooling. Save object metadata to
   `$WORK/jwks-cache-object-before.txt`.

3. Stop Kanidm:

   ```bash
   kubectl -n "$KANIDM_NAMESPACE" scale deployment/kanidm --replicas=0
   kubectl -n "$KANIDM_NAMESPACE" rollout status deployment/kanidm --timeout=120s || true
   ```

4. Restart Layerhouse pods while Kanidm is unavailable:

   ```bash
   kubectl -n "$ORB_NAMESPACE" rollout restart statefulset/layerhouse
   kubectl -n "$ORB_NAMESPACE" rollout status statefulset/layerhouse --timeout=420s \
     | tee "$WORK/orb-rollout.txt"
   ```

5. Verify Layerhouse starts from S3 cached JWKS and remains ready:

   ```bash
   curl -sk "https://$REGISTRY_ENDPOINT/readyz" | tee "$WORK/readyz-during-idp-outage.txt"
   curl -sk "https://$REGISTRY_ENDPOINT/metrics" | tee "$WORK/metrics-during-idp-outage.txt"
   kubectl -n "$ORB_NAMESPACE" logs statefulset/layerhouse --all-containers=true \
     > "$WORK/orb-logs-during-idp-outage.txt"
   ```

6. Restore Kanidm and verify fresh JWKS refresh exits stale-cache mode:

   ```bash
   kubectl -n "$KANIDM_NAMESPACE" scale deployment/kanidm --replicas=1
   kubectl -n "$KANIDM_NAMESPACE" rollout status deployment/kanidm --timeout=240s
   sleep 310
   curl -sk "https://$REGISTRY_ENDPOINT/metrics" | tee "$WORK/metrics-after-idp-restore.txt"
   ```

#### Expected Checks

- Layerhouse rollout succeeds while Kanidm is down.
- `/readyz` remains successful because S3 and Raft are healthy.
- Logs contain `using stale last-good JWKS cache`.
- Metrics during outage include `layerhouse_auth_jwks_stale_cache 1`.
- Metrics after Kanidm restore return to `layerhouse_auth_jwks_stale_cache 0`.
- `layerhouse_auth_jwks_refresh_failures_total` increments during outage.

#### Cleanup And Rollback

```bash
kubectl -n "$KANIDM_NAMESPACE" scale deployment/kanidm --replicas=1
kubectl -n "$KANIDM_NAMESPACE" rollout status deployment/kanidm --timeout=240s
kubectl -n "$ORB_NAMESPACE" rollout status statefulset/layerhouse --timeout=240s
```

#### Known Hazards

- This plan intentionally makes the IdP unavailable. Run only on disposable test
  clusters.
- Evidence may include tokens in logs if debug logging is enabled; keep `$WORK`
  private.

### AUTH-MANUAL-JWKS-XREGION-01: Ordered Issuer/JWKS Endpoint Failover

**Mode**: Agent-executable manual
**Priority**: P2

#### Preconditions And Environment

- A test deployment has at least two reachable internal issuer or JWKS endpoints
  serving the same public issuer URL and compatible keys.
- Helm values set `auth.issuerUrl` to the public issuer and set ordered
  `auth.issuerInternalUrls` or `auth.jwksUrls` for failover.

```bash
export RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
export WORK="/tmp/orb-auth-jwks-xregion-$RUN_ID"
export ORB_NAMESPACE="${ORB_NAMESPACE:-layerhouse-tilt}"
export REGISTRY_ENDPOINT="${REGISTRY_ENDPOINT:-localhost:32050}"
umask 077
mkdir -p "$WORK"
chmod 0700 "$WORK"
```

#### Commands

1. Render and save Helm values showing ordered endpoints:

   ```bash
   helm get values layerhouse -n "$ORB_NAMESPACE" -o yaml \
     | tee "$WORK/helm-values.yaml"
   ```

2. Record baseline JWKS metrics and active endpoint:

   ```bash
   curl -sk "https://$REGISTRY_ENDPOINT/metrics" | tee "$WORK/metrics-before.txt"
   ```

3. Make the first internal issuer/JWKS endpoint unreachable using the test
   environment's approved mechanism (DNS override, proxy rule, or deployment
   scale-down). Record the exact command in `$WORK/failover-command.txt`.

4. Trigger an immediate refresh path with a token signed by a key from the
   secondary endpoint, or wait one `jwks_refresh_seconds` interval:

   ```bash
   sleep 310
   curl -sk "https://$REGISTRY_ENDPOINT/metrics" | tee "$WORK/metrics-after-failover.txt"
   ```

5. Restore the primary endpoint and repeat metrics capture:

   ```bash
   curl -sk "https://$REGISTRY_ENDPOINT/metrics" | tee "$WORK/metrics-after-restore.txt"
   ```

#### Expected Checks

- Layerhouse does not restart or become unready when the first endpoint is down.
- `layerhouse_auth_jwks_refresh_failures_total` increments.
- `layerhouse_auth_jwks_endpoint_info{endpoint="..."}` changes to a secondary
  endpoint during failover.
- Tokens whose `iss` matches the public `issuer_url` remain valid.

#### Cleanup And Rollback

Undo the DNS/proxy/deployment change used to make the primary endpoint
unreachable. Save the rollback command and final metrics under `$WORK`.

#### Known Hazards

- Do not point `issuer_url` at an internal region-specific host; token validation
  keeps one public issuer.
- Endpoint failover fixtures can mask real DNS issues. Capture the exact
  failure injection command and restore it before leaving the cluster.
