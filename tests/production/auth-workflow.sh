#!/bin/bash
set -euo pipefail

# layerhouse Auth Smoke Test
# Runs against a docker compose auth cluster at localhost:5050
#
# Requires: docker, curl, jq, oras
#
# Prerequisites:
#   just compose-auth-up    (start the auth-enabled cluster)
#
# Environment:
#   REGISTRY       — registry host:port (default: localhost:5050)
#   RUN_ID         — unique test run identifier (default: timestamp)
#   EVIDENCE_ROOT  — where to write test evidence (default: /tmp/orb-auth-${RUN_ID})
#   AUTH_SMOKE_PAT — optional PAT for live authorized OCI client checks
#   AUTH_SMOKE_REPO — claimed repo covered by AUTH_SMOKE_PAT (default: demo/api)

REGISTRY="${REGISTRY:-localhost:5050}"
SCHEME="${SCHEME:-http}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-/tmp/orb-auth-${RUN_ID}}"
REPO_PREFIX="qa/auth-${RUN_ID}"
AUTH_SMOKE_USER="${AUTH_SMOKE_USER:-developer}"
AUTH_SMOKE_REPO="${AUTH_SMOKE_REPO:-demo/api}"

NODE_PORTS="${NODE_PORTS:-5050 5051 5052}"

PASS_FAIL=()

pass() {
    local test_id="$1"
    local detail="${2:-}"
    PASS_FAIL+=("$test_id=PASS")
    echo "  PASS: $test_id ${detail:+— $detail}"
}

fail() {
    local test_id="$1"
    local detail="${2:-}"
    PASS_FAIL+=("$test_id=FAIL")
    echo "  FAIL: $test_id ${detail:+— $detail}"
    return 1
}

assert_status() {
    local test_id="$1"
    local expected="$2"
    local actual="$3"
    local detail="${4:-}"
    if [ "$actual" -eq "$expected" ]; then
        pass "$test_id" "$detail"
    else
        fail "$test_id" "expected HTTP $expected, got $actual ${detail:+— $detail}"
    fi
}

cleanup() {
    echo "=== Cleaning up $REPO_PREFIX ==="
    curl -sf -X DELETE "$SCHEME://$REGISTRY/api/v1/repositories/$REPO_PREFIX" 2>/dev/null || true
    # Also clean up sub-repos
    for repo in $(curl -sf "$SCHEME://$REGISTRY/api/v1/repositories" | jq -r '.[].name' | grep "$REPO_PREFIX" 2>/dev/null); do
        curl -sf -X DELETE "$SCHEME://$REGISTRY/api/v1/repositories/$repo" 2>/dev/null || true
    done
    echo "Done"
}

mkdir -p "$EVIDENCE_ROOT"
echo "=== layerhouse Auth Smoke Test ==="
echo "Registry: $REGISTRY"
echo "Run ID:   $RUN_ID"
echo

# ---- AUTH1. Auth-disabled check (assumes separate non-auth cluster) ----
echo "--- AUTH1: Auth-disabled /v2/ returns 200 ---"
# This test passes if we're running against an auth-enabled cluster
# and we confirm it returns 401; the non-auth cluster test AUTH1 is manual.
# For smoke test purposes, we verify auth *is* enabled.
echo "  (AUTH1 is manual — verify non-auth cluster returns 200 separately)"
echo "  (AUTH2 is tested below — verifying auth IS enabled)"

# ---- AUTH2. Auth-enabled /v2/ returns 401 ----
echo "--- AUTH2: Auth-enabled /v2/ returns 401 ---"
HTTP_CODE=$(curl -s -o "$EVIDENCE_ROOT/v2-response.txt" -w "%{http_code}" "$SCHEME://$REGISTRY/v2/")
WWW_AUTH=$(grep -i 'www-authenticate' "$EVIDENCE_ROOT/v2-response.txt" 2>/dev/null || true)
assert_status AUTH2 401 "$HTTP_CODE" "Www-Authenticate present: ${WWW_AUTH:+yes}"

# ---- AUTH7. Docker pull without auth (denied) ----
echo "--- AUTH7: docker pull without auth (denied) ---"
docker logout "$REGISTRY" 2>/dev/null || true
# Try a plain curl to a protected endpoint
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$SCHEME://$REGISTRY/v2/$REPO_PREFIX/manifests/latest")
if [ "$HTTP_CODE" -eq 401 ]; then
    pass AUTH7 "unauthorized request correctly rejected"
else
    fail AUTH7 "expected 401, got $HTTP_CODE"
fi

# ---- AUTH15. Public path skip ----
echo "--- AUTH15: Public path skip ---"
HTTP_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "$SCHEME://$REGISTRY/healthz")
assert_status AUTH15a 200 "$HTTP_HEALTH" "/healthz accessible without auth"

# ---- PAT Flow (AUTH3, AUTH4, AUTH5, AUTH6, AUTH11) ----
echo
echo "--- PAT Flow ---"

# First, we need a PAT. The kanidm-setup script creates users and groups.
# We use the admin user which is in registry_admins group.
# For now, we check if we can reach the token endpoint.
TOKEN_RESP=$(curl -s -o "$EVIDENCE_ROOT/token-noauth.json" -w "%{http_code}" \
    "$SCHEME://$REGISTRY/v2/token?service=layerhouse&scope=repository:$REPO_PREFIX/*:pull,create,update")
if [ "$TOKEN_RESP" -eq 401 ]; then
    pass AUTH-TK1 "token endpoint returns 401 without credentials"
else
    fail AUTH-TK1 "token endpoint should return 401 without credentials, got $TOKEN_RESP"
fi

# For a full PAT test, we need to:
# 1. Authenticate to kanidm to get an access token
# 2. Use that token to create a PAT via /api/v1/tokens
# 3. Use the PAT for docker login
# This requires the kanidm setup to have completed successfully.
# See docs/test-plans/10-auth-workflows.md for the full test procedure.

if [ -n "${AUTH_SMOKE_PAT:-}" ]; then
    echo
    echo "--- AUTH21: OCI pull,push scope compatibility ---"
    TOKEN_BODY="$EVIDENCE_ROOT/token-pull-push.json"
    TOKEN_STATUS=$(curl -s -o "$TOKEN_BODY" -w "%{http_code}" \
        -u "$AUTH_SMOKE_USER:$AUTH_SMOKE_PAT" \
        "$SCHEME://$REGISTRY/v2/token?service=$REGISTRY&scope=repository:$AUTH_SMOKE_REPO:pull,push")
    assert_status AUTH21a 200 "$TOKEN_STATUS" "token endpoint accepts repository:$AUTH_SMOKE_REPO:pull,push"
    BEARER=$(jq -r '.token // empty' "$TOKEN_BODY")
    if [ -n "$BEARER" ]; then
        pass AUTH21b "bearer token minted"
    else
        fail AUTH21b "token response did not include bearer"
    fi

    UPLOAD_STATUS=$(curl -s -o "$EVIDENCE_ROOT/upload-start.txt" -w "%{http_code}" \
        -X POST \
        -H "Authorization: Bearer $BEARER" \
        "$SCHEME://$REGISTRY/v2/$AUTH_SMOKE_REPO/blobs/uploads/")
    assert_status AUTH21c 202 "$UPLOAD_STATUS" "pull,push bearer can start upload"

    if command -v oras >/dev/null 2>&1; then
        echo "$AUTH_SMOKE_PAT" | oras login "$REGISTRY" --username "$AUTH_SMOKE_USER" --password-stdin >/dev/null
        if oras push "$REGISTRY/$AUTH_SMOKE_REPO:auth-smoke-$RUN_ID" README.md:application/vnd.layerhouse.auth-smoke.readme.v1+text \
            >"$EVIDENCE_ROOT/oras-push.txt" 2>&1; then
            pass AUTH21d "ORAS push with pull,push scope succeeded"
        else
            fail AUTH21d "ORAS push failed; see $EVIDENCE_ROOT/oras-push.txt"
        fi
    else
        echo "  SKIP: AUTH21d — oras not installed"
    fi

    UNCLAIMED_REPO="qa-unclaimed-${RUN_ID}/smoke"
    UNCLAIMED_BODY="$EVIDENCE_ROOT/token-unclaimed.json"
    UNCLAIMED_STATUS=$(curl -s -o "$UNCLAIMED_BODY" -w "%{http_code}" \
        -u "$AUTH_SMOKE_USER:$AUTH_SMOKE_PAT" \
        "$SCHEME://$REGISTRY/v2/token?service=$REGISTRY&scope=repository:$UNCLAIMED_REPO:pull,push")
    assert_status AUTH21e 403 "$UNCLAIMED_STATUS" "pull,push does not bypass namespace claim gate"
else
    echo
    echo "--- AUTH21: OCI pull,push scope compatibility ---"
    echo "  SKIP: set AUTH_SMOKE_PAT and AUTH_SMOKE_REPO to run live pull,push checks"
fi

# ---- Summary ----
echo
echo "=== Summary ==="
pass_count=0
fail_count=0
for result in $(printf '%s\n' "${PASS_FAIL[@]}" | sort); do
    test_id="${result%%=*}"
    status="${result#*=}"
    echo "$status: $test_id"
    if [ "$status" = "PASS" ]; then
        ((pass_count++)) || true
    else
        ((fail_count++)) || true
    fi
done
echo
echo "$pass_count passed, $fail_count failed, $((pass_count + fail_count)) total"

# Cleanup (commented out by default — uncomment after confirming tests pass)
# cleanup

if [ "$fail_count" -gt 0 ]; then
    exit 1
fi
