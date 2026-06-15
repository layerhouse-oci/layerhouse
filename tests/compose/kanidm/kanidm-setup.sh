#!/bin/bash
set -eu

KANIDM_URL="https://kanidm:8443"
KANIDM_CONFIG="${KANIDM_CONFIG:-/data/server.toml}"
CURL="curl -sk"

echo "=== Waiting for Kanidm server ==="
i=0
while [ "$i" -lt 60 ]; do
  if $CURL -f "$KANIDM_URL/status" >/dev/null 2>&1; then
    echo "Kanidm is up"
    break
  fi
  i=$((i + 1))
  if [ "$i" -eq 60 ]; then
    echo "Kanidm never became ready"
    exit 1
  fi
  sleep 2
done

echo "=== Recovering idm_admin password ==="
OUTPUT=$(kanidmd recover-account idm_admin -c "$KANIDM_CONFIG" 2>&1) || true

PW=$(echo "$OUTPUT" | grep -oE 'new_password: [^ ]+' | head -1 | sed 's/new_password: //' | tr -d '"')
if [ -z "$PW" ]; then
  echo "ERROR: Could not extract admin password"
  echo "$OUTPUT"
  exit 1
fi
echo "Admin password recovered"

echo "=== Authenticating as idm_admin ==="
$CURL -D /tmp/auth-headers \
  -H "Content-Type: application/json" \
  -d '{"step":{"init":"idm_admin"}}' \
  "$KANIDM_URL/v1/auth" >/dev/null 2>/dev/null
SESSION_COOKIE=$(grep -i 'set-cookie:' /tmp/auth-headers | sed 's/[Ss]et-[Cc]ookie: //' | cut -d';' -f1 | tr -d '\r' | head -1)

$CURL \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{"step":{"begin":"password"}}' \
  "$KANIDM_URL/v1/auth" >/dev/null 2>/dev/null

TOKEN_RESP=$($CURL \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION_COOKIE" \
  -d "{\"step\":{\"cred\":{\"password\":\"$PW\"}}}" \
  "$KANIDM_URL/v1/auth" 2>/dev/null)

BEARER=$(echo "$TOKEN_RESP" | grep -o '"success":"[^"]*"' | cut -d'"' -f4 || true)
if [ -z "$BEARER" ]; then
  echo "ERROR: Failed to get bearer token"
  echo "Full response: $TOKEN_RESP"
  exit 1
fi
echo "  Bearer obtained"
AUTH="Authorization: Bearer $BEARER"

echo "=== Creating users ==="
for USER_INFO in \
  "admin|Admin User|admin@layerhouse.local" \
  "developer|Developer User|developer@layerhouse.local"; do
  NAME=$(echo "$USER_INFO" | cut -d'|' -f1)
  DISPLAY=$(echo "$USER_INFO" | cut -d'|' -f2)
  EMAIL=$(echo "$USER_INFO" | cut -d'|' -f3)
  $CURL -f -H "$AUTH" \
    -H "Content-Type: application/json" \
    -d "{\"attrs\":{\"name\":[\"$NAME\"],\"displayname\":[\"$DISPLAY\"],\"mail\":[\"$EMAIL\"]}}" \
    "$KANIDM_URL/v1/person" >/dev/null 2>&1 || echo "  ($NAME may exist)"
  echo "  $NAME created"
done

echo "=== Creating ci-bot service account ==="
$CURL -f -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{"attrs":{"name":["ci-bot"],"displayname":["CI Bot"]}}' \
  "$KANIDM_URL/v1/service_account" >/dev/null 2>&1 || echo "  (ci-bot may exist)"
echo "  ci-bot service account created"

echo "=== Setting user passwords ==="
for USER in admin developer; do
  REC_OUTPUT=$(kanidmd recover-account "$USER" -c "$KANIDM_CONFIG" 2>&1) || true
  USER_PW=$(echo "$REC_OUTPUT" | grep -oE 'new_password: [^ ]+' | head -1 | sed 's/new_password: //' | tr -d '"')
  if [ -n "$USER_PW" ]; then
    echo "  $USER password set: ${USER_PW:0:8}..."
    echo "$USER_PW" > "/shared/${USER}-pw"
  else
    echo "  WARN: could not set $USER password"
    echo "  Output: $REC_OUTPUT"
  fi
done

echo "=== Generating API token for ci-bot ==="
API_TOKEN_RESP=$($CURL -f -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{"label":"layerhouse-ci"}' \
  "$KANIDM_URL/v1/service_account/ci-bot/_api_token" 2>&1 || true)

CI_TOKEN=$(echo "$API_TOKEN_RESP" | grep -o '"token":"[^"]*"' | cut -d'"' -f4 || true)
if [ -n "$CI_TOKEN" ]; then
  echo "  API token generated: ${CI_TOKEN:0:12}..."
  echo "$CI_TOKEN" > "/shared/ci-bot-token"
else
  echo "  WARN: could not generate API token"
  echo "  Response: $API_TOKEN_RESP"
fi

echo "=== Creating groups ==="
$CURL -f -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{"attrs":{"name":["registry_admins"]}}' \
  "$KANIDM_URL/v1/group" >/dev/null 2>&1 || echo "  (group may exist)"
echo "  registry_admins group created"

$CURL -f -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{"attrs":{"name":["registry_developers"]}}' \
  "$KANIDM_URL/v1/group" >/dev/null 2>&1 || echo "  (group may exist)"
echo "  registry_developers group created"

echo "=== Adding users to groups ==="
$CURL -f -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '["admin"]' \
  "$KANIDM_URL/v1/group/registry_admins/_attr/member" -X POST >/dev/null 2>&1 || true
echo "  admin -> registry_admins"

$CURL -f -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '["developer"]' \
  "$KANIDM_URL/v1/group/registry_developers/_attr/member" -X POST >/dev/null 2>&1 || true
echo "  developer -> registry_developers"

echo "=== Creating OAuth2 client ==="
# Kanidm attribute names are confusing, so map them through clearly-named vars:
#   oauth2_rs_origin         = the allowed OAuth2 redirect (callback) URL set
#   oauth2_rs_origin_landing = the Kanidm app-portal landing page
# OAUTH2_REDIRECT_URL MUST equal the server's [auth] redirect_uri (auth-cluster.toml).
OAUTH2_REDIRECT_URL="http://localhost:5050/oauth2/callback"
OAUTH2_LANDING_URL="http://localhost:5050"
$CURL -f -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d "{\"attrs\":{\"name\":[\"layerhouse\"],\"displayname\":[\"Layerhouse Container Registry\"],\"oauth2_rs_origin\":[\"$OAUTH2_REDIRECT_URL\"],\"oauth2_rs_origin_landing\":[\"$OAUTH2_LANDING_URL\"]}}" \
  "$KANIDM_URL/v1/oauth2/_basic" >/dev/null 2>&1 || echo "  (oauth2 client may exist)"
echo "  layerhouse client created"

echo "=== Verifying OAuth2 redirect/landing mapping ==="
OAUTH2_GET_RESP=$($CURL -f -H "$AUTH" "$KANIDM_URL/v1/oauth2/layerhouse" 2>/dev/null || true)
echo "  $(echo "$OAUTH2_GET_RESP" | grep -o '"oauth2_rs_origin":\[[^]]*\]' | head -1)"
echo "  $(echo "$OAUTH2_GET_RESP" | grep -o '"oauth2_rs_origin_landing":\[[^]]*\]' | head -1)"
# Landing is the bare root, so the callback URL can only appear in oauth2_rs_origin.
if ! echo "$OAUTH2_GET_RESP" | grep -qF "$OAUTH2_REDIRECT_URL"; then
  echo "ERROR: oauth2_rs_origin does not contain the redirect URL $OAUTH2_REDIRECT_URL"
  echo "  Full response: $OAUTH2_GET_RESP"
  exit 1
fi
echo "  redirect/landing mapping verified"

echo "=== Configuring scopemaps ==="
$CURL -f -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '["openid","profile","email","groups","oci_admin"]' \
  "$KANIDM_URL/v1/oauth2/layerhouse/_scopemap/registry_admins" -X POST >/dev/null 2>&1 || true
echo "  registry_admins -> openid, profile, email, groups, oci_admin"

$CURL -f -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '["openid","profile","email","groups","oci_push","oci_pull"]' \
  "$KANIDM_URL/v1/oauth2/layerhouse/_scopemap/registry_developers" -X POST >/dev/null 2>&1 || true
echo "  registry_developers -> openid, profile, email, groups, oci_push, oci_pull"

echo "=== Getting client secret ==="
SECRET_RESP=$($CURL -f -H "$AUTH" \
  "$KANIDM_URL/v1/oauth2/layerhouse/_basic_secret" 2>&1 || true)
CLIENT_SECRET=$(echo "$SECRET_RESP" | tr -d '"' | tr -d '\n')

if [ -z "$CLIENT_SECRET" ] || [ "$CLIENT_SECRET" = "null" ]; then
  echo "ERROR: Failed to get client secret"
  echo "Response: $SECRET_RESP"
  exit 1
fi
echo "Client secret: ${CLIENT_SECRET:0:8}..."

echo "=== Generating keys ==="
SIGNING_KEY_B64=$(head -c 32 /dev/urandom | base64 | tr -d '\n')

ENCRYPTION_KEY_B64=$(head -c 32 /dev/urandom | base64 | tr -d '\n')

echo "=== Writing layerhouse auth config ==="
sed_escape() {
  printf '%s' "$1" | sed 's/[\/&]/\\&/g'
}

CLIENT_SECRET_ESCAPED=$(sed_escape "$CLIENT_SECRET")
SIGNING_KEY_ESCAPED=$(sed_escape "$SIGNING_KEY_B64")
ENCRYPTION_KEY_ESCAPED=$(sed_escape "$ENCRYPTION_KEY_B64")

sed \
  -e "s/PLACEHOLDER_CLIENT_SECRET/$CLIENT_SECRET_ESCAPED/" \
  -e "s/PLACEHOLDER_SIGNING_KEY/$SIGNING_KEY_ESCAPED/" \
  -e "s/PLACEHOLDER_ENCRYPTION_KEY/$ENCRYPTION_KEY_ESCAPED/" \
  /templates/auth-cluster.toml > /shared/auth-cluster.toml

echo "=== Kanidm setup complete ==="
