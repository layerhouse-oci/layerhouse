# Authentication Configuration

Auth is enabled by adding the `[auth]` section to the config. Without this section,
all endpoints are open.

```toml
[auth]
issuer_url = "https://registry.example.com/oauth2/openid/orb-chrysa"
issuer_internal_url = "https://kanidm:8443/oauth2/openid/orb-chrysa"
issuer_internal_urls = ["https://kanidm-a:8443/oauth2/openid/orb-chrysa", "https://kanidm-b:8443/oauth2/openid/orb-chrysa"]
jwks_urls = []
client_id = "orb-chrysa"
client_secret = "<secret>"
token_endpoint_url = "http://localhost:5050/v2/token"
redirect_uri = "http://localhost:5050/oauth2/callback"
tls_insecure_skip_verify = false
jwks_refresh_seconds = 300
jwks_cache_s3_key = "auth/jwks/last-good.json"
jwks_max_stale_seconds = 86400
token_signing_keys = ["<base64-encoded-key>"]
session_encryption_key = "<base64-encoded-key>"

[[auth.permissions]]
name = "admin-access"
groups = ["registry_admins"]
scopes = ["repository:*:*"]
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `issuer_url` | string | (required) | Public OIDC issuer URL advertised to browsers and tokens |
| `issuer_internal_url` | string | same as `issuer_url` | Internal issuer URL for discovery, token exchange, and JWKS (e.g., Docker network) |
| `issuer_internal_urls` | []string | `[]` | Ordered internal issuer URLs for discovery/JWKS failover; when set, this list takes precedence over `issuer_internal_url` |
| `jwks_urls` | []string | `[]` | Optional ordered JWKS endpoints; when empty, the discovered JWKS URI is used |
| `client_id` | string | (required) | OAuth2 client ID registered with the IdP |
| `client_secret` | string | (required) | OAuth2 client secret |
| `token_endpoint_url` | string | (required) | Public `/v2/token` URL (set in `Www-Authenticate` header) |
| `redirect_uri` | string | (required) | OAuth2 callback URL for dashboard OIDC |
| `tls_insecure_skip_verify` | bool | `false` | Skip TLS verification for the IdP (dev only) |
| `jwks_refresh_seconds` | integer | 300 | JWKS cache refresh interval |
| `jwks_cache_s3_key` | string | `auth/jwks/last-good.json` | S3 key used to persist public last-good discovery/JWKS material |
| `jwks_max_stale_seconds` | integer | 86400 | Maximum age for using S3 cached JWKS when all IdP endpoints are unreachable |
| `token_signing_keys` | []string | (required) | Base64-encoded HMAC keys for PAT/OCI token signing |
| `session_encryption_key` | string | (required) | Base64-encoded 32-byte AES-256-GCM key for dashboard cookies |
| `group_claim` | string | `"groups"` | Claim path for group extraction (e.g., `"roles"` for Azure AD, `"realm_access.roles"` for Keycloak realm roles) |
| `login_scopes` | string | `"openid profile email groups"` | OAuth2 scopes requested during dashboard login |
| `access_token_audience` | string | (client_id) | Expected `aud` claim in access tokens; defaults to `client_id` if unset |

## Permission Mappings

Each `[[auth.permissions]]` entry maps IdP groups to OCI scopes:

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Human-readable name for this rule |
| `groups` | []string | IdP groups that grant this permission |
| `scopes` | []string | OCI scope patterns (e.g., `repository:foo/*:push`) |

Scope patterns use wildcards:
- `repository:*:*` — all repositories, all actions
- `repository:foo/*:push` — push to any sub-repository of `foo`
- `repository:bar:pull` — pull only from `bar`
