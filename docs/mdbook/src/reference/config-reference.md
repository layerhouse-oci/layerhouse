# Configuration Reference

Complete reference of all TOML configuration keys with their defaults, types,
and descriptions.

## `[server]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen` | string | `"0.0.0.0:5050"` | Public registry/API listen address |
| `limits.max_concurrent_uploads` | integer | 64 | Max simultaneous blob uploads |
| `limits.max_concurrent_requests` | integer | 512 | Max concurrent HTTP requests |
| `tls` | optional | — | Native HTTPS config (cert_path, key_path) |

## `[storage.s3]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `endpoint` | string | — | S3 endpoint URL |
| `bucket` | string | — | S3 bucket name |
| `region` | string | `"us-east-1"` | AWS region |
| `access_key` | string | — | S3 access key |
| `secret_key` | string | — | S3 secret key |
| `path_style` | bool | `false` | Path-style addressing |
| `redirect.enabled` | bool | `false` | Enable S3 redirect mode |
| `redirect.public_endpoint` | string | `""` | Public S3 URL for redirect |
| `redirect.expires_secs` | integer | 900 | Pre-signed URL TTL |

## `[raft]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen` | string | `"0.0.0.0:5051"` | Raft RPC listen address |
| `data_dir` | string | `"/tmp/raft"` | Ephemeral redb log directory |
| `discovery_dns` | string | — | DNS name for peer discovery |
| `tls` | optional | — | Mutual TLS config (cert_path, key_path, server_ca_path, client_ca_path) |

### `[raft.kubernetes]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable Kubernetes StatefulSet replica reconciliation for automatic scale-down |
| `namespace` | string | `""` | Namespace containing the StatefulSet |
| `statefulset_name` | string | `""` | StatefulSet name to read for desired replica count |
| `reconcile_seconds` | integer | 2 | Poll interval for the leader-side desired-voter reconciliation |

## `[gc]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `interval_secs` | integer | 3600 | GC run interval |
| `grace_period_secs` | integer | 3600 | Blob age protection window |
| `dry_run` | bool | `false` | Log without deleting |

## `[auth]` (optional)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `provider_name` | string | `"oidc"` | Stable provider prefix used in user and group principal IDs |
| `issuer_url` | string | — | Public OIDC issuer URL |
| `issuer_internal_url` | string | same as issuer_url | Internal issuer URL for discovery/JWKS |
| `issuer_internal_urls` | []string | `[]` | Ordered internal issuer URLs for discovery/JWKS failover |
| `jwks_urls` | []string | `[]` | Optional ordered JWKS endpoints |
| `client_id` | string | — | OAuth2 client ID |
| `client_secret` | string | — | OAuth2 client secret |
| `token_endpoint_url` | string | — | Public `/v2/token` URL |
| `redirect_uri` | string | — | OAuth2 callback URL |
| `tls_insecure_skip_verify` | bool | `false` | Skip IdP TLS verify |
| `jwks_refresh_seconds` | integer | 300 | JWKS refresh interval |
| `jwks_cache_s3_key` | string | `auth/jwks/last-good.json` | S3 key for public last-good discovery/JWKS cache |
| `jwks_max_stale_seconds` | integer | 86400 | Maximum age for cached JWKS when IdP endpoints are down |
| `token_signing_keys` | []string | — | Base64 HMAC signing keys |
| `session_encryption_key` | string | — | Base64 AES-256-GCM key |
| `group_claim` | string | `"groups"` | Claim path for group extraction |
| `login_scopes` | string | `"openid profile email groups"` | OAuth2 scopes for dashboard login |
| `access_token_audience` | string | — | Expected `aud` claim; defaults to `client_id` |

### `[[auth.permissions]]`

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Rule name |
| `groups` | []string | Provider-qualified stable group IDs, e.g. `kanidm:group:<uuid>` |
| `scopes` | []string | OCI scope patterns using `pull`, `create`, `update`, and `delete` |
