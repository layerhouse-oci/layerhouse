# API Reference

Layerhouse implements the [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec)
plus additional admin and dashboard APIs.

## OCI Distribution API (`/v2/`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v2/` | API version check |
| `GET` | `/v2/token` | Token endpoint (when auth enabled) |
| `GET` | `/v2/_catalog` | List repositories |
| `GET` | `/v2/<name>/tags/list` | List tags for a repository |
| `GET` | `/v2/<name>/manifests/<ref>` | Get manifest |
| `HEAD` | `/v2/<name>/manifests/<ref>` | Check manifest existence |
| `PUT` | `/v2/<name>/manifests/<ref>` | Push manifest |
| `DELETE` | `/v2/<name>/manifests/<ref>` | Delete manifest |
| `GET` | `/v2/<name>/blobs/<digest>` | Download blob |
| `HEAD` | `/v2/<name>/blobs/<digest>` | Check blob existence |
| `POST` | `/v2/<name>/blobs/uploads/` | Start blob upload |
| `PATCH` | `/v2/<name>/blobs/uploads/<session>` | Upload blob chunk |
| `PUT` | `/v2/<name>/blobs/uploads/<session>` | Complete blob upload |
| `DELETE` | `/v2/<name>/blobs/<digest>` | Delete blob |
| `GET` | `/v2/<name>/referrers/<digest>` | List referrers |

## Dashboard API (`/api/v1/`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/repositories` | List repositories (paginated, filterable) |
| `GET` | `/api/v1/repositories/<name>/manifests` | List manifests for a repository |
| `GET` | `/api/v1/repositories/<name>/manifests/<digest>` | Get manifest detail |
| `DELETE` | `/api/v1/repositories/<name>/manifests/<digest>/tags/<tag>` | Delete tag |
| `DELETE` | `/api/v1/repositories/<name>/manifests/<digest>` | Delete manifest |
| `DELETE` | `/api/v1/repositories/<name>` | Delete entire repository |
| `POST` | `/api/v1/repositories/<name>/manifests:batch-delete` | Batch delete manifests |

## Admin API (`/api/v1/admin/`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/admin/cluster/status` | Cluster health |
| `POST` | `/api/v1/admin/cluster/join` | Join cluster |
| `POST` | `/api/v1/admin/cluster/leave` | Leave cluster |
| `DELETE` | `/api/v1/admin/cluster/members/<id>` | Remove member |
| `GET` | `/api/v1/admin/gc/status` | GC status |
| `GET` | `/api/v1/admin/policies` | List Cedar policy sets |
| `GET/PUT/DELETE` | `/api/v1/admin/policies/<id>` | Cedar policy set CRUD |
| `GET/PUT/DELETE` | `/api/v1/admin/mirror/rules/*` | Mirror rule CRUD |
| `GET/PUT/DELETE` | `/api/v1/admin/proxy-cache/*` | Proxy cache CRUD |
| `GET/PUT/DELETE` | `/api/v1/admin/mirror/warm/*` | Warm image CRUD |
| `GET` | `/api/v1/admin/helm/charts` | List helm charts |

## Token API (`/api/v1/tokens`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/tokens` | List user's PATs |
| `POST` | `/api/v1/tokens` | Create PAT |
| `DELETE` | `/api/v1/tokens/<id>` | Revoke PAT |

## OAuth2 (`/oauth2/`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/oauth2/start` | Initiate OIDC login flow |
| `GET` | `/oauth2/callback` | OIDC callback handler |
