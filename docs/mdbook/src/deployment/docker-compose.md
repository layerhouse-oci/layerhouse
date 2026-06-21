# Docker Compose

Single-node layerhouse with Caddy for automatic TLS and OIDC
authentication (kanidm shown).

## Architecture

```
Internet :443 → Caddy (TLS, auto Let's Encrypt) → layerhouse:5050 (plain HTTP)
                RustFS :9000 (S3-compatible blob storage)
                Kanidm (remote OIDC provider)
```

Caddy terminates TLS and reverse-proxies to layerhouse. layerhouse runs plain
HTTP internally — no TLS configuration needed in layerhouse itself.

## Quick start

```bash
# 1. Set secrets
cat > .env << 'EOF'
RUSTFS_ACCESS_KEY=layerhouse
RUSTFS_SECRET_KEY=<generate-a-strong-secret>
EOF

# 2. Create config (see Configuration section below)
mkdir -p config data/caddy data/rustfs
# write config/standalone.toml

# 3. Start
docker compose up -d
```

## Directory layout

```
~/layerhouse/
├── .env                   # S3 credentials (git-ignored)
├── Caddyfile              # Caddy reverse-proxy config
├── docker-compose.yml     # Service definitions
├── config/
│   └── standalone.toml    # layerhouse server config
└── data/
    ├── caddy/             # TLS certs (auto-managed by Caddy)
    └── rustfs/            # Blob storage (bind mount, not named volume)
```

Use bind mounts (`./data/<service>/`) rather than named volumes so data paths
are explicit and portable.

## Configuration

### Caddyfile

```
layerhouse.example.com {
    reverse_proxy layerhouse:5050
}
```

Caddy auto-obtains and renews Let's Encrypt certificates. Ports 80 and 443 must
be reachable from the internet for ACME challenges.

### Server config (`config/standalone.toml`)

```toml
[server]
listen = "0.0.0.0:5050"

[server.limits]
max_concurrent_uploads = 64
max_concurrent_requests = 512

[storage.s3]
endpoint = "http://rustfs:9000"
bucket = "layerhouse"
region = "us-east-1"
access_key = "layerhouse"
secret_key = "<same-as-.env-RUSTFS_SECRET_KEY>"
path_style = true

[storage.s3.redirect]
enabled = false

[raft]
listen = "0.0.0.0:5051"
data_dir = "/tmp/raft"
discovery_dns = "layerhouse"

[auth]
provider_name = "kanidm"
issuer_url = "https://kani.example.com/oauth2/openid/layerhouse"
client_id = "layerhouse"
client_secret = "<kanidm-oauth2-client-secret>"
token_endpoint_url = "https://layerhouse.example.com/v2/token"
redirect_uri = "https://layerhouse.example.com/oauth2/callback"
token_signing_keys = ["<base64-32-byte-key>"]
session_encryption_key = "<base64-32-byte-key>"

[[auth.permissions]]
name = "admin-full-access"
groups = ["kanidm:group:00000000-0000-0000-0000-000000000001"]
scopes = ["repository:*:*"]

[[auth.permissions]]
name = "developer-access"
groups = ["kanidm:group:00000000-0000-0000-0000-000000000002"]
scopes = ["repository:dev/*:pull,create,update", "repository:dev/*:pull"]
```

Generate signing and encryption keys:

```bash
python3 -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

## Kanidm OIDC setup

### 1. Create groups

```
layerhouse_admins
layerhouse_developers
```

### 2. Create OAuth2 client

Create a **confidential** OAuth2 client via `oauth2/_basic`:

| Field | Value |
|---|---|
| Name | `layerhouse` |
| Display name | `Layerhouse Container Registry` |
| `oauth2_rs_origin` | `https://layerhouse.example.com/oauth2/callback` |
| `oauth2_rs_origin_landing` | `https://layerhouse.example.com` |

### 3. Configure scopemaps

This is critical — **Kanidm denies authorization if any requested scope is
missing from the scopemap**. Docker clients request the `groups` scope by
default, so it must be included.

| Group | Scopes |
|---|---|
| `layerhouse_admins` | `openid`, `profile`, `email`, `groups`, `oci_admin`, `oci_pull`, `oci_push` |
| `layerhouse_developers` | `openid`, `profile`, `email`, `groups`, `oci_pull`, `oci_push` |

> **Why `groups` matters**: Docker's OAuth2 credential flow requests `groups`
> alongside `openid`. Without it, Kanidm rejects the entire authorization with
> "Access Denied" at `/ui/oauth2/resume` — even if all other scopes are
> correct.

### 4. Add users to groups

Add users who need registry access to the appropriate group. Users in
`layerhouse_admins` get full `repository:*:*` access. Users in
`layerhouse_developers` get push/pull on `dev/*` repositories.

## Operations

### Check status

```bash
curl -k https://layerhouse.example.com/v2/        # 401 = auth working
curl -k https://layerhouse.example.com/healthz     # health check
```

### View logs

```bash
docker compose logs layerhouse
docker compose logs caddy
```

### Restart after config change

```bash
docker compose restart layerhouse
```

### Rotate S3 credentials

1. Update `RUSTFS_SECRET_KEY` in `.env`
2. Update `secret_key` in `config/standalone.toml`
3. `docker compose up -d --force-recreate rustfs rustfs-init`
4. `docker compose restart layerhouse`

## Files in `deploy/compose/`

| File | Description |
|---|---|
| `standalone.yml` | Single node + RustFS (no TLS, no auth) |
| `standalone-tls.yml` | Single node + Caddy TLS + Kanidm OIDC |
| `cluster.yml` | Three-node cluster + RustFS |
| `auth-cluster.yml` | Three-node cluster + Kanidm (dev/test) |
| `Caddyfile` | Caddy reverse-proxy config |
| `config/standalone.toml` | Server config template |
| `config/cluster.toml` | Cluster config template |
