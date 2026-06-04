# Configuration

orb-chrysa uses a single TOML configuration file. All cluster nodes share identical
configuration — node identity is derived from the hostname at runtime.

## Sections

- [Server](configuration/server.md) — listen address, concurrency limits
- [Storage](configuration/storage.md) — S3 endpoint, bucket, credentials
- [Raft](configuration/raft.md) — consensus configuration, DNS discovery, TLS
- [Authentication](configuration/auth.md) — OIDC connection, permissions

## Minimal Configuration

```toml
[server]
listen = "0.0.0.0:5050"

[storage.s3]
endpoint = "http://rustfs:9000"
bucket = "orb-chrysa"
region = "us-east-1"
access_key = "rustfsadmin"
secret_key = "rustfsadmin"
path_style = true

[raft]
listen = "0.0.0.0:5051"
data_dir = "/tmp/raft"
discovery_dns = "orb-chrysa"
```

## Full Reference

See [Configuration Reference](reference/config-reference.md) for every config key
with defaults, types, and descriptions.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `HOSTNAME` | Node identity — must be `<prefix>-<N>` format |
| `ORB_CHRYSA_CONFIG` | Override config file path (Docker Compose) |
