# Binary Deployment

Run layerhouse directly from the binary. No root required. Deploy from a
self-contained tarball or build from source.

## Tarball deployment (recommended)

```bash
# Build the tarball (includes layerhouse + RustFS + OxMgr)
just pack-binary

# Or with explicit versions
RUSTFS_URL=https://github.com/rustfs/rustfs/releases/download/v1.0.0-beta.6/rustfs-linux-x86_64-gnu-latest.zip \
OXMGR_URL=https://github.com/Vladimir-Urik/OxMgr/releases/download/v0.3.0/oxmgr-x86_64-unknown-linux-gnu.tar.gz \
  just pack-binary
```

The tarball contains:
```
layerhouse-0.0.3-x86_64-unknown-linux-gnu.tar.gz
  bin/
    layerhouse-server     # the registry
    rustfs                # S3-compatible storage
    oxmgr                 # process manager
  config/
    standalone.toml       # ready-to-run single-node config
  oxfile.toml             # oxmgr process group
  README                  # quick-start instructions
```

Extract and run:
```bash
tar xzf layerhouse-0.0.3-x86_64-unknown-linux-gnu.tar.gz
cd layerhouse-*

# Option A: oxmgr (all-in-one)
./bin/oxmgr apply oxfile.toml

# Option B: manual
./bin/rustfs &
./bin/layerhouse-server --config config/standalone.toml
```

The tarball is self-contained — no external downloads, no root access needed.
Copy it to any Linux x86_64 host and run.

## Prerequisites

- layerhouse binary on `$PATH` (or use absolute path)
- RustFS running (binary or container)
- S3-compatible bucket created in RustFS

## Quick start (single node)

```bash
# 1. Start RustFS
rustfs &
# 2. Create bucket (one-time)
rc alias set local http://127.0.0.1:9000 mykey mysecret
rc bucket create local/layerhouse -p
# 3. Start layerhouse
layerhouse-server --config deploy/binary/config/standalone.toml
```

## Cluster (3 nodes)

On each host, set `HOSTNAME` and start:

```bash
# Host 1
HOSTNAME=layerhouse-0 layerhouse-server --config deploy/binary/config/cluster.toml

# Host 2
HOSTNAME=layerhouse-1 layerhouse-server --config deploy/binary/config/cluster.toml

# Host 3
HOSTNAME=layerhouse-2 layerhouse-server --config deploy/binary/config/cluster.toml
```

Each node discovers peers via DNS (`discovery_dns` in config).

## Process management

### oxmgr (recommended)

```bash
oxmgr apply deploy/binary/oxmgr/oxfile.toml
```

### systemd

```bash
sudo cp deploy/binary/systemd/layerhouse.service /etc/systemd/system/
sudo systemctl enable --now layerhouse
```

Systemd requires root for installation. The service runs as the `layerhouse` user.

## Configuration paths

Binary deployment uses paths relative to the working directory by default:

```
./config.toml          # layerhouse config
./data/raft/           # Raft log (ephemeral)
```

No `/etc/layerhouse/` writes required. Override with environment variables:
```bash
LAYERHOUSE_CONFIG=/path/to/config.toml layerhouse-server
```
