# Mirror & Proxy Cache

layerhouse can mirror upstream registries and act as a pull-through proxy cache.

## Mirror Rules

Mirror rules define a relationship between a local repository prefix and an upstream
registry. layerhouse periodically syncs images matching the configured strategy.

### Strategies

| Strategy | Description |
|----------|-------------|
| `all` | Mirror all tags |
| `latest { count }` | Mirror the `count` most recent tags |
| `pattern { pattern }` | Mirror tags matching a glob pattern |

### Directions

| Direction | Description |
|------------|-------------|
| `pull` | Pull images from upstream to local |
| `push` | Push local images to upstream |

### Example

```toml
# Managed via admin API: PUT /api/v1/admin/mirror/rules/my-rule
id = "my-rule"
direction = "pull"
local_prefix = "mirror/library"
upstream_registry = "docker.io"
upstream_prefix = "library"
strategy = { type = "latest", count = 5 }
```

## Proxy Cache

Proxy caches act as pull-through caches. When a client pulls an image from the local
registry, layerhouse checks if it exists locally. If not, it fetches from the upstream
registry, caches it, and returns it to the client.

```toml
# Managed via admin API: PUT /api/v1/admin/proxy-cache/my-cache
id = "my-cache"
local_prefix = "cache"
upstream_registry = "docker.io"
warm_filters = [{ type = "all" }]
```

### Tag Validation

Proxy-cache tag validation follows Amazon ECR pull-through cache behavior:

- A cached non-digest tag is validated against upstream at most once per
  24-hour window.
- Pulls inside the validation window serve the local cached manifest without
  contacting upstream.
- When the validation window expires, layerhouse sends an upstream `HEAD`.
  If the upstream digest is unchanged, layerhouse refreshes only the validation
  timestamp and serves the cached manifest.
- If the upstream digest changed, layerhouse fetches and stores the new manifest,
  updates the local tag mapping, records the new validation timestamp, and serves
  the new manifest.
- If upstream validation or refresh fails while a local cached tag exists,
  layerhouse serves the last cached manifest and leaves validation due for the
  next pull.

This policy applies to every non-digest tag reference. The literal tag `latest`
is not special. Digest references are immutable and bypass proxy-cache tag
validation, serving local content when present.

The 24-hour interval is fixed for now and has no public admin API or config
field. ECR's referrer artifact refresh cadence is not implemented by this
policy. Scheduled mirror rules remain schedule-driven; proxy-cache tag
validation affects only pull-through cache reads.

## Warm-Up

Proxy caches support warm-up — pre-fetching images on a schedule before clients request
them. Configured via the `warm_schedule` and `warm_filters` fields.

## Outbound Proxy

Both mirror rules and proxy caches support an optional outbound proxy for reaching
upstream registries through HTTP, SOCKS4, or SOCKS5 proxies.
