# Personal Access Tokens

Personal Access Tokens (PATs) are the primary way human users authenticate with
Layerhouse for `docker login`.

## Creating a PAT

PATs are created through the dashboard or API:

```bash
# Via the API
curl -X POST http://localhost:5050/api/v1/tokens \
  -H "Content-Type: application/json" \
  -H "Cookie: layerhouse_session=<session>" \
  -d '{"name": "my-laptop", "scopes": ["repository:dev/*:pull,create,update"]}'

# Response (token shown only once)
{
  "id": "a1b2c3d4-...",
  "name": "my-laptop",
  "token": "layerhouse-abcdef1234567890abcdef1234567890",
  "scopes": ["repository:dev/*:pull,create,update"],
  "created_at": 1716854400,
  "expires_at": null
}
```

## Using a PAT

```bash
echo "layerhouse-abcdef1234567890abcdef1234567890" | \
  docker login localhost:5050 --username developer --password-stdin
```

## PAT Format

- Prefix: `layerhouse-`
- Random component: 32 hex characters (16 bytes)
- Stored as SHA-256 hash in Raft state machine
- Only the first 12 characters are shown in listings (for identification)

## Managing PATs

```bash
# List your PATs
curl http://localhost:5050/api/v1/tokens \
  -H "Cookie: layerhouse_session=<session>"

# Revoke a PAT
curl -X DELETE http://localhost:5050/api/v1/tokens/a1b2c3d4-... \
  -H "Cookie: layerhouse_session=<session>"
```

## Scopes

PATs carry explicit OCI scope strings that define what the token can do:

| Scope | Allows |
|-------|--------|
| `repository:foo/*:pull,create,update` | Pull, create, or update manifests under `foo` and all sub-repositories |
| `repository:foo:pull` | Pull from `foo` |
| `repository:*:*` | All repositories, all actions (admin) |

## Expiry

PATs can optionally expire after a number of days. Set `expires_in_days` when
creating the token. Expired tokens are rejected with a 401 error.
