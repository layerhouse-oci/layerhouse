# Bring Your Own IdP

orb-chrysa works with any standard OIDC identity provider. While
[kanidm](https://kanidm.com) is the recommended and best-tested option,
you can use an existing IdP — Keycloak, Okta, Azure AD, Authentik,
Authelia, Zitadel, or any OIDC-compliant provider.

## What Your IdP Needs

orb-chrysa uses standard OIDC flows. Your IdP must provide:

| Capability | Used For |
|------------|----------|
| `/.well-known/openid-configuration` | OIDC discovery (endpoints, JWKS URI) |
| JWKS endpoint | Public key set for JWT signature verification |
| `groups` claim (or configurable path) | Group-based RBAC mapping |
| OAuth2 Authorization Code + PKCE | Dashboard browser login |
| Client credentials grant (optional) | CI pipeline service accounts |

## Configuration

### Step 1: Register an OAuth2 client

Create an OAuth2 client in your IdP with:
- **Grant types**: Authorization Code + PKCE (and client_credentials for CI)
- **Redirect URI**: `https://registry.example.com/oauth2/callback`
- **Scopes**: `openid profile email groups`

### Step 2: Configure orb-chrysa

```toml
[auth]
issuer_url = "https://idp.example.com/realms/your-realm"
issuer_internal_url = "https://keycloak.internal:8443/realms/your-realm"
client_id = "orb-chrysa"
client_secret = "<your-client-secret>"
token_endpoint_url = "https://registry.example.com/v2/token"
redirect_uri = "https://registry.example.com/oauth2/callback"
token_signing_keys = ["<base64-encoded-key>"]
session_encryption_key = "<base64-encoded-32-byte-key>"

[[auth.permissions]]
name = "admin-access"
groups = ["registry_admins"]
scopes = ["repository:*:*"]
```

### Step 3: Set `group_claim` if needed

Most providers put groups in the `"groups"` claim (the default). If your
IdP uses a different claim path, configure it:

| Provider | `group_claim` | Notes |
|----------|---------------|-------|
| Kanidm | `"groups"` (default) | Groups are SPN-formatted (`group@domain`); orb-chrysa matches by local name |
| Keycloak (default) | `"groups"` | Built-in group mapper; see note below about full group paths |
| Keycloak (realm roles) | `"realm_access.roles"` | When using realm roles instead of groups |
| Authentik | `"groups"` | Built-in group claim |
| Authelia | `"groups"` | Groups configured in Authelia YAML |
| Azure AD | `"roles"` | App role claims in the access token |
| Okta | `"groups"` | Available when groups claim is enabled |
| Zitadel | custom | Use Zitadel Actions to add a flat groups claim |

```toml
[auth]
group_claim = "realm_access.roles"  # example: Keycloak realm roles
```

The `group_claim` supports dotted paths. `"realm_access.roles"` traverses
into the `realm_access` object and extracts the `roles` array.

### Step 4: Adjust login scopes and audience if needed

**Login scopes** (default: `"openid profile email groups"`): Some IdPs reject
unknown scopes. If you change `group_claim` to a path that doesn't include a
`groups` scope, remove `groups` from the login scope list or replace it with
the scope your IdP requires.

**Access token audience** (default: uses `client_id`): orb-chrysa validates
that access tokens have `aud` matching the configured audience. Many OIDC
providers use the client ID as the audience (the default). If your IdP uses
a different API/resource audience, set `access_token_audience`.

```toml
[auth]
# Example: Keycloak realm roles without a "groups" scope
group_claim = "realm_access.roles"
login_scopes = "openid profile email"
# Example: IdP uses an API identifier as the audience
access_token_audience = "https://api.example.com"
```

## Provider-Specific Notes

### Keycloak

1. Create a realm (or use `master`)
2. Register an OAuth2 client with "Standard flow" and "Service accounts roles"
3. Add a client scope that maps group membership to the `groups` claim
4. Set `issuer_url` to `https://keycloak.example.com/realms/<realm>`

If using realm roles instead of groups for RBAC, set `group_claim = "realm_access.roles"` and assign realm roles to users.

> **Group path format**: By default, Keycloak emits group paths like `/registry_admins`.
> orb-chrysa's permission matcher does exact string comparison against the configured
> group names, so `groups = ["/registry_admins"]` (with the leading slash) is required.
> To disable full group paths in Keycloak, set the `--spi-group-full-path-enabled=false`
> option or use a custom claim mapper that strips the path prefix.

### Azure AD

1. Register an application under "App registrations"
2. Under "Expose an API" → add the OAuth2 callback redirect URI
3. Under "Token configuration" → add a "groups" claim (or use "roles" claim with app roles)
4. Set `group_claim = "roles"` if using app roles

For Azure AD with app roles, create roles under "App registrations → App roles" and assign them to users/groups via Enterprise applications.

### Authentik

1. Create a Provider (OAuth2/OIDC type) with the callback redirect URI
2. Bind it to an Application
3. Ensure the `groups` scope is included in the provider's "Advanced protocol settings → Scopes"

Users inherit groups from the groups assigned to the application.

### Authelia

1. Configure an OpenID Connect client in Authelia YAML:
```yaml
identity_providers:
  oidc:
    clients:
    - client_id: orb-chrysa
      client_secret: <secret>
      redirect_uris:
        - https://registry.example.com/oauth2/callback
      scopes:
        - openid
        - profile
        - email
        - groups
```

2. Groups are sourced from the Authelia user configuration (LDAP backend or YAML).

## Multiple Internal URLs (IdP HA)

If your IdP runs in a cluster, configure multiple internal URLs for
discovery/JWKS failover:

```toml
issuer_internal_urls = [
    "https://keycloak-0.keycloak:8443/realms/your-realm",
    "https://keycloak-1.keycloak:8443/realms/your-realm",
]
```

orb-chrysa tries each URL in order and uses the first successful response.

## IdP Resilience

If the IdP is unreachable at startup, orb-chrysa falls back to a cached
JWKS stored in S3 (`auth/jwks/last-good.json`). This allows pods to
restart during IdP outages.

Configure the cache window via `jwks_max_stale_seconds` (default: 24 hours).
