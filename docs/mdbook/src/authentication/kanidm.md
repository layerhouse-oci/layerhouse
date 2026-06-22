# Kanidm Setup

Kanidm is the **recommended and best-tested** identity provider for layerhouse.
It's a Rust-based identity management platform — the same language and design
philosophy as layerhouse — providing OIDC/OAuth2 authentication.

> If you already have an existing IdP (Keycloak, Okta, Azure AD, Authentik,
> etc.), layerhouse works with any standard OIDC provider. See
> [Bring Your Own IdP](bring-your-own-idp.md) for setup instructions.

## Docker Compose Deployment

The `deploy/compose/auth-cluster.yml` includes a full kanidm deployment:

```bash
docker compose -f deploy/compose/auth-cluster.yml up -d
```

Services:
1. `cert-init` — generates self-signed TLS certificates
2. `kanidm` — kanidm server listening on port 8443
3. `kanidm-setup` — bootstrap script that creates users, groups, and OAuth2 client

## Bootstrap Configuration

The setup script (`tests/compose/kanidm/kanidm-setup.sh`) creates:

**Users:**
- `admin` — registry administrator (full access)
- `developer` — regular user (push/pull within `dev/*`)
- `ci-bot` — service account (CI pipeline automation)

**Groups:**
- `registry_admins` — display label for the admin group; Layerhouse permissions use the group's stable UUID
- `registry_developers` — display label for the developer group; Layerhouse permissions use the group's stable UUID

**OAuth2 Client:**
- Name: `layerhouse`
- Type: Basic (confidential client with `client_secret`)
- Landing page (`oauth2_rs_origin_landing`): `http://layerhouse:5050`
- Redirect URI / allowed callback (`oauth2_rs_origin`): `http://layerhouse:5050/oauth2/callback`

> ### ⚠️ Attribute mapping (do not swap these)
>
> Kanidm's two OAuth2 URL attributes are easy to reverse, and reversing them breaks
> login with a `redirect_uri` mismatch. The names are counterintuitive — read them
> carefully:
>
> | Kanidm attribute | Holds | Value for layerhouse |
> |---|---|---|
> | `oauth2_rs_origin` | the **allowed redirect/callback URL(s)** — validated against the `redirect_uri` the client sends during the code exchange. **Despite "origin", this is NOT the base URL.** | `…/oauth2/callback` |
> | `oauth2_rs_origin_landing` | the **app-portal landing page** (where Kanidm's UI links to). Cosmetic; not part of the OAuth2 flow. | the registry root |
>
> **Rule:** `oauth2_rs_origin` **must contain** Layerhouse's configured
> [`auth.redirect_uri`](../configuration/auth.md) (`…/oauth2/callback`).
> `oauth2_rs_origin_landing` is the bare registry root. Layerhouse's runtime has no
> "landing" concept — it only ever sends `redirect_uri`.
>
> The setup scripts (`kanidm-setup.sh`, `bootstrap-kanidm.sh`) assert this after creating
> the client and **fail loudly** if `oauth2_rs_origin` does not contain the callback URL.

## Manual Setup

For production deployments, create the kanidm configuration manually:

1. Deploy a kanidm server (see [kanidm documentation](https://kanidm.github.io/kanidm/stable/))
2. Create an OAuth2 resource server with the kanidm CLI or API:
   ```bash
   # --origin is the allowed OAuth2 redirect/callback URL (Kanidm: oauth2_rs_origin);
   # --landing is the app-portal landing page (Kanidm: oauth2_rs_origin_landing).
   # The redirect URL must equal Layerhouse's [auth] redirect_uri.
   kanidm oauth2 create layerhouse \
     --display-name "Layerhouse Registry" \
     --origin "https://registry.example.com/oauth2/callback" \
     --landing "https://registry.example.com"
   ```
3. Create groups and scopemaps:
   ```bash
   kanidm group create registry_admins
   kanidm group create registry_developers
   kanidm oauth2 set-scopemap layerhouse registry_admins oci_admin
   kanidm oauth2 set-scopemap layerhouse registry_developers oci_push oci_pull
   ```
4. Add users to groups
5. Find the stable group UUIDs emitted in the OAuth2 `groups` claim
6. Generate signing and encryption keys for Layerhouse's config
7. Add the `[auth]` section to `config.toml`, using `Group::"kanidm:group:<uuid>"` principals in `[[auth.policy_sets]].cedar_text` for bootstrap admin access

## TLS

Kanidm requires TLS. In development, self-signed certificates are used. For
production, use proper certificates from a CA. Set `tls_insecure_skip_verify = true`
only for development with self-signed certs.
