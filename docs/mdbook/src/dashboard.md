# Dashboard

orb-chrysa includes an embedded SolidJS SPA dashboard built with Vite+. It is compiled
into the binary via `rust-embed`.

## Features

- **Repository browser** — list and filter repositories with pagination
- **Manifest viewer** — inspect manifest details, digests, tags, annotations
- **Tag management** — delete tags, delete manifests, batch delete
- **Cluster status** — view Raft leader, voters, membership
- **Mirror management** — create and manage mirror rules and proxy caches
- **Helm chart browser** — browse OCI-based Helm charts

## Access

The dashboard is served at the root path (`/`). In development, it is available at
`http://localhost:5050`.

## Authentication

When auth is enabled, the dashboard redirects unauthenticated users to the OIDC login
flow via the configured OIDC provider (e.g., kanidm). See [Dashboard OIDC](authentication/oidc.md) for details.
