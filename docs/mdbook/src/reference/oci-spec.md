# OCI Distribution Spec

Layerhouse implements the [OCI Distribution Specification v1.1](https://github.com/opencontainers/distribution-spec).

## Conformance

The OCI Distribution conformance tests are run via `tests/conformance/run.sh`.
The harness builds the official upstream `conformance.test` binary from the
pinned `opencontainers/distribution-spec` tag recorded in
`tests/conformance/distribution-spec.ref` when the local ignored cache is missing
or stale.

```bash
# Run conformance tests
just conformance
```

## Implemented Endpoints

All required endpoints from the specification are implemented:

- **Blob operations**: upload, download, mount, delete
- **Manifest operations**: push, pull, delete
- **Tag operations**: list, resolve
- **Referrers API**: list referrers for a subject digest
- **Catalog**: list repositories

## Unsupported Features

- **Cross-repository blob mounting** (POST with `?mount=<digest>&from=<repo>`):
  Mounts are metadata-only operations. The digest must already exist in S3.

## Authorization Scopes

Layerhouse accepts standard Docker/OCI bearer-token scopes such as
`repository:<name>:pull,push`. The client-facing `push` action maps to
Layerhouse's internal `update` action, which covers create and update writes but
does not grant delete or admin access.

This scope mapping is only authorization vocabulary compatibility. It does not
provision registry metadata. Writes to a normal repository handle still require
the namespace to be claimed first; if `<name>` is `acme/app` and `acme` is
unclaimed, a `pull,push` token is denied for create/update before Cedar policy
evaluation.

## Public Pull

Anonymous pull access is repository-level. A repository marked
`visibility = public_pull` allows unauthenticated `GET` and `HEAD` requests for
that exact repository's manifests and blobs. Anonymous clients still cannot
start uploads, push manifests, or delete content.

Namespace grants do not make repositories public. User and group grants control
authenticated access; repository visibility controls anonymous pull access.

Repository owners or actors with `update` access can change visibility from the
dashboard repository settings panel or with `PATCH /api/v1/repositories/<name>`:

```json
{ "visibility": "public_pull" }
```

Use `{ "visibility": "private" }` to require authentication for pulls again.

## OCI Error Codes

Layerhouse returns standard OCI error codes in the response body:

```json
{
  "errors": [
    {
      "code": "MANIFEST_UNKNOWN",
      "message": "MANIFEST_UNKNOWN: manifest not found",
      "detail": null
    }
  ]
}
```

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `BLOB_UNKNOWN` | 404 | Blob not found |
| `BLOB_UPLOAD_INVALID` | 400 | Invalid upload |
| `BLOB_UPLOAD_UNKNOWN` | 404 | Upload session not found |
| `DIGEST_INVALID` | 400 | Invalid digest format |
| `MANIFEST_BLOB_UNKNOWN` | 400 | Referenced blob not found |
| `MANIFEST_INVALID` | 400 | Invalid manifest |
| `MANIFEST_UNKNOWN` | 404 | Manifest not found |
| `NAME_INVALID` | 400 | Invalid repository name |
| `NAME_UNKNOWN` | 404 | Repository not found |
| `SIZE_INVALID` | 400 | Invalid size |
| `UNAUTHORIZED` | 401 | Authentication required |
| `DENIED` | 403 | Access denied |
| `UNSUPPORTED` | 405 | Unsupported operation |
| `TOOMANYREQUESTS` | 429 | Rate limit exceeded |
