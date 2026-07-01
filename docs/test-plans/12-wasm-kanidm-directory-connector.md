# WASM Kanidm Directory Connector Test Plan

**Date**: 2026-06-28
**Type**: Product, security, deployment, and DX coverage plan
**Status**: Planned for the WASM Kanidm directory connector MVP

This plan covers the first Layerhouse directory connector: a sandboxed WASM
component that resolves Kanidm user/group IDs into display/search metadata for
Admin workflows. Connector output is non-authoritative. Authorization must
continue to use provider-qualified IDs, Cedar, namespace ownership, namespace
grants, Rust safety checks, PAT ceilings, and public-pull rules.

## Preconditions

Run commands from the nested Rust workspace:

```bash
cd layerhouse
```

Docker, Docker Compose, curl, jq, and ORAS are available for compose smoke
coverage. The Kanidm compose fixture can start from
`tests/compose/auth-cluster.yml`.

The MVP adds or extends these commands before this plan can pass:

```bash
just connector-kanidm-build
just connector-kanidm-package
just compose-auth-directory-up
just connector-docker-check
just pack-binary
just helm-check
```

Expected connector outputs:

```text
wit/directory-connector.wit
target/connectors/kanidm-directory-connector.wasm
target/connectors/kanidm-directory-connector.wasm.sha256
```

The first implementation slice is the WIT ABI plus a fake compiled WASM
connector host roundtrip. That slice must prove connector metadata, `health`,
`search-principals`, and `resolve-principals` through the real server Wasmtime
component path before Kanidm-specific behavior, packaging, or startup validation
depends on the ABI. The fake connector lives at
`crates/connectors/fake-directory` as a tiny Rust component crate so tests use
the same WIT bindings and component build path as the real Kanidm connector.
`crates/connectors/fake-directory` and `crates/connectors/kanidm` are explicit
Cargo workspace members. `[workspace.default-members]` is
`crates/layerhouse-server` and `crates/layerhouse-ctl`, so normal `just check`
clippy/test and normal CI server checks do not require WASM target setup. `cargo
fmt --all --check` still covers the full workspace, and connector validation
runs through explicit `just connector-check` / CI connector jobs. For the first
implementation slice, `just connector-check` uses `cargo component` to
build/check `crates/connectors/fake-directory` for the component target in the
default/dev profile, copies the component to
`target/connectors/fake-directory-connector.wasm`, and then runs
`cargo test -p layerhouse-server directory_wasm` with
`LAYERHOUSE_TEST_FAKE_DIRECTORY_COMPONENT` pointing at that stable artifact. A
direct `directory_wasm` test run without the env var fails with a clear "run
`just connector-check`" message. The Rust test does not invoke `cargo component`
itself or guess cargo-component internal target paths. Kanidm is added to
connector validation after the provider crate
exists. Deployable connector packaging/build paths use release artifacts.
Fake-directory and Kanidm component builds use `cargo component`, not scripted
`wasm-tools` assembly or checked-in prebuilt component bytes. CI pins
`CARGO_COMPONENT_VERSION` and installs `cargo-component` only in connector jobs
using the existing `cargo-binstall` style. Local `just connector-check` fails
with a clear
`cargo binstall cargo-component --version "$CARGO_COMPONENT_VERSION" -y` command
when `cargo component` is missing; it does not auto-install.
`wit/directory-connector.wit` is the source of truth for host and connector Rust
bindings. Bindings are generated at build time; generated binding files are not
checked into the repository, and the MVP does not add a shared generated-bindings
crate. Host-side generated Wasmtime bindings live in a private
`directory::wasm::bindings` module and are converted into hand-written
Layerhouse directory types at the WASM boundary.

## Coverage Status

| Scenario | Mode | Command/Plan ID | Priority | Current Status | Evidence Path |
|---|---|---|---|---|---|
| WIT ABI round trip with `crates/connectors/fake-directory` | Automated | `cargo test -p layerhouse-server directory_wasm` | P0 | Implemented; fake compiled component roundtrip covered by connector validation | command log |
| Config/startup matrix for disabled directory, enabled missing component, digest mismatch, ABI mismatch, and token/base-origin validation | Automated | `cargo test -p layerhouse-server directory_config` | P0 | Partial; config schema validation covered, startup file/digest/ABI/token/CA content checks pending | command log |
| Host-mediated WASI HTTP SSRF/header/body protections | Automated | `cargo test -p layerhouse-server directory_http_host` | P0 | Planned; not implemented yet | command log |
| Kanidm component build and checksum package | Automated | `just connector-kanidm-build && just connector-kanidm-package` | P0 | Planned; not implemented yet | `target/connectors/` |
| Compose Kanidm search/resolve smoke | Automated | `just compose-auth-directory-up` | P0 | Planned; not implemented yet | `target/directory-smoke/<run_id>` |
| Admin directory route authorization and partial resolve envelope | Automated | `cargo test -p layerhouse-server directory_routes` | P0 | Planned; not implemented yet | command log |
| Grantable principal catalog publish/search/privacy | Automated | `cargo test -p layerhouse-server grantable_principal_catalog` | P0 | Planned; not implemented yet | command log |
| Grant display source/freshness persistence | Automated | `cargo test -p layerhouse-server namespace_grant_directory_display_context` | P0 | Planned; not implemented yet | command log |
| Dashboard principal picker and grant confirmation | Automated | dashboard test suite plus `just check` | P1 | Planned; not implemented yet | command log and screenshots when browser-verified |
| Docker image contains official connector artifact and checksum | Automated | `just connector-docker-check` | P0 | Planned; not implemented yet | image inspection log |
| Binary/VM package contains connector artifact, checksum, config, and docs | Automated | `just pack-binary` or release dry run | P0 | Planned; not implemented yet | `dist/` package contents |
| Helm directory connector render and secret/component mounts | Automated | `just helm-check` | P0 | Planned; not implemented yet | command log |
| Monitoring metrics and docs | Automated/manual | `just docs-check`, metrics scrape | P1 | Planned; not implemented yet | command log, `/metrics` sample |
| Kubernetes install with external Kanidm and connector token secret | Agent-executable manual | `DIR-MANUAL-KANIDM-HELM-01` | P1 | Manual plan only | `/tmp/orb-dir-kanidm-<run_id>` |
| Connector digest rotation and fail-fast startup | Agent-executable manual | `DIR-MANUAL-DIGEST-ROTATE-01` | P2 | Manual plan only | `/tmp/orb-dir-digest-<run_id>` |

## Automated Test Cases

### DIR-AUTO-01 WIT ABI Round Trip

Purpose: prove the host and component agree on the MVP ABI before Kanidm
behavior is debugged.

Use `crates/connectors/fake-directory`, a tiny Rust WASM component crate that
returns deterministic connector info, health, `free-text` search,
`exact-local-id` search, and per-ID resolve results with `found`, `not-found`,
and `failed` entries. The fixture is not inline server test code, checked-in
prebuilt component bytes, or a WAT-only substitute.

Assertions:

- The MVP ABI has no `capabilities()` export; support for users, groups,
  `free-text`, `exact-local-id`, resolve, and typed health is required.
- The MVP ABI has no `configure()` export. `health`, `search-principals`, and
  `resolve-principals` receive non-secret config through an explicit
  `connector-context` argument on each call.
- `connector-context` contains only `provider`, `base-origin`, `timeout-ms`, and
  non-secret TLS diagnostic mode.
- `connector-context` never contains the Kanidm service token, token file path,
  CA file path, component path, component digest, package path, or host-owned
  transport-policy inputs.
- Host-owned WASI HTTP hooks enforce origin, TLS trust, forbidden headers,
  body/header limits, deadline, and token injection outside the guest-facing
  context.
- The WIT source is `wit/directory-connector.wit`, with package
  `layerhouse:directory@0.0.3` and world `directory-connector`.
- Host and connector Rust bindings are generated at build time from
  `wit/directory-connector.wit`.
- Generated binding files are not checked into the repository.
- The MVP does not add a shared generated-bindings crate.
- Host-side generated Wasmtime bindings stay private under
  `directory::wasm::bindings`.
- Routes, store logic, Raft state, dashboard API types, and grant catalog code use
  hand-written Layerhouse directory types, not generated WIT structs.
- Boundary conversion tests prove WIT values are converted into Layerhouse types
  before leaving the WASM runtime layer.
- Host `DirectoryError` is a hand-written enum with the same semantic categories
  as WIT: `invalid_query`, `unsupported_provider`, `not_found`,
  `upstream_unavailable`, `upstream_unauthorized`, `rate_limited`, `timeout`,
  `invalid_response`, and `internal`.
- Boundary conversion tests prove WIT `directory-error` values are mapped into
  host `DirectoryError` after sanitizing connector-provided strings.
- Sanitization tests prove connector error strings are trimmed, control
  characters are replaced, length is capped at 512 UTF-8 bytes at a character
  boundary, and raw headers, bearer tokens, request or response bodies, full URLs
  with query strings, and connector debug dumps are rejected or redacted.
- Host-created connector failures use the same `DirectoryError` enum, and
  generated WIT error types do not leave `directory::wasm`.
- The host-facing `DirectoryConnector` trait exposes async `connector_info()`,
  `health(ctx)`, `search_principals(ctx, request)`, and
  `resolve_principals(ctx, request)` methods returning Layerhouse-owned types.
- Connector context is explicit on every host-facing call.
- Generated WIT signatures are not mirrored directly as the host trait.
- `crates/connectors/fake-directory` is an explicit Cargo workspace member, so
  workspace versioning and dependency policy apply to the fixture component.
- `[workspace.default-members]` contains only `crates/layerhouse-server` and
  `crates/layerhouse-ctl`; normal `just check` clippy/test and normal CI server
  checks use those default members.
- `cargo fmt --all --check` still formats the full workspace, including connector
  crates.
- `just connector-check` / CI connector jobs are the intentional path that
  requires WASM target setup for component validation.
- The first `just connector-check` builds/checks only
  `crates/connectors/fake-directory` with `cargo component` for the component
  target in the default/dev profile, copies the component to
  `target/connectors/fake-directory-connector.wasm`, and then runs
  `cargo test -p layerhouse-server directory_wasm` with
  `LAYERHOUSE_TEST_FAKE_DIRECTORY_COMPONENT` pointing at that path.
- Direct `directory_wasm` test runs without
  `LAYERHOUSE_TEST_FAKE_DIRECTORY_COMPONENT` fail with a clear "run
  `just connector-check`" message.
- The Rust test does not invoke `cargo component` itself or guess
  cargo-component internal target paths.
- Kanidm is not included in the first boundary check.
- Deployable connector package/build paths use release artifacts.
- Connector component builds use `cargo component`, not scripted `wasm-tools`
  assembly or checked-in prebuilt component bytes.
- CI connector jobs install a pinned `CARGO_COMPONENT_VERSION` with the existing
  `cargo-binstall` style used elsewhere in the repo.
- Local `just connector-check` does not auto-install `cargo-component`; when
  missing, it prints the pinned `cargo binstall cargo-component --version
  "$CARGO_COMPONENT_VERSION" -y` command and exits.
- Search returns stable provider-qualified IDs.
- `free-text` search is treated as provider-specific picker search, not exact
  identity lookup.
- Search pagination is in the MVP: WIT includes `search-request.cursor` and
  `search-response.next-cursor`, and the Admin API accepts `cursor` and returns
  `next_cursor`.
- Admin API cursors are Layerhouse-owned opaque host-wrapped cursors over
  connector-owned inner provider cursors. The host unwraps only the inner cursor
  before invoking `search-principals` and wraps returned inner cursors before
  returning `next_cursor`.
- Public Admin API cursor tokens are base64url-encoded AEAD ciphertext, not
  signed-only cleartext envelopes.
- Cursor AEAD uses a key derived from `auth.session_encryption_key` with
  explicit domain separation. The host does not use the raw session cookie key
  directly, require a separate cursor encryption key, or generate a per-process
  cursor key for the MVP.
- Cursor AEAD subkey derivation uses HKDF-SHA256 over the decoded 32-byte
  `auth.session_encryption_key` with fixed info label
  `layerhouse:directory-search-cursor:v1:aes-256-gcm`, producing a 32-byte
  AES-256-GCM key.
- The encrypted cursor payload contains `provider`, `search_shape_hash`, and
  `inner_cursor` only. It does not include `component_sha256`, a token version
  field, or an issued-at timestamp in the MVP.
- Encrypted cursor payload bytes use `postcard` serialization of a private
  host-only Rust struct in fixed field order, not JSON or a manual delimiter
  string. The struct name may be versioned internally, but the MVP payload does
  not add a token version field.
- Public cursor token layout is
  `base64url_no_pad(nonce || ciphertext_and_tag)`, with a fresh random 12-byte
  AES-GCM nonce per token. MVP tokens have no visible prefix, no dot-separated
  segments, and no deterministic nonce.
- Cursor encryption and decryption use fixed AEAD associated data
  `layerhouse:directory-search-cursor:v1`. `provider` and `search_shape_hash`
  remain encrypted payload fields, not AAD-only fields.
- Invalid Admin API cursors return `400 Bad Request` with directory error code
  `invalid_cursor` before connector execution. Invalid cursor failures include
  malformed base64url, wrong token layout, AEAD failure, payload deserialization
  failure, provider mismatch, and search-shape mismatch.
- Invalid cursor responses use the directory admin error envelope with
  `code = "invalid_cursor"`, generic message/cause/remediation, `doc_url`,
  `request_id`, and `health_state`. The response body does not reveal whether the
  cursor failed base64 parsing, token layout validation, AEAD authentication,
  payload decoding, provider matching, or search-shape matching.
- For `invalid_cursor`, `health_state` is the cached directory health state when
  available, otherwise `unknown`. The host does not invoke the connector or run a
  live health check just to populate `health_state`.
- Invalid cursor logs and metrics may use low-cardinality reason labels such as
  `malformed`, `undecryptable`, `provider_mismatch`, and
  `search_shape_mismatch`, but must not include raw cursor tokens, plaintext or
  decrypted payload fields, connector inner cursors, ciphertext, nonces,
  authentication tags, or hash values.
- `search_shape_hash` is `sha256:<64 lowercase hex>` over host-serialized
  `CursorSearchShapeV1` containing endpoint, filter, sorted/deduplicated kinds,
  and normalized limit. It is not derived from the raw Admin API query string or
  the connector-owned inner cursor.
- `CursorSearchShapeV1` hash input uses `postcard` serialization of the private
  Rust struct in fixed field order, not canonical JSON or a manual delimiter
  string.
- Pagination tests must prove that public cursors bind the active connector
  identity and canonical search shape (filter, kinds, limit, and search
  endpoint/kind), reject tampering or mismatched searches before component
  execution, and do not expose provider next links, page tokens, LDAP cookies,
  SCIM indexes, or offsets directly in the Admin API.
- Pagination does not require server-side cursor state or cursor caches in the
  MVP.
- `exact-local-id` returns only an exact local ID match for the requested kind.
- Resolve preserves one result per requested ID.
- The host validates provider-qualified stable IDs, rejects unsupported
  providers before component execution, and passes only `principal-ref` values
  in `resolve-request`.
- WIT resolve results use the `found`, `not-found`, and `failed` variant shape,
  avoiding nullable principal/error combinations.
- Connector warnings do not become whole-request failures.

### DIR-AUTO-02 Config And Startup Matrix

Purpose: ensure directory config is explicit and does not accidentally make a
display feature an availability dependency.

Cases:

- `[auth.directory]` omitted: directory service disabled and routes report
  disabled.
- `enabled = false`: directory service disabled.
- `[auth]` and `[auth.directory]` enabled, missing component: startup fails with
  problem, cause, fix, and config key.
- Missing `component_path` while `auth.directory.enabled = true`: startup fails.
- Absolute `component_path` values are accepted.
- Relative `component_path` values are resolved relative to the directory
  containing the Layerhouse config file, not process cwd.
- Relative `component_path` values fail config validation when the config source
  has no filesystem directory.
- No server-side default connector path exists when `component_path` is omitted.
- Symlinked `component_path` targets are allowed, and the digest check uses the
  exact bytes read through the configured path.
- Missing `component_sha256` while `auth.directory.enabled = true`: startup
  fails in local dev, compose, Docker, VM, and Helm paths; no unverified
  connector bypass exists.
- Invalid `component_sha256` format fails startup when directory is enabled:
  raw 64-character hex, uppercase hex, unsupported algorithm prefixes, short
  values, and malformed values are rejected.
- `component_sha256_file` is not a valid runtime config field; rendered config
  must contain literal `component_sha256`.
- Digest mismatch: startup fails and reports expected and actual digest.
- ABI mismatch: startup fails and reports expected and actual ABI version.
- Connector-declared provider fails principal namespace validation: startup
  fails and reports connector name, provider, and remediation.
- Unreadable token file: startup fails with secret path remediation.
- Absolute `api_token_file` values are accepted.
- Relative `api_token_file` values are resolved relative to the directory
  containing the Layerhouse config file, not process cwd.
- Relative `api_token_file` values fail config validation when the config source
  has no filesystem directory.
- Env-var token sources are not supported in the MVP.
- Token file content is raw token only: `Bearer ...`, full `Authorization`
  header values, empty content, leading whitespace, and internal whitespace are
  rejected.
- One final LF or CRLF is tolerated and trimmed before the host constructs
  `Authorization: Bearer <token>`.
- Invalid base origin: startup fails before any connector call.
- Config uses `base_origin`, WIT uses `base-origin`, and Helm values use
  `baseOrigin`; `base_url`, `baseUrl`, and generic `origin` are not the target
  names.
- Both `https://` and `http://` `base_origin` values are accepted in all
  environments. There is no loopback-only HTTP allowance and no production-only
  HTTPS enforcement in the MVP.
- For `https://` `base_origin`, `tls_insecure_skip_verify = true` and `false`
  are both valid config values.
- For `http://` `base_origin`, `tls_insecure_skip_verify` must be omitted or
  false; setting it to true fails startup validation.
- For `http://` `base_origin`, `tls_ca_file` must be omitted; setting it fails
  startup validation.
- `tls_ca_file` is supported for HTTPS origins so the local self-signed Kanidm
  fixture and private-CA deployments can validate TLS without
  `tls_insecure_skip_verify`.
- Absolute `tls_ca_file` values are accepted.
- Relative `tls_ca_file` values are resolved relative to the directory
  containing the Layerhouse config file, not process cwd.
- Relative `tls_ca_file` values fail config validation when the config source
  has no filesystem directory.
- `tls_ca_file` content is a PEM CA bundle with one or more CA certificates and
  no private keys.
- Missing, unreadable, empty, malformed, no-CA-certificate, or
  private-key-containing configured CA files fail startup before the connector
  is called.
- For HTTPS origins, system roots, `tls_ca_file`, and
  `tls_insecure_skip_verify = true` are distinct trust modes.
- Setting both `tls_ca_file` and `tls_insecure_skip_verify = true` fails startup
  validation.
- `[auth]` config has no `provider_name`; the connector provider is the source
  for the provider segment in Layerhouse principal IDs.

### DIR-AUTO-03 Host-Mediated WASI HTTP Limits

Purpose: prevent SSRF and token exfiltration through the guest component.
The connector uses standard `wasi:http` through `aioduct::WasiClient`; the
Layerhouse host owns the Wasmtime HTTP hook, origin policy, and service-token
injection. Provider endpoint choices are trusted connector code, not
Layerhouse-owned path policy.

Guest attempts must fail for:

- wrong scheme or authority
- forbidden `authorization`, `cookie`, `proxy-*`, `forwarded`, and
  `x-forwarded-*` headers
- overlong headers or request body
- timeout

Assertions:

- Host never injects the token for rejected requests.
- Layerhouse does not require an MVP path permission manifest. The official
  Kanidm connector's endpoint choices are covered by connector code review,
  fixture tests, digest pinning, and least-privilege Kanidm token setup.
- `timeout_ms` is enforced end-to-end per exported connector call, including
  guest WASM execution and any WASI HTTP work.
- A slow guest loop, slow outbound Kanidm request, or combined guest plus HTTP
  overrun returns a structured timeout error without outliving the call budget.
- There is no separate MVP HTTP timeout config; outbound HTTP consumes the same
  per-call budget.
- Missing `timeout_ms` uses the default value `2000`.
- Official examples render `timeout_ms = 2000` explicitly even though the field
  is optional.
- `timeout_ms = 0` and negative values fail config validation.
- Large positive `timeout_ms` values are accepted in the MVP; there is no upper
  bound validator yet.
- There is no `max_response_bytes` MVP config field; response pressure is
  bounded by request `limit`, guest memory limits, and `timeout_ms`.
- There is no config-level `max_results` MVP field.
- Missing Admin API search `limit` defaults to `20` before calling the
  connector.
- Admin API search `limit = 0` fails request validation.
- Positive Admin API search `limit` values are passed through to
  `search-request.limit` without a server-side clamp.
- Admin API `cursor` values are validated as Layerhouse host-wrapped cursors and
  translated into inner `search-request.cursor` values only after the search
  shape matches the original request.
- Connector `search-response.next-cursor` values are wrapped before they become
  Admin API `next_cursor` values.
- Public `next_cursor` tokens are URL-safe base64url strings whose decoded bytes
  do not expose the connector's inner cursor or provider pagination artifacts.
- Bit flips, truncation, malformed base64url, and valid AEAD tokens for a
  different search shape fail before component execution.
- Cursor token encryption/decryption works across Layerhouse nodes that share
  the same `auth.session_encryption_key`.
- Cursor token tests cover deterministic subkey derivation from a known session
  key and fixed HKDF info label.
- Cursor payload tests cover `provider`, `search_shape_hash`, and `inner_cursor`
  as the full MVP payload, plus provider/search-shape mismatch rejection before
  component execution.
- Cursor payload known-vector tests lock representative postcard bytes and prove
  no `component_sha256`, token version, or issued-at field is serialized.
- Public cursor token tests prove base64url-no-padding encoding, `nonce ||
  ciphertext_and_tag` parsing, rejection of malformed segment/dot formats, and
  different tokens for repeated encryption of the same payload.
- Cursor AEAD tests prove decryption succeeds with the fixed AAD and fails with
  missing or different AAD before component execution.
- Invalid cursor tests prove malformed, undecryptable, provider-mismatched, and
  search-shape-mismatched cursors return `400 invalid_cursor`, do not invoke the
  connector, and are not converted to empty result sets, `401`, or `403`.
- Invalid cursor response-body tests prove all cursor validation failure classes
  share the same generic `invalid_cursor` envelope and do not expose parse,
  decrypt, provider, or search-shape mismatch details.
- Invalid cursor `health_state` tests prove cached health is reused, missing
  cache becomes `unknown`, and neither path invokes the connector.
- Invalid cursor observability tests prove each validation class emits only the
  expected low-cardinality reason label and never logs cursor tokens, payload
  fields, connector inner cursors, ciphertext, nonces, tags, or hash values.
- Search-shape hash tests cover query-parameter reordering, duplicate kind
  removal, kind sorting, defaulted limit normalization, and raw query strings
  not being accepted as cursor identity.
- Search-shape hash known-vector tests lock representative
  `CursorSearchShapeV1` postcard bytes and resulting
  `sha256:<64 lowercase hex>` values.
- Direct provider pagination artifacts are not accepted or exposed as public
  Admin API cursors.
- Missing `max_concurrent_calls` uses the default value `8`.
- `max_concurrent_calls = 0` and negative values fail config validation.
- Positive `max_concurrent_calls` values bound concurrent exported connector
  calls in the Layerhouse process.
- Waiting for a `max_concurrent_calls` slot consumes the same `timeout_ms`
  deadline as the connector call.
- If no concurrency slot opens before the deadline, Layerhouse returns a
  structured timeout and does not invoke the connector.
- There is no unbounded connector-call queue.
- Missing `memory_limit_bytes` uses the default value `67108864` (64 MiB).
- `memory_limit_bytes = 0` and negative values fail config validation.
- Positive `memory_limit_bytes` values bound guest linear memory for connector
  execution.
- There is no `cache_ttl_seconds`, `negative_cache_ttl_seconds`, or
  process-local positive/negative connector result cache in the MVP.
- Search and resolve calls go through the connector. Persisted frozen display
  context and observed login identities are not connector result caches.
- There is no connector circuit breaker in the MVP.
- Denied attempts are counted in metrics.
- Errors do not include raw token or raw response body.

### DIR-AUTO-04 Kanidm Component Build And Package

Purpose: keep the MVP runnable for contributors and operators.

Commands:

```bash
just connector-kanidm-build
just connector-kanidm-package
```

Assertions:

- `target/connectors/kanidm-directory-connector.wasm` exists.
- `target/connectors/kanidm-directory-connector.wasm.sha256` exists and matches
  the artifact.
- `crates/connectors/kanidm` is an explicit Cargo workspace member, so workspace
  versioning and dependency policy apply to the official connector.
- `just connector-kanidm-build` uses `cargo component` for the Kanidm component
  crate and builds a release artifact for packaging.
- CI installs pinned `cargo-component` only in connector jobs; host-only CI jobs
  do not install it.
- The `.sha256` file contains exactly one newline-terminated
  `sha256:<64 lowercase hex>` line, with no artifact filename and no
  `sha256sum`-style output.
- No package manifest or bundle digest is required for MVP startup validation.
  `component_sha256` verifies the exact `.wasm` bytes loaded from
  `component_path`.
- Config uses strict `sha256:<64 lowercase hex>` syntax for
  `component_sha256`.
- Config examples and generated configs use literal `component_sha256`, not
  `component_sha256_file`.
- Re-running the package step is deterministic when source is unchanged.

### DIR-AUTO-05 Compose Kanidm Search/Resolve Smoke

Purpose: prove the official connector works against the same Kanidm fixture as
OIDC auth.

Command:

```bash
just compose-auth-directory-up
```

Assertions:

- Compose starts Kanidm, RustFS, and Layerhouse.
- Kanidm setup writes a directory service token path.
- Layerhouse renders `[auth.directory]` with component path, digest, base origin,
  and `api_token_file`.
- Admin search finds `admin` and `developer` users.
- Admin group search finds `registry_admins` and `registry_developers`.
- Admin can publish `registry_admins` into the grantable principal catalog.
- Account/Access search can find the published catalog entry without live
  connector search.
- Resolve by group UUID returns `kanidm:group:<uuid>` with connector source and
  fresh status.
- Connector runtime outage after a valid startup returns structured directory
  errors without changing auth allow/deny behavior.

### DIR-AUTO-06 Admin Routes

Purpose: guarantee route-level security and partial error behavior.

Assertions:

- Unauthenticated requests are rejected.
- Authenticated non-admin requests are rejected from live Admin directory
  search/resolve routes.
- Authenticated account users may call grantable-catalog search, but that route
  must not call the live connector.
- Admin search succeeds when connector is healthy.
- Mixed resolve returns found, not-found, connector failed, and host-level
  unsupported-provider results in one response.
- Request-level invalid JSON still returns normal HTTP error.

### DIR-AUTO-06B Grantable Principal Catalog

Purpose: give account owners useful grant search without exposing live Kanidm
directory enumeration.

Assertions:

- Admin can publish a connector-resolved user/group into the catalog.
- Admin can unpublish a catalog entry without revoking existing namespace
  grants.
- Catalog entry stores stable ID, kind, frozen display name, display source, last
  resolved time, published by, and published at.
- Account owner search returns only published catalog entries plus allowed
  observed identities.
- Account owner search does not invoke the live connector.
- Exact stable ID entry is accepted as raw/manual when it is not in the catalog
  or observed cache.
- Duplicate display names still show stable ID/provider/kind/source for
  disambiguation.

### DIR-AUTO-07 Grant Persistence

Purpose: prevent misleading display metadata from becoming hidden authority.

Assertions:

- Connector-selected grant persists stable ID, display name, display source, and
  resolved-at/freshness.
- Manual/raw grant persists raw/manual source.
- Stale fallback persists stale source.
- Authorization decisions ignore display name and freshness.
- Audit response shows frozen display context even when connector is down.

### DIR-AUTO-08 Dashboard Principal Picker

Purpose: make Admin grant workflows safe and usable.

Assertions:

- User and group tabs both search.
- Principal rows show display name, stable ID, kind, provider, source, and freshness.
- Admin can publish and unpublish connector results in the grantable catalog.
- Access searches grantable catalog entries, observed identities, and exact
  stable IDs only.
- Duplicate display names require stable-ID disambiguation.
- Exact-ID fallback rows are separate and not auto-selected.
- Save confirmation shows the stable ID as authority.
- Loading, no-results, disabled, degraded, unauthorized, unavailable,
  misconfigured, and unsupported-provider states are visible.
- Long IDs wrap on mobile without horizontal overflow.
- Keyboard navigation and screen-reader labels work for result rows and status
  chips.

### DIR-AUTO-09 Docker, Binary/VM, And Helm Packaging

Purpose: ensure both deployment targets, virtual machines and Kubernetes, carry
the connector artifact deliberately.

Assertions:

- Docker image includes the official Kanidm connector artifact at a stable path.
- Docker image includes `kanidm-directory-connector.wasm.sha256`, with
  config-ready content matching the exact component bytes used by default
  config.
- Compose, Docker, VM, and Helm generated configs contain literal
  `component_sha256`; they do not point the server at the checksum file.
- Official Compose, Docker, VM, and Helm generated example configs contain
  `component_path = "connectors/kanidm-directory-connector.wasm"` and place the
  artifact under the config directory's `connectors/` child. They do not rely on
  a server-side default connector path or cwd-relative behavior.
- Official Compose, Docker, VM, and Helm generated example configs contain
  `api_token_file = "secrets/kanidm-directory-token"` and place the token under
  the config directory's `secrets/` child. Absolute token paths remain valid for
  custom operator config.
- Binary/VM package includes `connectors/kanidm-directory-connector.wasm`,
  `connectors/kanidm-directory-connector.wasm.sha256`, config examples, and
  install/upgrade docs.
- VM/systemd docs show a stable connector path and token file path.
- Helm values support `auth.directory.baseOrigin`.
- Helm, Compose, and VM examples can provide a custom CA file for the local
  self-signed Kanidm fixture at `certs/kanidm-ca.pem` under the config
  directory.
- ConfigMap renders `[auth.directory]` under `[auth]`.
- Token secret is mounted read-only at `api_token_file`.
- Connector artifact is bundled or mounted read-only at `component_path`.
- NetworkPolicy allows egress to Kanidm when enabled.
- `just helm-check` includes a directory-enabled values fixture.

### DIR-AUTO-10 Observability

Purpose: make connector failures diagnosable.

Required metrics:

- connector health state: `healthy`, `degraded`, `unauthorized`, `unavailable`,
  or `misconfigured`
- connector request latency
- search/resolve error count by code
- stale fallback count
- denied host import count

Assertions:

- Metrics do not expose tokens.
- Logs include request ID, provider, operation, status, and duration.
- Monitoring docs list alerts for unauthorized connector runtime failures,
  repeated timeout, and startup validation failures.

## Manual Plan DIR-MANUAL-KANIDM-HELM-01

Scenario: install Layerhouse on Kubernetes with auth and Kanidm directory
connector enabled.

Steps:

1. Build or obtain the official Kanidm connector artifact and SHA256.
2. Create a Kubernetes secret containing the Kanidm directory token.
3. Install the Helm chart with `auth.enabled = true` and
   `auth.directory.enabled = true`.
4. Confirm pods start with read-only root filesystem.
5. Intentionally use a bad connector digest and confirm pods fail startup before
   serving traffic.
6. Restore the correct digest and confirm `/readyz` becomes healthy.
7. Log in as an admin and search for `registry_admins`.
8. Create a namespace grant to the resolved group.
9. Stop or block Kanidm after successful startup and confirm frozen display
   context remains visible while search degrades.
10. Restore Kanidm and confirm health recovers.

Evidence:

- Helm values file with secrets redacted.
- `helm template` output snippet for config, mounts, and network policy.
- Pod status and events.
- `/metrics` sample.
- Admin UI screenshots for healthy and runtime-degraded connector states.
- Cleanup commands and result.

## Manual Plan DIR-MANUAL-KANIDM-VM-01

Scenario: install Layerhouse on a virtual machine with auth and Kanidm directory
connector enabled.

Steps:

1. Build the binary/VM package with the official Kanidm connector artifact and
   SHA256.
2. Install `layerhouse-server` and
   `connectors/kanidm-directory-connector.wasm` into the documented VM config
   directory layout.
3. Write the Kanidm directory token to `secrets/kanidm-directory-token` under
   the documented VM config directory. The file contains the raw token only, not
   `Bearer ...`.
4. Configure `[auth]` and `[auth.directory]` with `component_path`,
   `component_sha256`, `base_origin`, and `api_token_file`.
5. Start Layerhouse through the documented systemd unit.
6. Confirm startup fails if the connector digest is intentionally wrong.
7. Restore the correct digest and confirm the service starts.
8. Search and resolve `registry_admins` through the Admin directory flow.

Evidence:

- Package file listing.
- Config with secrets redacted.
- systemd status and logs.
- Health response and Admin directory search response.
- Digest-failure log excerpt.

## Manual Plan DIR-MANUAL-DIGEST-ROTATE-01

Scenario: rotate the connector artifact digest and verify fail-fast startup
behavior.

Steps:

1. Install with a valid digest.
2. Replace the connector artifact without updating the digest.
3. Restart one pod and confirm startup fails before serving traffic.
4. Update digest to the new artifact.
5. Restart and confirm health recovers.

Evidence:

- Config snippets with secrets redacted.
- Pod logs showing expected/actual digest.
- Health response before and after digest update.
- Confirmation that registry auth decisions did not depend on connector health.

## Known Hazards

- Kanidm REST endpoint shapes must be verified against the compose fixture
  before being treated as a stable connector contract.
- Connector installation is a trust decision. WASM sandboxing limits host
  access, but it does not make arbitrary connector code semantically safe.
- Directory display metadata is mutable. Tests must assert stable IDs remain the
  authorization key.
- The connector token is sensitive and host-owned. Tests must assert it is never
  passed into guest config/env and logs must never print it.
- Helm and Docker packaging must work with read-only root filesystem.
- Binary/VM packaging must install the connector and checksum into stable paths
  before the service starts.
- Package-level manifests, signatures, and bundle digests are deferred until
  connector distribution needs them.

## Required Final Gate

Before this MVP is considered done:

```bash
just check
just helm-check
just docs-check
just connector-check
just connector-kanidm-build
just connector-kanidm-package
just compose-auth-directory-up
just connector-docker-check
just pack-binary
```

Record command output, commit SHA, and any browser screenshots under the
evidence path named by the runner.
