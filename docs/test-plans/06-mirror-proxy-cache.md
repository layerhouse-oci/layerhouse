# Mirror And Proxy Cache Test Plan

**Date**: 2026-05-25
**Type**: Product contract test plan
**Source**: Mirror/proxy cache product behavior, active UI mockups, and
implementation contracts
**Scope**: Mirror rules/jobs, trigger behavior, sync strategies, outbound
proxy configuration, proxy cache rules, warm-up, pull-through behavior, and
admin API semantics.

---

## Product Contract Summary

Mirror actively synchronizes artifacts between registries. Proxy Cache serves
upstream content through a local prefix, caching on first pull and optionally
warming selected tags. They are separate operating models and separate
dashboard surfaces.

## Features Tested

| Feature | Tests | Priority |
|---------|-------|----------|
| Mirror route and tabs | M1 | P0 |
| Mirror rule form | M2 | P0 |
| Direction, strategy, schedule display | M3 | P0 |
| Upstream transport, outbound proxy form, and secrecy | M4 | P0 |
| Trigger rule behavior | M5 | P0 |
| Mirror jobs read-only table | M6 | P0 |
| Mirror APIs | M7 | P0 |
| Scheduled execution and strategy resolution | M8 | P0 |
| Proxy cache route and table | P1 | P0 |
| Proxy cache form and warm-up filters | P2 | P0 |
| Proxy cache upstream transport and outbound proxy | P3 | P0 |
| Proxy cache warm now and pull-through | P4 | P1 |
| Proxy cache delete modal | P5 | P0 |
| Proxy cache APIs | P6 | P0 |
| Removed Warm Images behavior | P7 | P1 |
| Locale/theme invariants | P8 | P1 |

## Mirror Tests

### M1. Mirror Route And Tabs

**Steps**:
1. Load `#/mirror`.
2. Inspect top-level nav and tabs.
3. Switch between Rules and Jobs.

**Expected**:
- Mirror is a top-level nav item.
- Rules and Jobs are subtabs under Mirror.
- Old top-level Mirror Rules and Mirror Jobs sections are absent.

### M2. Mirror Rule Create/Edit Form

**Steps**:
1. Open Create Rule.
2. Select Scheduled.
3. Select Manual.
4. Select each strategy.

**Expected**:
- Type selector appears at top with Scheduled and Manual.
- Scheduled shows crontab input with placeholder `*/30 * * * *`.
- Manual hides crontab and shows `Runs only when triggered manually`.
- Strategy dropdown includes All tags, Latest N, and Tag pattern.
- Latest N shows count input.
- Tag pattern shows glob input.
- All tags hides count and pattern.

### M3. Mirror Rule Table Display

**Steps**:
1. Create pull and push rules.
2. Create scheduled and manual rules.
3. Create All tags, Latest N, and Tag pattern strategies.

**Expected**:
- Columns are ID, Direction, Local Prefix, Upstream, Strategy, Proxy, Schedule,
  Actions.
- Pull badge is green with down arrow.
- Push badge is blue with up arrow.
- Strategy text is friendly: All tags, Latest 5, or pattern like `v2.*`.
- Scheduled rules show schedule.
- Manual rules indicate manual-only behavior.

### M4. Mirror Upstream Transport And Outbound Proxy

**Steps**:
1. Open Advanced network.
2. Verify default upstream transport and proxy state.
3. Select Plain HTTP upstream.
4. Select Insecure HTTPS upstream.
5. Select HTTP, SOCKS4, and SOCKS5 outbound proxy.
6. Enter proxy credentials.
7. Save and reload list/detail responses.
8. Submit conflicting `plain_http=true` and `insecure_tls=true` directly to
   the API.
9. Submit an HTTPS proxy payload directly to the API.

**Expected**:
- Advanced network is below upstream username/password fields.
- Default upstream transport is verified TLS for non-localhost registries.
- Plain HTTP upstream stores `plain_http=true` and uses `http://` for upstream
  registry calls.
- Insecure HTTPS upstream stores `insecure_tls=true`, keeps `https://`, and
  disables upstream certificate validation for self-signed or otherwise
  untrusted registry certificates.
- Plain HTTP and Insecure HTTPS are mutually exclusive in the UI and API.
- Default is Direct.
- Direct hides proxy endpoint and proxy credential fields.
- Proxy protocols show endpoint, proxy username, and proxy password.
- Proxy username/password remain paired on desktop and stack together on mobile.
- Proxy password is write-only and not returned by list/detail APIs.
- Table Proxy column shows Direct, HTTP proxy, SOCKS4 proxy, or SOCKS5 proxy.
- HTTPS proxy is not offered in the UI and API rejects `protocol: "https"` with
  a structured error explaining it is deferred until `aioduct` supports it.

### M5. Trigger Rule

**Steps**:
1. Trigger a scheduled rule.
2. Trigger a manual rule.
3. Trigger again while a run is active.

**Expected**:
- Every rule row has Trigger.
- Scheduled rules show Trigger as a secondary action.
- Manual rules show Trigger as primary action.
- Trigger calls `POST /api/v1/admin/mirror/rules/{id}/trigger`.
- Button is disabled and shows progress while in flight.
- Success creates a job row and shows new job id.
- Duplicate active run returns conflict and UI shows `Rule is already running`.

### M6. Mirror Jobs Read-Only Table

**Steps**:
1. Load Mirror Jobs.
2. Inspect each row's actions.
3. Open job runs where supported.

**Expected**:
- Jobs table columns are Job ID, Rule, Image, Status, Last Run, Next Run, Last
  Error.
- Rule column shows rule id/name.
- Job rows do not expose Trigger.
- Job endpoints are read-only.

### M7. Mirror Admin APIs

**Steps**:
1. Exercise MirrorRule CRUD and trigger endpoints.
2. Fetch list/detail responses.
3. Fetch jobs/runs.

**Expected**:
- `GET /api/v1/admin/mirror/rules` returns no secrets.
- `GET /api/v1/admin/mirror/rules/{id}` returns no password values.
- PUT accepts direction, schedule, strategy, upstream transport, credentials,
  and outbound proxy.
- PUT rejects conflicting Plain HTTP and Insecure HTTPS upstream modes.
- DELETE removes only the rule, not local repositories/manifests/tags/blobs.
- Trigger endpoint allows one active run per rule.
- Jobs endpoints are read-only.

### M8. Scheduled Execution And Strategy Resolution

**Steps**:
1. Create a scheduled pull mirror rule with `*/30 * * * *`.
2. Create manual pull rules for All tags, Latest N, and Tag pattern.
3. Trigger manual rules and inspect the queued jobs/runs.
4. Run automated scheduler tests.
5. Create a push mirror rule and trigger it.

**Expected**:
- Scheduler reconciles scheduled rules into durable jobs.
- Manual triggers create one-shot jobs.
- All tags, Latest N, and Tag pattern resolve to concrete upstream tag names
  before pulling manifests.
- Latest N uses the upstream `/tags/list` order for pull rules and local
  manifest `last_modified` metadata for push rules; pushed-at ordering is a
  future enhancement when upstream registries expose portable tag metadata.
- Push mirror execution uploads missing blobs through OCI upload, recursively
  uploads child manifests for indexes, and PUTs the selected tag manifest to the
  upstream repository.
- Automated coverage includes crontab interval parsing and scheduled mirror job
  construction, plus push-rule strategy resolution from local tags.

## Proxy Cache Tests

### P1. Proxy Cache Route And Table

**Steps**:
1. Load `#/proxy-cache`.
2. Inspect table.

**Expected**:
- Proxy Cache is a top-level nav item.
- Columns are Cache ID, Local Prefix, Upstream, Warm-Up, Proxy, Schedule,
  Actions.

### P2. Proxy Cache Form And Warm-Up Filters

**Steps**:
1. Create/edit a proxy cache rule.
2. Select None, All tags, Latest N, and Tag pattern warm-up filters.
3. Combine multiple non-None filters.

**Expected**:
- None is exclusive and clears other warm-up filters.
- Selecting any warm-up filter clears None.
- Warm-up requires crontab schedule unless only manual Warm now is used.
- Table shows friendly warm-up text: All tags, Latest 5 (pushed), `v2.*`, or
  None.

### P3. Proxy Cache Upstream Transport And Outbound Proxy

**Steps**:
1. Open Advanced network below upstream username/password.
2. Test verified TLS, Plain HTTP, and Insecure HTTPS upstream modes.
3. Test Direct, HTTP, SOCKS4, and SOCKS5 outbound proxy.
4. Save and reload.
5. Submit conflicting `plain_http=true` and `insecure_tls=true` directly to
   the API.
6. Submit an HTTPS proxy payload directly to the API.

**Expected**:
- Same upstream transport behavior as mirror rules.
- Same proxy protocol behavior as mirror rules.
- Proxy credentials are write-only.
- Outbound proxy affects upstream cache misses and warm-up jobs.
- Client pulls to layerhouse are not proxied by this setting.
- HTTPS proxy is rejected with the same deferred-support validation error.

### P4. Warm Now And Pull-Through

**Steps**:
1. Create proxy cache rule.
2. Pull an uncached manifest through the local prefix.
3. Pull the same manifest again.
4. Force the cached tag validation record older than 24 hours and pull the tag
   again with unchanged upstream content.
5. Change the upstream tag digest and pull the stale cached tag again.
6. Make upstream validation fail and pull a stale cached tag.
7. Pull the cached manifest by digest.
8. Trigger Warm now.

**Expected**:
- First pull fetches upstream, stores locally, and serves content.
- Repeated tag pulls inside the 24-hour validation window serve local cached
  content without contacting upstream.
- Stale cached tag pulls validate upstream with `HEAD`; unchanged upstream
  content refreshes validation metadata without downloading the manifest again.
- If the upstream tag digest changed, the proxy cache downloads and stores the
  new manifest before serving it.
- If upstream validation or update fails while a local tag exists, the last
  cached manifest is served and the validation remains due.
- Literal `latest` is not special; every non-digest tag follows the same
  ECR-style validation rule.
- Digest pulls bypass tag validation and serve immutable local content when
  present.
- Cache key is manifest digest.
- Blob storage uses shared S3.
- Warm now calls `POST /api/v1/admin/proxy-cache/{id}/warm`.
- Warm filters resolve to concrete upstream tag names before pulling manifests.
- Automated coverage includes scheduled proxy-cache warm job construction.
- Focused automated validation from `layerhouse/` uses one Cargo test filter per
  command:

  ```bash
  cargo test -p layerhouse-server mirror::
  cargo test -p layerhouse-server routes::manifests::
  cargo test -p layerhouse-server store::metadata::
  cargo test -p layerhouse-server raft::state_machine::
  ```

### P5. Proxy Cache Delete Modal

**Steps**:
1. Click Delete on one proxy cache rule.
2. Cancel the modal.
3. Confirm delete.

**Expected**:
- Delete uses a modal, not inline row expansion.
- Title is `Delete cache {id}?`.
- Modal shows local prefix, upstream, and warm-up policy.
- Modal includes Cancel and Confirm delete.
- No typed confirmation for single cache delete.
- Warning says future pull-through and warm-up stop.
- Warning says cached manifests, tags, and blobs are not immediately purged.

### P6. Proxy Cache APIs

**Steps**:
1. Exercise list, get, put, delete, and warm endpoints.
2. Inspect responses for secrets.

**Expected**:
- `GET /api/v1/admin/proxy-cache` returns no secrets.
- `GET /api/v1/admin/proxy-cache/{id}` returns no password value.
- PUT accepts warm filters, schedule, upstream transport, credentials, and
  outbound proxy.
- PUT rejects conflicting Plain HTTP and Insecure HTTPS upstream modes.
- DELETE removes only the rule, not cached repository content.
- Warm endpoint starts a warm-up job.

### P7. Removed Warm Images Concept

**Steps**:
1. Inspect nav, routes, API usage, docs, and dashboard labels.

**Expected**:
- Warm Images is not a top-level dashboard section.
- Old warm-image behavior is represented by pull mirror with Latest N or proxy
  cache warm-up.
- Tests do not reintroduce WarmImage as a user-facing product concept.

### P8. Locale And Theme Invariants

**Steps**:
1. Switch to Light theme and repeat mirror rule and proxy cache create/edit
   forms.
2. Switch locale to Chinese and Arabic.
3. Repeat trigger, warm now, delete, proxy validation, and tab navigation.
4. Refresh/deep-link to `#/mirror` and `#/proxy-cache`.

**Expected**:
- Labels, tabs, buttons, empty states, and validation-adjacent UI text are
  translated where dashboard strings are user-visible.
- Light theme preserves compact tables, advanced-network sections, modal
  layout, and destructive action hierarchy.
- Arabic RTL does not break rule rows, job rows, cache rows, proxy credential
  pairs, cron/proxy technical fields, modal actions, or tabs.
- Create/edit modals remain vertically scrollable when their form content is
  taller than the viewport.
- Mirror and proxy-cache deep links emit no browser console errors in dark,
  light, system, English, Chinese, or Arabic.
- HTTPS proxy remains absent from UI selectors across locales.

## Coverage Map

| Contract Area | Tests |
|---------------|-------|
| Direction | M3 |
| Execution model | M2, M5 |
| Sync strategy | M2, M3, M8 |
| Rule resource | M7 |
| Upstream transport and outbound proxy | M4, P3 |
| Jobs | M6 |
| Trigger rule | M5, M8 |
| Proxy cache | P1-P6, M8 |
| Removed Warm Images | P7 |
| API design | M7, P6, P8 |
