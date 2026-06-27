# Repositories And Artifact Browser Test Plan

**Date**: 2026-05-25
**Type**: Product contract test plan
**Source**: Repository browser product behavior, active UI mockups, and
implementation contracts
**Scope**: Repository list, digest-first repository detail, tag chips, artifact
type detection, manifest details, destructive actions, batch selection, and
dashboard repository APIs.

---

## Product Contract Summary

Repository detail is digest-first. Rows are manifests addressed by digest; tags
are chips attached to rows. Helm, images, WASM, and other OCI artifacts share
the same browser surface.

## Features Tested

| Feature | Tests | Priority |
|---------|-------|----------|
| Repository list API and table | R1 | P0 |
| Repository filtering, sorting, pagination | R2 | P0 |
| Repository row actions | R3 | P0 |
| Digest-first repository detail | R4 | P0 |
| Tag chip deletion | R5 | P0 |
| Digest copy and full SHA display | R6 | P0 |
| Type detection and badges | R7 | P0 |
| Expand behavior and details | R8 | P1 |
| Detail filtering and sorting | R9 | P0 |
| Multi-select and batch actions | R10 | P1 |
| Manifest diff | R11 | P1 |
| Locale/theme invariants | R12 | P1 |
| Dashboard repository APIs | R13 | P0 |
| Edge cases | R14 | P1 |

## Fixture Requirements

Prepare a repository fixture with:

- One digest tagged as `15.0.0` and `latest`
- One image digest tagged as `debug`
- One untagged digest
- One unknown media type digest
- At least one digest with a full config digest and subject digest
- Enough repositories/manifests to exercise pagination

## Tests

### R1. Repository List Table

**Steps**:
1. Load `#/repos`.
2. Inspect rows and columns.
3. Open a repository with slashes in its name.

**Expected**:
- Rows represent repository namespaces.
- Columns include Repository, Tags, Digests, Size, Updated, and Actions.
- Repository-level type badges are not shown.
- Tag count excludes untagged manifests.
- Size is displayed from `stored_size_bytes`, not raw manifest JSON length.
- Clicking repository name opens `#/repos/{name}` with path remainder decoded.

### R2. Repository Search, Filters, Sort, Pagination

**Steps**:
1. Apply repository search.
2. Apply All, Recent, and Stale filters.
3. Sort by Recently updated, Name A-Z, and Tag count.
4. Move through pages.
5. Inspect requests.

**Expected**:
- Search is case-insensitive repository-name substring match.
- Recent means modified within 7 days.
- Stale means no modification in 30 days.
- Sort API values are `updated_desc`, `name_asc`, and `tag_count_desc`.
- Filtering/sorting happens before pagination on the server.
- Active filters appear as removable chips.

### R3. Repository Row Actions

**Steps**:
1. Copy repository name from a row action.
2. Delete one repository.
3. Cancel the delete modal.
4. Confirm the delete modal.

**Expected**:
- Copy copies the full repository name without navigating.
- Delete modal title is `Delete repository {name}?`.
- Modal shows manifest count, tag count, and estimated stored size when
  available.
- Warning states all manifests and tags in the repository are deleted.
- Single repository delete does not require typing.
- Deletion response returns deleted manifest/tag counts.
- Blob deletion remains GC-driven.

### R4. Digest-First Repository Detail

**Steps**:
1. Load `#/repos/{name}`.
2. Inspect table rows and tag chips.
3. Verify multi-tag and untagged digests.

**Expected**:
- Each row is one digest.
- Tags appear as chips on the digest row.
- Multiple tags pointing to the same digest are grouped on one row.
- Untagged digests show `-` in Tags column and remain deletable.
- Columns include Digest, Type, Tags, Size, and Info.

### R5. Tag Chip Delete

**Steps**:
1. Click a tag chip remove control once.
2. Click Cancel or outside where supported.
3. Click remove then Confirm.
4. Delete the last tag on a digest.

**Expected**:
- First click turns chip into an inline Confirm state.
- Second confirm deletes only that tag.
- Deleting last tag warns that the digest will become untagged.
- Digest remains present with no tags.
- Failure restores the chip and shows an error.

### R6. Digest Copy And Full SHA Display

**Steps**:
1. Copy a table digest.
2. Expand a row and copy full digest, config digest, and subject digest.
3. Resize viewport.

**Expected**:
- Table may shorten digest text, but Copy copies the full digest.
- Digest row click expands details; it does not copy.
- Config digest and subject digest are not ellipsized when layout can wrap or
  show a copyable field.
- Inline Copied feedback appears after copy.

### R7. Type Detection And Badges

**Steps**:
1. Load fixture digests for Image, Helm, WASM, OCI Artifact, and unknown type.
2. Inspect badges and info text.

**Expected**:
- Image uses teal image badge and shows OS/Arch or config summary.
- Helm uses blue Helm badge and shows chart description/app version.
- WASM uses amber WASM badge and shows module metadata.
- OCI Artifact uses purple OCI Artifact badge.
- Unknown type displays raw media type string in a gray badge.
- Type is a digest/manifest property, not a tag property.

### R8. Expand Behavior And Details

**Steps**:
1. Click a digest row.
2. Click a second row.
3. Click the active row again.
4. Use explicit Details/Hide control.

**Expected**:
- Only one row is expanded at a time.
- Clicking another row collapses the previous row.
- Clicking again collapses.
- In selection mode, row click no longer expands.
- Helm expanded row shows copyable `helm install` one-liner.
- Image expanded row shows config digest, layer count, and stored total size.
- WASM expanded row shows module metadata.
- Unknown expanded row shows raw JSON manifest viewer.

### R9. Detail Filtering And Sorting

**Steps**:
1. Search by digest prefix, tag name, artifact type, and config summary.
2. Filter by Type, Tag state, Tag exact/glob, platform, stored size, media
   type, and created time using `created_after` and `created_before`.
3. Sort by Recently updated, Stored Size, Digest, and Tag count.
4. Inspect requests.

**Expected**:
- Filters operate on digest rows.
- Tag filter matches any tag on the digest.
- Matching digest row still displays all tags, not only matching tags.
- Created time bounds are RFC 3339 timestamps and are applied by the
  dashboard API before pagination.
- Filtering/sorting is server-side.
- Active filters appear as chips.

### R10. Multi-Select And Batch Actions

**Steps**:
1. Enter Select mode.
2. Select visible rows and use Select all.
3. Copy selected digests.
4. Delete selected digests.
5. Try large batch delete above thresholds.

**Expected**:
- Sticky action bar shows selected count, Copy digests, Delete digests, Cancel.
- Copy digests copies full digests newline-separated.
- Batch delete modal title is `Delete N digests?`.
- Modal states total tag cascade count.
- Deleting more than 10 digests or more than 20 tags requires typing `delete`.
- Select all applies only to visible rows on the current filtered page.

### R11. Manifest Diff

**Steps**:
1. Navigate to `#/diff/{name}/{digestA}/{digestB}`.
2. Navigate from tag references where supported.

**Expected**:
- Diff works for any artifact type.
- Tag references resolve to digest before diff.
- Raw JSON manifest diff is readable.

### R12. Locale And Theme Invariants

**Steps**:
1. Switch to Light theme and repeat repository list and detail workflows.
2. Switch locale to Chinese and Arabic.
3. Repeat copy, tag delete, digest delete, filtering, sorting, and selection
   actions.
4. Refresh/deep-link to `#/repos` and `#/repos/{name}`.

**Expected**:
- Labels and action text are translated where dashboard strings are user-visible.
- Full copied values are unchanged across locales.
- Filters, sorts, delete confirmations, and selected row counts keep the same
  semantics in every locale.
- Arabic RTL does not break digest copy controls, tag chips, expanded details,
  batch action bars, or raw JSON viewers.
- Light theme keeps the same dense digest-first layout and readable type badges.
- Repository list/detail deep links emit no browser console errors in dark,
  light, system, English, Chinese, or Arabic.
- Topbar preference controls remain compact above repository filters and do not
  collide with table controls at the tested viewport widths.

### R13. Dashboard Repository APIs

**Steps**:
1. Exercise these endpoints:
   - `GET /api/v1/repositories`
   - `GET /api/v1/repositories/{name}`
   - `GET /api/v1/repositories/{name}/manifests`
   - `GET /api/v1/repositories/{name}/manifests/{digest}`
   - `GET /api/v1/repositories/{name}/manifests/{digest}/raw`
   - delete tag, delete manifest, batch delete, delete repository
2. Verify Link headers for paginated lists.
3. Verify dashboard network requests.

**Expected**:
- Dashboard uses `/api/v1/*` for enriched repository data.
- `/v2/*` remains OCI-spec-only for OCI clients.
- Repository list returns name, tag count, manifest count, `stored_size_bytes`,
  `manifest_size_bytes`, and last modified.
- Repository detail returns the exact repository metadata and access fields even
  when another repository has a matching name prefix.
- Manifest list returns digest rows with tags, type, `stored_size_bytes`,
  `manifest_size_bytes`, timestamps, and config summary.
- Untagged manifests return empty `tags`.
- Delete responses return affected counts.

### R14. Edge Cases

**Steps**:
1. Test repository with thousands of tags.
2. Test unknown artifact type and missing config media type.
3. Test index/multi-arch manifest when implemented.
4. Navigate directly to a deleted digest.

**Expected**:
- Large repositories remain responsive with server-side filtering/pagination.
- Unknown types do not fail rendering.
- Deleted digest route shows contextual 404.
- No dashboard route reintroduces Helm Charts as a top-level section.

## Coverage Map

| Contract Area | Tests |
|---------------|-------|
| Type detection | R4, R7, R13 |
| Repositories page | R1, R2, R3 |
| Digest-first detail | R4-R10, R12 |
| Manifest diff | R11 |
| API design | R13 |
| Backend behavior | R13, R14 |
| Edge cases | R14 |
