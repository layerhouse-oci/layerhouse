import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import { useNavigate, useParams } from "@solidjs/router";
import {
  batchDeleteManifestDigests,
  deleteManifestDigest,
  deleteManifestTag,
  fetchRepositories,
  fetchRepositoryManifests,
} from "../lib/api";
import type { ManifestSummary, RepositorySummary } from "../lib/types";
import { copyToClipboard, digestShort, formatAgo, formatBytes, manifestKind } from "../lib/format";
import { t } from "../lib/i18n";
import LoadingSpinner from "../components/LoadingSpinner";
import EmptyState from "../components/EmptyState";
import ErrorBanner from "../components/ErrorBanner";

const ACCESS_BADGE: Record<string, string> = {
  pull: "badge-blue",
  create: "badge-teal",
  update: "badge-amber",
  delete: "badge-purple",
};

const GRANT_BADGE: Record<string, string> = {
  personal: "badge-blue",
  group_grant: "badge-teal",
  public: "badge-gray",
};

function configValue(manifest: ManifestSummary, key: string): string | null {
  const value = manifest.config_summary?.[key];
  if (typeof value === "string") return value;
  if (typeof value === "number") return String(value);
  return null;
}

function annotationValue(manifest: ManifestSummary, key: string): string | null {
  const value = manifest.annotations?.[key];
  return typeof value === "string" && value ? value : null;
}

function infoTitle(manifest: ManifestSummary): string {
  return (
    annotationValue(manifest, "org.opencontainers.image.title") ??
    configValue(manifest, "platform") ??
    manifestKind(manifest).label
  );
}

function infoDetail(manifest: ManifestSummary): string {
  if (manifest.tags.length === 0) return t("repo.untaggedDigest");
  return manifest.artifact_type || manifest.media_type;
}

function helmCommand(repo: string, manifest: ManifestSummary): string {
  const version = manifest.tags[0] ?? "latest";
  return `helm install nginx oci://my-registry/${repo} --version ${version}`;
}

function rawJson(manifest: ManifestSummary): string {
  const kind = manifestKind(manifest).kind;
  if (kind === "wasm") {
    return JSON.stringify(manifest.config_summary ?? manifest.annotations ?? {}, null, 2);
  }
  return JSON.stringify(manifest.body, null, 2);
}

export default function RepoDetail() {
  const params = useParams<{ name: string }>();
  const navigate = useNavigate();
  const [manifests, setManifests] = createSignal<ManifestSummary[]>([]);
  const [total, setTotal] = createSignal(0);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [errorCount, setErrorCount] = createSignal(0);
  const [lastUpdated, setLastUpdated] = createSignal<number | null>(null);
  const [search, setSearch] = createSignal("");
  const [kind, setKind] = createSignal("all");
  const [tagState, setTagState] = createSignal("all");
  const [tagPattern, setTagPattern] = createSignal("");
  const [sort, setSort] = createSignal("updated_desc");
  const [expanded, setExpanded] = createSignal<string | null>(null);
  const [confirmTag, setConfirmTag] = createSignal<string | null>(null);
  const [inlineDelete, setInlineDelete] = createSignal<string | null>(null);
  const [selectMode, setSelectMode] = createSignal(false);
  const [selected, setSelected] = createSignal<Set<string>>(new Set());
  const [batchConfirm, setBatchConfirm] = createSignal(false);
  const [batchDeleteText, setBatchDeleteText] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [toast, setToast] = createSignal<string | null>(null);
  const [copied, setCopied] = createSignal<string | null>(null);

  const repo = () => decodeURIComponent(params.name);
  const [repoAccess, setRepoAccess] = createSignal<RepositorySummary | null>(null);

  createEffect(() => {
    const name = repo();
    fetchRepositories({ q: name, n: 1 })
      .then((res) => {
        const match = res.repositories.find((r) => r.name === name);
        setRepoAccess(match ?? null);
      })
      .catch(() => setRepoAccess(null));
  });

  async function load() {
    try {
      const response = await fetchRepositoryManifests(repo(), {
        n: 50,
        q: search(),
        type: kind(),
        tag: tagPattern(),
        tagged: tagState() === "tagged" ? true : tagState() === "untagged" ? false : undefined,
        sort: sort(),
      });
      setManifests(response.manifests);
      setTotal(response.total);
      setError(null);
      setErrorCount(0);
      setLastUpdated(Date.now());
    } catch (e) {
      setError(e instanceof Error ? e.message : t("repo.fetchError"));
      setErrorCount((c) => c + 1);
    } finally {
      setLoading(false);
    }
  }

  createEffect(() => {
    repo();
    search();
    kind();
    tagState();
    tagPattern();
    sort();
    setLoading(true);
    load();
    const id = setInterval(load, 15_000);
    onCleanup(() => clearInterval(id));
  });

  function showToast(message: string) {
    setToast(message);
    setTimeout(() => setToast(null), 2200);
  }

  async function copyValue(value: string, key: string) {
    const ok = await copyToClipboard(value);
    if (!ok) {
      showToast(t("common.copyError"));
      return;
    }
    setCopied(key);
    setTimeout(() => setCopied(null), 1400);
  }

  async function removeTag(manifest: ManifestSummary, tag: string) {
    const key = `${manifest.digest}:${tag}`;
    if (confirmTag() !== key) {
      setConfirmTag(key);
      if (manifest.tags.length === 1) showToast(t("repo.digestWillBecomeUntagged"));
      return;
    }
    setBusy(true);
    try {
      await deleteManifestTag(repo(), manifest.digest, tag);
      setConfirmTag(null);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("repo.deleteTagError"));
    } finally {
      setBusy(false);
    }
  }

  async function confirmDeleteDigest(manifest: ManifestSummary) {
    setBusy(true);
    try {
      await deleteManifestDigest(repo(), manifest.digest);
      setInlineDelete(null);
      setExpanded(null);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("repo.deleteDigestError"));
    } finally {
      setBusy(false);
    }
  }

  async function confirmBatchDelete() {
    const digests = [...selected()];
    if (digests.length === 0) return;
    if (requiresTypedBatchConfirm() && batchDeleteText().toLowerCase() !== "delete") return;
    setBusy(true);
    try {
      await batchDeleteManifestDigests(repo(), digests);
      setSelected(new Set<string>());
      setBatchConfirm(false);
      setBatchDeleteText("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("repo.deleteBatchError"));
    } finally {
      setBusy(false);
    }
  }

  function toggleSelected(digest: string) {
    const next = new Set(selected());
    if (next.has(digest)) next.delete(digest);
    else next.add(digest);
    setSelected(next);
  }

  function allVisibleSelected() {
    const rows = manifests();
    return rows.length > 0 && rows.every((manifest) => selected().has(manifest.digest));
  }

  function toggleSelectAll() {
    if (allVisibleSelected()) setSelected(new Set<string>());
    else setSelected(new Set(manifests().map((manifest) => manifest.digest)));
  }

  function selectedTagCount() {
    const digests = selected();
    return manifests()
      .filter((manifest) => digests.has(manifest.digest))
      .reduce((count, manifest) => count + manifest.tags.length, 0);
  }

  function requiresTypedBatchConfirm() {
    return selected().size > 10 || selectedTagCount() > 20;
  }

  function exitSelectMode() {
    setSelectMode(false);
    setSelected(new Set<string>());
  }

  type Chip = { label: string; reset: () => void };
  const activeChips = (): Chip[] => {
    const chips: Chip[] = [];
    if (search()) chips.push({ label: search(), reset: () => setSearch("") });
    if (kind() !== "all") {
      const label = kind() === "unknown" ? t("repo.type.unknown") : t(`repo.type.${kind()}`);
      chips.push({ label, reset: () => setKind("all") });
    }
    if (tagState() !== "all") {
      chips.push({
        label: tagState() === "tagged" ? t("repo.taggedOnly") : t("repo.untaggedOnly"),
        reset: () => setTagState("all"),
      });
    }
    if (tagPattern()) chips.push({ label: tagPattern(), reset: () => setTagPattern("") });
    return chips;
  };

  if (errorCount() >= 3) {
    return <ErrorBanner message={error() ?? t("common.unknown")} onRetry={load} fullPage />;
  }

  return (
    <div class={`repo-detail${selectMode() ? " select-mode" : ""}`}>
      <header class="page-head">
        <button class="back-link" type="button" onClick={() => navigate("/repos")}>
          {t("repo.back")}
        </button>
        <div class="title-row">
          <div>
            <h1>
              <span class="repo-path">{repo()}</span>
            </h1>
            <p class="route-hash">#/repos/{repo()}</p>
          </div>
          <Show when={lastUpdated()}>
            <div class="freshness">
              {t("common.updated")} {formatAgo(lastUpdated()! / 1000)}
            </div>
          </Show>
        </div>
      </header>

      {error() && <ErrorBanner message={error()!} onRetry={load} />}

      <Show when={repoAccess()}>
        {(access) => (
          <section class="access-panel glass">
            <span class="section-label">{t("repo.access")}</span>
            <div class="access-badges">
              <span class={`badge ${ACCESS_BADGE[access().access_level] ?? "badge-gray"}`}>
                {t(`access.action.${access().access_level}`)}
              </span>
              <Show when={access().max_grantable !== access().access_level}>
                <span class="badge badge-gray">
                  {t("repo.canGrant", { action: t(`access.action.${access().max_grantable}`) })}
                </span>
              </Show>
              <span class={`badge ${GRANT_BADGE[access().grant_source] ?? "badge-gray"}`}>
                {t("repo.accessSource", {
                  source: t(`access.grantSource.${access().grant_source}`),
                })}
              </span>
            </div>
          </section>
        )}
      </Show>

      <section class="panel glass">
        <div class="panel-head">
          <div>
            <p class="section-label">{t("repo.sectionLabel")}</p>
            <h2>{t("repo.manifests")}</h2>
          </div>
          <div class="summary">{t("repo.summary")}</div>
        </div>

        <div class="toolbar">
          <div class="filter-row">
            <input
              class="filter-input"
              type="search"
              placeholder={t("repo.search")}
              value={search()}
              onInput={(e) => setSearch(e.currentTarget.value)}
            />
            <select
              class="filter-select"
              aria-label={t("common.type")}
              value={kind()}
              onChange={(e) => setKind(e.currentTarget.value)}
            >
              <option value="all">{t("repo.allTypes")}</option>
              <option value="helm">{t("repo.type.helm")}</option>
              <option value="image">{t("repo.type.image")}</option>
              <option value="wasm">{t("repo.type.wasm")}</option>
              <option value="artifact">{t("repo.type.artifact")}</option>
              <option value="unknown">{t("repo.type.unknown")}</option>
            </select>
            <select
              class="filter-select"
              aria-label={t("common.tags")}
              value={tagState()}
              onChange={(e) => setTagState(e.currentTarget.value)}
            >
              <option value="all">{t("repo.taggedAll")}</option>
              <option value="tagged">{t("repo.taggedOnly")}</option>
              <option value="untagged">{t("repo.untaggedOnly")}</option>
            </select>
            <input
              class="filter-input"
              type="text"
              placeholder={t("repo.tagGlob")}
              value={tagPattern()}
              onInput={(e) => setTagPattern(e.currentTarget.value)}
            />
            <select
              class="filter-select"
              aria-label={t("repos.sort")}
              value={sort()}
              onChange={(e) => setSort(e.currentTarget.value)}
            >
              <option value="updated_desc">{t("repos.sort.recent")}</option>
              <option value="updated_asc">{t("repos.sort.oldest")}</option>
              <option value="stored_size_desc">{t("repo.sort.largest")}</option>
              <option value="stored_size_asc">{t("repo.sort.smallest")}</option>
              <option value="digest_asc">{t("repo.sort.digest")}</option>
              <option value="tag_count_desc">{t("repos.sort.tags")}</option>
            </select>
            <button
              class={`select-toggle${selectMode() ? " active" : ""}`}
              type="button"
              onClick={() => (selectMode() ? exitSelectMode() : setSelectMode(true))}
            >
              {t("repo.select")}
            </button>
          </div>
          <Show when={activeChips().length > 0}>
            <div class="toolbar-actions">
              <div class="filter-chips" aria-label={t("common.all")}>
                <For each={activeChips()}>
                  {(chip) => (
                    <span class="filter-chip">
                      <span>{chip.label}</span>
                      <button type="button" aria-label={t("common.clear")} onClick={chip.reset}>
                        ×
                      </button>
                    </span>
                  )}
                </For>
              </div>
            </div>
          </Show>
        </div>

        <div class={`batch-bar${selectMode() ? " visible" : ""}`}>
          <span class="batch-count">{t("repo.selected", { count: selected().size })}</span>
          <div class="batch-actions">
            <button
              class="batch-button"
              type="button"
              onClick={() => copyValue([...selected()].join("\n"), "selected")}
            >
              {copied() === "selected" ? t("common.copied") : t("repo.copyDigests")}
            </button>
            <button
              class="batch-button danger"
              type="button"
              disabled={selected().size === 0}
              onClick={() => setBatchConfirm(true)}
            >
              {t("repo.deleteDigests")}
            </button>
            <button class="batch-button" type="button" onClick={exitSelectMode}>
              {t("common.cancel")}
            </button>
          </div>
        </div>

        {loading() ? (
          <LoadingSpinner label={t("repo.loading")} />
        ) : manifests().length === 0 ? (
          <EmptyState title={t("repo.empty")} description={t("repo.emptyDesc")} />
        ) : (
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th class="select-col">
                    <input
                      class="select-all"
                      type="checkbox"
                      aria-label={t("repo.selectAllVisible")}
                      checked={allVisibleSelected()}
                      onChange={toggleSelectAll}
                    />
                  </th>
                  <th>{t("common.digest")}</th>
                  <th>{t("common.type")}</th>
                  <th>{t("common.tags")}</th>
                  <th>{t("common.size")}</th>
                  <th>{t("common.info")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={manifests()}>
                  {(manifest) => {
                    const type = manifestKind(manifest);
                    const isOpen = () => expanded() === manifest.digest;
                    return (
                      <>
                        <tr
                          class={`manifest-row${isOpen() ? " active" : ""}`}
                          onClick={() => setExpanded(isOpen() ? null : manifest.digest)}
                        >
                          <td class="select-col" onClick={(e) => e.stopPropagation()}>
                            <input
                              class="row-select"
                              type="checkbox"
                              aria-label={digestShort(manifest.digest)}
                              checked={selected().has(manifest.digest)}
                              onChange={() => toggleSelected(manifest.digest)}
                            />
                          </td>
                          <td>
                            <div class="digest-cell">
                              <span class="digest">{digestShort(manifest.digest)}</span>
                              <button
                                class="digest-copy"
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  copyValue(manifest.digest, manifest.digest);
                                }}
                              >
                                {copied() === manifest.digest
                                  ? t("common.copied")
                                  : t("common.copy")}
                              </button>
                              <button
                                class="details-button"
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setExpanded(isOpen() ? null : manifest.digest);
                                }}
                              >
                                {isOpen() ? t("common.hide") : t("common.details")}
                              </button>
                            </div>
                          </td>
                          <td>
                            <span class={`type-badge type-${type.kind}`}>{type.label}</span>
                          </td>
                          <td onClick={(e) => e.stopPropagation()}>
                            <div class="tags-cell">
                              <Show
                                when={manifest.tags.length > 0}
                                fallback={<span class="tags-empty">—</span>}
                              >
                                <For each={manifest.tags}>
                                  {(tag) => {
                                    const key = `${manifest.digest}:${tag}`;
                                    return (
                                      <span
                                        class={`tag-chip${confirmTag() === key ? " confirming" : ""}`}
                                      >
                                        <span>{tag}</span>
                                        <button
                                          class="chip-remove"
                                          type="button"
                                          disabled={busy()}
                                          aria-label={tag}
                                          onClick={() => removeTag(manifest, tag)}
                                        >
                                          {confirmTag() === key ? t("repo.confirmChip") : "×"}
                                        </button>
                                      </span>
                                    );
                                  }}
                                </For>
                              </Show>
                            </div>
                          </td>
                          <td class="size">{formatBytes(manifest.stored_size_bytes)}</td>
                          <td onClick={(e) => e.stopPropagation()}>
                            <div class="info-cell">
                              <span class="info-strong">{infoTitle(manifest)}</span>
                              <span>{infoDetail(manifest)}</span>
                              <Show
                                when={inlineDelete() !== manifest.digest}
                                fallback={
                                  <div class="delete-confirm visible">
                                    <span class="delete-warning">
                                      {t("repo.deleteConfirmWarning", {
                                        tags: manifest.tags.length,
                                      })}
                                    </span>
                                    <span class="delete-buttons">
                                      <button
                                        class="cancel-delete"
                                        type="button"
                                        disabled={busy()}
                                        onClick={() => setInlineDelete(null)}
                                      >
                                        {t("common.cancel")}
                                      </button>
                                      <button
                                        class="confirm-delete"
                                        type="button"
                                        disabled={busy()}
                                        onClick={() => confirmDeleteDigest(manifest)}
                                      >
                                        {busy() ? t("common.deleting") : t("common.confirmDelete")}
                                      </button>
                                    </span>
                                  </div>
                                }
                              >
                                <button
                                  class="delete-digest"
                                  type="button"
                                  onClick={() => setInlineDelete(manifest.digest)}
                                >
                                  {t("repo.deleteDigest")}
                                </button>
                              </Show>
                            </div>
                          </td>
                        </tr>
                        <Show when={isOpen()}>
                          <tr class="detail-row">
                            <td class="detail-cell" colspan={6}>
                              <div class="detail-panel">
                                <div class="detail-grid">
                                  <div class="metric metric-wide">
                                    <span>{t("repo.manifestDigest")}</span>
                                    <span class="copy-value">
                                      <span class="copy-value-text">{manifest.digest}</span>
                                      <button
                                        class="value-copy"
                                        type="button"
                                        onClick={() =>
                                          copyValue(manifest.digest, `full-${manifest.digest}`)
                                        }
                                      >
                                        {copied() === `full-${manifest.digest}`
                                          ? t("common.copied")
                                          : t("common.copy")}
                                      </button>
                                    </span>
                                  </div>

                                  <Show when={manifest.subject}>
                                    <div class="metric metric-wide">
                                      <span>{t("repo.subjectDigest")}</span>
                                      <span class="copy-value">
                                        <span class="copy-value-text">{manifest.subject}</span>
                                        <button
                                          class="value-copy"
                                          type="button"
                                          onClick={() =>
                                            copyValue(
                                              manifest.subject!,
                                              `subject-${manifest.digest}`,
                                            )
                                          }
                                        >
                                          {copied() === `subject-${manifest.digest}`
                                            ? t("common.copied")
                                            : t("common.copy")}
                                        </button>
                                      </span>
                                    </div>
                                  </Show>

                                  <Show when={configValue(manifest, "config_digest")}>
                                    {(digest) => (
                                      <div class="metric metric-wide">
                                        <span>{t("repo.configDigest")}</span>
                                        <span class="copy-value">
                                          <span class="copy-value-text">{digest()}</span>
                                          <button
                                            class="value-copy"
                                            type="button"
                                            onClick={() =>
                                              copyValue(digest(), `config-${manifest.digest}`)
                                            }
                                          >
                                            {copied() === `config-${manifest.digest}`
                                              ? t("common.copied")
                                              : t("common.copy")}
                                          </button>
                                        </span>
                                      </div>
                                    )}
                                  </Show>

                                  <Show when={configValue(manifest, "layer_count")}>
                                    {(layers) => (
                                      <div class="metric">
                                        <span>{t("repo.layerCount")}</span>
                                        <span>{layers()}</span>
                                      </div>
                                    )}
                                  </Show>

                                  <Show when={type.kind === "image"}>
                                    <div class="metric">
                                      <span>{t("repo.totalSize")}</span>
                                      <span>{formatBytes(manifest.stored_size_bytes)}</span>
                                    </div>
                                  </Show>

                                  <Show when={manifest.artifact_type}>
                                    <div class="metric">
                                      <span>{t("repo.artifactType")}</span>
                                      <span>{manifest.artifact_type}</span>
                                    </div>
                                  </Show>
                                </div>

                                <Show when={type.kind === "helm"}>
                                  <div class="copy-code">
                                    <code>{helmCommand(repo(), manifest)}</code>
                                    <button
                                      class="copy-button"
                                      type="button"
                                      onClick={() =>
                                        copyValue(
                                          helmCommand(repo(), manifest),
                                          `helm-${manifest.digest}`,
                                        )
                                      }
                                    >
                                      {copied() === `helm-${manifest.digest}`
                                        ? t("common.copied")
                                        : t("common.copy")}
                                    </button>
                                  </div>
                                </Show>

                                <Show
                                  when={
                                    type.kind === "wasm" ||
                                    type.kind === "unknown" ||
                                    type.kind === "artifact"
                                  }
                                >
                                  <div class="code-block">
                                    <pre>
                                      <code>{rawJson(manifest)}</code>
                                    </pre>
                                    <button
                                      class="copy-button"
                                      type="button"
                                      onClick={() =>
                                        copyValue(rawJson(manifest), `json-${manifest.digest}`)
                                      }
                                    >
                                      {copied() === `json-${manifest.digest}`
                                        ? t("common.copied")
                                        : t("common.copy")}
                                    </button>
                                  </div>
                                </Show>
                              </div>
                            </td>
                          </tr>
                        </Show>
                      </>
                    );
                  }}
                </For>
              </tbody>
            </table>

            <div class="table-footer">
              <span class="page-count">
                {t("repos.pagination", { shown: manifests().length, total: total() })}
              </span>
              <div class="pager">
                <button class="page-button" type="button" disabled>
                  {t("common.previous")}
                </button>
                <span class="page-number">1</span>
                <button class="page-button" type="button" disabled>
                  {t("common.next")}
                </button>
              </div>
            </div>
          </div>
        )}
      </section>

      <footer class="footer">
        <span>
          <strong>{t("common.updated")}:</strong>{" "}
          {lastUpdated() ? formatAgo(lastUpdated()! / 1000) : "—"}
        </span>
        <span>{t("repo.footerNote")}</span>
      </footer>

      <Show when={toast()}>{(message) => <div class="toast visible">{message()}</div>}</Show>

      <Show when={batchConfirm()}>
        <div
          class="modal-backdrop visible"
          onClick={() => {
            setBatchConfirm(false);
            setBatchDeleteText("");
          }}
        >
          <div class="modal" onClick={(e) => e.stopPropagation()}>
            <h3>{t("repo.deleteBatchTitle", { count: selected().size })}</h3>
            <p>
              {t("repo.deleteBatchWarning", { tags: selectedTagCount(), count: selected().size })}
            </p>
            <div class="selected-list">
              <For each={manifests().filter((m) => selected().has(m.digest))}>
                {(manifest) => (
                  <div>
                    <span>{digestShort(manifest.digest)}</span>
                    <span>{t("repo.selected", { count: manifest.tags.length })}</span>
                  </div>
                )}
              </For>
            </div>
            <Show when={requiresTypedBatchConfirm()}>
              <input
                class="filter-input"
                placeholder={t("repo.typeDelete")}
                value={batchDeleteText()}
                onInput={(e) => setBatchDeleteText(e.currentTarget.value)}
              />
            </Show>
            <div class="modal-actions">
              <button
                class="batch-button"
                type="button"
                disabled={busy()}
                onClick={() => {
                  setBatchConfirm(false);
                  setBatchDeleteText("");
                }}
              >
                {t("common.cancel")}
              </button>
              <button
                class="batch-button danger"
                type="button"
                disabled={
                  busy() ||
                  (requiresTypedBatchConfirm() && batchDeleteText().toLowerCase() !== "delete")
                }
                onClick={confirmBatchDelete}
              >
                {busy() ? t("common.deleting") : t("repo.deleteDigests")}
              </button>
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
}
