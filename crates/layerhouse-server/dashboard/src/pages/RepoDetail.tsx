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
import EmptyState from "../components/EmptyState";
import ErrorBanner from "../components/ErrorBanner";
import Pagination from "../components/Pagination";

function configValue(manifest: ManifestSummary, key: string): string | null {
  const value = manifest.config_summary?.[key];
  if (typeof value === "string") return value;
  if (typeof value === "number") return String(value);
  return null;
}

function expandedContent(repo: string, manifest: ManifestSummary) {
  const kind = manifestKind(manifest).kind;
  const version = manifest.tags[0] ?? "latest";
  if (kind === "helm") {
    return `helm install nginx oci://my-registry/${repo} --version ${version}`;
  }
  if (kind === "image") {
    return t("repo.expanded.config", {
      digest: configValue(manifest, "config_digest") ?? "-",
      layers: configValue(manifest, "layer_count") ?? "0",
      size: formatBytes(manifest.stored_size_bytes),
    });
  }
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
  const [pendingDelete, setPendingDelete] = createSignal<ManifestSummary | null>(null);
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
    fetchRepositories({ q: name, page_size: 1 })
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

  async function confirmDeleteDigest() {
    const manifest = pendingDelete();
    if (!manifest) return;
    setBusy(true);
    try {
      await deleteManifestDigest(repo(), manifest.digest);
      setPendingDelete(null);
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

  function selectAllVisible() {
    setSelected(new Set(manifests().map((manifest) => manifest.digest)));
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

  if (errorCount() >= 3) {
    return <ErrorBanner message={error() ?? t("common.unknown")} onRetry={load} fullPage />;
  }

  return (
    <div>
      <div class="page-header">
        <div>
          <button class="link-button breadcrumb" onClick={() => navigate("/repos")}>
            {t("repo.back")}
          </button>
          <h1>{repo()}</h1>
        </div>
        <span class="freshness">
          {lastUpdated() ? `${t("common.updated")} ${formatAgo(lastUpdated()! / 1000)}` : ""}
        </span>
      </div>

      {error() && <ErrorBanner message={error()!} onRetry={load} />}
      <Show when={toast()}>{(message) => <div class="toast">{message()}</div>}</Show>

      <Show when={repoAccess()}>
        {(access) => (
          <div class="card repo-access-panel">
            <div class="repo-access-summary">
              <span class="eyebrow">{t("repo.access")}</span>
              <div class="repo-access-badges">
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
            </div>
          </div>
        )}
      </Show>

      <div class="card">
        <div class="toolbar">
          <input
            type="search"
            placeholder={t("repo.search")}
            value={search()}
            onInput={(e) => setSearch(e.currentTarget.value)}
          />
          <select value={kind()} onChange={(e) => setKind(e.currentTarget.value)}>
            <option value="all">{t("repo.allTypes")}</option>
            <option value="image">{t("repo.type.image")}</option>
            <option value="helm">{t("repo.type.helm")}</option>
            <option value="wasm">{t("repo.type.wasm")}</option>
            <option value="artifact">{t("repo.type.artifact")}</option>
            <option value="unknown">{t("common.unknown")}</option>
          </select>
          <select value={tagState()} onChange={(e) => setTagState(e.currentTarget.value)}>
            <option value="all">{t("repo.taggedAll")}</option>
            <option value="tagged">{t("repo.taggedOnly")}</option>
            <option value="untagged">{t("repo.untaggedOnly")}</option>
          </select>
          <input
            type="text"
            placeholder={t("repo.tagGlob")}
            value={tagPattern()}
            onInput={(e) => setTagPattern(e.currentTarget.value)}
          />
          <select value={sort()} onChange={(e) => setSort(e.currentTarget.value)}>
            <option value="updated_desc">{t("repos.sort.recent")}</option>
            <option value="updated_asc">{t("repos.sort.oldest")}</option>
            <option value="stored_size_desc">{t("repo.sort.largest")}</option>
            <option value="stored_size_asc">{t("repo.sort.smallest")}</option>
            <option value="digest_asc">{t("repo.sort.digest")}</option>
            <option value="tag_count_desc">{t("repos.sort.tags")}</option>
          </select>
          <button
            class={`btn ${selectMode() ? "btn-primary" : ""}`}
            onClick={() => setSelectMode(!selectMode())}
          >
            {t("repo.select")}
          </button>
        </div>

        <Show when={selectMode()}>
          <div class="batch-bar">
            <span>{t("repo.selected", { count: selected().size })}</span>
            <button class="btn btn-compact" onClick={selectAllVisible}>
              {t("repo.selectAllVisible")}
            </button>
            <button class="btn btn-compact" onClick={() => setSelected(new Set<string>())}>
              {t("common.clear")}
            </button>
            <button
              class="btn btn-compact"
              onClick={() => copyValue([...selected()].join("\n"), "selected")}
            >
              {copied() === "selected" ? t("common.copied") : t("repo.copyDigests")}
            </button>
            <button
              class="btn btn-compact btn-danger"
              disabled={selected().size === 0}
              onClick={() => setBatchConfirm(true)}
            >
              {t("repo.deleteDigests")}
            </button>
          </div>
        </Show>

        {loading() ? (
          <LoadingSpinner label={t("repo.loading")} />
        ) : manifests().length === 0 ? (
          <EmptyState title={t("repo.empty")} description={t("repo.emptyDesc")} />
        ) : (
          <>
            <table class="digest-table">
              <thead>
                <tr>
                  <Show when={selectMode()}>
                    <th />
                  </Show>
                  <th>{t("common.digest")}</th>
                  <th>{t("common.type")}</th>
                  <th>{t("common.tags")}</th>
                  <th>{t("common.size")}</th>
                  <th>{t("common.info")}</th>
                  <th>{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={manifests()}>
                  {(manifest) => {
                    const type = manifestKind(manifest);
                    return (
                      <>
                        <tr
                          class="clickable-row"
                          onClick={() => {
                            if (!selectMode()) {
                              setExpanded(expanded() === manifest.digest ? null : manifest.digest);
                            }
                          }}
                        >
                          <Show when={selectMode()}>
                            <td onClick={(e) => e.stopPropagation()}>
                              <input
                                type="checkbox"
                                checked={selected().has(manifest.digest)}
                                onChange={() => toggleSelected(manifest.digest)}
                              />
                            </td>
                          </Show>
                          <td>
                            <div class="digest-cell">
                              <code>{digestShort(manifest.digest)}</code>
                              <button
                                class="btn btn-compact"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  copyValue(manifest.digest, manifest.digest);
                                }}
                              >
                                {copied() === manifest.digest
                                  ? t("common.copied")
                                  : t("common.copy")}
                              </button>
                            </div>
                          </td>
                          <td>
                            <span class={`badge ${type.className}`}>{type.label}</span>
                          </td>
                          <td onClick={(e) => e.stopPropagation()}>
                            <div class="chips">
                              <Show
                                when={manifest.tags.length > 0}
                                fallback={<span class="muted">—</span>}
                              >
                                <For each={manifest.tags}>
                                  {(tag) => {
                                    const key = `${manifest.digest}:${tag}`;
                                    return (
                                      <button
                                        class={`chip ${confirmTag() === key ? "confirming" : ""}`}
                                        disabled={busy()}
                                        onClick={() => removeTag(manifest, tag)}
                                      >
                                        {confirmTag() === key ? t("repo.confirmChip") : `${tag} ×`}
                                      </button>
                                    );
                                  }}
                                </For>
                              </Show>
                            </div>
                          </td>
                          <td>{formatBytes(manifest.stored_size_bytes)}</td>
                          <td>{formatAgo(manifest.last_modified)}</td>
                          <td onClick={(e) => e.stopPropagation()}>
                            <div class="row-actions">
                              <button
                                class="btn btn-compact"
                                onClick={() =>
                                  setExpanded(
                                    expanded() === manifest.digest ? null : manifest.digest,
                                  )
                                }
                              >
                                {expanded() === manifest.digest
                                  ? t("common.hide")
                                  : t("common.details")}
                              </button>
                              <button
                                class="btn btn-compact btn-danger"
                                onClick={() => setPendingDelete(manifest)}
                              >
                                {t("repo.deleteDigest")}
                              </button>
                            </div>
                          </td>
                        </tr>
                        <Show when={expanded() === manifest.digest}>
                          <tr class="expanded-row">
                            <td colspan={selectMode() ? 7 : 6}>
                              <div class="detail-grid">
                                <div>
                                  <div class="copy-line">
                                    <span>{t("repo.manifestDigest")}</span>
                                    <code>{manifest.digest}</code>
                                    <button
                                      class="btn btn-compact"
                                      onClick={() =>
                                        copyValue(manifest.digest, `full-${manifest.digest}`)
                                      }
                                    >
                                      {copied() === `full-${manifest.digest}`
                                        ? t("common.copied")
                                        : t("common.copy")}
                                    </button>
                                  </div>
                                  <Show when={manifestKind(manifest).kind === "helm"}>
                                    <div class="copy-line">
                                      <span>{t("repo.helmInstall")}</span>
                                      <code>{expandedContent(repo(), manifest)}</code>
                                      <button
                                        class="btn btn-compact"
                                        onClick={() =>
                                          copyValue(
                                            expandedContent(repo(), manifest),
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
                                  <Show when={manifest.subject}>
                                    <div class="copy-line">
                                      <span>{t("repo.subjectDigest")}</span>
                                      <code>{manifest.subject}</code>
                                      <button
                                        class="btn btn-compact"
                                        onClick={() =>
                                          copyValue(manifest.subject!, `subject-${manifest.digest}`)
                                        }
                                      >
                                        {copied() === `subject-${manifest.digest}`
                                          ? t("common.copied")
                                          : t("common.copy")}
                                      </button>
                                    </div>
                                  </Show>
                                  <Show when={configValue(manifest, "config_digest")}>
                                    {(digest) => (
                                      <div class="copy-line">
                                        <span>{t("repo.configDigest")}</span>
                                        <code>{digest()}</code>
                                        <button
                                          class="btn btn-compact"
                                          onClick={() =>
                                            copyValue(digest(), `config-${manifest.digest}`)
                                          }
                                        >
                                          {t("common.copy")}
                                        </button>
                                      </div>
                                    )}
                                  </Show>
                                </div>
                                <pre>{expandedContent(repo(), manifest)}</pre>
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
            <Pagination shown={manifests().length} total={total()} />
          </>
        )}
      </div>

      <Show when={pendingDelete()}>
        {(manifest) => (
          <div class="modal-overlay" onClick={() => setPendingDelete(null)}>
            <div class="modal" onClick={(e) => e.stopPropagation()}>
              <h2>{t("repo.deleteDigestTitle", { digest: digestShort(manifest().digest) })}</h2>
              <p class="warning">
                {t("repo.deleteDigestWarning", { tags: manifest().tags.length })}
              </p>
              <p>
                <code>{manifest().digest}</code>
              </p>
              <div class="modal-actions">
                <button class="btn" disabled={busy()} onClick={() => setPendingDelete(null)}>
                  {t("common.cancel")}
                </button>
                <button class="btn btn-danger" disabled={busy()} onClick={confirmDeleteDigest}>
                  {busy() ? t("common.deleting") : t("common.confirmDelete")}
                </button>
              </div>
            </div>
          </div>
        )}
      </Show>

      <Show when={batchConfirm()}>
        <div
          class="modal-overlay"
          onClick={() => {
            setBatchConfirm(false);
            setBatchDeleteText("");
          }}
        >
          <div class="modal" onClick={(e) => e.stopPropagation()}>
            <h2>{t("repo.deleteBatchTitle", { count: selected().size })}</h2>
            <p class="warning">
              {t("repo.deleteBatchWarning", { tags: selectedTagCount(), count: selected().size })}
            </p>
            <Show when={requiresTypedBatchConfirm()}>
              <div class="form-group">
                <label>{t("repo.typeDelete")}</label>
                <input
                  value={batchDeleteText()}
                  onInput={(e) => setBatchDeleteText(e.currentTarget.value)}
                />
              </div>
            </Show>
            <div class="modal-actions">
              <button
                class="btn"
                disabled={busy()}
                onClick={() => {
                  setBatchConfirm(false);
                  setBatchDeleteText("");
                }}
              >
                {t("common.cancel")}
              </button>
              <button
                class="btn btn-danger"
                disabled={
                  busy() ||
                  (requiresTypedBatchConfirm() && batchDeleteText().toLowerCase() !== "delete")
                }
                onClick={confirmBatchDelete}
              >
                {busy() ? t("common.deleting") : t("common.confirmDelete")}
              </button>
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
}
