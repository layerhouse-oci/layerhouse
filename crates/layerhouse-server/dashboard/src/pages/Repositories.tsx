import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { ApiError, deleteRepository, fetchAccountNamespaces, fetchRepositories } from "../lib/api";
import type {
  NamespaceResponse,
  RepositoryFilter,
  RepositoryRecencyFilter,
  RepositorySummary,
} from "../lib/types";
import { copyToClipboard, formatAgo, formatBytes } from "../lib/format";
import { t } from "../lib/i18n";
import LoadingSpinner from "../components/LoadingSpinner";
import EmptyState from "../components/EmptyState";
import ErrorBanner from "../components/ErrorBanner";
import Pagination from "../components/Pagination";
import Access from "./Access";

function repoInitials(name: string): string {
  const segment = name.split("/").filter(Boolean).pop() ?? name;
  const letters = segment.replace(/[^a-zA-Z0-9]/g, "");
  return (letters.slice(0, 2) || "OC").toUpperCase();
}

const PAGE_SIZE_OPTIONS = [25, 50, 100, 200];
type CatalogTab = "repositories" | "namespaces";

function repoQuery(): URLSearchParams {
  return new URLSearchParams(window.location.hash.split("?")[1] ?? "");
}

function initialPageSize(params: URLSearchParams): number {
  const n = Number(params.get("n"));
  return PAGE_SIZE_OPTIONS.includes(n) ? n : 50;
}

function initialRepositoryFilter(params: URLSearchParams): RepositoryFilter {
  const filter = params.get("filter");
  return filter === "mine" || filter === "shared" || filter === "public" ? filter : "all";
}

function initialRecencyFilter(params: URLSearchParams): RepositoryRecencyFilter {
  const recency = params.get("recency");
  return recency === "recent" || recency === "stale" ? recency : "all";
}

function initialCatalogTab(params: URLSearchParams): CatalogTab {
  return params.get("tab") === "namespaces" ? "namespaces" : "repositories";
}

function nextLast(nextCursor: string | null): string | null {
  if (!nextCursor) return null;
  try {
    return new URL(nextCursor, window.location.origin).searchParams.get("last");
  } catch {
    return null;
  }
}

export default function Repositories() {
  const initialQuery = repoQuery();
  const navigate = useNavigate();
  const [repos, setRepos] = createSignal<RepositorySummary[]>([]);
  const [namespaces, setNamespaces] = createSignal<NamespaceResponse[]>([]);
  const [total, setTotal] = createSignal(0);
  const [loading, setLoading] = createSignal(true);
  const [namespaceLoading, setNamespaceLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [namespaceError, setNamespaceError] = createSignal<string | null>(null);
  const [namespaceWorkflowAvailable, setNamespaceWorkflowAvailable] = createSignal(true);
  const [errorCount, setErrorCount] = createSignal(0);
  const [lastUpdated, setLastUpdated] = createSignal<number | null>(null);
  const [catalogTab, setCatalogTab] = createSignal<CatalogTab>(initialCatalogTab(initialQuery));
  const [search, setSearch] = createSignal(initialQuery.get("q") ?? "");
  const [filter, setFilter] = createSignal<RepositoryFilter>(initialRepositoryFilter(initialQuery));
  const [recency, setRecency] = createSignal<RepositoryRecencyFilter>(
    initialRecencyFilter(initialQuery),
  );
  const [sort, setSort] = createSignal(initialQuery.get("sort") ?? "updated_desc");
  const [pageSize, setPageSize] = createSignal(initialPageSize(initialQuery));
  const [currentLast, setCurrentLast] = createSignal<string | null>(initialQuery.get("last"));
  const [previousLasts, setPreviousLasts] = createSignal<(string | null)[]>([]);
  const [nextPageLast, setNextPageLast] = createSignal<string | null>(null);
  const [copied, setCopied] = createSignal<string | null>(null);
  const [toast, setToast] = createSignal<string | null>(null);
  const [pendingDelete, setPendingDelete] = createSignal<RepositorySummary | null>(null);
  const [deleting, setDeleting] = createSignal(false);
  const [showTokens, setShowTokens] = createSignal(false);

  function updateHashQuery() {
    const params = new URLSearchParams();
    if (catalogTab() === "namespaces") params.set("tab", "namespaces");
    if (search().trim()) params.set("q", search().trim());
    if (catalogTab() === "repositories") {
      if (filter() !== "all") params.set("filter", filter());
      if (recency() !== "all") params.set("recency", recency());
      if (sort() !== "updated_desc") params.set("sort", sort());
      if (pageSize() !== 50) params.set("n", String(pageSize()));
      if (currentLast()) params.set("last", currentLast()!);
    }
    const query = params.toString();
    window.history.replaceState(
      null,
      "",
      `${window.location.pathname}${window.location.search}#/repos${query ? `?${query}` : ""}`,
    );
  }

  async function load() {
    updateHashQuery();
    try {
      const response = await fetchRepositories({
        n: pageSize(),
        last: currentLast() ?? undefined,
        q: search().trim(),
        filter: filter(),
        recency: recency() === "all" ? undefined : recency(),
        sort: sort(),
      });
      setRepos(response.repositories);
      setTotal(response.total_reachable);
      setNextPageLast(nextLast(response.next_cursor));
      setError(null);
      setErrorCount(0);
      setLastUpdated(Date.now());
    } catch (e) {
      setError(e instanceof Error ? e.message : t("repos.fetchError"));
      setErrorCount((c) => c + 1);
    } finally {
      setLoading(false);
    }
  }

  async function loadNamespaces() {
    setNamespaceLoading(true);
    try {
      const response = await fetchAccountNamespaces();
      setNamespaces(response.namespaces);
      setNamespaceError(null);
      setNamespaceWorkflowAvailable(true);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setNamespaces([]);
        setNamespaceError(null);
      } else if (
        e instanceof ApiError &&
        e.status >= 500 &&
        e.message.toLowerCase().includes("auth is not configured")
      ) {
        setNamespaces([]);
        setNamespaceError(null);
        setNamespaceWorkflowAvailable(false);
      } else {
        setNamespaceError(e instanceof Error ? e.message : t("access.namespaceLoadError"));
      }
    } finally {
      setNamespaceLoading(false);
    }
  }

  createEffect(() => {
    if (catalogTab() !== "repositories") {
      updateHashQuery();
      setLoading(false);
      return;
    }

    search();
    filter();
    recency();
    sort();
    pageSize();
    currentLast();
    setLoading(true);
    const loadId = window.setTimeout(() => void load(), 220);
    const refreshId = window.setInterval(() => void load(), 10_000);
    onCleanup(() => {
      clearTimeout(loadId);
      clearInterval(refreshId);
    });
  });

  createEffect(() => {
    const tab = catalogTab();
    if (!namespaceWorkflowAvailable()) {
      if (tab === "namespaces") setCatalogTab("repositories");
      return;
    }

    if (tab === "namespaces") search();
    updateHashQuery();

    const loadId = window.setTimeout(() => void loadNamespaces(), tab === "namespaces" ? 220 : 0);
    const refreshId =
      tab === "namespaces" ? window.setInterval(() => void loadNamespaces(), 10_000) : null;
    onCleanup(() => {
      clearTimeout(loadId);
      if (refreshId) clearInterval(refreshId);
    });
  });

  function resetPaging() {
    setCurrentLast(null);
    setPreviousLasts([]);
    setNextPageLast(null);
  }

  function goNext() {
    const next = nextPageLast();
    if (!next) return;
    setPreviousLasts([...previousLasts(), currentLast()]);
    setCurrentLast(next);
  }

  function goPrevious() {
    const stack = previousLasts();
    if (stack.length === 0) return;
    setPreviousLasts(stack.slice(0, -1));
    setCurrentLast(stack[stack.length - 1] ?? null);
  }

  function showToast(message: string) {
    setToast(message);
    setTimeout(() => setToast(null), 2200);
  }

  async function copyRepo(name: string) {
    const ok = await copyToClipboard(name);
    if (!ok) {
      showToast(t("common.copyError"));
      return;
    }
    setCopied(name);
    setTimeout(() => setCopied(null), 1600);
  }

  async function copyNamespace(handle: string) {
    const ok = await copyToClipboard(handle);
    if (!ok) {
      showToast(t("common.copyError"));
      return;
    }
    setCopied(`namespace-${handle}`);
    setTimeout(() => setCopied(null), 1600);
  }

  async function confirmDelete() {
    const repo = pendingDelete();
    if (!repo) return;
    setDeleting(true);
    try {
      await deleteRepository(repo.name);
      setPendingDelete(null);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("repos.deleteError"));
    } finally {
      setDeleting(false);
    }
  }

  const RECENCY_FILTERS: { value: RepositoryRecencyFilter; label: string }[] = [
    { value: "all", label: t("common.all") },
    { value: "recent", label: t("common.recent") },
    { value: "stale", label: t("common.stale") },
  ];

  const ACCESS_FILTERS: { value: RepositoryFilter; label: string }[] = [
    { value: "mine", label: t("repos.filter.mine") },
    { value: "shared", label: t("repos.filter.shared") },
    { value: "public", label: t("repos.filter.public") },
  ];

  const filteredNamespaces = () => {
    const query = search().trim().toLowerCase();
    if (!query) return namespaces();
    return namespaces().filter(
      (namespace) =>
        namespace.handle.toLowerCase().includes(query) ||
        namespace.owner_label.toLowerCase().includes(query),
    );
  };

  if (catalogTab() === "repositories" && errorCount() >= 3) {
    return <ErrorBanner message={error() ?? t("common.unknown")} onRetry={load} fullPage />;
  }

  return (
    <div class="repos-page">
      <section class="hero glass">
        <div>
          <p class="eyebrow">
            <span class="status-dot" aria-hidden="true" />
            {t("repos.heroEyebrow")}
          </p>
          <h1>{t("repos.title")}</h1>
          <p class="hero-copy">{t("repos.heroCopy")}</p>
        </div>
      </section>

      {error() && <ErrorBanner message={error()!} onRetry={load} />}
      <Show when={toast()}>{(message) => <div class="toast">{message()}</div>}</Show>

      <section class="panel glass">
        <div class="toolbar">
          <div class="toolbar-title">
            <p class="section-label">{t("repos.catalog")}</p>
            <h2>{t("repos.eyebrow")}</h2>
            <div class="tabs catalog-tabs" role="tablist">
              <button
                class={catalogTab() === "repositories" ? "active" : ""}
                type="button"
                onClick={() => setCatalogTab("repositories")}
              >
                {t("repos.tab.repositories")}
              </button>
              <Show when={namespaceWorkflowAvailable()}>
                <button
                  class={catalogTab() === "namespaces" ? "active" : ""}
                  type="button"
                  onClick={() => setCatalogTab("namespaces")}
                >
                  {t("repos.tab.namespaces")}
                </button>
              </Show>
            </div>
          </div>
          <div class="list-controls">
            <div class="search" role="search">
              <input
                type="search"
                aria-label={
                  catalogTab() === "namespaces" ? t("repos.searchNamespaces") : t("repos.search")
                }
                placeholder={
                  catalogTab() === "namespaces" ? t("repos.searchNamespaces") : t("repos.search")
                }
                value={search()}
                onInput={(e) => {
                  resetPaging();
                  setSearch(e.currentTarget.value);
                }}
              />
            </div>
            <Show when={catalogTab() === "repositories"}>
              <div class="filter-group">
                <For each={RECENCY_FILTERS}>
                  {(item) => (
                    <button
                      type="button"
                      class={`filter${recency() === item.value ? " active" : ""}`}
                      onClick={() => {
                        resetPaging();
                        setRecency(item.value);
                      }}
                    >
                      {item.label}
                    </button>
                  )}
                </For>
              </div>
              <div class="filter-group access-filter-group" aria-label={t("repos.accessFilters")}>
                <button
                  type="button"
                  class={`filter${filter() === "all" ? " active" : ""}`}
                  onClick={() => {
                    resetPaging();
                    setFilter("all");
                  }}
                >
                  {t("repos.filter.all")}
                </button>
                <For each={ACCESS_FILTERS}>
                  {(item) => (
                    <button
                      type="button"
                      class={`filter${filter() === item.value ? " active" : ""}`}
                      onClick={() => {
                        resetPaging();
                        setFilter(item.value);
                      }}
                    >
                      {item.label}
                    </button>
                  )}
                </For>
              </div>
              <div class="sort-control">
                <label for="repo-sort">{t("repos.sort")}</label>
                <select
                  id="repo-sort"
                  value={sort()}
                  onChange={(e) => {
                    resetPaging();
                    setSort(e.currentTarget.value);
                  }}
                >
                  <option value="updated_desc">{t("repos.sort.recent")}</option>
                  <option value="updated_asc">{t("repos.sort.oldest")}</option>
                  <option value="name_asc">{t("repos.sort.name")}</option>
                  <option value="tag_count_desc">{t("repos.sort.tags")}</option>
                </select>
              </div>
            </Show>
            <button class="action" type="button" onClick={() => setShowTokens(true)}>
              {t("repos.manageTokens")}
            </button>
          </div>
        </div>

        <Show when={catalogTab() === "repositories"}>
          {loading() ? (
            <LoadingSpinner label={t("repos.loading")} />
          ) : repos().length === 0 ? (
            <div class="repos-empty-state">
              <EmptyState
                title={
                  search()
                    ? t("repos.empty.filtered")
                    : namespaces().length > 0
                      ? t("repos.empty.withNamespaces")
                      : t("repos.empty")
                }
                description={
                  search()
                    ? t("repos.empty.filteredDesc")
                    : namespaces().length > 0
                      ? t("repos.empty.withNamespacesDesc")
                      : t("repos.emptyDesc")
                }
              />
              <div class="row-actions">
                <Show when={namespaces().length > 0}>
                  <button type="button" class="action" onClick={() => setCatalogTab("namespaces")}>
                    {t("repos.viewNamespaces")}
                  </button>
                </Show>
                <button class="action" type="button" onClick={() => setShowTokens(true)}>
                  {t("repos.claimNamespace")}
                </button>
              </div>
            </div>
          ) : (
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{t("common.repository")}</th>
                    <th>{t("common.tags")}</th>
                    <th>{t("common.updated")}</th>
                    <th>{t("common.actions")}</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={repos()}>
                    {(repo) => (
                      <tr>
                        <td>
                          <button class="repo-name" onClick={() => navigate(`/repos/${repo.name}`)}>
                            <span class="repo-icon" aria-hidden="true">
                              {repoInitials(repo.name)}
                            </span>
                            <span>{repo.name}</span>
                          </button>
                        </td>
                        <td class="value">{repo.tag_count}</td>
                        <td class="muted">
                          <span class="mono">{formatAgo(repo.last_modified)}</span>
                        </td>
                        <td>
                          <div class="row-actions">
                            <button
                              class="action copy"
                              type="button"
                              onClick={() => copyRepo(repo.name)}
                            >
                              {copied() === repo.name ? t("common.copied") : t("common.copy")}
                            </button>
                            <button
                              class="action"
                              type="button"
                              onClick={() => navigate(`/repos/${repo.name}`)}
                            >
                              {t("common.details")}
                            </button>
                            <Show when={repo.access_level === "delete"}>
                              <button
                                class="action danger"
                                type="button"
                                onClick={() => setPendingDelete(repo)}
                              >
                                {t("common.delete")}
                              </button>
                            </Show>
                          </div>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
              <div class="table-footer">
                <Pagination
                  start={previousLasts().length * pageSize() + 1}
                  shown={repos().length}
                  total={total()}
                  page={previousLasts().length + 1}
                  pageSize={pageSize()}
                  pageSizeOptions={PAGE_SIZE_OPTIONS}
                  hasPrevious={previousLasts().length > 0}
                  hasNext={nextPageLast() !== null}
                  onPrevious={goPrevious}
                  onNext={goNext}
                  onPageSizeChange={(size) => {
                    resetPaging();
                    setPageSize(size);
                  }}
                />
              </div>
            </div>
          )}
        </Show>

        <Show when={catalogTab() === "namespaces"}>
          {namespaceError() ? (
            <ErrorBanner message={namespaceError()!} onRetry={loadNamespaces} />
          ) : namespaceLoading() ? (
            <LoadingSpinner label={t("repos.loadingNamespaces")} />
          ) : filteredNamespaces().length === 0 ? (
            <div class="repos-empty-state">
              <EmptyState
                title={
                  search() ? t("repos.namespaces.empty.filtered") : t("repos.namespaces.empty")
                }
                description={
                  search()
                    ? t("repos.namespaces.empty.filteredDesc")
                    : t("repos.namespaces.emptyDesc")
                }
              />
              <button class="action" type="button" onClick={() => setShowTokens(true)}>
                {t("repos.claimNamespace")}
              </button>
            </div>
          ) : (
            <div class="table-wrap namespace-table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{t("access.namespaceHandle")}</th>
                    <th>{t("access.owner")}</th>
                    <th>{t("access.created")}</th>
                    <th>{t("common.actions")}</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={filteredNamespaces()}>
                    {(namespace) => (
                      <tr>
                        <td>
                          <div class="namespace-cell">
                            <span class="repo-icon" aria-hidden="true">
                              {repoInitials(namespace.handle)}
                            </span>
                            <div>
                              <code>{namespace.handle}</code>
                              <span>
                                {t("repos.namespacePushHint", { handle: namespace.handle })}
                              </span>
                            </div>
                          </div>
                        </td>
                        <td>
                          <div class="access-owner-cell">
                            <strong>{namespace.owner_label}</strong>
                            <span>{t(`access.ownerKind.${namespace.owner_kind}`)}</span>
                          </div>
                        </td>
                        <td class="muted">
                          <span class="mono">{formatAgo(namespace.created_at)}</span>
                        </td>
                        <td>
                          <div class="row-actions">
                            <button
                              class="action copy"
                              type="button"
                              onClick={() => copyNamespace(namespace.handle)}
                            >
                              {copied() === `namespace-${namespace.handle}`
                                ? t("common.copied")
                                : t("common.copy")}
                            </button>
                          </div>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          )}
        </Show>
      </section>

      <footer class="footer">
        <span>
          <strong>{t("common.updated")}:</strong>{" "}
          {lastUpdated() ? formatAgo(lastUpdated()! / 1000) : "—"}
        </span>
        <span>{t("app.productName")}</span>
      </footer>

      <Show when={pendingDelete()}>
        {(repo) => (
          <div class="modal-backdrop" onClick={() => setPendingDelete(null)}>
            <div class="modal glass" onClick={(e) => e.stopPropagation()}>
              <div class="modal-head">
                <div>
                  <p class="section-label">{t("repos.deleteEyebrow")}</p>
                  <h2 class="modal-title">{t("repos.deleteTitle", { name: repo().name })}</h2>
                </div>
                <button
                  class="close"
                  type="button"
                  aria-label={t("common.cancel")}
                  onClick={() => setPendingDelete(null)}
                />
              </div>
              <div class="modal-body">
                <p class="warning">{t("repos.deleteWarning")}</p>
                <div class="delete-facts">
                  <div class="delete-fact">
                    <span>{t("repos.manifests")}</span>
                    <strong>{repo().manifest_count}</strong>
                  </div>
                  <div class="delete-fact">
                    <span>{t("common.tags")}</span>
                    <strong>{repo().tag_count}</strong>
                  </div>
                  <div class="delete-fact">
                    <span>{t("repos.storedSize")}</span>
                    <strong>{formatBytes(repo().stored_size_bytes)}</strong>
                  </div>
                </div>
                <div class="modal-actions">
                  <button
                    class="action"
                    disabled={deleting()}
                    onClick={() => setPendingDelete(null)}
                  >
                    {t("common.cancel")}
                  </button>
                  <button
                    class="action confirm-delete"
                    disabled={deleting()}
                    onClick={confirmDelete}
                  >
                    {deleting() ? t("common.deleting") : t("common.confirmDelete")}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </Show>

      <Show when={showTokens()}>
        <Access onClose={() => setShowTokens(false)} />
      </Show>
    </div>
  );
}
