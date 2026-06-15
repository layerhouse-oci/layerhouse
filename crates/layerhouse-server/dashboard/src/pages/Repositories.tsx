import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { deleteRepository, fetchRepositories } from "../lib/api";
import type { RepositoryFilter, RepositorySummary } from "../lib/types";
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

export default function Repositories() {
  const navigate = useNavigate();
  const [repos, setRepos] = createSignal<RepositorySummary[]>([]);
  const [total, setTotal] = createSignal(0);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [errorCount, setErrorCount] = createSignal(0);
  const [lastUpdated, setLastUpdated] = createSignal<number | null>(null);
  const [search, setSearch] = createSignal("");
  const [filter, setFilter] = createSignal<RepositoryFilter>("all");
  const [sort, setSort] = createSignal("updated_desc");
  const [copied, setCopied] = createSignal<string | null>(null);
  const [toast, setToast] = createSignal<string | null>(null);
  const [pendingDelete, setPendingDelete] = createSignal<RepositorySummary | null>(null);
  const [deleting, setDeleting] = createSignal(false);
  const [showTokens, setShowTokens] = createSignal(false);

  async function load() {
    try {
      const response = await fetchRepositories({
        page_size: 50,
        q: search(),
        filter: filter(),
        sort: sort(),
      });
      setRepos(response.repositories);
      setTotal(response.total_reachable);
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

  createEffect(() => {
    search();
    filter();
    sort();
    setLoading(true);
    load();
    const id = setInterval(load, 10_000);
    onCleanup(() => clearInterval(id));
  });

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

  const FILTERS: { value: RepositoryFilter; label: string }[] = [
    { value: "all", label: t("repos.filter.all") },
    { value: "mine", label: t("repos.filter.mine") },
    { value: "shared", label: t("repos.filter.shared") },
    { value: "public", label: t("repos.filter.public") },
  ];

  if (errorCount() >= 3) {
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
          </div>
          <div class="list-controls">
            <div class="search" role="search">
              <input
                type="search"
                aria-label={t("repos.search")}
                placeholder={t("repos.search")}
                value={search()}
                onInput={(e) => setSearch(e.currentTarget.value)}
              />
            </div>
            <div class="filter-group">
              <For each={FILTERS}>
                {(item) => (
                  <button
                    type="button"
                    class={`filter${filter() === item.value ? " active" : ""}`}
                    onClick={() => setFilter(item.value)}
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
                onChange={(e) => setSort(e.currentTarget.value)}
              >
                <option value="updated_desc">{t("repos.sort.recent")}</option>
                <option value="updated_asc">{t("repos.sort.oldest")}</option>
                <option value="name_asc">{t("repos.sort.name")}</option>
                <option value="tag_count_desc">{t("repos.sort.tags")}</option>
              </select>
            </div>
            <button class="action" type="button" onClick={() => setShowTokens(true)}>
              {t("repos.manageTokens")}
            </button>
          </div>
        </div>

        {loading() ? (
          <LoadingSpinner label={t("repos.loading")} />
        ) : repos().length === 0 ? (
          <EmptyState
            title={search() ? t("repos.empty.filtered") : t("repos.empty")}
            description={search() ? t("repos.empty.filteredDesc") : t("repos.emptyDesc")}
          />
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
              <Pagination shown={repos().length} total={total()} />
            </div>
          </div>
        )}
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
