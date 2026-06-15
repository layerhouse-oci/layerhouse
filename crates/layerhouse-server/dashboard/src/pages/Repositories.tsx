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

type ActionBadge = "badge-blue" | "badge-teal" | "badge-amber" | "badge-purple" | "badge-gray";

const ACCESS_BADGE: Record<string, ActionBadge> = {
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

  if (errorCount() >= 3) {
    return <ErrorBanner message={error() ?? t("common.unknown")} onRetry={load} fullPage />;
  }

  return (
    <div>
      <div class="page-header">
        <div>
          <p class="eyebrow">{t("repos.eyebrow")}</p>
          <h1>{t("repos.title")}</h1>
        </div>
        <span class="freshness">
          {lastUpdated() ? `${t("common.updated")} ${formatAgo(lastUpdated()! / 1000)}` : ""}
        </span>
      </div>

      {error() && <ErrorBanner message={error()!} onRetry={load} />}
      <Show when={toast()}>{(message) => <div class="toast">{message()}</div>}</Show>

      <div class="card">
        <div class="toolbar">
          <input
            type="search"
            placeholder={t("repos.search")}
            value={search()}
            onInput={(e) => setSearch(e.currentTarget.value)}
          />
          <div class="segmented">
            <button class={filter() === "all" ? "active" : ""} onClick={() => setFilter("all")}>
              {t("repos.filter.all")}
            </button>
            <button class={filter() === "mine" ? "active" : ""} onClick={() => setFilter("mine")}>
              {t("repos.filter.mine")}
            </button>
            <button
              class={filter() === "shared" ? "active" : ""}
              onClick={() => setFilter("shared")}
            >
              {t("repos.filter.shared")}
            </button>
            <button
              class={filter() === "public" ? "active" : ""}
              onClick={() => setFilter("public")}
            >
              {t("repos.filter.public")}
            </button>
          </div>
          <select value={sort()} onChange={(e) => setSort(e.currentTarget.value)}>
            <option value="updated_desc">{t("repos.sort.recent")}</option>
            <option value="updated_asc">{t("repos.sort.oldest")}</option>
            <option value="name_asc">{t("repos.sort.name")}</option>
            <option value="tag_count_desc">{t("repos.sort.tags")}</option>
          </select>
          <button class="btn" onClick={() => setShowTokens(true)}>
            {t("repos.manageTokens")}
          </button>
        </div>

        {loading() ? (
          <LoadingSpinner label={t("repos.loading")} />
        ) : repos().length === 0 ? (
          <EmptyState
            title={search() ? t("repos.empty.filtered") : t("repos.empty")}
            description={search() ? t("repos.empty.filteredDesc") : t("repos.emptyDesc")}
          />
        ) : (
          <>
            <table>
              <thead>
                <tr>
                  <th>{t("common.repository")}</th>
                  <th>{t("common.tags")}</th>
                  <th>{t("common.digests")}</th>
                  <th>{t("common.size")}</th>
                  <th>{t("common.updated")}</th>
                  <th>{t("repos.colAccess")}</th>
                  <th>{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={repos()}>
                  {(repo) => (
                    <tr>
                      <td>
                        <button
                          class="link-button repo-name"
                          onClick={() => navigate(`/repos/${repo.name}`)}
                        >
                          {repo.name}
                        </button>
                      </td>
                      <td>{repo.tag_count}</td>
                      <td>{repo.manifest_count}</td>
                      <td>{formatBytes(repo.stored_size_bytes)}</td>
                      <td>{formatAgo(repo.last_modified)}</td>
                      <td>
                        <div class="repo-access-badges">
                          <span class={`badge ${ACCESS_BADGE[repo.access_level] ?? "badge-gray"}`}>
                            {t(`access.action.${repo.access_level}`)}
                          </span>
                          <Show when={repo.max_grantable !== repo.access_level}>
                            <span class="badge badge-gray">
                              {t("repos.maxGrantable", {
                                action: t(`access.action.${repo.max_grantable}`),
                              })}
                            </span>
                          </Show>
                          <span class={`badge ${GRANT_BADGE[repo.grant_source] ?? "badge-gray"}`}>
                            {t(`access.grantSource.${repo.grant_source}`)}
                          </span>
                        </div>
                      </td>
                      <td>
                        <div class="row-actions">
                          <button class="btn btn-compact" onClick={() => copyRepo(repo.name)}>
                            {copied() === repo.name ? t("common.copied") : t("common.copy")}
                          </button>
                          <button
                            class="btn btn-compact"
                            onClick={() => navigate(`/repos/${repo.name}`)}
                          >
                            {t("common.details")}
                          </button>
                          <Show when={repo.access_level === "delete"}>
                            <button
                              class="btn btn-compact btn-danger"
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
            <Pagination shown={repos().length} total={total()} />
          </>
        )}
      </div>

      <Show when={pendingDelete()}>
        {(repo) => (
          <div class="modal-overlay" onClick={() => setPendingDelete(null)}>
            <div class="modal" onClick={(e) => e.stopPropagation()}>
              <h2>{t("repos.deleteTitle", { name: repo().name })}</h2>
              <p class="warning">{t("repos.deleteWarning")}</p>
              <div class="fact-grid">
                <div>
                  <span>{t("repos.manifests")}</span>
                  <strong>{repo().manifest_count}</strong>
                </div>
                <div>
                  <span>{t("common.tags")}</span>
                  <strong>{repo().tag_count}</strong>
                </div>
                <div>
                  <span>{t("repos.storedSize")}</span>
                  <strong>{formatBytes(repo().stored_size_bytes)}</strong>
                </div>
              </div>
              <div class="modal-actions">
                <button class="btn" disabled={deleting()} onClick={() => setPendingDelete(null)}>
                  {t("common.cancel")}
                </button>
                <button class="btn btn-danger" disabled={deleting()} onClick={confirmDelete}>
                  {deleting() ? t("common.deleting") : t("common.confirmDelete")}
                </button>
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
