import { createEffect, createSignal, For, Show } from "solid-js";
import { fetchHelmCharts, fetchHelmChartVersions } from "../lib/api";
import type { HelmChart, HelmChartVersion } from "../lib/types";
import LoadingSpinner from "../components/LoadingSpinner";
import EmptyState from "../components/EmptyState";
import ErrorBanner from "../components/ErrorBanner";

export default function HelmCharts() {
  const [charts, setCharts] = createSignal<HelmChart[]>([]);
  const [versions, setVersions] = createSignal<Record<string, HelmChartVersion[]>>({});
  const [expanded, setExpanded] = createSignal<Set<string>>(new Set());
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [errorCount, setErrorCount] = createSignal(0);
  const [search, setSearch] = createSignal("");

  async function load() {
    try {
      setCharts(await fetchHelmCharts());
      setError(null);
      setErrorCount(0);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch helm charts");
      setErrorCount((c) => c + 1);
    } finally {
      setLoading(false);
    }
  }

  createEffect(() => {
    load();
  });

  async function loadVersions(name: string) {
    try {
      const v = await fetchHelmChartVersions(name);
      setVersions((prev) => ({ ...prev, [name]: v }));
    } catch {
      // non-fatal
    }
  }

  function toggleExpand(name: string) {
    const s = new Set(expanded());
    if (s.has(name)) {
      s.delete(name);
    } else {
      s.add(name);
      loadVersions(name);
    }
    setExpanded(s);
  }

  const filtered = () => {
    const s = search().toLowerCase();
    if (!s) return charts();
    return charts().filter(
      (c) => c.name.toLowerCase().includes(s) || c.description.toLowerCase().includes(s),
    );
  };

  if (errorCount() >= 3) {
    return <ErrorBanner message={error() ?? "Unknown error"} onRetry={load} fullPage />;
  }

  return (
    <div>
      <div class="page-header">
        <h1>Helm Charts</h1>
      </div>

      {error() && <ErrorBanner message={error()!} onRetry={load} />}

      <div class="search-bar">
        <input
          type="text"
          placeholder="Search charts..."
          value={search()}
          onInput={(e) => setSearch(e.currentTarget.value)}
        />
      </div>

      {loading() ? (
        <LoadingSpinner label="Loading helm charts..." />
      ) : filtered().length === 0 ? (
        <EmptyState
          title={search() ? "No matching charts" : "No helm charts"}
          description={
            search()
              ? "Try a different search term."
              : "Configure an OCI-based Helm repository to see charts here."
          }
        />
      ) : (
        <div class="card">
          <table>
            <thead>
              <tr>
                <th>Chart</th>
                <th>Description</th>
                <th>Latest</th>
                <th />
              </tr>
            </thead>
            <tbody>
              <For each={filtered()}>
                {(chart) => (
                  <>
                    <tr>
                      <td>
                        <code>{chart.name}</code>
                      </td>
                      <td>{chart.description}</td>
                      <td>
                        <span class="badge badge-success">{chart.latest_version}</span>
                      </td>
                      <td>
                        <button class="btn" onClick={() => toggleExpand(chart.name)}>
                          {expanded().has(chart.name) ? "Hide" : "Versions"} (
                          {chart.versions.length})
                        </button>
                      </td>
                    </tr>
                    <Show when={expanded().has(chart.name)}>
                      <tr>
                        <td colspan="4" style="padding:0">
                          <div style="padding:0.75rem;background:var(--color-bg)">
                            <table>
                              <thead>
                                <tr>
                                  <th>Version</th>
                                  <th>App Version</th>
                                  <th>Description</th>
                                  <th>Created</th>
                                </tr>
                              </thead>
                              <tbody>
                                <For each={versions()[chart.name] ?? []}>
                                  {(v) => (
                                    <tr>
                                      <td>
                                        <code>{v.version}</code>
                                      </td>
                                      <td>{v.app_version ?? "-"}</td>
                                      <td>{v.description}</td>
                                      <td>{v.created}</td>
                                    </tr>
                                  )}
                                </For>
                              </tbody>
                            </table>
                          </div>
                        </td>
                      </tr>
                    </Show>
                  </>
                )}
              </For>
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
