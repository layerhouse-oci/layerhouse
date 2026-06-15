import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import { fetchSyncJobs, fetchSyncJobRuns, triggerSyncJob } from "../lib/api";
import type { SyncJob, SyncJobRun } from "../lib/types";
import LoadingSpinner from "../components/LoadingSpinner";
import EmptyState from "../components/EmptyState";
import ErrorBanner from "../components/ErrorBanner";

export default function MirrorJobs() {
  const [jobs, setJobs] = createSignal<SyncJob[]>([]);
  const [runs, setRuns] = createSignal<Record<string, SyncJobRun[]>>({});
  const [expanded, setExpanded] = createSignal<Set<string>>(new Set());
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [errorCount, setErrorCount] = createSignal(0);

  async function load() {
    try {
      const j = await fetchSyncJobs();
      setJobs(j);
      setError(null);
      setErrorCount(0);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch jobs");
      setErrorCount((c) => c + 1);
    } finally {
      setLoading(false);
    }
  }

  createEffect(() => {
    load();
    const id = setInterval(load, 10_000);
    onCleanup(() => clearInterval(id));
  });

  async function loadRuns(jobId: string) {
    try {
      const r = await fetchSyncJobRuns(jobId, 20);
      setRuns((prev) => ({ ...prev, [jobId]: r }));
    } catch {
      // non-fatal
    }
  }

  function toggleExpand(jobId: string) {
    const s = new Set(expanded());
    if (s.has(jobId)) {
      s.delete(jobId);
    } else {
      s.add(jobId);
      loadRuns(jobId);
    }
    setExpanded(s);
  }

  async function handleTrigger(jobId: string) {
    try {
      await triggerSyncJob(jobId);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to trigger job");
    }
  }

  function formatTime(ts: number | null): string {
    if (!ts) return "-";
    return new Date(ts * 1000).toLocaleString();
  }

  function statusBadge(status: string) {
    const cls =
      status === "Running"
        ? "badge-warning"
        : status === "Succeeded"
          ? "badge-success"
          : status === "Failed" || status === "PartialFailure"
            ? "badge-error"
            : "";
    return <span class={`badge ${cls}`}>{status}</span>;
  }

  if (errorCount() >= 3) {
    return <ErrorBanner message={error() ?? "Unknown error"} onRetry={load} fullPage />;
  }

  return (
    <div>
      <div class="page-header">
        <h1>Mirror Jobs</h1>
      </div>

      {error() && <ErrorBanner message={error()!} onRetry={load} />}

      {loading() ? (
        <LoadingSpinner label="Loading mirror jobs..." />
      ) : jobs().length === 0 ? (
        <EmptyState
          title="No mirror jobs"
          description="Mirror jobs are created automatically from warm images."
        />
      ) : (
        <div class="card">
          <table>
            <thead>
              <tr>
                <th>Job ID</th>
                <th>Image</th>
                <th>Status</th>
                <th>Last Run</th>
                <th>Next Run</th>
                <th>Last Error</th>
                <th />
              </tr>
            </thead>
            <tbody>
              <For each={jobs()}>
                {(job) => (
                  <>
                    <tr>
                      <td>
                        <code>{job.id}</code>
                      </td>
                      <td>{job.image}</td>
                      <td>{statusBadge(job.status)}</td>
                      <td>{formatTime(job.last_run_at)}</td>
                      <td>{formatTime(job.next_run_at)}</td>
                      <td
                        style={{
                          color: "var(--color-error)",
                          "max-width": "200px",
                          overflow: "hidden",
                          "text-overflow": "ellipsis",
                          "white-space": "nowrap",
                        }}
                      >
                        {job.last_error ?? "-"}
                      </td>
                      <td>
                        <button
                          class="btn"
                          disabled={job.status === "Running"}
                          onClick={() => handleTrigger(job.id)}
                        >
                          Trigger
                        </button>{" "}
                        <button class="btn" onClick={() => toggleExpand(job.id)}>
                          {expanded().has(job.id) ? "Hide Runs" : "Runs"}
                        </button>
                      </td>
                    </tr>
                    <Show when={expanded().has(job.id)}>
                      <tr>
                        <td colspan="7" style="padding:0">
                          <div style="padding:0.75rem;background:var(--color-bg)">
                            <table>
                              <thead>
                                <tr>
                                  <th>Run ID</th>
                                  <th>Node</th>
                                  <th>Started</th>
                                  <th>Finished</th>
                                  <th>Status</th>
                                  <th>Synced</th>
                                  <th>Failed</th>
                                </tr>
                              </thead>
                              <tbody>
                                <For each={runs()[job.id] ?? []}>
                                  {(run) => (
                                    <tr>
                                      <td>
                                        <code style="font-size:0.75rem">{run.id.slice(0, 12)}</code>
                                      </td>
                                      <td>{run.node_id}</td>
                                      <td>{formatTime(run.started_at)}</td>
                                      <td>{formatTime(run.finished_at)}</td>
                                      <td>{statusBadge(run.status)}</td>
                                      <td>{run.tags_synced.length}</td>
                                      <td>{run.tags_failed.length}</td>
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
