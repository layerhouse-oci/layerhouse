import { createEffect, createMemo, createSignal, For, onCleanup, Show } from "solid-js";
import {
  ApiError,
  createMirrorRule,
  deleteMirrorRule,
  fetchMirrorRules,
  fetchSession,
  fetchSyncJobs,
  fetchSyncJobRuns,
  redirectToSignIn,
  triggerMirrorRule,
} from "../lib/api";
import type {
  DashboardSession,
  MirrorDirection,
  MirrorRule,
  MirrorRuleCreate,
  MirrorStrategy,
  OutboundProxyProtocol,
  SyncJob,
  SyncJobRun,
} from "../lib/types";
import {
  formatAgo,
  formatTime,
  normalizeOptionalPrefix,
  normalizeRegistry,
  upstreamLabel,
} from "../lib/format";
import { t } from "../lib/i18n";
import LoadingSpinner from "../components/LoadingSpinner";
import EmptyState from "../components/EmptyState";
import ErrorBanner from "../components/ErrorBanner";

type RuleType = "scheduled" | "manual";

interface RuleForm {
  id: string;
  type: RuleType;
  direction: MirrorDirection;
  local_prefix: string;
  upstream_registry: string;
  upstream_prefix: string;
  schedule: string;
  strategy_type: "all" | "latest" | "pattern";
  latest_count: number;
  pattern: string;
  plain_http: boolean;
  insecure_tls: boolean;
  username: string;
  password: string;
  proxy_protocol: OutboundProxyProtocol;
  proxy_url: string;
  proxy_username: string;
  proxy_password: string;
}

const EMPTY_FORM: RuleForm = {
  id: "",
  type: "scheduled",
  direction: "pull",
  local_prefix: "",
  upstream_registry: "",
  upstream_prefix: "",
  schedule: "*/30 * * * *",
  strategy_type: "all",
  latest_count: 5,
  pattern: "v2.*",
  plain_http: false,
  insecure_tls: false,
  username: "",
  password: "",
  proxy_protocol: "none",
  proxy_url: "",
  proxy_username: "",
  proxy_password: "",
};

function toStrategy(form: RuleForm): MirrorStrategy {
  if (form.strategy_type === "latest") return { type: "latest", count: form.latest_count };
  if (form.strategy_type === "pattern") return { type: "pattern", pattern: form.pattern };
  return { type: "all" };
}

function toPayload(form: RuleForm): MirrorRuleCreate {
  return {
    id: form.id,
    direction: form.direction,
    local_prefix: form.local_prefix,
    upstream_registry: normalizeRegistry(form.upstream_registry),
    upstream_prefix: normalizeOptionalPrefix(form.upstream_prefix),
    schedule: form.type === "scheduled" ? form.schedule : null,
    strategy: toStrategy(form),
    plain_http: form.plain_http,
    insecure_tls: form.insecure_tls,
    username: form.username || null,
    password: form.password || null,
    outbound_proxy: {
      protocol: form.proxy_protocol,
      url: form.proxy_protocol === "none" ? null : form.proxy_url,
      username: form.proxy_username || null,
      password: form.proxy_password || null,
    },
  };
}

function strategyPill(strategy: MirrorStrategy) {
  if (strategy.type === "all") return "All tags";
  if (strategy.type === "latest") return `Latest ${strategy.count}`;
  if (strategy.type === "pattern") return strategy.pattern;
  return "—";
}

function proxyBadge(rule: MirrorRule) {
  const proto = rule.outbound_proxy.protocol;
  if (proto === "none")
    return { cls: "network-badge", label: t("common.direct"), title: undefined };
  const protocolLabel =
    proto === "http"
      ? t("proxy.protocol.http")
      : proto === "https"
        ? t("proxy.protocol.https")
        : proto === "socks4"
          ? t("proxy.protocol.socks4")
          : t("proxy.protocol.socks5");
  return {
    cls: "network-badge proxy",
    label: t("mirror.proxyBadge", { protocol: protocolLabel }),
    title: rule.outbound_proxy.url ?? undefined,
  };
}

function jobStatusBadge(job: SyncJob, prefix: (id: string) => SyncJobRun | null | undefined) {
  const run = prefix(job.id);
  if (run) {
    if (run.status === "Succeeded") return { cls: "badge", label: t("mirror.status.succeeded") };
    if (run.status === "Running")
      return { cls: "badge running", label: t("mirror.status.running") };
    if (run.status === "Failed") return { cls: "badge failed", label: t("mirror.status.failed") };
    if (run.status === "PartialFailure")
      return { cls: "badge warn", label: t("mirror.status.partialFailure") };
  }
  if (job.status === "Running") return { cls: "badge running", label: t("mirror.status.running") };
  return { cls: "badge idle", label: t("mirror.status.idle") };
}

const RUN_REFRESH_SECONDS = 30;

function isTerminalRun(run: SyncJobRun | null | undefined) {
  return !!run && run.status !== "Running";
}

function progressPercent(run: SyncJobRun | null | undefined) {
  if (!run) return 0;
  const totalTags = run.total_tags ?? 0;
  const completedTags = run.completed_tags ?? 0;
  if (totalTags <= 0) return run.status === "Running" ? 0 : 100;
  return Math.round((completedTags / totalTags) * 100);
}

function progressSummary(run: SyncJobRun | null | undefined) {
  if (!run) return t("common.notAvailable");
  const totalTags = run.total_tags ?? 0;
  const completedTags = run.completed_tags ?? 0;
  if (totalTags <= 0) {
    return run.status === "Running" ? (run.phase ?? run.status) : run.status;
  }
  return `${completedTags} / ${totalTags} tags`;
}

function formatDuration(startedAt: number | null | undefined, finishedAt?: number | null) {
  if (!startedAt) return t("time.never");
  const end = finishedAt ?? Math.floor(Date.now() / 1000);
  const seconds = Math.max(0, end - startedAt);
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
}

function eventClass(kind: SyncJobRun["recent_events"][number]["kind"]) {
  if (kind === "Success") return "run-event-success";
  if (kind === "Warning") return "run-event-warning";
  if (kind === "Error") return "run-event-error";
  return "run-event-info";
}

export default function Mirror() {
  const [tab, setTab] = createSignal<"rules" | "jobs">("rules");
  const [rules, setRules] = createSignal<MirrorRule[]>([]);
  const [jobs, setJobs] = createSignal<SyncJob[]>([]);
  const [selectedJobId, setSelectedJobId] = createSignal<string | null>(null);
  const [latestRuns, setLatestRuns] = createSignal<Record<string, SyncJobRun | null>>({});
  const [runLoading, setRunLoading] = createSignal(false);
  const [runError, setRunError] = createSignal<string | null>(null);
  const [refreshCountdown, setRefreshCountdown] = createSignal(RUN_REFRESH_SECONDS);
  const [session, setSession] = createSignal<DashboardSession | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [errorCount, setErrorCount] = createSignal(0);
  const [showForm, setShowForm] = createSignal(false);
  const [form, setForm] = createSignal<RuleForm>({ ...EMPTY_FORM });
  const [saving, setSaving] = createSignal(false);
  const [triggering, setTriggering] = createSignal<string | null>(null);
  const [deleteId, setDeleteId] = createSignal<string | null>(null);
  const selectedJob = createMemo(() => {
    const id = selectedJobId();
    return id ? (jobs().find((job) => job.id === id) ?? null) : null;
  });
  const selectedRun = createMemo(() => {
    const id = selectedJobId();
    return id ? (latestRuns()[id] ?? null) : null;
  });
  const selectedEvents = createMemo(() => (selectedRun()?.recent_events ?? []).slice().reverse());

  function nextSelectedJobId(nextJobs: SyncJob[]) {
    const current = selectedJobId();
    if (current && nextJobs.some((job) => job.id === current)) return current;
    return nextJobs.find((job) => job.status === "Running")?.id ?? nextJobs[0]?.id ?? null;
  }

  function selectDefaultJob(nextJobs: SyncJob[]) {
    const nextId = nextSelectedJobId(nextJobs);
    setSelectedJobId(nextId);
    return nextId;
  }

  async function fetchLatestRunEntry(jobId: string) {
    const runs = await fetchSyncJobRuns(jobId, 1);
    return [jobId, runs[0] ?? null] as const;
  }

  async function primeLatestRuns(nextJobs: SyncJob[], selectedId: string | null) {
    const jobIds = new Set(nextJobs.filter((job) => job.status === "Running").map((job) => job.id));
    if (selectedId) jobIds.add(selectedId);

    for (const jobId of jobIds) {
      try {
        const [id, run] = await fetchLatestRunEntry(jobId);
        setLatestRuns((current) => ({ ...current, [id]: run }));
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) {
          redirectToSignIn();
          return;
        }
      }
    }
  }

  function pruneLatestRuns(nextJobs: SyncJob[]) {
    const jobIds = new Set(nextJobs.map((job) => job.id));
    setLatestRuns((current) =>
      Object.fromEntries(Object.entries(current).filter(([jobId]) => jobIds.has(jobId))),
    );
  }

  async function load() {
    try {
      const [s, nextRules, nextJobs] = await Promise.all([
        fetchSession(),
        fetchMirrorRules(),
        fetchSyncJobs(),
      ]);
      setSession(s);
      setRules(nextRules);
      setJobs(nextJobs);
      pruneLatestRuns(nextJobs);
      const selectedId = selectDefaultJob(nextJobs);
      void primeLatestRuns(nextJobs, selectedId);
      setError(null);
      setErrorCount(0);
      setRunError(null);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        redirectToSignIn();
        return;
      }
      if (e instanceof ApiError && e.status === 403) {
        setError(t("cluster.adminRequired"));
        setErrorCount(0);
        setRules([]);
        setJobs([]);
      } else {
        setError(e instanceof Error ? e.message : t("mirror.fetchError"));
        setErrorCount((c) => c + 1);
      }
    } finally {
      setLoading(false);
    }
  }

  async function refreshJobList() {
    const nextJobs = await fetchSyncJobs();
    setJobs(nextJobs);
    pruneLatestRuns(nextJobs);
    const selectedId = selectDefaultJob(nextJobs);
    void primeLatestRuns(nextJobs, selectedId);
  }

  async function refreshSelectedRun(jobId = selectedJobId()) {
    if (!jobId) return;
    setRunLoading(true);
    try {
      const runs = await fetchSyncJobRuns(jobId, 1);
      const run = runs[0] ?? null;
      setLatestRuns((current) => ({ ...current, [jobId]: run }));
      setRunError(null);
      setRefreshCountdown(RUN_REFRESH_SECONDS);
      if (isTerminalRun(run)) {
        await refreshJobList();
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        redirectToSignIn();
        return;
      }
      const message = e instanceof Error ? e.message : t("mirror.fetchError");
      setRunError(message);
      setRefreshCountdown(RUN_REFRESH_SECONDS);
    } finally {
      setRunLoading(false);
    }
  }

  createEffect(() => {
    load();
  });

  let lastSelectedJobId: string | null = null;
  createEffect(() => {
    const jobId = selectedJobId();
    if (tab() !== "jobs" || !jobId || jobId === lastSelectedJobId) return;
    lastSelectedJobId = jobId;
    void refreshSelectedRun(jobId);
  });

  createEffect(() => {
    const jobId = selectedJobId();
    if (tab() !== "jobs" || !jobId) return;
    setRefreshCountdown(RUN_REFRESH_SECONDS);
    const id = window.setInterval(() => {
      if (runLoading()) return;
      setRefreshCountdown((seconds) => {
        const next = Math.max(0, seconds - 1);
        if (next === 0) void refreshSelectedRun(jobId);
        return next;
      });
    }, 1000);
    onCleanup(() => clearInterval(id));
  });

  async function saveRule() {
    setSaving(true);
    try {
      await createMirrorRule(toPayload(form()));
      setShowForm(false);
      setForm({ ...EMPTY_FORM });
      await load();
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        setError(t("cluster.adminRequired"));
      } else {
        setError(e instanceof Error ? e.message : t("mirror.saveError"));
      }
    } finally {
      setSaving(false);
    }
  }

  async function runRule(id: string) {
    setTriggering(id);
    try {
      await triggerMirrorRule(id);
      await load();
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        setError(t("cluster.adminRequired"));
      } else {
        setError(e instanceof Error ? e.message : t("mirror.triggerError"));
      }
    } finally {
      setTriggering(null);
    }
  }

  async function confirmDelete(id: string) {
    try {
      await deleteMirrorRule(id);
      setDeleteId(null);
      await load();
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        setError(t("cluster.adminRequired"));
      } else {
        setError(e instanceof Error ? e.message : t("mirror.deleteError"));
      }
    }
  }

  function directionLabel(rule: MirrorRule) {
    return rule.direction === "pull" ? t("mirror.direction.pull") : t("mirror.direction.push");
  }

  function directionBadgeCls(rule: MirrorRule) {
    return rule.direction === "pull" ? "badge pull" : "badge push";
  }

  if (errorCount() >= 3) {
    return <ErrorBanner message={error() ?? t("common.unknown")} onRetry={load} fullPage />;
  }

  return (
    <div class="mirror-page">
      <section class="hero glass" aria-labelledby="mirror-title">
        <div>
          <p class="eyebrow">
            <span class="status-dot" aria-hidden="true" />
            {t("mirror.eyebrow")}
          </p>
          <h1 id="mirror-title">{t("mirror.title")}</h1>
          <p class="hero-copy">{t("mirror.heroCopy")}</p>
          <div class="hero-note">{t("mirror.heroNote")}</div>
        </div>
      </section>

      <Show when={error()}>
        <ErrorBanner message={error()!} onRetry={load} />
      </Show>

      <section class="mirror-tabs" aria-label="Mirror subsections">
        <div class="tab-strip glass" role="tablist" aria-label="Mirror sections">
          <button
            class="tab-option"
            classList={{ active: tab() === "rules" }}
            role="tab"
            aria-selected={tab() === "rules"}
            aria-controls="mirror-panel-rules"
            onClick={() => setTab("rules")}
          >
            {t("mirror.rules")}
          </button>
          <button
            class="tab-option"
            classList={{ active: tab() === "jobs" }}
            role="tab"
            aria-selected={tab() === "jobs"}
            aria-controls="mirror-panel-jobs"
            onClick={() => setTab("jobs")}
          >
            {t("mirror.jobs")}
          </button>
        </div>

        <div class="tab-panels">
          {/* ---- Rules panel ---- */}
          <section
            class="tab-panel panel glass"
            classList={{ "panel-rules": true, "tab-panel-active": tab() === "rules" }}
            id="mirror-panel-rules"
            role="tabpanel"
            aria-labelledby="mirror-tab-rules-label"
          >
            <div class="panel-head">
              <div>
                <p class="section-label">{t("mirror.ruleCatalog")}</p>
                <h2 class="panel-title">{t("mirror.mirrorRules")}</h2>
              </div>
              <Show when={session()?.is_admin}>
                <button class="button" onClick={() => setShowForm(true)}>
                  {t("mirror.create")}
                </button>
              </Show>
            </div>

            <Show
              when={!loading()}
              fallback={
                <div style={{ padding: "48px 0" }}>
                  <LoadingSpinner label={t("mirror.loading")} />
                </div>
              }
            >
              <Show
                when={rules().length > 0}
                fallback={
                  <div style={{ padding: "48px 0" }}>
                    <EmptyState title={t("mirror.noRules")} description={t("mirror.noRulesDesc")} />
                  </div>
                }
              >
                <div class="table-wrap">
                  <table aria-label="Mirror rules">
                    <thead>
                      <tr>
                        <th scope="col">{t("common.id")}</th>
                        <th scope="col">{t("mirror.direction")}</th>
                        <th scope="col">{t("mirror.localPrefix")}</th>
                        <th scope="col">{t("common.upstream")}</th>
                        <th scope="col">{t("mirror.strategy")}</th>
                        <th scope="col">{t("common.proxy")}</th>
                        <th scope="col">{t("common.schedule")}</th>
                        <th scope="col">{t("common.actions")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={rules()}>
                        {(rule) => {
                          const pb = () => proxyBadge(rule);
                          return (
                            <tr>
                              <td class="rule-id">{rule.id}</td>
                              <td>
                                <span class={directionBadgeCls(rule)}>{directionLabel(rule)}</span>
                              </td>
                              <td class="path">{rule.local_prefix}</td>
                              <td class="path">
                                {upstreamLabel(rule.upstream_registry, rule.upstream_prefix)}
                              </td>
                              <td>
                                <span class="strategy">{strategyPill(rule.strategy)}</span>
                              </td>
                              <td>
                                <span class={pb().cls} title={pb().title}>
                                  {pb().label}
                                </span>
                              </td>
                              <td class="mono">{rule.schedule ?? t("common.manual")}</td>
                              <td>
                                <Show when={session()?.is_admin}>
                                  <div class="actions">
                                    <button
                                      class={`action ${rule.schedule ? "secondary" : "primary"}`}
                                      disabled={triggering() === rule.id}
                                      onClick={() => runRule(rule.id)}
                                    >
                                      {triggering() === rule.id
                                        ? t("mirror.triggering")
                                        : t("mirror.trigger")}
                                    </button>
                                    <span class="delete-flow" data-rule-id={rule.id}>
                                      <button
                                        class="action remove"
                                        onClick={() =>
                                          setDeleteId(deleteId() === rule.id ? null : rule.id)
                                        }
                                      >
                                        {t("mirror.remove")}
                                      </button>
                                      <Show when={deleteId() === rule.id}>
                                        <span class="confirm-actions">
                                          <span class="confirm-text">{t("mirror.removeHint")}</span>
                                          <button
                                            class="action confirm"
                                            onClick={() => confirmDelete(rule.id)}
                                          >
                                            {t("mirror.confirmRemove")}
                                          </button>
                                          <button
                                            class="action secondary"
                                            onClick={() => setDeleteId(null)}
                                          >
                                            {t("common.cancel")}
                                          </button>
                                        </span>
                                      </Show>
                                    </span>
                                  </div>
                                </Show>
                              </td>
                            </tr>
                          );
                        }}
                      </For>
                    </tbody>
                  </table>
                </div>
                <div class="table-footer" aria-label="Rules pagination">
                  <div class="page-count">
                    {t("repos.pagination", { shown: rules().length, total: rules().length })}
                  </div>
                  <div class="pager">
                    <label class="page-size">
                      {t("common.rows")}
                      <select aria-label={t("common.rows")}>
                        <option>25</option>
                        <option selected>50</option>
                        <option>100</option>
                      </select>
                    </label>
                    <button class="page-button" type="button" disabled>
                      {t("common.previous")}
                    </button>
                    <span class="page-number">1</span>
                    <button class="page-button" type="button" disabled>
                      {t("common.next")}
                    </button>
                  </div>
                </div>
              </Show>
            </Show>
          </section>

          {/* ---- Jobs panel ---- */}
          <section
            class="tab-panel panel glass"
            classList={{ "panel-jobs": true, "tab-panel-active": tab() === "jobs" }}
            id="mirror-panel-jobs"
            role="tabpanel"
            aria-labelledby="mirror-tab-jobs-label"
          >
            <div class="panel-head">
              <div>
                <p class="section-label">{t("mirror.runtimeHistory")}</p>
                <h2 class="panel-title">{t("mirror.mirrorJobs")}</h2>
              </div>
              <div class="badge idle">{t("mirror.readOnlyHistory")}</div>
            </div>

            <Show
              when={!loading()}
              fallback={
                <div style={{ padding: "48px 0" }}>
                  <LoadingSpinner label={t("mirror.loading")} />
                </div>
              }
            >
              <Show
                when={jobs().length > 0}
                fallback={
                  <div style={{ padding: "48px 0" }}>
                    <EmptyState title={t("mirror.noJobs")} description={t("mirror.noJobsDesc")} />
                  </div>
                }
              >
                <div class="table-wrap">
                  <table aria-label="Mirror jobs">
                    <thead>
                      <tr>
                        <th scope="col">{t("mirror.job")}</th>
                        <th scope="col">{t("mirror.rule")}</th>
                        <th scope="col">{t("mirror.image")}</th>
                        <th scope="col">{t("common.status")}</th>
                        <th scope="col">{t("mirror.lastRun")}</th>
                        <th scope="col">{t("mirror.nextRun")}</th>
                        <th scope="col">{t("mirror.lastError")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={jobs()}>
                        {(job) => {
                          const badge = () => jobStatusBadge(job, (id) => latestRuns()[id] ?? null);
                          return (
                            <tr
                              class="job-row"
                              classList={{ selected: selectedJobId() === job.id }}
                              tabIndex={0}
                              onClick={() => setSelectedJobId(job.id)}
                              onKeyDown={(event) => {
                                if (event.key === "Enter" || event.key === " ") {
                                  event.preventDefault();
                                  setSelectedJobId(job.id);
                                }
                              }}
                            >
                              <td class="job-id">{job.id}</td>
                              <td class="rule-id">{job.rule_name ?? job.rule_id ?? "-"}</td>
                              <td class="image">{job.image}</td>
                              <td>
                                <span class={badge().cls}>{badge().label}</span>
                              </td>
                              <td class="time">{formatTime(job.last_run_at)}</td>
                              <td class="time">
                                {job.status === "Running"
                                  ? "—"
                                  : job.schedule
                                    ? t("mirror.scheduled")
                                    : t("common.manual")}
                              </td>
                              <td class="error">
                                {job.last_error ??
                                  latestRuns()[job.id]?.tags_failed?.[0]?.[1] ??
                                  "—"}
                              </td>
                            </tr>
                          );
                        }}
                      </For>
                    </tbody>
                  </table>
                </div>
                <div class="table-footer" aria-label="Jobs pagination">
                  <div class="page-count">
                    {t("repos.pagination", { shown: jobs().length, total: jobs().length })}
                  </div>
                  <div class="pager">
                    <label class="page-size">
                      {t("common.rows")}
                      <select aria-label={t("common.rows")}>
                        <option>25</option>
                        <option selected>50</option>
                        <option>100</option>
                      </select>
                    </label>
                    <button class="page-button" type="button" disabled>
                      {t("common.previous")}
                    </button>
                    <span class="page-number">1</span>
                    <button class="page-button" type="button" disabled>
                      {t("common.next")}
                    </button>
                  </div>
                </div>
              </Show>
            </Show>
          </section>
        </div>
      </section>

      {/* ---- Run inspector (jobs tab, separate panel) ---- */}
      <Show when={tab() === "jobs"}>
        <Show
          when={selectedJob()}
          fallback={
            <section class="panel glass run-inspector-panel">
              <div style={{ padding: "24px", color: "var(--muted)", "font-size": "14px" }}>
                {t("mirror.noRunSelected")}
              </div>
            </section>
          }
        >
          {(job) => (
            <section class="panel glass run-inspector-panel">
              <div class="panel-head">
                <div>
                  <p class="section-label">{t("mirror.selectedRun")}</p>
                  <h2 class="panel-title">{job().id}</h2>
                  <p style={{ color: "var(--muted)", "font-size": "13px", margin: 0 }}>
                    {job().rule_name ?? job().rule_id ?? "-"}
                  </p>
                </div>
                <div class="run-refresh">
                  <button
                    class="action secondary"
                    aria-label={t("mirror.refreshRun")}
                    disabled={runLoading() || !selectedJobId()}
                    onClick={() => void refreshSelectedRun()}
                  >
                    {runLoading() ? "..." : "↻"}
                  </button>
                  <span class="run-countdown">
                    {t("mirror.refreshIn", { seconds: refreshCountdown() })}
                  </span>
                </div>
              </div>

              <Show when={runError()}>
                <p class="run-error">{runError()}</p>
              </Show>

              <Show
                when={selectedRun()}
                fallback={
                  <div style={{ padding: "24px", color: "var(--muted)", "font-size": "14px" }}>
                    {t("mirror.noRunSelected")}
                  </div>
                }
              >
                {(run) => (
                  <div class="run-inspector-body">
                    <div class="run-summary">
                      <div
                        class="run-ring"
                        style={{
                          "--run-progress": `${progressPercent(run()) * 3.6}deg`,
                        }}
                      >
                        <span>{progressPercent(run())}%</span>
                      </div>
                      <div>
                        <p class="label">{t("mirror.progress")}</p>
                        <h3>{progressSummary(run())}</h3>
                        <p>
                          {t("mirror.elapsed", {
                            duration: formatDuration(run().started_at, run().finished_at),
                          })}
                        </p>
                      </div>
                    </div>

                    <div class="run-current">
                      <p class="label">{t("mirror.current")}</p>
                      <h3>{run().phase ?? run().status}</h3>
                      <p>
                        {run().current_tag
                          ? t("mirror.currentTag", { tag: run().current_tag ?? "" })
                          : t("mirror.updated", {
                              time: formatAgo(
                                run().updated_at ?? run().finished_at ?? run().started_at,
                              ),
                            })}
                      </p>
                      <p>{t("mirror.failures", { count: (run().tags_failed ?? []).length })}</p>
                    </div>

                    <div class="run-events">
                      <div class="run-events-header">
                        <p class="label">{t("mirror.recentEvents")}</p>
                        <span>{selectedEvents().length}</span>
                      </div>
                      <Show
                        when={selectedEvents().length > 0}
                        fallback={<p class="run-empty">{t("mirror.noEvents")}</p>}
                      >
                        <For each={selectedEvents()}>
                          {(event) => (
                            <div class="run-event">
                              <span class={`run-event-kind ${eventClass(event.kind)}`}>
                                {event.kind}
                              </span>
                              <div>
                                <p>
                                  {event.tag ? `${event.tag} · ${event.message}` : event.message}
                                </p>
                                <span>{formatAgo(event.at)}</span>
                              </div>
                            </div>
                          )}
                        </For>
                      </Show>
                    </div>
                  </div>
                )}
              </Show>
            </section>
          )}
        </Show>
      </Show>

      <footer class="footer">
        <span>
          <strong>{t("common.updated")}:</strong> {refreshCountdown()}s ago
        </span>
        <span>Mirror rules trigger jobs through /api/v1/admin/mirror/rules/{`{id}`}/trigger</span>
      </footer>

      {/* ---- Create rule modal ---- */}
      <Show when={showForm()}>
        <div class="modal-backdrop visible" onClick={() => setShowForm(false)}>
          <div
            class="modal glass"
            role="dialog"
            aria-modal="true"
            aria-labelledby="create-rule-title"
            onClick={(e) => e.stopPropagation()}
          >
            <div class="modal-head">
              <div>
                <p class="section-label">{t("mirror.newRule")}</p>
                <h2 class="modal-title" id="create-rule-title">
                  {t("mirror.createTitle")}
                </h2>
              </div>
              <button
                class="close"
                aria-label={t("common.close")}
                onClick={() => setShowForm(false)}
              />
            </div>
            <div class="form">
              {/* Type */}
              <div class="field full">
                <span class="choice-label">{t("common.type")}</span>
                <div class="radio-row" role="radiogroup" aria-label={t("common.type")}>
                  <label
                    classList={{ active: form().type === "scheduled" }}
                    onClick={() => setForm({ ...form(), type: "scheduled" })}
                  >
                    <input type="radio" name="rule-type" checked={form().type === "scheduled"} />
                    {t("mirror.scheduled")}
                  </label>
                  <label
                    classList={{ active: form().type === "manual" }}
                    onClick={() => setForm({ ...form(), type: "manual" })}
                  >
                    <input type="radio" name="rule-type" checked={form().type === "manual"} />
                    {t("common.manual")}
                  </label>
                </div>
              </div>

              {/* Direction */}
              <div class="field full">
                <span class="choice-label">{t("mirror.direction")}</span>
                <div class="segmented" role="group" aria-label={t("mirror.direction")}>
                  <label
                    classList={{ active: form().direction === "pull" }}
                    onClick={() => setForm({ ...form(), direction: "pull" })}
                  >
                    {t("mirror.direction.pull")}
                  </label>
                  <label
                    classList={{ active: form().direction === "push" }}
                    onClick={() => setForm({ ...form(), direction: "push" })}
                  >
                    {t("mirror.direction.push")}
                  </label>
                </div>
              </div>

              {/* ID */}
              <div class="field">
                <label for="rule-id">{t("common.id")}</label>
                <input
                  id="rule-id"
                  value={form().id}
                  onInput={(e) => setForm({ ...form(), id: e.currentTarget.value })}
                />
              </div>

              {/* Local prefix */}
              <div class="field">
                <label for="local-prefix">{t("mirror.localPrefix")}</label>
                <input
                  id="local-prefix"
                  value={form().local_prefix}
                  onInput={(e) => setForm({ ...form(), local_prefix: e.currentTarget.value })}
                />
              </div>

              {/* Upstream registry */}
              <div class="field">
                <label for="upstream-registry">{t("mirror.upstreamRegistry")}</label>
                <input
                  id="upstream-registry"
                  value={form().upstream_registry}
                  onInput={(e) => setForm({ ...form(), upstream_registry: e.currentTarget.value })}
                />
              </div>

              {/* Upstream prefix */}
              <div class="field">
                <label for="upstream-prefix">{t("mirror.upstreamPrefix")}</label>
                <input
                  id="upstream-prefix"
                  value={form().upstream_prefix}
                  onInput={(e) => setForm({ ...form(), upstream_prefix: e.currentTarget.value })}
                />
              </div>

              {/* Schedule or manual hint */}
              <Show
                when={form().type === "scheduled"}
                fallback={
                  <div class="field full manual-hint">
                    <span class="choice-label">{t("common.schedule")}</span>
                    <div class="hint">{t("mirror.manualHint")}</div>
                  </div>
                }
              >
                <div class="field full schedule-field">
                  <label for="schedule">{t("mirror.crontab")}</label>
                  <input
                    id="schedule"
                    placeholder="*/30 * * * *"
                    value={form().schedule}
                    onInput={(e) => setForm({ ...form(), schedule: e.currentTarget.value })}
                  />
                </div>
              </Show>

              {/* Strategy */}
              <div class="field">
                <label for="strategy-type">{t("mirror.strategy")}</label>
                <select
                  id="strategy-type"
                  value={form().strategy_type}
                  onChange={(e) =>
                    setForm({
                      ...form(),
                      strategy_type: e.currentTarget.value as RuleForm["strategy_type"],
                    })
                  }
                >
                  <option value="all">{t("mirror.allTags")}</option>
                  <option value="latest">{t("mirror.latestN")}</option>
                  <option value="pattern">{t("mirror.tagPattern")}</option>
                </select>
              </div>

              {/* Count (latest) */}
              <Show when={form().strategy_type === "latest"}>
                <div class="field strategy-count">
                  <label for="strategy-count">{t("mirror.count")}</label>
                  <input
                    id="strategy-count"
                    type="number"
                    min="1"
                    value={form().latest_count}
                    onInput={(e) =>
                      setForm({ ...form(), latest_count: Number(e.currentTarget.value) || 1 })
                    }
                  />
                </div>
              </Show>

              {/* Pattern */}
              <Show when={form().strategy_type === "pattern"}>
                <div class="field strategy-pattern">
                  <label for="strategy-pattern">{t("mirror.glob")}</label>
                  <input
                    id="strategy-pattern"
                    placeholder="v2.*"
                    value={form().pattern}
                    onInput={(e) => setForm({ ...form(), pattern: e.currentTarget.value })}
                  />
                </div>
              </Show>

              {/* Credentials */}
              <div class="credential-grid">
                <div class="field">
                  <label for="username">{t("common.username")}</label>
                  <input
                    id="username"
                    autocomplete="off"
                    value={form().username}
                    onInput={(e) => setForm({ ...form(), username: e.currentTarget.value })}
                  />
                </div>
                <div class="field">
                  <label for="password-secret">{t("common.password")}</label>
                  <div class="password-row">
                    <input
                      id="password-secret"
                      type="password"
                      autocomplete="new-password"
                      value={form().password}
                      onInput={(e) => setForm({ ...form(), password: e.currentTarget.value })}
                    />
                  </div>
                </div>
              </div>

              {/* Advanced network */}
              <details class="advanced-section">
                <summary>{t("mirror.advancedNetwork")}</summary>
                <div class="advanced-grid">
                  <label class="checkbox field full">
                    <input
                      type="checkbox"
                      checked={form().plain_http}
                      onChange={(e) =>
                        setForm({
                          ...form(),
                          plain_http: e.currentTarget.checked,
                          insecure_tls: e.currentTarget.checked ? false : form().insecure_tls,
                        })
                      }
                    />
                    <span>{t("mirror.plainHttp")}</span>
                  </label>
                  <label class="checkbox field full">
                    <input
                      type="checkbox"
                      checked={form().insecure_tls}
                      onChange={(e) =>
                        setForm({
                          ...form(),
                          insecure_tls: e.currentTarget.checked,
                          plain_http: e.currentTarget.checked ? false : form().plain_http,
                        })
                      }
                    />
                    <span>{t("mirror.insecureTls")}</span>
                  </label>
                  <div class="field full">
                    <label for="outbound-proxy-protocol">{t("mirror.outboundProxy")}</label>
                    <select
                      id="outbound-proxy-protocol"
                      value={form().proxy_protocol}
                      onChange={(e) =>
                        setForm({
                          ...form(),
                          proxy_protocol: e.currentTarget.value as OutboundProxyProtocol,
                        })
                      }
                    >
                      <option value="none">{t("common.direct")}</option>
                      <option value="http">{t("proxy.protocol.http")}</option>
                      <option value="socks4">{t("proxy.protocol.socks4")}</option>
                      <option value="socks5">{t("proxy.protocol.socks5")}</option>
                    </select>
                  </div>
                  <Show when={form().proxy_protocol !== "none"}>
                    <div class="field outbound-proxy-field full">
                      <label for="outbound-proxy-url">{t("mirror.proxyUrl")}</label>
                      <input
                        id="outbound-proxy-url"
                        placeholder="proxy.internal:8080"
                        value={form().proxy_url}
                        onInput={(e) => setForm({ ...form(), proxy_url: e.currentTarget.value })}
                      />
                    </div>
                    <div class="credential-grid outbound-proxy-field">
                      <div class="field">
                        <label for="outbound-proxy-username">{t("mirror.proxyUsername")}</label>
                        <input
                          id="outbound-proxy-username"
                          value={form().proxy_username}
                          onInput={(e) =>
                            setForm({ ...form(), proxy_username: e.currentTarget.value })
                          }
                        />
                      </div>
                      <div class="field">
                        <label for="outbound-proxy-password-secret">
                          {t("mirror.proxyPassword")}
                        </label>
                        <input
                          id="outbound-proxy-password-secret"
                          type="password"
                          value={form().proxy_password}
                          onInput={(e) =>
                            setForm({ ...form(), proxy_password: e.currentTarget.value })
                          }
                        />
                      </div>
                    </div>
                  </Show>
                </div>
              </details>

              <div class="modal-actions">
                <button class="button secondary" onClick={() => setShowForm(false)}>
                  {t("common.cancel")}
                </button>
                <button class="button" disabled={saving()} onClick={saveRule}>
                  {saving() ? t("common.creating") : t("mirror.create")}
                </button>
              </div>
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
}
