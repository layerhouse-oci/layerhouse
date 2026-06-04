import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import {
  ApiError,
  createMirrorRule,
  deleteMirrorRule,
  fetchMirrorRules,
  fetchSession,
  fetchSyncJobs,
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
} from "../lib/types";
import { formatAgo, formatTime, strategyLabel } from "../lib/format";
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
    upstream_registry: form.upstream_registry,
    upstream_prefix: form.upstream_prefix || null,
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

function statusBadge(status: string) {
  const cls = status === "Running" ? "badge-warning" : "badge-success";
  return <span class={`badge ${cls}`}>{status}</span>;
}

export default function Mirror() {
  const [tab, setTab] = createSignal<"rules" | "jobs">("rules");
  const [rules, setRules] = createSignal<MirrorRule[]>([]);
  const [jobs, setJobs] = createSignal<SyncJob[]>([]);
  const [session, setSession] = createSignal<DashboardSession | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [errorCount, setErrorCount] = createSignal(0);
  const [showForm, setShowForm] = createSignal(false);
  const [form, setForm] = createSignal<RuleForm>({ ...EMPTY_FORM });
  const [saving, setSaving] = createSignal(false);
  const [triggering, setTriggering] = createSignal<string | null>(null);
  const [deleteId, setDeleteId] = createSignal<string | null>(null);

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
      setError(null);
      setErrorCount(0);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        redirectToSignIn();
        return;
      }
      if (e instanceof ApiError && e.status === 403) {
        // Non-admin user — show permission message, reset error count.
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

  createEffect(() => {
    load();
    const id = setInterval(load, 10_000);
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

  function proxyLabel(protocol: OutboundProxyProtocol, url?: string | null) {
    if (protocol === "none") return t("common.direct");
    const label =
      protocol === "http"
        ? t("proxy.protocol.http")
        : protocol === "https"
          ? t("proxy.protocol.https")
          : protocol === "socks4"
            ? t("proxy.protocol.socks4")
            : t("proxy.protocol.socks5");
    return url ? `${label}: ${url}` : label;
  }

  function transportLabel(rule: MirrorRule) {
    if (rule.plain_http) return t("mirror.transportPlainHttp");
    if (rule.insecure_tls) return t("mirror.transportInsecureTls");
    return t("mirror.transportVerifiedTls");
  }

  if (errorCount() >= 3) {
    return <ErrorBanner message={error() ?? t("common.unknown")} onRetry={load} fullPage />;
  }

  return (
    <div>
      <div class="page-header">
        <div>
          <p class="eyebrow">{t("mirror.eyebrow")}</p>
          <h1>{t("mirror.title")}</h1>
        </div>
        <Show when={session()?.is_admin}>
          <button class="btn btn-primary" onClick={() => setShowForm(true)}>
            {t("mirror.create")}
          </button>
        </Show>
      </div>

      {error() && <ErrorBanner message={error()!} onRetry={load} />}

      <div class="card">
        <div class="tabs">
          <button class={tab() === "rules" ? "active" : ""} onClick={() => setTab("rules")}>{t("mirror.rules")}</button>
          <button class={tab() === "jobs" ? "active" : ""} onClick={() => setTab("jobs")}>{t("mirror.jobs")}</button>
        </div>

        {loading() ? (
          <LoadingSpinner label={t("mirror.loading")} />
        ) : tab() === "rules" ? (
          <Show
            when={rules().length > 0}
            fallback={<EmptyState title={t("mirror.noRules")} description={t("mirror.noRulesDesc")} />}
          >
            <table>
              <thead>
                <tr>
                  <th>{t("common.id")}</th>
                  <th>{t("mirror.direction")}</th>
                  <th>{t("mirror.localPrefix")}</th>
                  <th>{t("common.upstream")}</th>
                  <th>{t("mirror.strategy")}</th>
                  <th>{t("common.proxy")}</th>
                  <th>{t("common.schedule")}</th>
                  <th>{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={rules()}>
                  {(rule) => (
                    <tr>
                      <td><code>{rule.id}</code></td>
                      <td>
                        <span class={`badge ${rule.direction === "pull" ? "badge-success" : "badge-blue"}`}>
                          {directionLabel(rule)}
                        </span>
                      </td>
                      <td>{rule.local_prefix}</td>
                      <td>
                        {rule.upstream_registry}/{rule.upstream_prefix ?? ""}
                        <span class="badge badge-gray inline-badge">{transportLabel(rule)}</span>
                      </td>
                      <td>{strategyLabel(rule.strategy)}</td>
                      <td>{proxyLabel(rule.outbound_proxy.protocol, rule.outbound_proxy.url)}</td>
                      <td>{rule.schedule ?? t("common.manual")}</td>
                      <td>
                        <Show when={session()?.is_admin}>
                          <div class="row-actions">
                            <button
                              class={`btn btn-compact ${rule.schedule ? "" : "btn-primary"}`}
                              disabled={triggering() === rule.id}
                              onClick={() => runRule(rule.id)}
                            >
                              {triggering() === rule.id ? t("mirror.triggering") : t("mirror.trigger")}
                            </button>
                            <button class="btn btn-compact btn-danger" onClick={() => setDeleteId(rule.id)}>
                              {t("common.delete")}
                            </button>
                          </div>
                        </Show>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </Show>
        ) : (
          <Show
            when={jobs().length > 0}
            fallback={<EmptyState title={t("mirror.noJobs")} description={t("mirror.noJobsDesc")} />}
          >
            <table>
              <thead>
                <tr>
                  <th>{t("mirror.job")}</th>
                  <th>{t("mirror.rule")}</th>
                  <th>{t("mirror.image")}</th>
                  <th>{t("common.status")}</th>
                  <th>{t("mirror.lastRun")}</th>
                  <th>{t("mirror.nextRun")}</th>
                  <th>{t("mirror.lastError")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={jobs()}>
                  {(job) => (
                    <tr>
                      <td><code>{job.id}</code></td>
                      <td>{job.rule_name ?? job.rule_id ?? "-"}</td>
                      <td>{job.image}</td>
                      <td>{statusBadge(job.status)}</td>
                      <td>{formatTime(job.last_run_at)}</td>
                      <td>{job.interval_secs === 0 ? t("common.adHoc") : formatAgo(job.next_run_at)}</td>
                      <td class="error-cell">{job.last_error ?? "-"}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </Show>
        )}
      </div>

      <Show when={showForm()}>
        <div class="modal-overlay" onClick={() => setShowForm(false)}>
          <div class="modal modal-wide" onClick={(e) => e.stopPropagation()}>
            <h2>{t("mirror.createTitle")}</h2>
            <div class="form-grid">
              <div class="form-group full">
                <label>{t("common.type")}</label>
                <div class="segmented">
                  <button type="button" class={form().type === "scheduled" ? "active" : ""} onClick={() => setForm({ ...form(), type: "scheduled" })}>{t("mirror.scheduled")}</button>
                  <button type="button" class={form().type === "manual" ? "active" : ""} onClick={() => setForm({ ...form(), type: "manual" })}>{t("common.manual")}</button>
                </div>
              </div>
              <Show when={form().type === "scheduled"} fallback={<p class="hint full">{t("mirror.manualHint")}</p>}>
                <div class="form-group full">
                  <label>{t("mirror.crontab")}</label>
                  <input value={form().schedule} placeholder="*/30 * * * *" onInput={(e) => setForm({ ...form(), schedule: e.currentTarget.value })} />
                </div>
              </Show>
              <div class="form-group"><label>{t("common.id")}</label><input value={form().id} onInput={(e) => setForm({ ...form(), id: e.currentTarget.value })} /></div>
              <div class="form-group"><label>{t("mirror.direction")}</label><select value={form().direction} onChange={(e) => setForm({ ...form(), direction: e.currentTarget.value as MirrorDirection })}><option value="pull">{t("mirror.direction.pull")}</option><option value="push">{t("mirror.direction.push")}</option></select></div>
              <div class="form-group"><label>{t("mirror.localPrefix")}</label><input value={form().local_prefix} onInput={(e) => setForm({ ...form(), local_prefix: e.currentTarget.value })} /></div>
              <div class="form-group"><label>{t("mirror.upstreamRegistry")}</label><input value={form().upstream_registry} onInput={(e) => setForm({ ...form(), upstream_registry: e.currentTarget.value })} /></div>
              <div class="form-group"><label>{t("mirror.upstreamPrefix")}</label><input value={form().upstream_prefix} onInput={(e) => setForm({ ...form(), upstream_prefix: e.currentTarget.value })} /></div>
              <div class="form-group"><label>{t("mirror.strategy")}</label><select value={form().strategy_type} onChange={(e) => setForm({ ...form(), strategy_type: e.currentTarget.value as RuleForm["strategy_type"] })}><option value="all">{t("mirror.allTags")}</option><option value="latest">{t("mirror.latestN")}</option><option value="pattern">{t("mirror.tagPattern")}</option></select></div>
              <Show when={form().strategy_type === "latest"}>
                <div class="form-group"><label>{t("mirror.count")}</label><input type="number" value={form().latest_count} onInput={(e) => setForm({ ...form(), latest_count: Number(e.currentTarget.value) || 1 })} /></div>
              </Show>
              <Show when={form().strategy_type === "pattern"}>
                <div class="form-group"><label>{t("mirror.glob")}</label><input value={form().pattern} placeholder="v2.*" onInput={(e) => setForm({ ...form(), pattern: e.currentTarget.value })} /></div>
              </Show>
              <div class="form-group"><label>{t("common.username")}</label><input value={form().username} autocomplete="off" onInput={(e) => setForm({ ...form(), username: e.currentTarget.value })} /></div>
              <div class="form-group"><label>{t("common.password")}</label><input type="password" value={form().password} autocomplete="new-password" onInput={(e) => setForm({ ...form(), password: e.currentTarget.value })} /></div>
              <div class="form-group full advanced">
                <h3>{t("mirror.advancedNetwork")}</h3>
                <div class="form-grid">
                  <label class="checkbox-row">
                    <input
                      type="checkbox"
                      checked={form().plain_http}
                      onChange={(e) => setForm({ ...form(), plain_http: e.currentTarget.checked, insecure_tls: e.currentTarget.checked ? false : form().insecure_tls })}
                    />
                    <span>{t("mirror.plainHttp")}</span>
                  </label>
                  <label class="checkbox-row">
                    <input
                      type="checkbox"
                      checked={form().insecure_tls}
                      onChange={(e) => setForm({ ...form(), insecure_tls: e.currentTarget.checked, plain_http: e.currentTarget.checked ? false : form().plain_http })}
                    />
                    <span>{t("mirror.insecureTls")}</span>
                  </label>
                  <div class="form-group"><label>{t("mirror.outboundProxy")}</label><select value={form().proxy_protocol} onChange={(e) => setForm({ ...form(), proxy_protocol: e.currentTarget.value as OutboundProxyProtocol })}><option value="none">{t("common.direct")}</option><option value="http">HTTP</option><option value="socks4">SOCKS4</option><option value="socks5">SOCKS5</option></select></div>
                  <Show when={form().proxy_protocol !== "none"}>
                    <div class="form-group"><label>{t("mirror.proxyUrl")}</label><input value={form().proxy_url} placeholder="proxy.internal:8080" onInput={(e) => setForm({ ...form(), proxy_url: e.currentTarget.value })} /></div>
                    <div class="form-group"><label>{t("mirror.proxyUsername")}</label><input value={form().proxy_username} onInput={(e) => setForm({ ...form(), proxy_username: e.currentTarget.value })} /></div>
                    <div class="form-group"><label>{t("mirror.proxyPassword")}</label><input type="password" value={form().proxy_password} onInput={(e) => setForm({ ...form(), proxy_password: e.currentTarget.value })} /></div>
                  </Show>
                </div>
                <p class="hint">{t("mirror.httpsDeferred")}</p>
              </div>
            </div>
            <div class="modal-actions">
              <button class="btn" onClick={() => setShowForm(false)}>{t("common.cancel")}</button>
              <button class="btn btn-primary" disabled={saving()} onClick={saveRule}>{saving() ? t("common.creating") : t("mirror.create")}</button>
            </div>
          </div>
        </div>
      </Show>

      <Show when={deleteId()}>
        {(id) => (
          <div class="modal-overlay" onClick={() => setDeleteId(null)}>
            <div class="modal" onClick={(e) => e.stopPropagation()}>
              <h2>{t("mirror.deleteTitle", { id: id() })}</h2>
              <p class="warning">{t("mirror.deleteWarning")}</p>
              <div class="modal-actions">
                <button class="btn" onClick={() => setDeleteId(null)}>{t("common.cancel")}</button>
                <button class="btn btn-danger" onClick={() => confirmDelete(id())}>{t("common.confirmDelete")}</button>
              </div>
            </div>
          </div>
        )}
      </Show>
    </div>
  );
}
