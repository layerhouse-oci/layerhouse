import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import {
  ApiError,
  createProxyCache,
  deleteProxyCache,
  fetchProxyCaches,
  fetchSession,
  triggerProxyCacheWarm,
} from "../lib/api";
import type {
  DashboardSession,
  OutboundProxyProtocol,
  ProxyCache,
  ProxyCacheCreate,
  WarmFilter,
  WarmSortBy,
} from "../lib/types";
import LoadingSpinner from "../components/LoadingSpinner";
import EmptyState from "../components/EmptyState";
import ErrorBanner from "../components/ErrorBanner";
import { t } from "../lib/i18n";

interface CacheForm {
  id: string;
  local_prefix: string;
  upstream_registry: string;
  upstream_prefix: string;
  warm_type: "none" | "all" | "latest" | "pattern";
  latest_count: number;
  sort_by: WarmSortBy;
  pattern: string;
  warm_schedule: string;
  plain_http: boolean;
  insecure_tls: boolean;
  username: string;
  password: string;
  proxy_protocol: OutboundProxyProtocol;
  proxy_url: string;
  proxy_username: string;
  proxy_password: string;
}

const EMPTY_FORM: CacheForm = {
  id: "",
  local_prefix: "",
  upstream_registry: "",
  upstream_prefix: "",
  warm_type: "none",
  latest_count: 5,
  sort_by: "pushed",
  pattern: "v2.*",
  warm_schedule: "",
  plain_http: false,
  insecure_tls: false,
  username: "",
  password: "",
  proxy_protocol: "none",
  proxy_url: "",
  proxy_username: "",
  proxy_password: "",
};

function warmFilter(form: CacheForm): WarmFilter[] {
  if (form.warm_type === "all") return [{ type: "all" }];
  if (form.warm_type === "latest") {
    return [{ type: "latest", count: form.latest_count, sort_by: form.sort_by }];
  }
  if (form.warm_type === "pattern") return [{ type: "pattern", pattern: form.pattern }];
  return [{ type: "none" }];
}

function warmLabel(cache: ProxyCache): string {
  if (cache.warm_filters.length === 0) return t("common.none");
  return cache.warm_filters
    .map((filter) => {
      if (filter.type === "all") return t("mirror.allTags");
      if (filter.type === "latest") return `${t("mirror.latestCount", { count: filter.count })} (${filter.sort_by})`;
      if (filter.type === "pattern") return filter.pattern;
      return t("common.none");
    })
    .join(", ");
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

function transportLabel(cache: ProxyCache) {
  if (cache.plain_http) return t("mirror.transportPlainHttp");
  if (cache.insecure_tls) return t("mirror.transportInsecureTls");
  return t("mirror.transportVerifiedTls");
}

function toPayload(form: CacheForm): ProxyCacheCreate {
  return {
    id: form.id,
    local_prefix: form.local_prefix,
    upstream_registry: form.upstream_registry,
    upstream_prefix: form.upstream_prefix || null,
    warm_filters: warmFilter(form),
    warm_schedule: form.warm_schedule || null,
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

export default function ProxyCache() {
  const [caches, setCaches] = createSignal<ProxyCache[]>([]);
  const [session, setSession] = createSignal<DashboardSession | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [errorCount, setErrorCount] = createSignal(0);
  const [showForm, setShowForm] = createSignal(false);
  const [form, setForm] = createSignal<CacheForm>({ ...EMPTY_FORM });
  const [saving, setSaving] = createSignal(false);
  const [deleteTarget, setDeleteTarget] = createSignal<ProxyCache | null>(null);
  const [warming, setWarming] = createSignal<string | null>(null);

  async function load() {
    try {
      const [s, c] = await Promise.all([fetchSession(), fetchProxyCaches()]);
      setSession(s);
      setCaches(c);
      setError(null);
      setErrorCount(0);
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        setError(t("cluster.adminRequired"));
        setErrorCount(0);
        setCaches([]);
      } else {
        setError(e instanceof Error ? e.message : t("proxy.fetchError"));
        setErrorCount((c) => c + 1);
      }
    } finally {
      setLoading(false);
    }
  }

  createEffect(() => {
    load();
    const id = setInterval(load, 15_000);
    onCleanup(() => clearInterval(id));
  });

  async function save() {
    setSaving(true);
    try {
      await createProxyCache(toPayload(form()));
      setShowForm(false);
      setForm({ ...EMPTY_FORM });
      await load();
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        setError(t("cluster.adminRequired"));
      } else {
        setError(e instanceof Error ? e.message : t("proxy.saveError"));
      }
    } finally {
      setSaving(false);
    }
  }

  async function warm(id: string) {
    setWarming(id);
    try {
      await triggerProxyCacheWarm(id);
      await load();
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        setError(t("cluster.adminRequired"));
      } else {
        setError(e instanceof Error ? e.message : t("proxy.warmError"));
      }
    } finally {
      setWarming(null);
    }
  }

  async function confirmDelete() {
    const target = deleteTarget();
    if (!target) return;
    try {
      await deleteProxyCache(target.id);
      setDeleteTarget(null);
      await load();
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        setError(t("cluster.adminRequired"));
      } else {
        setError(e instanceof Error ? e.message : t("proxy.deleteError"));
      }
    }
  }

  if (errorCount() >= 3) {
    return <ErrorBanner message={error() ?? t("common.unknown")} onRetry={load} fullPage />;
  }

  return (
    <div>
      <div class="page-header">
        <div>
          <p class="eyebrow">{t("proxy.eyebrow")}</p>
          <h1>{t("proxy.title")}</h1>
        </div>
        <Show when={session()?.is_admin}>
          <button class="btn btn-primary" onClick={() => setShowForm(true)}>
            {t("proxy.create")}
          </button>
        </Show>
      </div>

      {error() && <ErrorBanner message={error()!} onRetry={load} />}

      <div class="card">
        {loading() ? (
          <LoadingSpinner label={t("proxy.loading")} />
        ) : caches().length === 0 ? (
          <EmptyState title={t("proxy.empty")} description={t("proxy.emptyDesc")} />
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t("proxy.cacheId")}</th>
                <th>{t("mirror.localPrefix")}</th>
                <th>{t("common.upstream")}</th>
                <th>{t("proxy.warmUp")}</th>
                <th>{t("common.proxy")}</th>
                <th>{t("common.schedule")}</th>
                <th>{t("common.actions")}</th>
              </tr>
            </thead>
            <tbody>
              <For each={caches()}>
                {(cache) => (
                  <tr>
                    <td><code>{cache.id}</code></td>
                    <td>{cache.local_prefix}</td>
                    <td>
                      {cache.upstream_registry}/{cache.upstream_prefix ?? ""}
                      <span class="badge badge-gray inline-badge">{transportLabel(cache)}</span>
                    </td>
                    <td>{warmLabel(cache)}</td>
                    <td>{proxyLabel(cache.outbound_proxy.protocol, cache.outbound_proxy.url)}</td>
                    <td>{cache.warm_schedule ?? "—"}</td>
                    <td>
                      <Show when={session()?.is_admin}>
                        <div class="row-actions">
                          <button class="btn btn-compact" disabled={warming() === cache.id} onClick={() => warm(cache.id)}>
                            {warming() === cache.id ? t("proxy.warming") : t("proxy.warm")}
                          </button>
                          <button class="btn btn-compact btn-danger" onClick={() => setDeleteTarget(cache)}>
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
        )}
      </div>

      <Show when={showForm()}>
        <div class="modal-overlay" onClick={() => setShowForm(false)}>
          <div class="modal modal-wide" onClick={(e) => e.stopPropagation()}>
            <h2>{t("proxy.createTitle")}</h2>
            <div class="form-grid">
              <div class="form-group"><label>{t("common.id")}</label><input value={form().id} onInput={(e) => setForm({ ...form(), id: e.currentTarget.value })} /></div>
              <div class="form-group"><label>{t("mirror.localPrefix")}</label><input value={form().local_prefix} onInput={(e) => setForm({ ...form(), local_prefix: e.currentTarget.value })} /></div>
              <div class="form-group"><label>{t("mirror.upstreamRegistry")}</label><input value={form().upstream_registry} onInput={(e) => setForm({ ...form(), upstream_registry: e.currentTarget.value })} /></div>
              <div class="form-group"><label>{t("mirror.upstreamPrefix")}</label><input value={form().upstream_prefix} onInput={(e) => setForm({ ...form(), upstream_prefix: e.currentTarget.value })} /></div>
              <div class="form-group"><label>{t("proxy.warmFilter")}</label><select value={form().warm_type} onChange={(e) => setForm({ ...form(), warm_type: e.currentTarget.value as CacheForm["warm_type"] })}><option value="none">{t("common.none")}</option><option value="all">{t("mirror.allTags")}</option><option value="latest">{t("mirror.latestN")}</option><option value="pattern">{t("mirror.tagPattern")}</option></select></div>
              <Show when={form().warm_type === "latest"}>
                <div class="form-group"><label>{t("mirror.count")}</label><input type="number" value={form().latest_count} onInput={(e) => setForm({ ...form(), latest_count: Number(e.currentTarget.value) || 1 })} /></div>
                <div class="form-group"><label>{t("proxy.sortBy")}</label><select value={form().sort_by} onChange={(e) => setForm({ ...form(), sort_by: e.currentTarget.value as WarmSortBy })}><option value="created">{t("proxy.sort.created")}</option><option value="pushed">{t("proxy.sort.pushed")}</option><option value="pulled">{t("proxy.sort.pulled")}</option></select></div>
              </Show>
              <Show when={form().warm_type === "pattern"}>
                <div class="form-group"><label>{t("mirror.glob")}</label><input value={form().pattern} onInput={(e) => setForm({ ...form(), pattern: e.currentTarget.value })} /></div>
              </Show>
              <div class="form-group"><label>{t("proxy.warmSchedule")}</label><input placeholder="*/30 * * * *" value={form().warm_schedule} onInput={(e) => setForm({ ...form(), warm_schedule: e.currentTarget.value })} /></div>
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
              <button class="btn btn-primary" disabled={saving()} onClick={save}>{saving() ? t("common.creating") : t("proxy.create")}</button>
            </div>
          </div>
        </div>
      </Show>

      <Show when={deleteTarget()}>
        {(cache) => (
          <div class="modal-overlay" onClick={() => setDeleteTarget(null)}>
            <div class="modal" onClick={(e) => e.stopPropagation()}>
              <h2>{t("proxy.deleteTitle", { id: cache().id })}</h2>
              <p class="warning">
                {t("proxy.deleteWarning", { id: cache().id })}
              </p>
              <div class="modal-actions">
                <button class="btn" onClick={() => setDeleteTarget(null)}>{t("common.cancel")}</button>
                <button class="btn btn-danger" onClick={confirmDelete}>{t("common.confirmDelete")}</button>
              </div>
            </div>
          </div>
        )}
      </Show>
    </div>
  );
}
