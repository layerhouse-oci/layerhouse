import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import {
  ApiError,
  createProxyCache,
  deleteProxyCache,
  fetchProxyCaches,
  fetchSession,
  redirectToSignIn,
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
import { normalizeOptionalPrefix, normalizeRegistry, upstreamLabel } from "../lib/format";
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

function warmupBadge(cache: ProxyCache) {
  if (cache.warm_filters.length === 0) return { cls: "warmup", label: t("common.none") };
  const filter = cache.warm_filters[0];
  if (filter.type === "all") return { cls: "warmup hot", label: t("mirror.allTags") };
  if (filter.type === "latest")
    return {
      cls: "warmup latest",
      label: `${t("mirror.latestCount", { count: filter.count })} (${filter.sort_by})`,
    };
  if (filter.type === "pattern") return { cls: "warmup pattern", label: filter.pattern };
  return { cls: "warmup", label: t("common.none") };
}

function proxyBadge(protocol: OutboundProxyProtocol, url?: string | null) {
  if (protocol === "none")
    return { cls: "network-badge", label: t("common.direct"), title: undefined };
  const label =
    protocol === "http"
      ? t("proxy.protocol.http")
      : protocol === "https"
        ? t("proxy.protocol.https")
        : protocol === "socks4"
          ? t("proxy.protocol.socks4")
          : t("proxy.protocol.socks5");
  return {
    cls: "network-badge proxy",
    label: t("mirror.proxyBadge", { protocol: label }),
    title: url ?? undefined,
  };
}

function toPayload(form: CacheForm): ProxyCacheCreate {
  return {
    id: form.id,
    local_prefix: form.local_prefix,
    upstream_registry: normalizeRegistry(form.upstream_registry),
    upstream_prefix: normalizeOptionalPrefix(form.upstream_prefix),
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
      if (e instanceof ApiError && e.status === 401) {
        redirectToSignIn();
        return;
      }
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
    <div class="proxy-page">
      <section class="hero glass" aria-labelledby="proxy-cache-title">
        <div>
          <p class="eyebrow">
            <span class="status-dot" aria-hidden="true" />
            {t("proxy.eyebrow")}
          </p>
          <h1 id="proxy-cache-title">{t("proxy.title")}</h1>
          <p class="hero-copy">{t("proxy.heroCopy")}</p>
        </div>
      </section>

      <Show when={error()}>
        <ErrorBanner message={error()!} onRetry={load} />
      </Show>

      <section class="panel glass" aria-labelledby="cache-table-title">
        <div class="panel-head">
          <div>
            <p class="section-label">{t("proxy.cacheCatalog")}</p>
            <h2 class="panel-title" id="cache-table-title">
              {t("proxy.pullThroughCaches")}
            </h2>
          </div>
          <Show when={session()?.is_admin}>
            <button class="button" onClick={() => setShowForm(true)}>
              {t("proxy.create")}
            </button>
          </Show>
        </div>

        <Show
          when={!loading()}
          fallback={
            <div style={{ padding: "48px 0" }}>
              <LoadingSpinner label={t("proxy.loading")} />
            </div>
          }
        >
          <Show
            when={caches().length > 0}
            fallback={
              <div style={{ padding: "48px 0" }}>
                <EmptyState title={t("proxy.empty")} description={t("proxy.emptyDesc")} />
              </div>
            }
          >
            <div class="table-wrap">
              <table aria-label="Proxy cache rules">
                <thead>
                  <tr>
                    <th scope="col">{t("proxy.cacheId")}</th>
                    <th scope="col">{t("mirror.localPrefix")}</th>
                    <th scope="col">{t("common.upstream")}</th>
                    <th scope="col">{t("proxy.warmUp")}</th>
                    <th scope="col">{t("common.proxy")}</th>
                    <th scope="col">{t("common.schedule")}</th>
                    <th scope="col">{t("common.actions")}</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={caches()}>
                    {(cache) => {
                      const badge = () => warmupBadge(cache);
                      const pb = () =>
                        proxyBadge(cache.outbound_proxy.protocol, cache.outbound_proxy.url);
                      return (
                        <tr>
                          <td class="cache-id">{cache.id}</td>
                          <td class="path">{cache.local_prefix}</td>
                          <td class="path">
                            {upstreamLabel(cache.upstream_registry, cache.upstream_prefix)}
                          </td>
                          <td>
                            <span class={badge().cls}>{badge().label}</span>
                          </td>
                          <td>
                            <span class={pb().cls} title={pb().title}>
                              {pb().label}
                            </span>
                          </td>
                          <td class="schedule">{cache.warm_schedule ?? t("common.manual")}</td>
                          <td>
                            <Show when={session()?.is_admin}>
                              <div class="actions">
                                <button
                                  class="action"
                                  disabled={warming() === cache.id}
                                  onClick={() => warm(cache.id)}
                                >
                                  {warming() === cache.id ? t("proxy.warming") : t("proxy.warmNow")}
                                </button>
                                <button
                                  class="action remove"
                                  onClick={() => setDeleteTarget(cache)}
                                >
                                  {t("common.delete")}
                                </button>
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
            <div class="table-footer" aria-label="Proxy cache pagination">
              <div class="page-count">
                {t("repos.pagination", { shown: caches().length, total: caches().length })}
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

      <footer class="footer">
        <span>
          <strong>{t("common.updated")}:</strong> {new Date().toLocaleString()}
        </span>
        <span>{t("app.brandName")}</span>
      </footer>

      {/* ---- Create cache modal ---- */}
      <Show when={showForm()}>
        <div class="modal-backdrop visible" onClick={() => setShowForm(false)}>
          <div
            class="modal glass"
            role="dialog"
            aria-modal="true"
            aria-labelledby="create-cache-title"
            onClick={(e) => e.stopPropagation()}
          >
            <div class="modal-head">
              <div>
                <p class="section-label">{t("proxy.eyebrow")}</p>
                <h2 class="modal-title" id="create-cache-title">
                  {t("proxy.createTitle")}
                </h2>
              </div>
              <button
                class="close"
                aria-label={t("common.close")}
                onClick={() => setShowForm(false)}
              />
            </div>
            <div class="form">
              <div class="field">
                <label for="cache-id">{t("common.id")}</label>
                <input
                  id="cache-id"
                  value={form().id}
                  onInput={(e) => setForm({ ...form(), id: e.currentTarget.value })}
                />
              </div>
              <div class="field">
                <label for="local-prefix">{t("mirror.localPrefix")}</label>
                <input
                  id="local-prefix"
                  value={form().local_prefix}
                  onInput={(e) => setForm({ ...form(), local_prefix: e.currentTarget.value })}
                />
              </div>
              <div class="field">
                <label for="upstream-registry">{t("mirror.upstreamRegistry")}</label>
                <input
                  id="upstream-registry"
                  value={form().upstream_registry}
                  onInput={(e) => setForm({ ...form(), upstream_registry: e.currentTarget.value })}
                />
              </div>
              <div class="field">
                <label for="upstream-prefix">{t("mirror.upstreamPrefix")}</label>
                <input
                  id="upstream-prefix"
                  value={form().upstream_prefix}
                  onInput={(e) => setForm({ ...form(), upstream_prefix: e.currentTarget.value })}
                />
              </div>

              {/* Warm-up filters */}
              <div class="field full">
                <span class="choice-label">{t("proxy.warmFilter")}</span>
                <div class="filter-grid">
                  <label
                    class="check-tile"
                    classList={{ active: form().warm_type === "all" }}
                    onClick={() => setForm({ ...form(), warm_type: "all" })}
                  >
                    <input type="radio" name="warm-type" checked={form().warm_type === "all"} />
                    {t("mirror.allTags")}
                  </label>
                  <label
                    class="check-tile"
                    classList={{ active: form().warm_type === "latest" }}
                    onClick={() => setForm({ ...form(), warm_type: "latest" })}
                  >
                    <input type="radio" name="warm-type" checked={form().warm_type === "latest"} />
                    {t("mirror.latestN")}
                  </label>
                  <label
                    class="check-tile"
                    classList={{ active: form().warm_type === "pattern" }}
                    onClick={() => setForm({ ...form(), warm_type: "pattern" })}
                  >
                    <input type="radio" name="warm-type" checked={form().warm_type === "pattern"} />
                    {t("mirror.tagPattern")}
                  </label>
                  <label
                    class="check-tile"
                    classList={{ active: form().warm_type === "none" }}
                    onClick={() => setForm({ ...form(), warm_type: "none" })}
                  >
                    <input type="radio" name="warm-type" checked={form().warm_type === "none"} />
                    {t("common.none")}
                  </label>
                  <div class="filter-line">
                    <div class="field">
                      <label for="tag-pattern">{t("mirror.tagPattern")}</label>
                      <input
                        id="tag-pattern"
                        disabled={form().warm_type !== "pattern"}
                        value={form().pattern}
                        onInput={(e) => setForm({ ...form(), pattern: e.currentTarget.value })}
                      />
                    </div>
                    <div class="field">
                      <label for="latest-count">{t("mirror.count")}</label>
                      <input
                        id="latest-count"
                        type="number"
                        min="1"
                        disabled={form().warm_type !== "latest"}
                        value={form().latest_count}
                        onInput={(e) =>
                          setForm({ ...form(), latest_count: Number(e.currentTarget.value) || 1 })
                        }
                      />
                    </div>
                    <div class="field">
                      <label for="sort-by">{t("proxy.sortBy")}</label>
                      <select
                        id="sort-by"
                        disabled={form().warm_type !== "latest"}
                        value={form().sort_by}
                        onChange={(e) =>
                          setForm({ ...form(), sort_by: e.currentTarget.value as WarmSortBy })
                        }
                      >
                        <option value="created">{t("proxy.sort.created")}</option>
                        <option value="pushed">{t("proxy.sort.pushed")}</option>
                        <option value="pulled">{t("proxy.sort.pulled")}</option>
                      </select>
                    </div>
                  </div>
                </div>
              </div>

              <div class="field full">
                <label for="schedule">{t("proxy.warmSchedule")}</label>
                <input
                  id="schedule"
                  placeholder="0 */4 * * *"
                  value={form().warm_schedule}
                  onInput={(e) => setForm({ ...form(), warm_schedule: e.currentTarget.value })}
                />
              </div>

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
                  <input
                    id="password-secret"
                    type="password"
                    autocomplete="new-password"
                    value={form().password}
                    onInput={(e) => setForm({ ...form(), password: e.currentTarget.value })}
                  />
                </div>
              </div>

              {/* Advanced network */}
              <details class="advanced-section">
                <summary>{t("mirror.advancedNetwork")}</summary>
                <div class="advanced-grid">
                  <label class="toggle">
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
                  <label class="toggle">
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
                <button class="button" disabled={saving()} onClick={save}>
                  {saving() ? t("common.creating") : t("proxy.create")}
                </button>
              </div>
            </div>
          </div>
        </div>
      </Show>

      {/* ---- Delete cache modal ---- */}
      <Show when={deleteTarget()}>
        {(cache) => {
          const badge = () => warmupBadge(cache());
          return (
            <div class="modal-backdrop visible" onClick={() => setDeleteTarget(null)}>
              <div
                class="modal glass"
                role="dialog"
                aria-modal="true"
                aria-labelledby="delete-cache-title"
                onClick={(e) => e.stopPropagation()}
              >
                <div class="modal-head">
                  <div>
                    <p class="section-label">{t("proxy.deleteEyebrow")}</p>
                    <h2 class="modal-title" id="delete-cache-title">
                      {t("proxy.deleteTitle", { id: cache().id })}
                    </h2>
                  </div>
                  <button
                    class="close"
                    aria-label={t("common.close")}
                    onClick={() => setDeleteTarget(null)}
                  />
                </div>
                <div class="modal-body">
                  <p class="warning">{t("proxy.deleteWarning")}</p>
                  <div class="delete-facts" aria-label="Proxy cache delete impact">
                    <div class="delete-fact">
                      <span>{t("proxy.deleteFactPrefix")}</span>
                      <strong>{cache().local_prefix}</strong>
                    </div>
                    <div class="delete-fact">
                      <span>{t("proxy.deleteFactUpstream")}</span>
                      <strong>
                        {upstreamLabel(cache().upstream_registry, cache().upstream_prefix)}
                      </strong>
                    </div>
                    <div class="delete-fact">
                      <span>{t("proxy.deleteFactWarmup")}</span>
                      <strong>{badge().label}</strong>
                    </div>
                  </div>
                  <p class="delete-note">{t("proxy.deleteNote")}</p>
                  <div class="modal-actions">
                    <button class="action secondary" onClick={() => setDeleteTarget(null)}>
                      {t("common.cancel")}
                    </button>
                    <button class="action confirm" onClick={confirmDelete}>
                      {t("common.confirmDelete")}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          );
        }}
      </Show>
    </div>
  );
}
