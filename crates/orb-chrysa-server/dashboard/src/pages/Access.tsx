import { createEffect, createSignal, For, Show } from "solid-js";
import EmptyState from "../components/EmptyState";
import ErrorBanner from "../components/ErrorBanner";
import LoadingSpinner from "../components/LoadingSpinner";
import {
  ApiError,
  createPersonalAccessToken,
  deletePersonalAccessToken,
  fetchPersonalAccessTokens,
  fetchSession,
} from "../lib/api";
import { copyToClipboard, formatAgo, formatTime } from "../lib/format";
import { t } from "../lib/i18n";
import type {
  CreateTokenResponse,
  DashboardSession,
  PersonalAccessToken,
} from "../lib/types";

type AccessTab = "tokens" | "session" | "permissions";
type TokenAction = "pull" | "push" | "delete";

interface TokenForm {
  name: string;
  repositoryPattern: string;
  expiresInDays: string;
  actions: Record<TokenAction, boolean>;
}

const EMPTY_FORM: TokenForm = {
  name: "",
  repositoryPattern: "qa/*",
  expiresInDays: "30",
  actions: {
    pull: true,
    push: true,
    delete: false,
  },
};

function userLabel(session: DashboardSession | null): string {
  return session?.display_name || session?.username || session?.email || session?.subject || t("access.account");
}

function dockerLoginUser(session: DashboardSession | null): string {
  return session?.username || session?.email || session?.subject || userLabel(session);
}

function scopesFor(form: TokenForm): string[] {
  const repo = form.repositoryPattern.trim();
  if (!repo) return [];
  return (Object.entries(form.actions) as [TokenAction, boolean][])
    .filter(([, enabled]) => enabled)
    .map(([action]) => `repository:${repo}:${action}`);
}

function expiresSoon(token: PersonalAccessToken): boolean {
  if (!token.expires_at) return false;
  const seconds = token.expires_at - Math.floor(Date.now() / 1000);
  return seconds > 0 && seconds <= 7 * 24 * 60 * 60;
}

function registryHost(): string {
  return window.location.host || "localhost:5050";
}

function dockerLoginCommand(user: string): string {
  return `echo "$TOKEN" | docker login ${registryHost()} --username ${user} --password-stdin`;
}

function envVarCommand(token: string): string {
  return `REGISTRY_TOKEN=${token}`;
}

export default function Access() {
  const [tab, setTab] = createSignal<AccessTab>("tokens");
  const [session, setSession] = createSignal<DashboardSession | null>(null);
  const [tokens, setTokens] = createSignal<PersonalAccessToken[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [showCreate, setShowCreate] = createSignal(false);
  const [form, setForm] = createSignal<TokenForm>({ ...EMPTY_FORM });
  const [formError, setFormError] = createSignal<string | null>(null);
  const [saving, setSaving] = createSignal(false);
  const [createdToken, setCreatedToken] = createSignal<CreateTokenResponse | null>(null);
  const [revokeTarget, setRevokeTarget] = createSignal<PersonalAccessToken | null>(null);
  const [revoking, setRevoking] = createSignal(false);
  const [revokeError, setRevokeError] = createSignal<string | null>(null);
  const [copied, setCopied] = createSignal<string | null>(null);

  async function load() {
    setLoading(true);
    try {
      const nextSession = await fetchSession();
      setSession(nextSession);
      if (nextSession.auth_enabled) {
        setTokens(await fetchPersonalAccessTokens());
      } else {
        setTokens([]);
      }
      setError(null);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setSession(null);
        setTokens([]);
        setError(null);
      } else {
        setError(e instanceof Error ? e.message : t("access.loadError"));
      }
    } finally {
      setLoading(false);
    }
  }

  createEffect(() => {
    load();
  });

  function resetCreate() {
    setForm({ ...EMPTY_FORM, actions: { ...EMPTY_FORM.actions } });
    setFormError(null);
    setCreatedToken(null);
    setCopied(null);
  }

  function openCreate() {
    resetCreate();
    setShowCreate(true);
  }

  function closeCreate() {
    setShowCreate(false);
    resetCreate();
    load();
  }

  function updateAction(action: TokenAction, enabled: boolean) {
    setForm({
      ...form(),
      actions: {
        ...form().actions,
        [action]: enabled,
        // Push implies pull: a push-only token can't satisfy the
        // pull,push challenge the registry emits for blob uploads.
        ...(action === "push" && enabled ? { pull: true } : {}),
        // Unchecking pull also unchecks push (push requires pull).
        ...(action === "pull" && !enabled ? { push: false } : {}),
      },
    });
  }

  function validateForm(): string | null {
    if (!form().name.trim()) return t("access.nameRequired");
    if (!form().repositoryPattern.trim()) return t("access.patternRequired");
    if (scopesFor(form()).length === 0) return t("access.actionRequired");
    return null;
  }

  async function createToken() {
    const validation = validateForm();
    if (validation) {
      setFormError(validation);
      return;
    }

    setSaving(true);
    setFormError(null);
    try {
      const expiresInDays =
        form().expiresInDays === "never" ? null : Number(form().expiresInDays);
      const created = await createPersonalAccessToken({
        name: form().name.trim(),
        scopes: scopesFor(form()),
        expires_in_days: Number.isFinite(expiresInDays) ? expiresInDays : null,
      });
      setCreatedToken(created);
    } catch (e) {
      setFormError(e instanceof Error ? e.message : t("access.createError"));
    } finally {
      setSaving(false);
    }
  }

  async function revokeToken() {
    const target = revokeTarget();
    if (!target) return;
    setRevokeError(null);
    setRevoking(true);
    // Optimistic removal: immediately remove the token from the list so the UI
    // feels responsive. If the API call fails in a recoverable way, we restore
    // it. For ambiguous outcomes (timeout, 404) we reload from the server.
    const previous = tokens();
    setTokens(previous.filter((t) => t.id !== target.id));
    try {
      console.debug("[orb-chrysa] revoking token", { id: target.id, name: target.name });
      await deletePersonalAccessToken(target.id);
      await load();
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") {
        // Timeout: server-side delete may still have committed. Don't restore
        // the token — we'd be resurrecting a potentially-revoked credential.
        // Reload to get authoritative server state.
        console.warn("[orb-chrysa] revoke timed out, reloading to reconcile", { id: target.id });
        setError(t("access.revokeTimeout"));
        await load();
      } else if (e instanceof ApiError && e.status === 404) {
        // Token already gone — reload to confirm. Don't restore.
        console.warn("[orb-chrysa] revoke got 404, token already removed", { id: target.id });
        await load();
      } else {
        // Recoverable failure (network error, server error): restore token.
        console.warn("[orb-chrysa] revoke failed", { id: target.id, message: (e as Error).message });
        setTokens(previous);
        setError(e instanceof Error ? e.message : t("access.revokeError"));
      }
    } finally {
      setRevokeTarget(null);
      setRevoking(false);
    }
  }

  async function copyValue(key: string, value: string) {
    if (await copyToClipboard(value)) {
      setCopied(key);
      window.setTimeout(() => setCopied((current) => (current === key ? null : current)), 1600);
    } else {
      setFormError(t("common.copyFailed"));
    }
  }

  const activeTokens = () => tokens().length;
  const expiringSoonCount = () => tokens().filter(expiresSoon).length;
  const currentScopes = () => scopesFor(form());

  return (
    <div>
      <div class="page-header">
        <div>
          <p class="eyebrow">{t("access.eyebrow")}</p>
          <h1>{t("access.title")}</h1>
          <p class="page-copy">{t("access.copy")}</p>
        </div>
        <Show when={session()?.auth_enabled && session()?.subject}>
          <button class="btn btn-primary" onClick={openCreate}>
            {t("access.createToken")}
          </button>
        </Show>
      </div>

      {error() && <ErrorBanner message={error()!} onRetry={load} />}

      <Show when={!loading()} fallback={<LoadingSpinner label={t("access.loading")} />}>
        <Show
          when={session()?.auth_enabled !== false}
          fallback={
            <div class="card">
              <EmptyState
                title={t("access.authDisabled")}
                description={t("access.authDisabledDesc")}
              />
            </div>
          }
        >
          <Show
            when={session()?.subject}
            fallback={
              <div class="access-signin card">
                <div>
                  <p class="eyebrow">{t("access.signIn")}</p>
                  <h2>{t("access.signInTitle")}</h2>
                  <p>{t("access.signInDesc")}</p>
                  <p class="hint">{t("access.dockerClientsUsePat")}</p>
                </div>
                <a class="btn btn-primary" href="/oauth2/start">
                  {t("access.signInWithOidc")}
                </a>
              </div>
            }
          >
            <div class="access-stats">
              <div class="fact-grid">
                <div>
                  <span>{t("access.signedInAs")}</span>
                  <strong>{userLabel(session())}</strong>
                </div>
                <div>
                  <span>{t("access.activeTokens")}</span>
                  <strong>{activeTokens()}</strong>
                </div>
                <div>
                  <span>{t("access.expiringSoon")}</span>
                  <strong>{expiringSoonCount()}</strong>
                </div>
              </div>
            </div>

            <div class="tabs" role="tablist">
              <button
                class={tab() === "tokens" ? "active" : ""}
                type="button"
                onClick={() => setTab("tokens")}
              >
                {t("access.personalTokens")}
              </button>
              <button
                class={tab() === "session" ? "active" : ""}
                type="button"
                onClick={() => setTab("session")}
              >
                {t("access.session")}
              </button>
              <button
                class={tab() === "permissions" ? "active" : ""}
                type="button"
                onClick={() => setTab("permissions")}
              >
                {t("access.permissions")}
              </button>
            </div>

            <Show when={tab() === "tokens"}>
              <div class="card">
                {tokens().length === 0 ? (
                  <EmptyState
                    title={t("access.noTokens")}
                    description={t("access.noTokensDesc")}
                  />
                ) : (
                  <table>
                    <thead>
                      <tr>
                        <th>{t("access.tokenName")}</th>
                        <th>{t("access.prefix")}</th>
                        <th>{t("access.scopes")}</th>
                        <th>{t("access.created")}</th>
                        <th>{t("access.lastUsed")}</th>
                        <th>{t("access.expires")}</th>
                        <th>{t("common.actions")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={tokens()}>
                        {(token) => (
                          <tr>
                            <td class="repo-name">{token.name}</td>
                            <td><code>{token.prefix}</code></td>
                            <td>
                              <div class="chips">
                                <For each={token.scopes}>
                                  {(scope) => <span class="chip">{scope}</span>}
                                </For>
                              </div>
                            </td>
                            <td>{formatTime(token.created_at)}</td>
                            <td>{formatAgo(token.last_used_at)}</td>
                            <td>
                              {token.expires_at ? (
                                <span class={expiresSoon(token) ? "badge badge-warning" : ""}>
                                  {formatTime(token.expires_at)}
                                </span>
                              ) : (
                                t("access.neverExpires")
                              )}
                            </td>
                            <td>
                              <button
                                class="btn btn-compact btn-danger"
                                onClick={() => setRevokeTarget(token)}
                              >
                                {t("access.revoke")}
                              </button>
                            </td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                )}
              </div>
            </Show>

            <Show when={tab() === "session"}>
              <div class="card">
                <div class="fact-grid">
                  <div>
                    <span>{t("access.signedInAs")}</span>
                    <strong>{userLabel(session())}</strong>
                  </div>
                  <div>
                    <span>{t("access.tokenType")}</span>
                    <strong>{session()?.token_type ?? t("common.notAvailable")}</strong>
                  </div>
                  <div>
                    <span>{t("access.groups")}</span>
                    <strong>{session()?.groups.length ?? 0}</strong>
                  </div>
                </div>
              </div>
            </Show>

            <Show when={tab() === "permissions"}>
              <div class="card">
                <h2 class="card-header">{t("access.scopes")}</h2>
                <div class="chips">
                  <For each={session()?.scopes ?? []} fallback={<span class="muted">{t("common.none")}</span>}>
                    {(scope) => <span class="chip">{scope}</span>}
                  </For>
                </div>
              </div>
            </Show>
          </Show>
        </Show>
      </Show>

      <Show when={showCreate()}>
        <div class="modal-overlay" onClick={() => !createdToken() && closeCreate()}>
          <div class="modal modal-wide" onClick={(event) => event.stopPropagation()}>
            <Show
              when={createdToken()}
              fallback={
                <>
                  <h2>{t("access.createTitle")}</h2>
                  <p class="hint modal-copy">{t("access.createDesc")}</p>
                  {formError() && <p class="warning modal-copy">{formError()}</p>}
                  <div class="form-grid">
                    <div class="form-group">
                      <label>{t("access.tokenName")}</label>
                      <input
                        value={form().name}
                        onInput={(event) => setForm({ ...form(), name: event.currentTarget.value })}
                      />
                    </div>
                    <div class="form-group">
                      <label>{t("access.expiresIn")}</label>
                      <select
                        value={form().expiresInDays}
                        onChange={(event) =>
                          setForm({ ...form(), expiresInDays: event.currentTarget.value })
                        }
                      >
                        <option value="7">{t("access.expiry.7")}</option>
                        <option value="30">{t("access.expiry.30")}</option>
                        <option value="90">{t("access.expiry.90")}</option>
                        <option value="never">{t("access.expiry.never")}</option>
                      </select>
                    </div>
                    <div class="form-group full">
                      <label>{t("access.repositoryPattern")}</label>
                      <input
                        value={form().repositoryPattern}
                        onInput={(event) =>
                          setForm({ ...form(), repositoryPattern: event.currentTarget.value })
                        }
                      />
                      <p class="hint">{t("access.repositoryPatternHint")}</p>
                    </div>
                  </div>

                  <div class="advanced">
                    <h3>{t("access.allowedActions")}</h3>
                    <div class="access-scope-grid">
                      <label class="checkbox-row">
                        <input
                          type="checkbox"
                          checked={form().actions.pull}
                          onChange={(event) => updateAction("pull", event.currentTarget.checked)}
                        />
                        <span>{t("access.pull")}</span>
                      </label>
                      <label class="checkbox-row">
                        <input
                          type="checkbox"
                          checked={form().actions.push}
                          onChange={(event) => updateAction("push", event.currentTarget.checked)}
                        />
                        <span>{t("access.push")}</span>
                      </label>
                      <label class="checkbox-row">
                        <input
                          type="checkbox"
                          checked={form().actions.delete}
                          onChange={(event) => updateAction("delete", event.currentTarget.checked)}
                        />
                        <span>{t("access.delete")}</span>
                      </label>
                    </div>
                    <div class="chips access-scope-preview">
                      <For each={currentScopes()}>
                        {(scope) => <span class="chip">{scope}</span>}
                      </For>
                    </div>
                  </div>

                  <div class="modal-actions">
                    <button class="btn" onClick={closeCreate}>{t("common.cancel")}</button>
                    <button class="btn btn-primary" disabled={saving()} onClick={createToken}>
                      {saving() ? t("common.creating") : t("access.createToken")}
                    </button>
                  </div>
                </>
              }
            >
              {(created) => (
                <>
                  <h2>{t("access.tokenCreated")}</h2>
                  <p class="hint modal-copy">{t("access.tokenCreatedDesc")}</p>
                  {formError() && <p class="warning modal-copy">{formError()}</p>}
                  <div class="access-secret-block">
                    <h3>{t("access.fullToken")}</h3>
                    <code>{created().token}</code>
                    <div class="row-actions">
                      <button
                        class="btn btn-primary"
                        onClick={() => copyValue("token", created().token)}
                      >
                        {copied() === "token" ? t("common.copied") : t("access.copyToken")}
                      </button>
                    </div>
                  </div>

                  <div class="form-grid">
                    <div class="access-command">
                      <h3>{t("access.dockerLogin")}</h3>
                      <code>{dockerLoginCommand(dockerLoginUser(session()))}</code>
                      <button
                        class="btn btn-compact"
                        onClick={() =>
                          copyValue("docker", dockerLoginCommand(dockerLoginUser(session())))
                        }
                      >
                        {copied() === "docker" ? t("common.copied") : t("access.copyDocker")}
                      </button>
                    </div>
                    <div class="access-command">
                      <h3>{t("access.ciSecret")}</h3>
                      <code>{envVarCommand(created().token)}</code>
                      <button
                        class="btn btn-compact"
                        onClick={() => copyValue("env", envVarCommand(created().token))}
                      >
                        {copied() === "env" ? t("common.copied") : t("access.copyVariable")}
                      </button>
                    </div>
                  </div>

                  <div class="modal-actions">
                    <button class="btn" onClick={openCreate}>{t("access.createAnother")}</button>
                    <button class="btn btn-primary" onClick={closeCreate}>{t("common.done")}</button>
                  </div>
                </>
              )}
            </Show>
          </div>
        </div>
      </Show>

      <Show when={revokeTarget()}>
        {(target) => (
          <div class="modal-overlay" onClick={() => setRevokeTarget(null)}>
            <div class="modal" onClick={(event) => event.stopPropagation()}>
              <h2>{t("access.revokeTitle", { name: target().name })}</h2>
              <p class="warning">
                {t("access.revokeWarning", { prefix: target().prefix })}
              </p>
              <div class="modal-actions">
                <button class="btn" onClick={() => setRevokeTarget(null)}>
                  {t("common.cancel")}
                </button>
                <button class="btn btn-danger" disabled={revoking()} onClick={revokeToken}>
                  {revoking() ? t("common.deleting") : t("access.revoke")}
                </button>
              </div>
            </div>
          </div>
        )}
      </Show>
    </div>
  );
}
