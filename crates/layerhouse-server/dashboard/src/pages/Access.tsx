import { createEffect, createSignal, For, Show } from "solid-js";
import EmptyState from "../components/EmptyState";
import ErrorBanner from "../components/ErrorBanner";
import LoadingSpinner from "../components/LoadingSpinner";
import {
  ApiError,
  claimNamespace,
  createAccountNamespaceGrant,
  createPersonalAccessToken,
  deleteAccountNamespaceGrant,
  deletePersonalAccessToken,
  fetchAccountNamespaces,
  fetchAccountNamespaceGrants,
  fetchGrantableScopes,
  fetchObservedUsers,
  fetchPersonalAccessTokens,
  fetchSession,
  releaseNamespace,
  redirectToSignIn,
  updateAccountNamespaceGrant,
} from "../lib/api";
import { copyToClipboard, formatAgo, formatTime } from "../lib/format";
import { t } from "../lib/i18n";
import type {
  CreateTokenResponse,
  DashboardSession,
  GrantSource,
  GrantableScope,
  NamespaceGrant,
  NamespaceGrantGrantee,
  NamespaceResponse,
  NamespacePatternScope,
  ObservedIdentity,
  OciAction,
  PersonalAccessToken,
} from "../lib/types";

type AccessTab = "tokens" | "namespaces" | "session" | "permissions";
type ScopeKind = "repository" | "namespace_pattern";
type GrantScope = "account";
type GrantGranteeKind = NamespaceGrantGrantee["kind"];

interface TokenForm {
  name: string;
  expiresInDays: string;
}

interface SelectedScope {
  repository: string;
  displayName: string;
  kind: ScopeKind;
  maxGrantable: OciAction;
  grantSource: GrantSource;
  currentMatchCount?: number;
  actions: OciAction[];
}

interface GrantModalState {
  scope: GrantScope;
  namespace: NamespaceResponse;
  grant?: NamespaceGrant;
}

interface GrantForm {
  granteeKind: GrantGranteeKind;
  groupName: string;
  userQuery: string;
  selectedUser: ObservedIdentity | null;
  publicLabel: string;
  action: OciAction;
  reason: string;
}

const EMPTY_FORM: TokenForm = {
  name: "",
  expiresInDays: "30",
};

const EMPTY_GRANT_FORM: GrantForm = {
  granteeKind: "group",
  groupName: "",
  userQuery: "",
  selectedUser: null,
  publicLabel: "Public",
  action: "pull",
  reason: "",
};

const ACTIONS: OciAction[] = ["pull", "create", "update", "delete"];
const ACTION_RANK: Record<OciAction, number> = {
  pull: 0,
  create: 1,
  update: 2,
  delete: 3,
};

function userLabel(session: DashboardSession | null): string {
  return (
    session?.display_name ||
    session?.username ||
    session?.email ||
    session?.subject ||
    t("access.account")
  );
}

function dockerLoginUser(session: DashboardSession | null): string {
  return session?.username || session?.email || session?.subject || userLabel(session);
}

function actionAllowed(action: OciAction, maxGrantable: OciAction): boolean {
  return ACTION_RANK[action] <= ACTION_RANK[maxGrantable];
}

function isProviderQualifiedId(value: string, kind: "user" | "group"): boolean {
  const parts = value.trim().split(":");
  return parts.length === 3 && parts[0] !== "" && parts[1] === kind && parts[2] !== "";
}

function defaultActions(maxGrantable: OciAction): OciAction[] {
  return ACTIONS.filter((action) => actionAllowed(action, maxGrantable) && action !== "delete");
}

function normalizeScopeRepository(value: string): string {
  return value.replace(/^repository:/, "").trim();
}

function scopeKey(kind: ScopeKind, repository: string): string {
  return `${kind}:${normalizeScopeRepository(repository)}`;
}

function grantSourceLabel(source: GrantSource): string {
  return t(`access.grantSource.${source}`);
}

function actionLabel(action: OciAction): string {
  return t(`access.action.${action}`);
}

function actionSummary(action: OciAction): string {
  return t("access.grantAllows", { action: actionLabel(action) });
}

function formatScopeActions(actions: OciAction[]): string {
  return actions.map(actionLabel).join(", ");
}

function observedUserLabel(user: ObservedIdentity): string {
  return user.display_name || user.username || user.email || user.subject;
}

function granteeKindLabel(kind: GrantGranteeKind): string {
  return t(`access.grantee.${kind}`);
}

function grantLabel(grant: NamespaceGrant): string {
  if (grant.label) return grant.label;
  if (grant.grantee.kind === "group") return grant.grantee.id;
  if (grant.grantee.kind === "user") return grant.grantee.id;
  return t("access.grantee.public");
}

function granteeDetail(grant: NamespaceGrant): string {
  if (grant.grantee.kind === "group") return grant.grantee.id;
  if (grant.grantee.kind === "user") return grant.grantee.id;
  return t("access.publicPullOnly");
}

function scopeFromRepository(scope: GrantableScope): SelectedScope {
  return {
    repository: scope.repository,
    displayName: scope.repository,
    kind: "repository",
    maxGrantable: scope.max_grantable,
    grantSource: scope.grant_source,
    actions: defaultActions(scope.max_grantable),
  };
}

function scopeFromPattern(scope: NamespacePatternScope): SelectedScope {
  const repository = normalizeScopeRepository(scope.pattern);
  return {
    repository,
    displayName: repository,
    kind: "namespace_pattern",
    maxGrantable: scope.max_grantable,
    grantSource: scope.grant_source,
    currentMatchCount: scope.current_match_count,
    actions: defaultActions(scope.max_grantable),
  };
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

function normalizeNamespaceHandle(value: string): string {
  return value.trim().toLowerCase();
}

function GrantTable(props: {
  grants: NamespaceGrant[];
  scope: GrantScope;
  namespace: NamespaceResponse;
  onEdit: (grant: NamespaceGrant) => void;
  onDelete: (grant: NamespaceGrant) => void;
}) {
  return (
    <Show when={props.grants.length > 0} fallback={<p class="hint">{t("access.noGrants")}</p>}>
      <div class="access-grants-table">
        <table>
          <thead>
            <tr>
              <th>{t("access.grantee")}</th>
              <th>{t("access.permission")}</th>
              <th>{t("access.updated")}</th>
              <th>{t("common.actions")}</th>
            </tr>
          </thead>
          <tbody>
            <For each={props.grants}>
              {(grant) => (
                <tr>
                  <td>
                    <div class="access-owner-cell">
                      <strong>{grantLabel(grant)}</strong>
                      <span>
                        {granteeKindLabel(grant.grantee.kind)} · {granteeDetail(grant)}
                      </span>
                    </div>
                  </td>
                  <td>
                    <span class="badge badge-blue">{actionSummary(grant.action)}</span>
                  </td>
                  <td>{formatTime(grant.updated_at)}</td>
                  <td>
                    <div class="row-actions">
                      <button class="btn btn-compact" onClick={() => props.onEdit(grant)}>
                        {t("common.edit")}
                      </button>
                      <button
                        class="btn btn-compact btn-danger"
                        onClick={() => props.onDelete(grant)}
                      >
                        {t("common.delete")}
                      </button>
                    </div>
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </div>
    </Show>
  );
}

export default function Access(props: { onClose?: () => void }) {
  const isModal = () => props.onClose !== undefined;
  const [tab, setTab] = createSignal<AccessTab>("tokens");
  const [session, setSession] = createSignal<DashboardSession | null>(null);
  const [tokens, setTokens] = createSignal<PersonalAccessToken[]>([]);
  const [accountNamespaces, setAccountNamespaces] = createSignal<NamespaceResponse[]>([]);
  const [accountNamespaceGrants, setAccountNamespaceGrants] = createSignal<
    Record<string, NamespaceGrant[]>
  >({});
  const [selectedAccountNamespace, setSelectedAccountNamespace] =
    createSignal<NamespaceResponse | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [showCreate, setShowCreate] = createSignal(false);
  const [form, setForm] = createSignal<TokenForm>({ ...EMPTY_FORM });
  const [scopeQuery, setScopeQuery] = createSignal("");
  const [scopeResults, setScopeResults] = createSignal<GrantableScope[]>([]);
  const [namespaceResults, setNamespaceResults] = createSignal<NamespacePatternScope[]>([]);
  const [selectedScopes, setSelectedScopes] = createSignal<SelectedScope[]>([]);
  const [scopeSearchLoading, setScopeSearchLoading] = createSignal(false);
  const [scopeSearchError, setScopeSearchError] = createSignal<string | null>(null);
  const [formError, setFormError] = createSignal<string | null>(null);
  const [saving, setSaving] = createSignal(false);
  const [createdToken, setCreatedToken] = createSignal<CreateTokenResponse | null>(null);
  const [revokeTarget, setRevokeTarget] = createSignal<PersonalAccessToken | null>(null);
  const [revoking, setRevoking] = createSignal(false);
  const [_revokeError, setRevokeError] = createSignal<string | null>(null);
  const [copied, setCopied] = createSignal<string | null>(null);
  const [claimHandle, setClaimHandle] = createSignal("");
  const [claimOwnerLabel, setClaimOwnerLabel] = createSignal("");
  const [claiming, setClaiming] = createSignal(false);
  const [namespaceMessage, setNamespaceMessage] = createSignal<string | null>(null);
  const [namespaceError, setNamespaceError] = createSignal<string | null>(null);
  const [grantModal, setGrantModal] = createSignal<GrantModalState | null>(null);
  const [grantForm, setGrantForm] = createSignal<GrantForm>({ ...EMPTY_GRANT_FORM });
  const [grantSaving, setGrantSaving] = createSignal(false);
  const [grantError, setGrantError] = createSignal<string | null>(null);
  const [observedUsers, setObservedUsers] = createSignal<ObservedIdentity[]>([]);
  const [observedUserLoading, setObservedUserLoading] = createSignal(false);
  const [grantDeleteTarget, setGrantDeleteTarget] = createSignal<{
    scope: GrantScope;
    namespace: NamespaceResponse;
    grant: NamespaceGrant;
  } | null>(null);
  const [grantDeleting, setGrantDeleting] = createSignal(false);
  const [releaseTarget, setReleaseTarget] = createSignal<NamespaceResponse | null>(null);
  const [releaseReason, setReleaseReason] = createSignal("");
  const [releasing, setReleasing] = createSignal(false);

  async function load() {
    setLoading(true);
    try {
      const nextSession = await fetchSession();
      setSession(nextSession);
      if (nextSession.auth_enabled) {
        setTokens(await fetchPersonalAccessTokens());
        const accountResponse = await fetchAccountNamespaces();
        setAccountNamespaces(accountResponse.namespaces);
        if (!selectedAccountNamespace() && accountResponse.namespaces.length > 0) {
          setSelectedAccountNamespace(accountResponse.namespaces[0]);
        }
        await refreshAccountGrantMap(accountResponse.namespaces);
      } else {
        setTokens([]);
        setAccountNamespaces([]);
        setAccountNamespaceGrants({});
      }
      setError(null);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setSession(null);
        setTokens([]);
        setAccountNamespaces([]);
        setError(null);
      } else {
        setError(e instanceof Error ? e.message : t("access.loadError"));
      }
    } finally {
      setLoading(false);
    }
  }

  async function refreshAccountGrantMap(namespaces = accountNamespaces()) {
    const entries = await Promise.all(
      namespaces.map(async (namespace) => {
        const response = await fetchAccountNamespaceGrants(namespace.handle);
        return [namespace.handle, response.grants] as const;
      }),
    );
    setAccountNamespaceGrants(Object.fromEntries(entries));
  }

  async function refreshAccountNamespaceGrants(handle: string) {
    const response = await fetchAccountNamespaceGrants(handle);
    setAccountNamespaceGrants({
      ...accountNamespaceGrants(),
      [handle]: response.grants,
    });
  }

  createEffect(() => {
    load();
  });

  function resetCreate() {
    setForm({ ...EMPTY_FORM });
    setScopeQuery("");
    setScopeResults([]);
    setNamespaceResults([]);
    setSelectedScopes([]);
    setScopeSearchError(null);
    setScopeSearchLoading(false);
    setFormError(null);
    setCreatedToken(null);
    setCopied(null);
  }

  function openCreate() {
    resetCreate();
    setShowCreate(true);
    void loadGrantableScopes("");
  }

  function closeCreate() {
    setShowCreate(false);
    resetCreate();
    load();
  }

  async function loadGrantableScopes(query = scopeQuery()) {
    setScopeSearchLoading(true);
    setScopeSearchError(null);
    try {
      const response = await fetchGrantableScopes({ q: query.trim(), n: 12 });
      setScopeResults(response.scopes);
      setNamespaceResults(response.namespace_patterns);
    } catch (e) {
      setScopeSearchError(e instanceof Error ? e.message : t("access.scopeSearchError"));
    } finally {
      setScopeSearchLoading(false);
    }
  }

  function addScope(scope: SelectedScope) {
    const key = scopeKey(scope.kind, scope.repository);
    if (selectedScopes().some((selected) => scopeKey(selected.kind, selected.repository) === key)) {
      return;
    }
    setSelectedScopes([...selectedScopes(), scope]);
    setFormError(null);
  }

  function removeScope(scope: SelectedScope) {
    const key = scopeKey(scope.kind, scope.repository);
    setSelectedScopes(
      selectedScopes().filter((selected) => scopeKey(selected.kind, selected.repository) !== key),
    );
  }

  function isScopeSelected(kind: ScopeKind, repository: string): boolean {
    const key = scopeKey(kind, repository);
    return selectedScopes().some(
      (selected) => scopeKey(selected.kind, selected.repository) === key,
    );
  }

  function updateScopeAction(scope: SelectedScope, action: OciAction, enabled: boolean) {
    const key = scopeKey(scope.kind, scope.repository);
    setSelectedScopes(
      selectedScopes().map((selected) => {
        if (scopeKey(selected.kind, selected.repository) !== key) return selected;
        const actions = enabled
          ? [...new Set([...selected.actions, action])]
          : selected.actions.filter((current) => current !== action);
        return {
          ...selected,
          actions: actions.sort((a, b) => ACTION_RANK[a] - ACTION_RANK[b]),
        };
      }),
    );
  }

  function validateForm(): string | null {
    if (!form().name.trim()) return t("access.nameRequired");
    if (selectedScopes().length === 0) return t("access.scopeRequired");
    if (selectedScopes().some((scope) => scope.actions.length === 0)) {
      return t("access.actionRequired");
    }
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
      const expiresInDays = form().expiresInDays === "never" ? null : Number(form().expiresInDays);
      const created = await createPersonalAccessToken({
        name: form().name.trim(),
        scopes: selectedScopes().map((scope) => ({
          repository: normalizeScopeRepository(scope.repository),
          actions: scope.actions,
        })),
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
      console.debug("[layerhouse] revoking token", { id: target.id, name: target.name });
      await deletePersonalAccessToken(target.id);
      await load();
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") {
        // Timeout: server-side delete may still have committed. Don't restore
        // the token — we'd be resurrecting a potentially-revoked credential.
        // Reload to get authoritative server state.
        console.warn("[layerhouse] revoke timed out, reloading to reconcile", { id: target.id });
        setError(t("access.revokeTimeout"));
        await load();
      } else if (e instanceof ApiError && e.status === 404) {
        // Token already gone — reload to confirm. Don't restore.
        console.warn("[layerhouse] revoke got 404, token already removed", { id: target.id });
        await load();
      } else {
        // Recoverable failure (network error, server error): restore token.
        console.warn("[layerhouse] revoke failed", {
          id: target.id,
          message: (e as Error).message,
        });
        setTokens(previous);
        setError(e instanceof Error ? e.message : t("access.revokeError"));
      }
    } finally {
      setRevokeTarget(null);
      setRevoking(false);
    }
  }

  async function refreshAccountNamespaces() {
    try {
      const response = await fetchAccountNamespaces();
      setAccountNamespaces(response.namespaces);
      await refreshAccountGrantMap(response.namespaces);
      if (!selectedAccountNamespace() && response.namespaces.length > 0) {
        setSelectedAccountNamespace(response.namespaces[0]);
      }
      if (
        selectedAccountNamespace() &&
        !response.namespaces.some(
          (namespace) => namespace.handle === selectedAccountNamespace()?.handle,
        )
      ) {
        setSelectedAccountNamespace(response.namespaces[0] ?? null);
      }
      return response.namespaces;
    } catch (e) {
      setNamespaceError(e instanceof Error ? e.message : t("access.namespaceLoadError"));
      return accountNamespaces();
    }
  }

  async function claimNamespaceHandle() {
    const handle = normalizeNamespaceHandle(claimHandle());
    if (!handle) {
      setNamespaceError(t("access.namespaceHandleRequired"));
      return;
    }
    setClaiming(true);
    setNamespaceError(null);
    setNamespaceMessage(null);
    try {
      const namespace = await claimNamespace(handle, {
        owner_label: claimOwnerLabel().trim() || userLabel(session()),
      });
      await refreshAccountNamespaces();
      setClaimHandle("");
      setClaimOwnerLabel("");
      setNamespaceMessage(t("access.namespaceClaimed", { handle: namespace.handle }));
    } catch (e) {
      const nextNamespaces = await refreshAccountNamespaces();
      if (
        e instanceof ApiError &&
        e.status === 409 &&
        nextNamespaces.some((item) => item.handle === handle)
      ) {
        setClaimHandle("");
        setClaimOwnerLabel("");
        setNamespaceMessage(t("access.namespaceAlreadyClaimedByYou", { handle }));
      } else {
        setNamespaceError(e instanceof Error ? e.message : t("access.namespaceClaimError"));
      }
    } finally {
      setClaiming(false);
    }
  }

  async function confirmReleaseNamespace() {
    const target = releaseTarget();
    if (!target) return;
    setReleasing(true);
    setNamespaceError(null);
    setNamespaceMessage(null);
    try {
      await releaseNamespace(target.handle, { reason: releaseReason().trim() || null });
      await refreshAccountNamespaces();
      setNamespaceMessage(t("access.namespaceReleased", { handle: target.handle }));
      setReleaseTarget(null);
      setReleaseReason("");
    } catch (e) {
      setNamespaceError(e instanceof Error ? e.message : t("access.namespaceReleaseError"));
    } finally {
      setReleasing(false);
    }
  }

  function openGrantModal(scope: GrantScope, namespace: NamespaceResponse, grant?: NamespaceGrant) {
    setGrantError(null);
    setObservedUsers([]);
    setGrantModal({ scope, namespace, grant });
    if (grant) {
      setGrantForm({
        granteeKind: grant.grantee.kind,
        groupName: grant.grantee.kind === "group" ? grant.grantee.id : "",
        userQuery: grant.grantee.kind === "user" ? grant.label : "",
        selectedUser: null,
        publicLabel: grant.grantee.kind === "public" ? grant.label : "Public",
        action: grant.action,
        reason: "",
      });
    } else {
      setGrantForm({ ...EMPTY_GRANT_FORM });
    }
  }

  function closeGrantModal() {
    if (grantSaving()) return;
    setGrantModal(null);
    setGrantError(null);
    setObservedUsers([]);
    setGrantForm({ ...EMPTY_GRANT_FORM });
  }

  async function searchUsers(query = grantForm().userQuery) {
    setObservedUserLoading(true);
    setGrantError(null);
    try {
      const response = await fetchObservedUsers(query.trim());
      setObservedUsers(response.users);
    } catch (e) {
      setGrantError(e instanceof Error ? e.message : t("access.observedUserSearchError"));
    } finally {
      setObservedUserLoading(false);
    }
  }

  function selectObservedUser(user: ObservedIdentity) {
    setGrantForm({
      ...grantForm(),
      selectedUser: user,
      userQuery: observedUserLabel(user),
    });
  }

  function setGrantGranteeKind(kind: GrantGranteeKind) {
    setGrantForm({
      ...grantForm(),
      granteeKind: kind,
      action: kind === "public" ? "pull" : grantForm().action,
    });
    setGrantError(null);
  }

  function buildGrantRequest(): {
    grantee: NamespaceGrantGrantee;
    label: string | null;
    action: OciAction;
    reason: string | null;
  } | null {
    const form = grantForm();
    const action = form.granteeKind === "public" ? "pull" : form.action;
    if (form.granteeKind === "group") {
      const group = form.groupName.trim();
      if (!group) {
        setGrantError(t("access.groupRequired"));
        return null;
      }
      if (!isProviderQualifiedId(group, "group")) {
        setGrantError(t("access.groupIdInvalid"));
        return null;
      }
      return {
        grantee: { kind: "group", id: group },
        label: group,
        action,
        reason: form.reason.trim() || null,
      };
    }
    if (form.granteeKind === "user") {
      const id = form.selectedUser?.principal || form.userQuery.trim();
      if (!id) {
        setGrantError(t("access.userRequired"));
        return null;
      }
      if (!isProviderQualifiedId(id, "user")) {
        setGrantError(t("access.userIdInvalid"));
        return null;
      }
      return {
        grantee: { kind: "user", id },
        label: form.selectedUser ? observedUserLabel(form.selectedUser) : form.userQuery.trim(),
        action,
        reason: form.reason.trim() || null,
      };
    }
    setGrantError(t("access.publicGrantDeprecated"));
    return null;
  }

  async function saveNamespaceGrant() {
    const modal = grantModal();
    if (!modal) return;
    const request = buildGrantRequest();
    if (!request) return;
    setGrantSaving(true);
    setGrantError(null);
    try {
      if (modal.grant) {
        await updateAccountNamespaceGrant(modal.namespace.handle, modal.grant.id, {
          action: request.action,
          label: request.label,
        });
      } else {
        await createAccountNamespaceGrant(modal.namespace.handle, request);
      }
      await refreshAccountNamespaceGrants(modal.namespace.handle);
      setNamespaceMessage(t("access.grantSaved"));
      setGrantModal(null);
      setGrantError(null);
      setObservedUsers([]);
      setGrantForm({ ...EMPTY_GRANT_FORM });
    } catch (e) {
      setGrantError(e instanceof Error ? e.message : t("access.grantSaveError"));
    } finally {
      setGrantSaving(false);
    }
  }

  async function confirmDeleteGrant() {
    const target = grantDeleteTarget();
    if (!target) return;
    setGrantDeleting(true);
    setGrantError(null);
    try {
      await deleteAccountNamespaceGrant(target.namespace.handle, target.grant.id);
      await refreshAccountNamespaceGrants(target.namespace.handle);
      setGrantDeleteTarget(null);
      setNamespaceMessage(t("access.grantDeleted"));
    } catch (e) {
      setGrantError(e instanceof Error ? e.message : t("access.grantDeleteError"));
    } finally {
      setGrantDeleting(false);
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

  const content = (
    <div>
      <Show when={!isModal()}>
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
      </Show>
      <Show when={isModal()}>
        <div class="access-modal-header">
          <h2>{t("access.title")}</h2>
          <div class="access-modal-header-actions">
            <Show when={session()?.auth_enabled && session()?.subject}>
              <button class="btn btn-primary" onClick={openCreate}>
                {t("access.createToken")}
              </button>
            </Show>
            <button class="btn btn-compact" onClick={() => props.onClose?.()}>
              {t("common.close")}
            </button>
          </div>
        </div>
      </Show>

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
                <button type="button" class="btn btn-primary" onClick={redirectToSignIn}>
                  {t("access.signInWithOidc")}
                </button>
              </div>
            }
          >
            <Show when={true}>
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
                  class={tab() === "namespaces" ? "active" : ""}
                  type="button"
                  onClick={() => setTab("namespaces")}
                >
                  {t("access.namespaces")}
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
            </Show>

            <Show when={tab() === "tokens"}>
              <div class="card">
                {tokens().length === 0 ? (
                  <EmptyState title={t("access.noTokens")} description={t("access.noTokensDesc")} />
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
                            <td>
                              <code>{token.prefix}</code>
                            </td>
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

            <Show when={tab() === "namespaces"}>
              <div class="card access-namespace-card">
                <div class="access-section-head">
                  <div>
                    <h2 class="card-header">{t("access.namespaceTitle")}</h2>
                    <p class="hint">{t("access.namespaceDesc")}</p>
                  </div>
                </div>

                {namespaceError() && <p class="warning">{namespaceError()}</p>}
                {namespaceMessage() && <p class="hint access-success">{namespaceMessage()}</p>}

                <div class="access-claim-box">
                  <div class="form-grid">
                    <div class="form-group">
                      <label>{t("access.namespaceHandle")}</label>
                      <input
                        value={claimHandle()}
                        placeholder={t("access.namespaceHandlePlaceholder")}
                        onInput={(event) => setClaimHandle(event.currentTarget.value)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter") void claimNamespaceHandle();
                        }}
                      />
                    </div>
                    <div class="form-group">
                      <label>{t("access.ownerLabel")}</label>
                      <input
                        value={claimOwnerLabel()}
                        placeholder={userLabel(session())}
                        onInput={(event) => setClaimOwnerLabel(event.currentTarget.value)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter") void claimNamespaceHandle();
                        }}
                      />
                    </div>
                  </div>
                  <div class="access-claim-actions">
                    <p class="hint">{t("access.namespaceClaimHint")}</p>
                    <button
                      class="btn btn-primary"
                      disabled={claiming()}
                      onClick={() => void claimNamespaceHandle()}
                    >
                      {claiming() ? t("common.creating") : t("access.claimNamespace")}
                    </button>
                  </div>
                </div>

                <div class="access-namespace-list">
                  <h3>{t("access.claimedNamespaces")}</h3>
                  <Show
                    when={accountNamespaces().length > 0}
                    fallback={<p class="hint">{t("access.noNamespaces")}</p>}
                  >
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
                        <For each={accountNamespaces()}>
                          {(namespace) => (
                            <tr>
                              <td>
                                <code>{namespace.handle}</code>
                              </td>
                              <td>
                                <div class="access-owner-cell">
                                  <strong>{namespace.owner_label}</strong>
                                  <span>{t(`access.ownerKind.${namespace.owner_kind}`)}</span>
                                </div>
                              </td>
                              <td>{formatTime(namespace.created_at)}</td>
                              <td>
                                <div class="row-actions">
                                  <button
                                    class="btn btn-compact"
                                    onClick={() =>
                                      copyValue(`namespace-${namespace.handle}`, namespace.handle)
                                    }
                                  >
                                    {copied() === `namespace-${namespace.handle}`
                                      ? t("common.copied")
                                      : t("common.copy")}
                                  </button>
                                  <button
                                    class="btn btn-compact"
                                    onClick={() => setReleaseTarget(namespace)}
                                  >
                                    {t("access.releaseNamespace")}
                                  </button>
                                  <button
                                    class="btn btn-compact"
                                    onClick={() => setSelectedAccountNamespace(namespace)}
                                  >
                                    {t("access.manageGrants")}
                                  </button>
                                </div>
                              </td>
                            </tr>
                          )}
                        </For>
                      </tbody>
                    </table>
                  </Show>
                </div>

                <Show when={selectedAccountNamespace()}>
                  {(namespace) => (
                    <div class="access-grants-panel">
                      <div class="access-section-head">
                        <div>
                          <h3>{t("access.namespaceGrants")}</h3>
                          <p class="hint">
                            {t("access.namespaceGrantDesc", { handle: namespace().handle })}
                          </p>
                        </div>
                        <button
                          class="btn btn-primary"
                          onClick={() => openGrantModal("account", namespace())}
                        >
                          {t("access.addGrant")}
                        </button>
                      </div>
                      <p class="hint">{t("access.grantHelper")}</p>
                      <GrantTable
                        grants={accountNamespaceGrants()[namespace().handle] ?? []}
                        scope="account"
                        namespace={namespace()}
                        onEdit={(grant) => openGrantModal("account", namespace(), grant)}
                        onDelete={(grant) =>
                          setGrantDeleteTarget({
                            scope: "account",
                            namespace: namespace(),
                            grant,
                          })
                        }
                      />
                    </div>
                  )}
                </Show>
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
                  <For
                    each={session()?.scopes ?? []}
                    fallback={<span class="muted">{t("common.none")}</span>}
                  >
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
                      <label>{t("access.scopeSearch")}</label>
                      <div class="access-scope-search">
                        <input
                          value={scopeQuery()}
                          placeholder={t("access.scopeSearchPlaceholder")}
                          onInput={(event) => setScopeQuery(event.currentTarget.value)}
                          onKeyDown={(event) => {
                            if (event.key === "Enter") {
                              void loadGrantableScopes();
                            }
                          }}
                        />
                        <button
                          class="btn"
                          disabled={scopeSearchLoading()}
                          onClick={() => void loadGrantableScopes()}
                        >
                          {scopeSearchLoading() ? t("common.loading") : t("access.searchScopes")}
                        </button>
                      </div>
                      <p class="hint">{t("access.scopeSearchHint")}</p>
                      {scopeSearchError() && <p class="warning">{scopeSearchError()}</p>}
                    </div>
                  </div>

                  <div class="access-scope-picker">
                    <div>
                      <h3>{t("access.availableRepositories")}</h3>
                      <div class="access-scope-results">
                        <For
                          each={scopeResults()}
                          fallback={<p class="hint">{t("access.noRepositoryScopes")}</p>}
                        >
                          {(scope) => (
                            <div class="access-scope-option">
                              <div>
                                <strong>{scope.repository}</strong>
                                <span>
                                  {t("access.maxGrantable", {
                                    action: actionLabel(scope.max_grantable),
                                  })}{" "}
                                  · {grantSourceLabel(scope.grant_source)}
                                </span>
                              </div>
                              <button
                                class="btn btn-compact"
                                disabled={isScopeSelected("repository", scope.repository)}
                                onClick={() => addScope(scopeFromRepository(scope))}
                              >
                                {isScopeSelected("repository", scope.repository)
                                  ? t("access.addedScope")
                                  : t("access.addScope")}
                              </button>
                            </div>
                          )}
                        </For>
                      </div>
                    </div>

                    <div>
                      <h3>{t("access.availablePatterns")}</h3>
                      <p class="warning access-pattern-warning">
                        {t("access.namespacePatternWarning")}
                      </p>
                      <div class="access-scope-results">
                        <For
                          each={namespaceResults()}
                          fallback={<p class="hint">{t("access.noNamespaceScopes")}</p>}
                        >
                          {(scope) => {
                            const repository = normalizeScopeRepository(scope.pattern);
                            return (
                              <div class="access-scope-option access-scope-option-pattern">
                                <div>
                                  <strong>{repository}</strong>
                                  <span>
                                    {t("access.currentMatchCount", {
                                      count: scope.current_match_count,
                                    })}{" "}
                                    ·{" "}
                                    {t("access.maxGrantable", {
                                      action: actionLabel(scope.max_grantable),
                                    })}{" "}
                                    · {grantSourceLabel(scope.grant_source)}
                                  </span>
                                </div>
                                <button
                                  class="btn btn-compact"
                                  disabled={isScopeSelected("namespace_pattern", repository)}
                                  onClick={() => addScope(scopeFromPattern(scope))}
                                >
                                  {isScopeSelected("namespace_pattern", repository)
                                    ? t("access.addedScope")
                                    : t("access.addPatternScope")}
                                </button>
                              </div>
                            );
                          }}
                        </For>
                      </div>
                    </div>
                  </div>

                  <div class="advanced">
                    <h3>{t("access.selectedScopes")}</h3>
                    <Show
                      when={selectedScopes().length > 0}
                      fallback={<p class="hint">{t("access.selectedScopesEmpty")}</p>}
                    >
                      <div class="access-selected-scopes">
                        <For each={selectedScopes()}>
                          {(scope) => (
                            <div class="access-selected-scope">
                              <div class="access-selected-scope-header">
                                <div>
                                  <strong>{scope.displayName}</strong>
                                  <span>
                                    {scope.kind === "namespace_pattern"
                                      ? t("access.namespacePattern")
                                      : t("common.repository")}{" "}
                                    ·{" "}
                                    {t("access.maxGrantable", {
                                      action: actionLabel(scope.maxGrantable),
                                    })}{" "}
                                    · {grantSourceLabel(scope.grantSource)}
                                  </span>
                                </div>
                                <button class="btn btn-compact" onClick={() => removeScope(scope)}>
                                  {t("common.unlink")}
                                </button>
                              </div>
                              <div class="access-scope-grid">
                                <For each={ACTIONS}>
                                  {(action) => (
                                    <label class="checkbox-row">
                                      <input
                                        type="checkbox"
                                        checked={scope.actions.includes(action)}
                                        disabled={!actionAllowed(action, scope.maxGrantable)}
                                        onChange={(event) =>
                                          updateScopeAction(
                                            scope,
                                            action,
                                            event.currentTarget.checked,
                                          )
                                        }
                                      />
                                      <span>{actionLabel(action)}</span>
                                    </label>
                                  )}
                                </For>
                              </div>
                              <p class="hint">
                                {t("access.selectedActions", {
                                  actions: formatScopeActions(scope.actions) || t("common.none"),
                                })}
                              </p>
                            </div>
                          )}
                        </For>
                      </div>
                    </Show>
                  </div>

                  <div class="modal-actions">
                    <button class="btn" onClick={closeCreate}>
                      {t("common.cancel")}
                    </button>
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
                    <button class="btn" onClick={openCreate}>
                      {t("access.createAnother")}
                    </button>
                    <button class="btn btn-primary" onClick={closeCreate}>
                      {t("common.done")}
                    </button>
                  </div>
                </>
              )}
            </Show>
          </div>
        </div>
      </Show>

      <Show when={grantModal()}>
        {(modal) => (
          <div class="modal-overlay" onClick={closeGrantModal}>
            <div class="modal modal-wide" onClick={(event) => event.stopPropagation()}>
              <h2>
                {modal().grant
                  ? t("access.editGrantTitle", { handle: modal().namespace.handle })
                  : t("access.addGrantTitle", { handle: modal().namespace.handle })}
              </h2>
              <p class="hint modal-copy">{t("access.grantHelper")}</p>
              {grantError() && <p class="warning modal-copy">{grantError()}</p>}

              <div class="access-grant-form">
                <div class="segmented" role="tablist">
                  <For each={["group", "user"] as GrantGranteeKind[]}>
                    {(kind) => (
                      <button
                        type="button"
                        class={grantForm().granteeKind === kind ? "active" : ""}
                        disabled={Boolean(modal().grant)}
                        onClick={() => setGrantGranteeKind(kind)}
                      >
                        {granteeKindLabel(kind)}
                      </button>
                    )}
                  </For>
                </div>

                <Show when={grantForm().granteeKind === "group"}>
                  <div class="form-group">
                    <label>{t("access.groupId")}</label>
                    <input
                      value={grantForm().groupName}
                      disabled={Boolean(modal().grant)}
                      placeholder={t("access.groupIdPlaceholder")}
                      onInput={(event) =>
                        setGrantForm({ ...grantForm(), groupName: event.currentTarget.value })
                      }
                    />
                    <p class="hint">{t("access.groupIdHint")}</p>
                  </div>
                </Show>

                <Show when={grantForm().granteeKind === "user"}>
                  <div class="form-group">
                    <label>{t("access.user")}</label>
                    <div class="access-scope-search">
                      <input
                        value={grantForm().userQuery}
                        disabled={Boolean(modal().grant)}
                        placeholder={t("access.userSearchPlaceholder")}
                        onInput={(event) =>
                          setGrantForm({
                            ...grantForm(),
                            selectedUser: null,
                            userQuery: event.currentTarget.value,
                          })
                        }
                        onKeyDown={(event) => {
                          if (event.key === "Enter") void searchUsers();
                        }}
                      />
                      <button
                        class="btn"
                        disabled={observedUserLoading() || Boolean(modal().grant)}
                        onClick={() => void searchUsers()}
                      >
                        {observedUserLoading() ? t("common.loading") : t("access.searchUsers")}
                      </button>
                    </div>
                    <div class="access-user-results">
                      <For each={observedUsers()}>
                        {(user) => (
                          <button
                            type="button"
                            class={
                              grantForm().selectedUser?.subject === user.subject ? "active" : ""
                            }
                            onClick={() => selectObservedUser(user)}
                          >
                            <strong>{observedUserLabel(user)}</strong>
                            <span>{user.email || user.subject}</span>
                          </button>
                        )}
                      </For>
                    </div>
                    <p class="hint">{t("access.userIdHint")}</p>
                  </div>
                </Show>

                <Show when={grantForm().granteeKind === "public"}>
                  <div class="access-public-grant">
                    <strong>{t("access.publicPullOnly")}</strong>
                    <span>{t("access.publicPullOnlyDesc")}</span>
                  </div>
                </Show>

                <div class="form-group">
                  <label>{t("access.permission")}</label>
                  <div class="access-action-ladder">
                    <For each={ACTIONS}>
                      {(action) => (
                        <button
                          type="button"
                          class={grantForm().action === action ? "active" : ""}
                          disabled={grantForm().granteeKind === "public" && action !== "pull"}
                          onClick={() => setGrantForm({ ...grantForm(), action })}
                        >
                          {actionLabel(action)}
                        </button>
                      )}
                    </For>
                  </div>
                  <p class="hint">
                    {grantForm().granteeKind === "public"
                      ? t("access.publicPullOnlyDesc")
                      : actionSummary(grantForm().action)}
                  </p>
                </div>
              </div>

              <div class="modal-actions">
                <button class="btn" onClick={closeGrantModal}>
                  {t("common.cancel")}
                </button>
                <button
                  class="btn btn-primary"
                  disabled={grantSaving()}
                  onClick={saveNamespaceGrant}
                >
                  {grantSaving() ? t("common.saving") : t("common.save")}
                </button>
              </div>
            </div>
          </div>
        )}
      </Show>

      <Show when={grantDeleteTarget()}>
        {(target) => (
          <div class="modal-overlay" onClick={() => setGrantDeleteTarget(null)}>
            <div class="modal" onClick={(event) => event.stopPropagation()}>
              <h2>{t("access.deleteGrantTitle", { label: grantLabel(target().grant) })}</h2>
              <p class="warning">{t("access.deleteGrantWarning")}</p>
              {grantError() && <p class="warning">{grantError()}</p>}
              <div class="modal-actions">
                <button class="btn" onClick={() => setGrantDeleteTarget(null)}>
                  {t("common.cancel")}
                </button>
                <button
                  class="btn btn-danger"
                  disabled={grantDeleting()}
                  onClick={confirmDeleteGrant}
                >
                  {grantDeleting() ? t("common.deleting") : t("common.delete")}
                </button>
              </div>
            </div>
          </div>
        )}
      </Show>

      <Show when={releaseTarget()}>
        {(target) => (
          <div class="modal-overlay" onClick={() => setReleaseTarget(null)}>
            <div class="modal" onClick={(event) => event.stopPropagation()}>
              <h2>{t("access.releaseNamespaceTitle", { handle: target().handle })}</h2>
              <p class="hint">{t("access.releaseNamespaceDesc")}</p>
              <div class="form-group">
                <label>{t("access.releaseReason")}</label>
                <input
                  value={releaseReason()}
                  placeholder={t("access.releaseReasonPlaceholder")}
                  onInput={(event) => setReleaseReason(event.currentTarget.value)}
                />
              </div>
              <div class="modal-actions">
                <button class="btn" onClick={() => setReleaseTarget(null)}>
                  {t("common.cancel")}
                </button>
                <button
                  class="btn btn-danger"
                  disabled={releasing()}
                  onClick={confirmReleaseNamespace}
                >
                  {releasing() ? t("common.deleting") : t("access.releaseNamespace")}
                </button>
              </div>
            </div>
          </div>
        )}
      </Show>

      <Show when={revokeTarget()}>
        {(target) => (
          <div class="modal-overlay" onClick={() => setRevokeTarget(null)}>
            <div class="modal" onClick={(event) => event.stopPropagation()}>
              <h2>{t("access.revokeTitle", { name: target().name })}</h2>
              <p class="warning">{t("access.revokeWarning", { prefix: target().prefix })}</p>
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

  return (
    <Show when={isModal()} fallback={content}>
      <div class="modal-overlay" onClick={() => props.onClose?.()}>
        <div class="modal modal-wide access-modal" onClick={(e) => e.stopPropagation()}>
          {content}
        </div>
      </div>
    </Show>
  );
}
