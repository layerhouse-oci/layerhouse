import { A } from "@solidjs/router";
import { createEffect, createMemo, createSignal, For, onMount, Show, type Setter } from "solid-js";
import EmptyState from "../components/EmptyState";
import ErrorBanner from "../components/ErrorBanner";
import LoadingSpinner from "../components/LoadingSpinner";
import {
  ApiError,
  createAdminNamespaceGrant,
  deleteAdminNamespaceGrant,
  fetchAdminNamespaceGrantAudit,
  fetchAdminNamespaceGrants,
  fetchMirrorRules,
  fetchNamespaces,
  fetchObservedUsers,
  fetchPolicySets,
  fetchProxyCaches,
  fetchRepositories,
  fetchSession,
  fetchSyncJobs,
  redirectToSignIn,
  updateAdminNamespaceGrant,
} from "../lib/api";
import {
  formatAgo,
  formatBytes,
  formatTime,
  prefixLabel,
  strategyLabel,
  upstreamLabel,
} from "../lib/format";
import { t } from "../lib/i18n";
import type {
  DashboardSession,
  MirrorRule,
  NamespaceGrant,
  NamespaceGrantAuditEvent,
  NamespaceGrantGrantee,
  NamespaceResponse,
  ObservedIdentity,
  OciAction,
  PolicySet,
  ProxyCache,
  PutNamespaceGrantRequest,
  RepositorySummary,
  SyncJob,
} from "../lib/types";

type LoadStatus = "idle" | "loading" | "ready" | "error";
type GrantGranteeKind = NamespaceGrantGrantee["kind"];
type ResourceKind =
  | "repository"
  | "namespace"
  | "handle"
  | "policy"
  | "mirror-rule"
  | "sync-job"
  | "proxy-cache"
  | "identity"
  | "setup";

interface SourceState<T> {
  status: LoadStatus;
  data: T;
  error: string | null;
  lastLoaded: number | null;
}

interface DetailPair {
  label: string;
  value: string;
}

interface ResourceAction {
  label: string;
  description: string;
  href?: string;
  tone?: "primary" | "neutral" | "warn";
  disabled?: boolean;
}

interface ResourceRow {
  key: string;
  id: string;
  kind: ResourceKind;
  title: string;
  subtitle: string;
  source: string;
  status: string;
  statusTone: "good" | "warn" | "danger" | "neutral";
  updatedAt: number | null;
  description: string;
  actions: ResourceAction[];
  details: DetailPair[];
  policy?: PolicySet;
  namespace?: NamespaceResponse;
}

interface SourceCard {
  id: string;
  label: string;
  status: LoadStatus;
  count: number;
  lastLoaded: number | null;
  error: string | null;
  onRefresh: () => void;
}

interface AdminGrantEditor {
  mode: "create" | "edit";
  namespace: NamespaceResponse;
  grant?: NamespaceGrant;
}

interface AdminGrantForm {
  granteeKind: GrantGranteeKind;
  groupName: string;
  userQuery: string;
  selectedUser: ObservedIdentity | null;
  publicLabel: string;
  action: OciAction;
  label: string;
  reason: string;
}

interface AdminGrantDeleteTarget {
  namespace: NamespaceResponse;
  grant: NamespaceGrant;
}

type AuditOperationTone = "good" | "warn" | "danger";

const RESOURCE_KIND_ORDER: Record<ResourceKind, number> = {
  policy: 0,
  repository: 1,
  namespace: 2,
  handle: 2,
  "sync-job": 3,
  "mirror-rule": 4,
  "proxy-cache": 5,
  identity: 6,
  setup: 7,
};

const KINDS: ResourceKind[] = [
  "repository",
  "namespace",
  "handle",
  "policy",
  "mirror-rule",
  "sync-job",
  "proxy-cache",
  "identity",
  "setup",
];

const GRANT_ACTIONS: OciAction[] = ["pull", "create", "update", "delete"];

const EMPTY_GRANT_FORM: AdminGrantForm = {
  granteeKind: "group",
  groupName: "",
  userQuery: "",
  selectedUser: null,
  publicLabel: "Public",
  action: "pull",
  label: "",
  reason: "",
};

function emptySource<T>(data: T): SourceState<T> {
  return { status: "idle", data, error: null, lastLoaded: null };
}

function nowEpoch(): number {
  return Math.floor(Date.now() / 1000);
}

function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof ApiError && error.status === 403) return t("cluster.adminRequired");
  return error instanceof Error ? error.message : fallback;
}

async function loadSource<T>(
  setSource: Setter<SourceState<T>>,
  fallback: string,
  loader: () => Promise<T>,
) {
  setSource((previous) => ({ ...previous, status: "loading", error: null }));
  try {
    const data = await loader();
    setSource({ status: "ready", data, error: null, lastLoaded: nowEpoch() });
  } catch (error) {
    setSource((previous) => ({
      ...previous,
      status: "error",
      error: errorMessage(error, fallback),
    }));
  }
}

function kindLabel(kind: ResourceKind): string {
  return t(`admin.kind.${kind}`);
}

function policySourceLabel(policy: PolicySet): string {
  return t(`admin.policySource.${policy.source}`);
}

function loadStatusLabel(status: LoadStatus): string {
  return t(`admin.sourceStatus.${status}`);
}

function sourceHint(source: SourceCard): string {
  if (source.status === "error") return source.error ?? t("common.unknownError");
  if (source.id === "principals" && source.status === "idle") {
    return t("admin.sourceHint.principalsIdle");
  }
  if (source.status === "idle") return t("admin.sourceHint.idle");
  if (source.status === "loading") return t("admin.sourceHint.loading");
  return t("admin.sourceHint.ready", { count: source.count });
}

function compareResourceRows(a: ResourceRow, b: ResourceRow, groupByKind: boolean): number {
  if (groupByKind) {
    const kindDelta = RESOURCE_KIND_ORDER[a.kind] - RESOURCE_KIND_ORDER[b.kind];
    if (kindDelta !== 0) return kindDelta;
  }
  const updatedDelta = (b.updatedAt ?? 0) - (a.updatedAt ?? 0);
  if (updatedDelta !== 0) return updatedDelta;
  return a.title.localeCompare(b.title);
}

function repositoryNamespace(name: string): string {
  return name.split("/")[0] || name;
}

function rowMatches(row: ResourceRow, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  return [
    row.id,
    row.title,
    row.subtitle,
    row.source,
    row.status,
    row.description,
    ...row.details.flatMap((detail) => [detail.label, detail.value]),
  ]
    .join(" ")
    .toLowerCase()
    .includes(needle);
}

function policyEditable(policy: PolicySet): boolean {
  return policy.editable ?? policy.source === "raft";
}

function isProviderQualifiedId(value: string, kind: "user" | "group"): boolean {
  const parts = value.trim().split(":");
  return parts.length === 3 && parts[0] !== "" && parts[1] === kind && parts[2] !== "";
}

function observedUserLabel(user: ObservedIdentity): string {
  return user.display_name || user.username || user.email || user.subject;
}

function grantLabel(grant: NamespaceGrant): string {
  if (grant.label) return grant.label;
  if (grant.grantee.kind === "public") return t("access.grantee.public");
  return grant.grantee.id;
}

function grantDetail(grant: NamespaceGrant): string {
  if (grant.grantee.kind === "public") return t("access.publicPullOnly");
  return grant.grantee.id;
}

function actionLabel(action: OciAction): string {
  return t(`access.action.${action}`);
}

function actionSummary(action: OciAction): string {
  return t("access.grantAllows", { action: actionLabel(action) });
}

function granteeKindLabel(kind: GrantGranteeKind): string {
  return t(`access.grantee.${kind}`);
}

function auditOperationLabel(operation: NamespaceGrantAuditEvent["operation"]): string {
  return t(`admin.auditOperation.${operation}`);
}

function auditOperationTone(operation: NamespaceGrantAuditEvent["operation"]): AuditOperationTone {
  if (operation === "create") return "good";
  if (operation === "delete") return "danger";
  return "warn";
}

function auditGrantSummary(grant: NamespaceGrant | null): string {
  if (!grant) return t("common.none");
  return t("admin.auditGrantSummary", {
    label: grantLabel(grant),
    kind: granteeKindLabel(grant.grantee.kind),
    detail: grantDetail(grant),
    action: actionLabel(grant.action),
  });
}

function auditChangeSummary(event: NamespaceGrantAuditEvent): string {
  if (event.operation === "create") {
    return t("admin.auditChange.create", { after: auditGrantSummary(event.after) });
  }
  if (event.operation === "delete") {
    return t("admin.auditChange.delete", { before: auditGrantSummary(event.before) });
  }
  return t("admin.auditChange.update", {
    before: auditGrantSummary(event.before),
    after: auditGrantSummary(event.after),
  });
}

function policyActions(policy: PolicySet): ResourceAction[] {
  if (policyEditable(policy)) {
    return [
      {
        label: t("admin.action.editRaftPolicy"),
        description: t("admin.action.editRaftPolicyDesc"),
        href: "/policies",
        tone: "primary",
      },
    ];
  }
  return [
    {
      label: t("admin.action.readOnlyPolicy"),
      description: t(`admin.action.readOnlyPolicyDesc.${policy.source}`),
      tone: "warn",
      disabled: true,
    },
  ];
}

function repositoryRows(repositories: RepositorySummary[]): ResourceRow[] {
  return repositories.map((repo) => ({
    key: `repository:${repo.name}`,
    id: repo.name,
    kind: "repository",
    title: repo.name,
    subtitle: t("admin.repositorySubtitle", { namespace: repositoryNamespace(repo.name) }),
    source: t("admin.source.repositories"),
    status: t("admin.repositoryAccess", { action: repo.access_level }),
    statusTone: repo.access_level === "delete" ? "good" : "neutral",
    updatedAt: repo.last_modified,
    description: repo.description || t("admin.noDescription"),
    actions: [
      {
        label: t("admin.action.openRepository"),
        description: t("admin.action.openRepositoryDesc"),
        href: `/repos/${repo.name}`,
        tone: "primary",
      },
    ],
    details: [
      { label: t("common.tags"), value: String(repo.tag_count) },
      { label: t("common.digests"), value: String(repo.manifest_count) },
      { label: t("common.size"), value: formatBytes(repo.stored_size_bytes) },
      { label: t("admin.manifestBytes"), value: formatBytes(repo.manifest_size_bytes) },
      { label: t("admin.visibility"), value: repo.visibility },
      { label: t("admin.grantSource"), value: t(`access.grantSource.${repo.grant_source}`) },
      { label: t("admin.maxGrantable"), value: repo.max_grantable },
    ],
  }));
}

function namespaceRows(namespaces: NamespaceResponse[]): ResourceRow[] {
  return namespaces.map((namespace) => ({
    key: `namespace:${namespace.handle}`,
    id: namespace.handle,
    kind: "namespace",
    title: namespace.handle,
    subtitle: t("admin.namespaceSubtitle", { owner: namespace.owner_label }),
    source: t("admin.source.namespaces"),
    status: t("admin.claimed"),
    statusTone: "good",
    updatedAt: namespace.created_at,
    description: t("admin.namespaceDescription", { generation: namespace.generation }),
    actions: [
      {
        label: t("admin.action.inspectGrants"),
        description: t("admin.action.inspectGrantsDesc"),
        tone: "primary",
      },
    ],
    details: [
      { label: t("admin.owner"), value: namespace.owner_label },
      { label: t("admin.ownerKind"), value: namespace.owner_kind },
      { label: t("admin.generation"), value: String(namespace.generation) },
      { label: t("admin.created"), value: formatTime(namespace.created_at) },
    ],
    namespace,
  }));
}

function observedHandleRows(repositories: RepositorySummary[]): ResourceRow[] {
  const counts = new Map<string, number>();
  repositories.forEach((repo) => {
    const handle = repositoryNamespace(repo.name);
    counts.set(handle, (counts.get(handle) ?? 0) + 1);
  });
  return [...counts.entries()].map(([handle, count]) => ({
    key: `handle:${handle}`,
    id: handle,
    kind: "handle",
    title: handle,
    subtitle: t("admin.observedHandleSubtitle", { count }),
    source: t("admin.source.repositories"),
    status: t("admin.openRegistry"),
    statusTone: "warn",
    updatedAt: null,
    description: t("admin.observedHandleDescription"),
    actions: [
      {
        label: t("admin.action.observedHandle"),
        description: t("admin.action.observedHandleDesc"),
        tone: "warn",
        disabled: true,
      },
    ],
    details: [
      { label: t("common.repositories"), value: String(count) },
      { label: t("admin.authorization"), value: t("admin.authDisabled") },
    ],
  }));
}

function policyRows(policies: PolicySet[]): ResourceRow[] {
  return policies.map((policy) => ({
    key: `policy:${policy.id}`,
    id: policy.id,
    kind: "policy",
    title: policy.name,
    subtitle: policy.id,
    source: policySourceLabel(policy),
    status: policy.enabled ? t("policies.enabled") : t("policies.disabled"),
    statusTone: policy.enabled ? "good" : "warn",
    updatedAt: policy.updated_at,
    description: policy.description || t("admin.policyDescription"),
    actions: policyActions(policy),
    details: [
      { label: t("policies.source"), value: policySourceLabel(policy) },
      {
        label: t("admin.editability"),
        value: policyEditable(policy) ? t("admin.editable") : t("admin.readOnly"),
      },
      { label: t("admin.createdBy"), value: policy.created_by },
      { label: t("admin.updatedBy"), value: policy.updated_by },
    ],
    policy,
  }));
}

function mirrorRuleRows(rules: MirrorRule[]): ResourceRow[] {
  return rules.map((rule) => ({
    key: `mirror-rule:${rule.id}`,
    id: rule.id,
    kind: "mirror-rule",
    title: rule.local_prefix,
    subtitle: upstreamLabel(rule.upstream_registry, rule.upstream_prefix),
    source: t("admin.source.mirrorRules"),
    status: rule.schedule ? t("common.schedule") : t("common.manual"),
    statusTone: "neutral",
    updatedAt: rule.created_at,
    description: t("admin.mirrorRuleDescription"),
    actions: [
      {
        label: t("admin.action.openMirror"),
        description: t("admin.action.openMirrorDesc"),
        href: "/mirror",
        tone: "primary",
      },
    ],
    details: [
      { label: t("common.id"), value: rule.id },
      {
        label: t("common.upstream"),
        value: upstreamLabel(rule.upstream_registry, rule.upstream_prefix),
      },
      { label: t("common.schedule"), value: rule.schedule || t("common.manual") },
      { label: t("mirror.strategy"), value: strategyLabel(rule.strategy) },
      { label: t("common.proxy"), value: rule.outbound_proxy.protocol },
    ],
  }));
}

function syncJobRows(jobs: SyncJob[]): ResourceRow[] {
  return jobs.map((job) => ({
    key: `sync-job:${job.id}`,
    id: job.id,
    kind: "sync-job",
    title: job.rule_name || job.rule_id || job.image || job.id,
    subtitle: job.image,
    source: t("admin.source.jobs"),
    status: job.last_error ? t("admin.jobErrored") : job.status,
    statusTone: job.last_error ? "danger" : job.status === "Running" ? "warn" : "good",
    updatedAt: job.last_run_at ?? job.claimed_at ?? job.next_run_at,
    description: job.last_error || t("admin.jobDescription"),
    actions: [
      {
        label: t("admin.action.openJobs"),
        description: t("admin.action.openJobsDesc"),
        href: job.kind === "proxy_cache" ? "/proxy-cache" : "/mirror",
        tone: "primary",
      },
    ],
    details: [
      { label: t("common.id"), value: job.id },
      { label: t("common.type"), value: job.kind || t("common.unknown") },
      { label: t("admin.rule"), value: job.rule_id || t("common.none") },
      { label: t("admin.nextRun"), value: formatTime(job.next_run_at) },
      { label: t("admin.lastRun"), value: formatTime(job.last_run_at) },
      { label: t("admin.claimedBy"), value: job.claimed_by || t("common.none") },
    ],
  }));
}

function proxyCacheRows(caches: ProxyCache[]): ResourceRow[] {
  return caches.map((cache) => ({
    key: `proxy-cache:${cache.id}`,
    id: cache.id,
    kind: "proxy-cache",
    title: cache.local_prefix,
    subtitle: upstreamLabel(cache.upstream_registry, cache.upstream_prefix),
    source: t("admin.source.proxyCaches"),
    status: cache.warm_schedule ? t("common.schedule") : t("common.manual"),
    statusTone: "neutral",
    updatedAt: cache.created_at,
    description: t("admin.proxyCacheDescription"),
    actions: [
      {
        label: t("admin.action.openProxyCache"),
        description: t("admin.action.openProxyCacheDesc"),
        href: "/proxy-cache",
        tone: "primary",
      },
    ],
    details: [
      { label: t("common.id"), value: cache.id },
      {
        label: t("common.upstream"),
        value: upstreamLabel(cache.upstream_registry, cache.upstream_prefix),
      },
      { label: t("common.repository"), value: prefixLabel(cache.local_prefix) },
      { label: t("common.schedule"), value: cache.warm_schedule || t("common.manual") },
      { label: t("admin.warmFilters"), value: String(cache.warm_filters.length) },
      { label: t("common.proxy"), value: cache.outbound_proxy.protocol },
    ],
  }));
}

function identityRows(identities: ObservedIdentity[]): ResourceRow[] {
  return identities.map((identity) => ({
    key: `identity:${identity.principal}`,
    id: identity.principal,
    kind: "identity",
    title: identity.display_name || identity.username || identity.email || identity.subject,
    subtitle: identity.principal,
    source: t("admin.source.principals"),
    status: t("admin.observed"),
    statusTone: "neutral",
    updatedAt: identity.last_seen_at,
    description: t("admin.identityDescription"),
    actions: [
      {
        label: t("admin.action.observedPrincipal"),
        description: t("admin.action.observedPrincipalDesc"),
        disabled: true,
      },
    ],
    details: [
      { label: t("admin.subject"), value: identity.subject },
      { label: t("common.username"), value: identity.username || t("common.none") },
      { label: t("admin.email"), value: identity.email || t("common.none") },
      { label: t("admin.groups"), value: String(identity.groups.length) },
      { label: t("admin.groupIds"), value: String(identity.group_ids.length) },
    ],
  }));
}

function setupRows(): ResourceRow[] {
  return [
    {
      key: "setup:auth-config",
      id: "auth-config",
      kind: "setup",
      title: t("admin.setupAuthTitle"),
      subtitle: t("admin.setupAuthSubtitle"),
      source: t("admin.source.setup"),
      status: t("admin.todo"),
      statusTone: "warn",
      updatedAt: null,
      description: t("admin.setupAuthDescription"),
      actions: [
        {
          label: t("admin.action.configureAuth"),
          description: t("admin.action.configureAuthDesc"),
          tone: "warn",
          disabled: true,
        },
      ],
      details: [
        { label: t("admin.authorization"), value: t("admin.authDisabled") },
        { label: t("admin.nextStep"), value: t("admin.setupAuthNextStep") },
      ],
    },
    {
      key: "setup:config-policy",
      id: "config-policy",
      kind: "setup",
      title: t("admin.setupPolicyTitle"),
      subtitle: t("admin.setupPolicySubtitle"),
      source: t("admin.source.setup"),
      status: t("admin.todo"),
      statusTone: "warn",
      updatedAt: null,
      description: t("admin.setupPolicyDescription"),
      actions: [
        {
          label: t("admin.action.bootstrapPolicy"),
          description: t("admin.action.bootstrapPolicyDesc"),
          tone: "warn",
          disabled: true,
        },
      ],
      details: [
        { label: t("policies.source"), value: t("admin.policySource.config") },
        { label: t("admin.nextStep"), value: t("admin.setupPolicyNextStep") },
      ],
    },
  ];
}

function ResourceInspector(props: {
  row: ResourceRow;
  authEnabled: boolean;
  grants: SourceState<NamespaceGrant[]>;
  audit: SourceState<NamespaceGrantAuditEvent[]>;
  grantEditor: AdminGrantEditor | null;
  grantForm: AdminGrantForm;
  grantError: string | null;
  grantMessage: string | null;
  grantSaving: boolean;
  grantDeleteTarget: AdminGrantDeleteTarget | null;
  grantDeleteReason: string;
  grantDeleting: boolean;
  observedUsers: ObservedIdentity[];
  observedUserLoading: boolean;
  onStartCreateGrant: (namespace: NamespaceResponse) => void;
  onStartEditGrant: (namespace: NamespaceResponse, grant: NamespaceGrant) => void;
  onCloseGrantEditor: () => void;
  onUpdateGrantForm: (form: AdminGrantForm) => void;
  onSetGrantGranteeKind: (kind: GrantGranteeKind) => void;
  onSearchGrantUsers: () => void;
  onSelectGrantUser: (user: ObservedIdentity) => void;
  onSaveGrant: () => void;
  onStartDeleteGrant: (namespace: NamespaceResponse, grant: NamespaceGrant) => void;
  onUpdateDeleteReason: (reason: string) => void;
  onCancelDeleteGrant: () => void;
  onConfirmDeleteGrant: () => void;
  onRefreshGrants: () => void;
  onLoadAudit: () => void;
  onClose: () => void;
}) {
  return (
    <aside class="admin-inspector glass" aria-label={t("admin.inspector")}>
      <div class="admin-inspector-head">
        <div>
          <p class="eyebrow">{kindLabel(props.row.kind)}</p>
          <h2>{props.row.title}</h2>
          <p>{props.row.subtitle}</p>
        </div>
        <button type="button" class="btn btn-compact admin-inspector-close" onClick={props.onClose}>
          {t("common.close")}
        </button>
      </div>

      <div class="admin-inspector-status">
        <span class={`resource-status ${props.row.statusTone}`}>{props.row.status}</span>
        <span>{props.row.source}</span>
        <span>{formatAgo(props.row.updatedAt)}</span>
      </div>

      <p class="admin-inspector-description">{props.row.description}</p>

      <Show when={props.row.actions.length > 0}>
        <section class="admin-inspector-section admin-inspector-actions">
          <div class="admin-section-head">
            <h3>{t("admin.actions")}</h3>
          </div>
          <div class="admin-action-list">
            <For each={props.row.actions}>
              {(action) => (
                <Show
                  when={action.href}
                  fallback={
                    <div
                      class={`admin-action-card ${action.tone ?? "neutral"}`}
                      classList={{ disabled: action.disabled }}
                    >
                      <strong>{action.label}</strong>
                      <span>{action.description}</span>
                    </div>
                  }
                >
                  {(href) => (
                    <A class={`admin-action-card ${action.tone ?? "neutral"}`} href={href()}>
                      <strong>{action.label}</strong>
                      <span>{action.description}</span>
                    </A>
                  )}
                </Show>
              )}
            </For>
          </div>
        </section>
      </Show>

      <dl class="admin-detail-grid">
        <For each={props.row.details}>
          {(detail) => (
            <div>
              <dt>{detail.label}</dt>
              <dd>{detail.value}</dd>
            </div>
          )}
        </For>
      </dl>

      <Show when={props.row.policy}>
        {(policy) => (
          <section class="admin-inspector-section">
            <div class="admin-section-head">
              <h3>{t("policies.cedarText")}</h3>
              <span>{policyEditable(policy()) ? t("admin.editable") : t("admin.readOnly")}</span>
            </div>
            <Show
              when={policy().cedar_text.trim()}
              fallback={<p class="hint">{t("admin.builtinPolicyNoCedar")}</p>}
            >
              <pre class="admin-code">
                <code>{policy().cedar_text}</code>
              </pre>
            </Show>
          </section>
        )}
      </Show>

      <Show when={props.authEnabled ? props.row.namespace : null}>
        {(namespace) => (
          <section class="admin-inspector-section">
            <div class="admin-section-head">
              <h3>{t("admin.grants")}</h3>
              <div class="admin-section-actions">
                <button
                  type="button"
                  class="btn btn-compact"
                  onClick={() => props.onStartCreateGrant(namespace())}
                >
                  {t("admin.addGrant")}
                </button>
                <button type="button" class="btn btn-compact" onClick={props.onRefreshGrants}>
                  {t("admin.refreshGrants")}
                </button>
              </div>
            </div>

            <Show when={props.grantMessage}>
              <p class="hint admin-grant-success">{props.grantMessage}</p>
            </Show>

            <Show when={props.grantError}>
              <p class="warning">{props.grantError}</p>
            </Show>

            <Show when={props.grantEditor}>
              {(editor) => (
                <div class="admin-grant-editor">
                  <div class="admin-grant-editor-head">
                    <strong>
                      {editor().mode === "edit" ? t("admin.editGrant") : t("admin.addGrant")}
                    </strong>
                    <button
                      type="button"
                      class="btn btn-compact"
                      disabled={props.grantSaving}
                      onClick={props.onCloseGrantEditor}
                    >
                      {t("common.cancel")}
                    </button>
                  </div>

                  <div
                    class="admin-grantee-tabs"
                    role="tablist"
                    aria-label={t("admin.granteeKind")}
                  >
                    <For each={["group", "user", "public"] as GrantGranteeKind[]}>
                      {(kind) => (
                        <button
                          type="button"
                          classList={{ active: props.grantForm.granteeKind === kind }}
                          disabled={editor().mode === "edit"}
                          onClick={() => props.onSetGrantGranteeKind(kind)}
                        >
                          {granteeKindLabel(kind)}
                        </button>
                      )}
                    </For>
                  </div>

                  <Show when={props.grantForm.granteeKind === "group"}>
                    <label class="admin-grant-field">
                      <span>{t("admin.groupStableId")}</span>
                      <input
                        value={props.grantForm.groupName}
                        disabled={editor().mode === "edit"}
                        placeholder="kanidm:group:550e8400-e29b-41d4-a716-446655440000"
                        onInput={(event) =>
                          props.onUpdateGrantForm({
                            ...props.grantForm,
                            groupName: event.currentTarget.value,
                          })
                        }
                      />
                    </label>
                  </Show>

                  <Show when={props.grantForm.granteeKind === "user"}>
                    <div class="admin-grant-field">
                      <span>{t("admin.userStableId")}</span>
                      <div class="admin-user-search-row">
                        <input
                          value={props.grantForm.userQuery}
                          disabled={editor().mode === "edit"}
                          placeholder="kanidm:user:550e8400-e29b-41d4-a716-446655440000"
                          onInput={(event) =>
                            props.onUpdateGrantForm({
                              ...props.grantForm,
                              selectedUser: null,
                              userQuery: event.currentTarget.value,
                            })
                          }
                        />
                        <button
                          type="button"
                          class="btn btn-compact"
                          disabled={editor().mode === "edit" || props.observedUserLoading}
                          onClick={props.onSearchGrantUsers}
                        >
                          {props.observedUserLoading
                            ? t("common.loading")
                            : t("access.searchUsers")}
                        </button>
                      </div>
                      <Show when={props.observedUsers.length > 0 && editor().mode !== "edit"}>
                        <div class="admin-user-results">
                          <For each={props.observedUsers}>
                            {(user) => (
                              <button
                                type="button"
                                classList={{
                                  active:
                                    props.grantForm.selectedUser?.principal === user.principal,
                                }}
                                onClick={() => props.onSelectGrantUser(user)}
                              >
                                <strong>{observedUserLabel(user)}</strong>
                                <span>{user.principal}</span>
                              </button>
                            )}
                          </For>
                        </div>
                      </Show>
                    </div>
                  </Show>

                  <Show when={props.grantForm.granteeKind === "public"}>
                    <label class="admin-grant-field">
                      <span>{t("admin.publicLabel")}</span>
                      <input
                        value={props.grantForm.publicLabel}
                        disabled={editor().mode === "edit"}
                        onInput={(event) =>
                          props.onUpdateGrantForm({
                            ...props.grantForm,
                            publicLabel: event.currentTarget.value,
                          })
                        }
                      />
                    </label>
                  </Show>

                  <label class="admin-grant-field">
                    <span>{t("admin.grantLabel")}</span>
                    <input
                      value={props.grantForm.label}
                      placeholder={t("admin.grantLabelPlaceholder")}
                      onInput={(event) =>
                        props.onUpdateGrantForm({
                          ...props.grantForm,
                          label: event.currentTarget.value,
                        })
                      }
                    />
                  </label>

                  <div class="admin-grant-field">
                    <span>{t("access.permission")}</span>
                    <div class="admin-action-ladder">
                      <For each={GRANT_ACTIONS}>
                        {(action) => (
                          <button
                            type="button"
                            classList={{ active: props.grantForm.action === action }}
                            disabled={props.grantForm.granteeKind === "public" && action !== "pull"}
                            onClick={() => props.onUpdateGrantForm({ ...props.grantForm, action })}
                          >
                            {actionLabel(action)}
                          </button>
                        )}
                      </For>
                    </div>
                  </div>

                  <label class="admin-grant-field">
                    <span>{t("admin.reason")}</span>
                    <textarea
                      value={props.grantForm.reason}
                      placeholder={t("admin.grantReasonPlaceholder")}
                      onInput={(event) =>
                        props.onUpdateGrantForm({
                          ...props.grantForm,
                          reason: event.currentTarget.value,
                        })
                      }
                    />
                  </label>

                  <div class="admin-grant-editor-actions">
                    <button
                      type="button"
                      class="btn btn-primary"
                      disabled={props.grantSaving}
                      onClick={props.onSaveGrant}
                    >
                      {props.grantSaving ? t("common.saving") : t("common.save")}
                    </button>
                  </div>
                </div>
              )}
            </Show>

            <Show when={props.grantDeleteTarget}>
              {(target) => (
                <div class="admin-grant-delete">
                  <strong>
                    {t("admin.deleteGrantTitle", { label: grantLabel(target().grant) })}
                  </strong>
                  <p class="hint">{t("admin.deleteGrantDesc")}</p>
                  <label class="admin-grant-field">
                    <span>{t("admin.reason")}</span>
                    <textarea
                      value={props.grantDeleteReason}
                      placeholder={t("admin.deleteGrantReasonPlaceholder")}
                      onInput={(event) => props.onUpdateDeleteReason(event.currentTarget.value)}
                    />
                  </label>
                  <div class="admin-grant-editor-actions">
                    <button
                      type="button"
                      class="btn btn-compact"
                      disabled={props.grantDeleting}
                      onClick={props.onCancelDeleteGrant}
                    >
                      {t("common.cancel")}
                    </button>
                    <button
                      type="button"
                      class="btn btn-compact btn-danger"
                      disabled={props.grantDeleting}
                      onClick={props.onConfirmDeleteGrant}
                    >
                      {props.grantDeleting ? t("common.deleting") : t("common.delete")}
                    </button>
                  </div>
                </div>
              )}
            </Show>

            <Show
              when={props.grants.status !== "loading"}
              fallback={<LoadingSpinner label={t("admin.grantsLoading")} />}
            >
              <Show
                when={props.grants.status !== "error"}
                fallback={
                  <ErrorBanner
                    message={props.grants.error ?? t("admin.grantsError")}
                    onRetry={props.onRefreshGrants}
                  />
                }
              >
                <Show
                  when={props.grants.data.length > 0}
                  fallback={<p class="hint">{t("admin.noNamespaceGrants")}</p>}
                >
                  <div class="admin-grant-list">
                    <For each={props.grants.data}>
                      {(grant) => (
                        <div class="admin-grant-card">
                          <div>
                            <strong>{grantLabel(grant)}</strong>
                            <span>
                              {granteeKindLabel(grant.grantee.kind)} · {grantDetail(grant)}
                            </span>
                          </div>
                          <span class="resource-status neutral">{actionSummary(grant.action)}</span>
                          <span class="mono">{grant.id}</span>
                          <span>{formatTime(grant.updated_at)}</span>
                          <div class="admin-grant-row-actions">
                            <button
                              type="button"
                              class="btn btn-compact"
                              onClick={() => props.onStartEditGrant(namespace(), grant)}
                            >
                              {t("common.edit")}
                            </button>
                            <button
                              type="button"
                              class="btn btn-compact btn-danger"
                              onClick={() => props.onStartDeleteGrant(namespace(), grant)}
                            >
                              {t("common.delete")}
                            </button>
                          </div>
                        </div>
                      )}
                    </For>
                  </div>
                </Show>
              </Show>
            </Show>

            <section class="admin-audit-panel">
              <div class="admin-section-head">
                <div>
                  <h3>{t("admin.grantAudit")}</h3>
                  <p class="hint">{t("admin.grantAuditDesc")}</p>
                </div>
                <button type="button" class="btn btn-compact" onClick={props.onLoadAudit}>
                  {props.audit.status === "idle" ? t("admin.loadAudit") : t("admin.refreshAudit")}
                </button>
              </div>

              <Show when={props.audit.status !== "idle"}>
                <Show
                  when={props.audit.status !== "loading"}
                  fallback={<LoadingSpinner label={t("admin.auditLoading")} />}
                >
                  <Show
                    when={props.audit.status !== "error"}
                    fallback={
                      <ErrorBanner
                        message={props.audit.error ?? t("admin.auditError")}
                        onRetry={props.onLoadAudit}
                      />
                    }
                  >
                    <Show
                      when={props.audit.data.length > 0}
                      fallback={<p class="hint">{t("admin.noGrantAudit")}</p>}
                    >
                      <div class="admin-audit-list">
                        <For each={props.audit.data}>
                          {(event) => (
                            <article class="admin-audit-card">
                              <div class="admin-audit-card-head">
                                <span
                                  class={`resource-status ${auditOperationTone(event.operation)}`}
                                >
                                  {auditOperationLabel(event.operation)}
                                </span>
                                <span>{formatTime(event.created_at)}</span>
                              </div>
                              <p class="admin-audit-change">{auditChangeSummary(event)}</p>
                              <p class="admin-audit-reason">{event.reason}</p>
                              <div class="admin-audit-meta">
                                <span>{t("admin.auditActor", { actor: event.actor_label })}</span>
                                <Show when={event.grant_id}>
                                  {(grantId) => <span class="mono">{grantId()}</span>}
                                </Show>
                              </div>
                            </article>
                          )}
                        </For>
                      </div>
                    </Show>
                  </Show>
                </Show>
              </Show>
            </section>
          </section>
        )}
      </Show>
    </aside>
  );
}

export default function Admin() {
  const [session, setSession] = createSignal<DashboardSession | null>(null);
  const [sessionLoading, setSessionLoading] = createSignal(true);
  const [sessionError, setSessionError] = createSignal<string | null>(null);
  const [query, setQuery] = createSignal("");
  const [kindFilter, setKindFilter] = createSignal<ResourceKind | "all">("all");
  const [selectedKey, setSelectedKey] = createSignal<string | null>(null);
  const [selectionDismissed, setSelectionDismissed] = createSignal(false);

  const [repoSource, setRepoSource] = createSignal(emptySource<RepositorySummary[]>([]));
  const [namespaceSource, setNamespaceSource] = createSignal(emptySource<NamespaceResponse[]>([]));
  const [policySource, setPolicySource] = createSignal(emptySource<PolicySet[]>([]));
  const [mirrorRuleSource, setMirrorRuleSource] = createSignal(emptySource<MirrorRule[]>([]));
  const [jobSource, setJobSource] = createSignal(emptySource<SyncJob[]>([]));
  const [proxyCacheSource, setProxyCacheSource] = createSignal(emptySource<ProxyCache[]>([]));
  const [identitySource, setIdentitySource] = createSignal(emptySource<ObservedIdentity[]>([]));
  const [grantSource, setGrantSource] = createSignal(emptySource<NamespaceGrant[]>([]));
  const [grantAuditSource, setGrantAuditSource] = createSignal(
    emptySource<NamespaceGrantAuditEvent[]>([]),
  );
  const [grantEditor, setGrantEditor] = createSignal<AdminGrantEditor | null>(null);
  const [grantForm, setGrantForm] = createSignal<AdminGrantForm>({ ...EMPTY_GRANT_FORM });
  const [grantError, setGrantError] = createSignal<string | null>(null);
  const [grantMessage, setGrantMessage] = createSignal<string | null>(null);
  const [grantSaving, setGrantSaving] = createSignal(false);
  const [grantDeleteTarget, setGrantDeleteTarget] = createSignal<AdminGrantDeleteTarget | null>(
    null,
  );
  const [grantDeleteReason, setGrantDeleteReason] = createSignal("");
  const [grantDeleting, setGrantDeleting] = createSignal(false);
  const [grantObservedUsers, setGrantObservedUsers] = createSignal<ObservedIdentity[]>([]);
  const [grantObservedUserLoading, setGrantObservedUserLoading] = createSignal(false);

  async function loadRepositories() {
    await loadSource(setRepoSource, t("repos.fetchError"), async () => {
      const response = await fetchRepositories({ n: 100, sort: "updated_desc" });
      return response.repositories;
    });
  }

  async function loadNamespaces() {
    await loadSource(setNamespaceSource, t("access.namespaceLoadError"), async () => {
      const response = await fetchNamespaces();
      return response.namespaces;
    });
  }

  async function loadPolicies() {
    await loadSource(setPolicySource, t("policies.fetchError"), fetchPolicySets);
  }

  async function loadMirrorRules() {
    await loadSource(setMirrorRuleSource, t("mirror.fetchError"), () => fetchMirrorRules(false));
  }

  async function loadJobs() {
    await loadSource(setJobSource, t("mirror.fetchError"), fetchSyncJobs);
  }

  async function loadProxyCaches() {
    await loadSource(setProxyCacheSource, t("proxy.fetchError"), fetchProxyCaches);
  }

  async function loadAll() {
    setSessionLoading(true);
    setSessionError(null);
    try {
      const next = await fetchSession();
      setSession(next);
      if (next.auth_enabled && !next.subject) return;
      if (next.auth_enabled && !next.is_admin) return;

      const tasks = [
        loadRepositories(),
        loadPolicies(),
        loadMirrorRules(),
        loadJobs(),
        loadProxyCaches(),
      ];
      if (next.auth_enabled) {
        tasks.push(loadNamespaces());
      } else {
        setNamespaceSource({ status: "ready", data: [], error: null, lastLoaded: nowEpoch() });
        setIdentitySource({ status: "idle", data: [], error: null, lastLoaded: null });
        setGrantSource({ status: "idle", data: [], error: null, lastLoaded: null });
        resetGrantAudit();
      }
      await Promise.all(tasks);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        redirectToSignIn();
        return;
      }
      setSessionError(error instanceof Error ? error.message : t("admin.fetchError"));
    } finally {
      setSessionLoading(false);
    }
  }

  function selectResource(key: string | null) {
    setSelectionDismissed(false);
    setSelectedKey(key);
    resetGrantFeedback();
    resetGrantAudit();
    closeGrantEditor();
    cancelDeleteGrant();
  }

  function dismissInspector() {
    setSelectionDismissed(true);
    setSelectedKey(null);
    resetGrantFeedback();
    resetGrantAudit();
    closeGrantEditor();
    cancelDeleteGrant();
  }

  function updateQuery(value: string) {
    setSelectionDismissed(false);
    resetGrantFeedback();
    resetGrantAudit();
    closeGrantEditor();
    cancelDeleteGrant();
    setQuery(value);
  }

  function updateKindFilter(kind: ResourceKind | "all") {
    setSelectionDismissed(false);
    resetGrantFeedback();
    resetGrantAudit();
    closeGrantEditor();
    cancelDeleteGrant();
    setKindFilter(kind);
  }

  async function refreshSelectedNamespaceGrants() {
    const row = selected();
    if (!row?.namespace || !session()?.auth_enabled) return;
    await loadSource(setGrantSource, t("admin.grantsError"), async () => {
      const response = await fetchAdminNamespaceGrants(row.namespace!.handle);
      return response.grants;
    });
  }

  function resetGrantAudit() {
    setGrantAuditSource({ status: "idle", data: [], error: null, lastLoaded: null });
  }

  async function loadSelectedNamespaceGrantAudit() {
    const row = selected();
    if (!row?.namespace || !session()?.auth_enabled) return;
    await loadSource(setGrantAuditSource, t("admin.auditError"), async () => {
      const response = await fetchAdminNamespaceGrantAudit(row.namespace!.handle);
      return response.audit;
    });
  }

  async function refreshGrantAuditIfLoaded() {
    if (grantAuditSource().status === "idle") return;
    await loadSelectedNamespaceGrantAudit();
  }

  function resetGrantFeedback() {
    setGrantError(null);
    setGrantMessage(null);
  }

  function openCreateGrant(namespace: NamespaceResponse) {
    resetGrantFeedback();
    setGrantDeleteTarget(null);
    setGrantDeleteReason("");
    setGrantObservedUsers([]);
    setGrantForm({ ...EMPTY_GRANT_FORM });
    setGrantEditor({ mode: "create", namespace });
  }

  function openEditGrant(namespace: NamespaceResponse, grant: NamespaceGrant) {
    resetGrantFeedback();
    setGrantDeleteTarget(null);
    setGrantDeleteReason("");
    setGrantObservedUsers([]);
    setGrantForm({
      granteeKind: grant.grantee.kind,
      groupName: grant.grantee.kind === "group" ? grant.grantee.id : "",
      userQuery: grant.grantee.kind === "user" ? grant.grantee.id : "",
      selectedUser: null,
      publicLabel: grant.grantee.kind === "public" ? grant.label : "Public",
      action: grant.action,
      label: grant.label,
      reason: "",
    });
    setGrantEditor({ mode: "edit", namespace, grant });
  }

  function closeGrantEditor() {
    if (grantSaving()) return;
    setGrantEditor(null);
    setGrantForm({ ...EMPTY_GRANT_FORM });
    setGrantObservedUsers([]);
    setGrantObservedUserLoading(false);
  }

  function setGrantGranteeKind(kind: GrantGranteeKind) {
    setGrantForm({
      ...grantForm(),
      granteeKind: kind,
      action: kind === "public" ? "pull" : grantForm().action,
    });
    resetGrantFeedback();
  }

  async function searchGrantUsers() {
    const query = grantForm().userQuery.trim();
    if (query.length < 2) {
      setGrantError(t("admin.userSearchRequired"));
      return;
    }
    setGrantObservedUserLoading(true);
    setGrantError(null);
    try {
      const response = await fetchObservedUsers(query);
      setGrantObservedUsers(response.users);
    } catch (error) {
      setGrantError(errorMessage(error, t("access.observedUserSearchError")));
    } finally {
      setGrantObservedUserLoading(false);
    }
  }

  function selectGrantUser(user: ObservedIdentity) {
    setGrantForm({
      ...grantForm(),
      selectedUser: user,
      userQuery: observedUserLabel(user),
      label: observedUserLabel(user),
    });
    resetGrantFeedback();
  }

  function buildGrantRequest(): PutNamespaceGrantRequest | null {
    const form = grantForm();
    const reason = form.reason.trim();
    if (!reason) {
      setGrantError(t("admin.reasonRequired"));
      return null;
    }

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
        action,
        label: form.label.trim() || group,
        reason,
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
      const label =
        form.label.trim() || (form.selectedUser ? observedUserLabel(form.selectedUser) : id);
      return {
        grantee: { kind: "user", id },
        action,
        label,
        reason,
      };
    }

    return {
      grantee: { kind: "public" },
      action: "pull",
      label: form.label.trim() || form.publicLabel.trim() || t("access.grantee.public"),
      reason,
    };
  }

  async function saveGrant() {
    const editor = grantEditor();
    if (!editor) return;
    const request = buildGrantRequest();
    if (!request) return;

    setGrantSaving(true);
    setGrantError(null);
    setGrantMessage(null);
    try {
      if (editor.mode === "edit" && editor.grant) {
        await updateAdminNamespaceGrant(editor.namespace.handle, editor.grant.id, {
          action: request.action,
          label: request.label,
          reason: request.reason,
        });
      } else {
        await createAdminNamespaceGrant(editor.namespace.handle, request);
      }
      await refreshSelectedNamespaceGrants();
      await refreshGrantAuditIfLoaded();
      setGrantMessage(t(editor.mode === "edit" ? "admin.grantUpdated" : "admin.grantCreated"));
      setGrantEditor(null);
      setGrantForm({ ...EMPTY_GRANT_FORM });
      setGrantObservedUsers([]);
    } catch (error) {
      setGrantError(errorMessage(error, t("admin.grantSaveError")));
    } finally {
      setGrantSaving(false);
    }
  }

  function openDeleteGrant(namespace: NamespaceResponse, grant: NamespaceGrant) {
    resetGrantFeedback();
    closeGrantEditor();
    setGrantDeleteReason("");
    setGrantDeleteTarget({ namespace, grant });
  }

  function cancelDeleteGrant() {
    if (grantDeleting()) return;
    setGrantDeleteTarget(null);
    setGrantDeleteReason("");
  }

  async function confirmDeleteGrant() {
    const target = grantDeleteTarget();
    if (!target) return;
    const reason = grantDeleteReason().trim();
    if (!reason) {
      setGrantError(t("admin.reasonRequired"));
      return;
    }

    setGrantDeleting(true);
    setGrantError(null);
    setGrantMessage(null);
    try {
      await deleteAdminNamespaceGrant(target.namespace.handle, target.grant.id, reason);
      await refreshSelectedNamespaceGrants();
      await refreshGrantAuditIfLoaded();
      setGrantMessage(t("admin.grantDeleted"));
      setGrantDeleteTarget(null);
      setGrantDeleteReason("");
    } catch (error) {
      setGrantError(errorMessage(error, t("admin.grantDeleteError")));
    } finally {
      setGrantDeleting(false);
    }
  }

  const rows = createMemo<ResourceRow[]>(() => {
    return [
      ...repositoryRows(repoSource().data),
      ...(session()?.auth_enabled
        ? namespaceRows(namespaceSource().data)
        : observedHandleRows(repoSource().data)),
      ...policyRows(policySource().data),
      ...mirrorRuleRows(mirrorRuleSource().data),
      ...syncJobRows(jobSource().data),
      ...proxyCacheRows(proxyCacheSource().data),
      ...(session()?.auth_enabled ? identityRows(identitySource().data) : setupRows()),
    ];
  });

  const filteredRows = createMemo(() => {
    const groupByKind = !query().trim() && kindFilter() === "all";
    return rows()
      .filter((row) => {
        if (kindFilter() !== "all" && row.kind !== kindFilter()) return false;
        return rowMatches(row, query());
      })
      .sort((a, b) => compareResourceRows(a, b, groupByKind));
  });

  const selected = createMemo(() => {
    const key = selectedKey();
    if (!key) return null;
    return filteredRows().find((row) => row.key === key) ?? null;
  });

  createEffect(() => {
    const visibleRows = filteredRows();
    const currentKey = selectedKey();
    if (visibleRows.length === 0) {
      if (currentKey !== null) setSelectedKey(null);
      return;
    }
    if (currentKey && visibleRows.some((row) => row.key === currentKey)) return;
    if (selectionDismissed()) return;

    const preferPolicy = !query().trim() && kindFilter() === "all";
    const nextRow = preferPolicy
      ? (visibleRows.find((row) => row.kind === "policy") ?? visibleRows[0])
      : visibleRows[0];
    setSelectedKey(nextRow.key);
  });

  const sourceCards = createMemo<SourceCard[]>(() => {
    const cards: SourceCard[] = [
      {
        id: "repositories",
        label: t("admin.source.repositories"),
        status: repoSource().status,
        count: repoSource().data.length,
        lastLoaded: repoSource().lastLoaded,
        error: repoSource().error,
        onRefresh: loadRepositories,
      },
      {
        id: "policies",
        label: t("admin.source.policies"),
        status: policySource().status,
        count: policySource().data.length,
        lastLoaded: policySource().lastLoaded,
        error: policySource().error,
        onRefresh: loadPolicies,
      },
      {
        id: "mirror-rules",
        label: t("admin.source.mirrorRules"),
        status: mirrorRuleSource().status,
        count: mirrorRuleSource().data.length,
        lastLoaded: mirrorRuleSource().lastLoaded,
        error: mirrorRuleSource().error,
        onRefresh: loadMirrorRules,
      },
      {
        id: "jobs",
        label: t("admin.source.jobs"),
        status: jobSource().status,
        count: jobSource().data.length,
        lastLoaded: jobSource().lastLoaded,
        error: jobSource().error,
        onRefresh: loadJobs,
      },
      {
        id: "proxy-caches",
        label: t("admin.source.proxyCaches"),
        status: proxyCacheSource().status,
        count: proxyCacheSource().data.length,
        lastLoaded: proxyCacheSource().lastLoaded,
        error: proxyCacheSource().error,
        onRefresh: loadProxyCaches,
      },
    ];
    if (session()?.auth_enabled) {
      cards.splice(1, 0, {
        id: "namespaces",
        label: t("admin.source.namespaces"),
        status: namespaceSource().status,
        count: namespaceSource().data.length,
        lastLoaded: namespaceSource().lastLoaded,
        error: namespaceSource().error,
        onRefresh: loadNamespaces,
      });
      cards.push({
        id: "principals",
        label: t("admin.source.principals"),
        status: identitySource().status,
        count: identitySource().data.length,
        lastLoaded: identitySource().lastLoaded,
        error: identitySource().error,
        onRefresh: () => void loadObservedIdentities(query()),
      });
    } else {
      cards.push({
        id: "setup",
        label: t("admin.source.setup"),
        status: "ready",
        count: setupRows().length,
        lastLoaded: null,
        error: null,
        onRefresh: loadAll,
      });
    }
    return cards;
  });

  const kindOptions = createMemo(() => {
    const counts = new Map<ResourceKind, number>();
    rows().forEach((row) => counts.set(row.kind, (counts.get(row.kind) ?? 0) + 1));
    return [
      { kind: "all" as const, label: t("common.all"), count: rows().length },
      ...KINDS.filter((kind) => counts.has(kind)).map((kind) => ({
        kind,
        label: kindLabel(kind),
        count: counts.get(kind) ?? 0,
      })),
    ];
  });

  const sourceErrors = createMemo(() =>
    sourceCards().filter((source) => source.status === "error"),
  );
  const authEnabled = createMemo(() => session()?.auth_enabled !== false);

  let identityRequest = 0;
  async function loadObservedIdentities(searchValue: string) {
    if (!session()?.auth_enabled || searchValue.trim().length < 2) {
      setIdentitySource({ status: "idle", data: [], error: null, lastLoaded: null });
      return;
    }
    const request = ++identityRequest;
    setIdentitySource((previous) => ({ ...previous, status: "loading", error: null }));
    try {
      const response = await fetchObservedUsers(searchValue.trim());
      if (request === identityRequest) {
        setIdentitySource({
          status: "ready",
          data: response.users,
          error: null,
          lastLoaded: nowEpoch(),
        });
      }
    } catch (error) {
      if (request === identityRequest) {
        setIdentitySource((previous) => ({
          ...previous,
          status: "error",
          error: errorMessage(error, t("access.observedUserSearchError")),
        }));
      }
    }
  }

  createEffect(() => {
    void loadObservedIdentities(query());
  });

  createEffect(() => {
    const row = selected();
    if (!row?.namespace || !session()?.auth_enabled) {
      setGrantSource({ status: "idle", data: [], error: null, lastLoaded: null });
      resetGrantAudit();
      return;
    }
    void refreshSelectedNamespaceGrants();
  });

  onMount(() => {
    void loadAll();
  });

  return (
    <div class="admin-page">
      <section class="hero glass admin-hero">
        <div>
          <p class="eyebrow">
            <span class="status-dot" aria-hidden="true" />
            {t("admin.eyebrow")}
          </p>
          <h1>{t("admin.title")}</h1>
          <p class="hero-copy">{t("admin.copy")}</p>
        </div>
        <div class="admin-hero-pills" aria-label={t("admin.summary")}>
          <span class={authEnabled() ? "admin-pill good" : "admin-pill warn"}>
            {authEnabled() ? t("admin.authEnabledStatus") : t("admin.authDisabledStatus")}
          </span>
          <Show when={session()?.is_admin}>
            <span class="admin-pill good">{t("admin.adminSession")}</span>
          </Show>
          <span class="admin-pill">{t("admin.resourceCount", { count: rows().length })}</span>
          <span class={sourceErrors().length > 0 ? "admin-pill danger" : "admin-pill good"}>
            {sourceErrors().length > 0
              ? t("admin.sourceErrorCount", { count: sourceErrors().length })
              : t("admin.sourcesHealthy")}
          </span>
        </div>
      </section>

      <Show when={sessionError()}>
        <ErrorBanner message={sessionError()!} onRetry={loadAll} />
      </Show>

      <Show when={!sessionLoading()} fallback={<LoadingSpinner label={t("admin.loading")} />}>
        <Show
          when={!authEnabled() || session()?.subject}
          fallback={
            <section class="access-signin card">
              <div>
                <p class="eyebrow">{t("access.signIn")}</p>
                <h2>{t("admin.signInTitle")}</h2>
                <p>{t("admin.signInDesc")}</p>
              </div>
              <button type="button" class="btn btn-primary" onClick={redirectToSignIn}>
                {t("access.signInWithOidc")}
              </button>
            </section>
          }
        >
          <Show
            when={!authEnabled() || session()?.is_admin}
            fallback={
              <div class="card">
                <EmptyState
                  title={t("admin.requiredTitle")}
                  description={t("admin.requiredDesc")}
                />
              </div>
            }
          >
            <Show when={!authEnabled()}>
              <section class="admin-open-mode glass admin-open-mode-compact">
                <p class="eyebrow">{t("admin.authDisabledEyebrow")}</p>
                <p>{t("admin.authDisabledDesc")}</p>
              </section>
            </Show>

            <section class="admin-source-strip glass" aria-label={t("admin.sources")}>
              <div class="admin-source-strip-head">
                <span>{t("admin.sources")}</span>
                <button type="button" class="btn btn-compact" onClick={loadAll}>
                  {t("admin.refreshAll")}
                </button>
              </div>
              <div class="admin-source-chips">
                <For each={sourceCards()}>
                  {(source) => (
                    <article class={`admin-source-chip ${source.status}`}>
                      <div>
                        <span>{source.label}</span>
                        <strong>{source.count}</strong>
                      </div>
                      <div class="admin-source-meta">
                        <span>{loadStatusLabel(source.status)}</span>
                        <span>{sourceHint(source)}</span>
                      </div>
                      <Show when={source.lastLoaded}>
                        <span class="admin-source-updated">{formatAgo(source.lastLoaded)}</span>
                      </Show>
                      <Show when={source.status === "error"}>
                        <button type="button" class="btn btn-compact" onClick={source.onRefresh}>
                          {t("common.retry")}
                        </button>
                      </Show>
                    </article>
                  )}
                </For>
              </div>
            </section>

            <section class="admin-workbench">
              <div class="admin-results glass">
                <div class="admin-searchbar">
                  <label>
                    <span>{t("admin.searchLabel")}</span>
                    <input
                      type="search"
                      value={query()}
                      placeholder={t("admin.searchPlaceholder")}
                      onInput={(event) => updateQuery(event.currentTarget.value)}
                    />
                  </label>
                  <span class="admin-results-count">
                    {t("admin.loadedResourceCount", { count: filteredRows().length })}
                  </span>
                </div>

                <div class="admin-kind-filters" role="list" aria-label={t("admin.filters")}>
                  <For each={kindOptions()}>
                    {(option) => (
                      <button
                        type="button"
                        classList={{ active: kindFilter() === option.kind }}
                        onClick={() => updateKindFilter(option.kind)}
                      >
                        <span>{option.label}</span>
                        <strong>{option.count}</strong>
                      </button>
                    )}
                  </For>
                </div>

                <Show
                  when={filteredRows().length > 0}
                  fallback={
                    <div class="admin-empty">
                      <EmptyState
                        title={t("admin.noResults")}
                        description={t("admin.noResultsDesc")}
                      />
                    </div>
                  }
                >
                  <div class="admin-resource-list" role="list" aria-label={t("admin.results")}>
                    <For each={filteredRows()}>
                      {(row) => (
                        <button
                          type="button"
                          classList={{
                            "admin-resource-row": true,
                            selected: selected()?.key === row.key,
                          }}
                          onClick={() => selectResource(row.key)}
                        >
                          <span class="resource-kind">{kindLabel(row.kind)}</span>
                          <span class="resource-main">
                            <strong>{row.title}</strong>
                            <span>{row.subtitle}</span>
                          </span>
                          <span class={`resource-status ${row.statusTone}`}>{row.status}</span>
                          <span class="resource-source">{row.source}</span>
                          <span class="resource-updated">{formatAgo(row.updatedAt)}</span>
                        </button>
                      )}
                    </For>
                  </div>
                </Show>
              </div>

              <Show
                when={selected()}
                fallback={
                  <aside class="admin-inspector glass">
                    <EmptyState
                      title={t("admin.noSelection")}
                      description={t("admin.noSelectionDesc")}
                    />
                  </aside>
                }
              >
                {(row) => (
                  <ResourceInspector
                    row={row()}
                    authEnabled={authEnabled()}
                    grants={grantSource()}
                    audit={grantAuditSource()}
                    grantEditor={grantEditor()}
                    grantForm={grantForm()}
                    grantError={grantError()}
                    grantMessage={grantMessage()}
                    grantSaving={grantSaving()}
                    grantDeleteTarget={grantDeleteTarget()}
                    grantDeleteReason={grantDeleteReason()}
                    grantDeleting={grantDeleting()}
                    observedUsers={grantObservedUsers()}
                    observedUserLoading={grantObservedUserLoading()}
                    onStartCreateGrant={openCreateGrant}
                    onStartEditGrant={openEditGrant}
                    onCloseGrantEditor={closeGrantEditor}
                    onUpdateGrantForm={setGrantForm}
                    onSetGrantGranteeKind={setGrantGranteeKind}
                    onSearchGrantUsers={searchGrantUsers}
                    onSelectGrantUser={selectGrantUser}
                    onSaveGrant={saveGrant}
                    onStartDeleteGrant={openDeleteGrant}
                    onUpdateDeleteReason={setGrantDeleteReason}
                    onCancelDeleteGrant={cancelDeleteGrant}
                    onConfirmDeleteGrant={confirmDeleteGrant}
                    onRefreshGrants={refreshSelectedNamespaceGrants}
                    onLoadAudit={loadSelectedNamespaceGrantAudit}
                    onClose={dismissInspector}
                  />
                )}
              </Show>
            </section>
          </Show>
        </Show>
      </Show>
    </div>
  );
}
