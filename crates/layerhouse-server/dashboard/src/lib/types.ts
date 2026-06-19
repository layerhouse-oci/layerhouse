// ---- Cluster Status ----

export type NodeState = "leader" | "follower" | "candidate" | "learner";

export interface NodeInfo {
  id: number;
  addr: string;
}

export interface ClusterStatus {
  node_id: number;
  state: NodeState;
  leader_id: number | null;
  leader_addr: string | null;
  voters: NodeInfo[];
  learners: NodeInfo[];
  last_applied_log: number | null;
  last_membership_log_id: number | null;
}

export interface ClusterMember {
  node_id: number;
  address: string;
  role: string;
  status: string;
  commit_index: number | null;
  replication_lag_ms: number | null;
}

export interface DashboardClusterStatus {
  cluster_id: string;
  leader_id: number | null;
  term: number;
  quorum: number;
  healthy_voters: number;
  updated_at: number;
  voters: ClusterMember[];
  learners: ClusterMember[];
}

// ---- OCI v2 Compatibility ----

export interface CatalogResponse {
  repositories: string[];
}

export interface TagListResponse {
  name: string;
  tags: string[];
}

export interface ManifestResponse {
  digest: string;
  content_type: string;
  body: Record<string, unknown>;
  subject: string | null;
  artifact_type: string | null;
  annotations: Record<string, unknown> | null;
}

// ---- Repository Browser ----

export type OciAction = "pull" | "create" | "update" | "delete";
export type GrantSource = "personal" | "group_grant" | "public";
export type RepoKind = "image" | "helm" | "wasm" | "artifact" | "unknown";
export type RepositoryFilter = "all" | "mine" | "shared" | "public";
export type RepositoryRecencyFilter = "all" | "recent" | "stale";

export interface RepositorySummary {
  name: string;
  tag_count: number;
  manifest_count: number;
  stored_size_bytes: number;
  manifest_size_bytes: number;
  last_modified: number;
  description: string;
  created_by: string | null;
  visibility: string;
  access_level: OciAction;
  max_grantable: OciAction;
  grant_source: GrantSource;
}

export interface RepositoryListResponse {
  repositories: RepositorySummary[];
  total_reachable: number;
  next_cursor: string | null;
}

export interface ManifestSummary {
  digest: string;
  media_type: string;
  artifact_type: string | null;
  stored_size_bytes: number;
  manifest_size_bytes: number;
  created_at: number;
  last_modified: number;
  tags: string[];
  subject: string | null;
  annotations: Record<string, unknown> | null;
  config_summary: Record<string, unknown> | null;
  body: Record<string, unknown> | unknown[];
}

export interface ManifestListResponse {
  name: string;
  manifests: ManifestSummary[];
  total: number;
  has_more: boolean;
}

export interface ManifestDetailResponse extends ManifestSummary {
  access_source?: GrantSource | null;
  max_grantable_action?: OciAction | null;
}

export interface DeleteCounts {
  deleted_manifests: number;
  deleted_tags: number;
}

// ---- Access / Auth ----

export interface DashboardSession {
  auth_enabled: boolean;
  subject: string | null;
  principal: string | null;
  username: string | null;
  display_name: string | null;
  email: string | null;
  groups: string[];
  group_ids: string[];
  scopes: string[];
  token_type: string | null;
  is_admin: boolean;
}

export interface PersonalAccessToken {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  created_at: number;
  last_used_at: number | null;
  expires_at: number | null;
}

export interface PatScopeSelection {
  repository: string;
  actions: OciAction[];
}

export interface CreateTokenRequest {
  name: string;
  scopes: PatScopeSelection[];
  expires_in_days?: number | null;
}

export interface CreateTokenResponse {
  id: string;
  name: string;
  token: string;
  scopes: string[];
  created_at: number;
  expires_at: number | null;
}

export interface GrantableScope {
  repository: string;
  max_grantable: OciAction;
  kind: RepoKind[];
  grant_source: GrantSource;
}

export interface NamespacePatternScope {
  pattern: string;
  current_match_count: number;
  max_grantable: OciAction;
  grant_source: GrantSource;
}

export interface GrantableScopeListResponse {
  scopes: GrantableScope[];
  namespace_patterns: NamespacePatternScope[];
  total_matches: number;
  next_cursor: string | null;
}

export type NamespaceOwnerKind = "user" | "org";

export interface NamespaceResponse {
  handle: string;
  owner_kind: NamespaceOwnerKind;
  owner_label: string;
  created_at: number;
}

export interface NamespaceListResponse {
  namespaces: NamespaceResponse[];
}

export interface ClaimNamespaceRequest {
  owner_label?: string | null;
  admin_override?: boolean;
}

export interface ReleaseNamespaceRequest {
  reason?: string | null;
}

export type NamespaceGrantGrantee =
  | { kind: "group"; id: string }
  | { kind: "user"; id: string }
  | { kind: "public" };

export interface NamespaceGrant {
  id: string;
  namespace: string;
  grantee: NamespaceGrantGrantee;
  action: OciAction;
  label: string;
  created_by: string;
  created_at: number;
  updated_by: string;
  updated_at: number;
}

export interface NamespaceGrantListResponse {
  grants: NamespaceGrant[];
}

export interface PutNamespaceGrantRequest {
  grantee: NamespaceGrantGrantee;
  action: OciAction;
  label?: string | null;
  reason?: string | null;
}

export interface PatchNamespaceGrantRequest {
  action: OciAction;
  label?: string | null;
  reason?: string | null;
}

export interface NamespaceGrantAuditEvent {
  id: string;
  namespace: string;
  grant_id: string | null;
  operation: "create" | "update" | "delete";
  actor: string;
  actor_label: string;
  reason: string;
  before: NamespaceGrant | null;
  after: NamespaceGrant | null;
  created_at: number;
}

export interface NamespaceGrantAuditListResponse {
  audit: NamespaceGrantAuditEvent[];
}

export interface ObservedIdentity {
  subject: string;
  principal: string;
  username: string | null;
  display_name: string | null;
  email: string | null;
  groups: string[];
  group_ids: string[];
  last_seen_at: number;
}

export interface ObservedIdentityListResponse {
  users: ObservedIdentity[];
}

// ---- Mirror Rules ----

export type MirrorDirection = "pull" | "push";

export type MirrorStrategy =
  | { type: "all" }
  | { type: "latest"; count: number }
  | { type: "pattern"; pattern: string };

export type OutboundProxyProtocol = "none" | "http" | "https" | "socks4" | "socks5";

export interface OutboundProxy {
  protocol: OutboundProxyProtocol;
  url?: string | null;
  username?: string | null;
  password?: string | null;
}

export interface OutboundProxyPublic {
  protocol: OutboundProxyProtocol;
  url: string | null;
  username_configured: boolean;
  password_configured: boolean;
}

export interface MirrorRule {
  id: string;
  direction: MirrorDirection;
  local_prefix: string;
  upstream_registry: string;
  upstream_prefix: string | null;
  schedule: string | null;
  strategy: MirrorStrategy;
  plain_http: boolean;
  insecure_tls: boolean;
  outbound_proxy: OutboundProxyPublic;
  username_configured: boolean;
  password_configured: boolean;
  created_at: number;
}

export interface MirrorRuleCreate {
  id: string;
  direction: MirrorDirection;
  local_prefix: string;
  upstream_registry: string;
  upstream_prefix?: string | null;
  schedule?: string | null;
  strategy: MirrorStrategy;
  plain_http?: boolean;
  insecure_tls?: boolean;
  outbound_proxy?: OutboundProxy;
  username?: string | null;
  password?: string | null;
  created_at?: number;
}

export interface SyncJob {
  id: string;
  kind?: "mirror" | "proxy_cache" | "legacy_warm";
  rule_id: string | null;
  rule_name: string | null;
  image: string;
  tags: string[];
  interval_secs: number;
  status: "Idle" | "Running";
  claimed_by: string | null;
  claimed_at: number | null;
  last_run_at: number | null;
  next_run_at: number;
  last_error: string | null;
}

export interface SyncJobRun {
  id: string;
  job_id: string;
  node_id: string;
  started_at: number;
  finished_at: number | null;
  status: "Running" | "Succeeded" | "PartialFailure" | "Failed";
  phase: string;
  total_tags: number;
  completed_tags: number;
  current_tag: string | null;
  updated_at: number;
  recent_events: SyncRunEvent[];
  tags_synced: string[];
  tags_failed: [string, string][];
}

export interface SyncRunEvent {
  at: number;
  kind: "Info" | "Success" | "Warning" | "Error";
  tag: string | null;
  message: string;
}

// ---- Proxy Cache ----

export type WarmSortBy = "created" | "pushed" | "pulled";

export type WarmFilter =
  | { type: "none" }
  | { type: "all" }
  | { type: "latest"; count: number; sort_by: WarmSortBy }
  | { type: "pattern"; pattern: string };

export interface ProxyCache {
  id: string;
  local_prefix: string;
  upstream_registry: string;
  upstream_prefix: string | null;
  warm_filters: WarmFilter[];
  warm_schedule: string | null;
  plain_http: boolean;
  insecure_tls: boolean;
  outbound_proxy: OutboundProxyPublic;
  username_configured: boolean;
  password_configured: boolean;
  created_at: number;
}

export interface ProxyCacheCreate {
  id: string;
  local_prefix: string;
  upstream_registry: string;
  upstream_prefix?: string | null;
  warm_filters: WarmFilter[];
  warm_schedule?: string | null;
  plain_http?: boolean;
  insecure_tls?: boolean;
  outbound_proxy?: OutboundProxy;
  username?: string | null;
  password?: string | null;
  created_at?: number;
}

// ---- Legacy Warm Images / Helm ----

export interface WarmImage {
  id: string;
  image: string;
  tags: string[];
  interval_secs: number;
}

export interface HelmChart {
  name: string;
  description: string;
  latest_version: string;
  versions: string[];
}

export interface HelmChartVersion {
  name: string;
  version: string;
  app_version: string | null;
  description: string;
  created: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  has_more: boolean;
  next_link: string | null;
}
