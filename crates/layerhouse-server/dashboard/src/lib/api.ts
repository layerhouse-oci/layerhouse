import type {
  CatalogResponse,
  ClaimNamespaceRequest,
  ClusterStatus,
  CreateTokenRequest,
  CreateTokenResponse,
  DashboardSession,
  DashboardClusterStatus,
  DeleteCounts,
  GrantableScopeListResponse,
  HelmChart,
  HelmChartVersion,
  ManifestDetailResponse,
  ManifestListResponse,
  ManifestResponse,
  MirrorRule,
  MirrorRuleCreate,
  NamespaceGrant,
  NamespaceGrantAuditListResponse,
  NamespaceGrantListResponse,
  NamespaceListResponse,
  NamespaceResponse,
  ObservedIdentityListResponse,
  PatchNamespaceGrantRequest,
  PersonalAccessToken,
  PolicySet,
  ProxyCache,
  ProxyCacheCreate,
  PutPolicySetRequest,
  PutNamespaceGrantRequest,
  ReleaseNamespaceRequest,
  RepositoryFilter,
  RepositoryListResponse,
  SyncJob,
  SyncJobRun,
  TagListResponse,
  ValidatePolicyRequest,
  ValidatePolicyResponse,
  WarmImage,
} from "./types";

const BASE = "";

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

// Idempotent redirect guard — prevents polling loaders from firing
// multiple navigations before the first one completes.
let _redirectingToLogin = false;
export function redirectToSignIn() {
  if (_redirectingToLogin) return;
  _redirectingToLogin = true;
  window.location.href = "/oauth2/start";
}

async function readError(res: Response): Promise<ApiError> {
  const text = await res.text().catch(() => res.statusText);
  try {
    const json = JSON.parse(text);
    const message = json?.errors?.[0]?.message ?? text;
    return new ApiError(message || res.statusText, res.status);
  } catch {
    return new ApiError(text || res.statusText, res.status);
  }
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + url, {
    ...init,
    // Only apply default timeout if caller didn't provide a signal.
    signal: init?.signal ?? AbortSignal.timeout(5000),
  });
  if (!res.ok) throw await readError(res);
  return res.json();
}

async function fetchNoBody(url: string, init?: RequestInit): Promise<void> {
  const res = await fetch(BASE + url, {
    ...init,
    signal: init?.signal ?? AbortSignal.timeout(5000),
  });
  if (!res.ok) throw await readError(res);
}

function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      search.set(key, String(value));
    }
  }
  const out = search.toString();
  return out ? `?${out}` : "";
}

function parseLinkHeader(link: string | null): { next: string | null } {
  if (!link) return { next: null };
  const match = link.match(/<([^>]+)>;\s*rel="next"/);
  return { next: match ? match[1] : null };
}

async function fetchAllPages<TResponse, TItem>(
  url: string,
  params: Record<string, string>,
  extractItems: (data: TResponse) => TItem[],
): Promise<TItem[]> {
  const firstQs = params ? "?" + new URLSearchParams(params).toString() : "";
  let target: string | null = BASE + url + firstQs;
  const results: TItem[] = [];

  while (target) {
    const res: Response = await fetch(target, { signal: AbortSignal.timeout(5000) });
    if (res.status === 401) {
      redirectToSignIn();
      throw new ApiError("session expired", 401);
    }
    if (!res.ok) throw await readError(res);
    const data: TResponse = await res.json();
    results.push(...extractItems(data));
    target = parseLinkHeader(res.headers.get("Link")).next;
  }
  return results;
}

// ---- Cluster ----

export function fetchStatus(): Promise<ClusterStatus> {
  return fetchJson("/raft/status");
}

export function fetchClusterStatus(): Promise<DashboardClusterStatus> {
  // Use the authenticated (non-admin) endpoint so non-admin dashboard users
  // can view cluster status. The /api/v1/admin/ variant remains available
  // for admin-only contexts but requires delete-on-* permission.
  return fetchJson("/api/v1/cluster/status");
}

export async function joinCluster(nodeId: number, addr: string): Promise<void> {
  await fetchNoBody("/api/v1/admin/cluster/join", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ node_id: nodeId, addr }),
  });
}

export async function leaveCluster(nodeId?: number): Promise<void> {
  const target = nodeId
    ? `/api/v1/admin/cluster/members/${encodeURIComponent(nodeId)}`
    : "/api/v1/admin/cluster/leave";
  await fetchNoBody(target, { method: nodeId ? "DELETE" : "POST" });
}

// ---- OCI v2 Compatibility ----

export function fetchCatalog(n?: number, last?: string): Promise<CatalogResponse> {
  return fetchJson(`/v2/_catalog${qs({ n, last })}`);
}

export function fetchAllRepos(): Promise<string[]> {
  return fetchAllPages<CatalogResponse, string>(
    "/v2/_catalog",
    { n: "100" },
    (data) => data.repositories,
  );
}

export function fetchTags(repo: string, n?: number, last?: string): Promise<TagListResponse> {
  return fetchJson(`/v2/${repo}/tags/list${qs({ n, last })}`);
}

export function fetchAllTags(repo: string): Promise<string[]> {
  return fetchAllPages<TagListResponse, string>(
    `/v2/${repo}/tags/list`,
    { n: "100" },
    (data) => data.tags,
  );
}

export function fetchManifest(repo: string, ref: string): Promise<ManifestResponse> {
  return fetchJson(`/v2/${repo}/manifests/${ref}`);
}

// ---- Repository Browser ----

export function fetchRepositories(
  params: {
    q?: string;
    filter?: RepositoryFilter;
    recency?: string;
    sort?: string;
    n?: number;
    last?: string;
  } = {},
): Promise<RepositoryListResponse> {
  return fetchJson(`/api/v1/repositories${qs(params)}`);
}

export function fetchRepositoryManifests(
  repo: string,
  params: {
    n?: number;
    last?: string;
    q?: string;
    type?: string;
    tag?: string;
    tagged?: boolean;
    platform?: string;
    media_type?: string;
    stored_size_min?: number;
    stored_size_max?: number;
    created_after?: string;
    created_before?: string;
    sort?: string;
  } = {},
): Promise<ManifestListResponse> {
  return fetchJson(`/api/v1/repositories/${repo}/manifests${qs(params)}`);
}

export function fetchManifestDetail(repo: string, digest: string): Promise<ManifestDetailResponse> {
  return fetchJson(`/api/v1/repositories/${repo}/manifests/${digest}`);
}

export function fetchRawManifest(repo: string, digest: string): Promise<unknown> {
  return fetchJson(`/api/v1/repositories/${repo}/manifests/${digest}/raw`);
}

export function deleteRepository(repo: string): Promise<DeleteCounts> {
  return fetchJson(`/api/v1/repositories/${repo}`, { method: "DELETE" });
}

export function deleteManifestDigest(repo: string, digest: string): Promise<DeleteCounts> {
  return fetchJson(`/api/v1/repositories/${repo}/manifests/${digest}`, {
    method: "DELETE",
  });
}

export function batchDeleteManifestDigests(repo: string, digests: string[]): Promise<DeleteCounts> {
  return fetchJson(`/api/v1/repositories/${repo}/manifests:batch-delete`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ digests }),
  });
}

export async function deleteManifestTag(repo: string, digest: string, tag: string): Promise<void> {
  await fetchNoBody(
    `/api/v1/repositories/${repo}/manifests/${digest}/tags/${encodeURIComponent(tag)}`,
    { method: "DELETE" },
  );
}

// ---- Access / Auth ----

export function fetchSession(): Promise<DashboardSession> {
  return fetchJson("/api/v1/session");
}

export function logoutSession(): void {
  // Set window.location directly — the browser navigates to the logout
  // endpoint immediately, before any caller cleanup can cancel it.
  // Do NOT use window.location.assign() (returns a Promise-like that
  // resolves before navigation, letting callers overwrite the location).
  window.location.href = "/api/v1/session/logout";
}

export function fetchPersonalAccessTokens(): Promise<PersonalAccessToken[]> {
  return fetchJson("/api/v1/tokens");
}

export function fetchGrantableScopes(
  params: {
    q?: string;
    n?: number;
    cursor?: string;
  } = {},
): Promise<GrantableScopeListResponse> {
  return fetchJson(`/api/v1/tokens/grantable-scopes${qs(params)}`);
}

export function fetchAccountNamespaces(): Promise<NamespaceListResponse> {
  return fetchJson("/api/v1/account/namespaces");
}

export function fetchNamespaces(): Promise<NamespaceListResponse> {
  return fetchJson("/api/v1/admin/namespaces");
}

export function fetchNamespace(handle: string): Promise<NamespaceResponse> {
  return fetchJson(`/api/v1/admin/namespaces/${encodeURIComponent(handle)}`);
}

export function claimNamespace(
  handle: string,
  request: ClaimNamespaceRequest = {},
): Promise<NamespaceResponse> {
  return fetchJson(`/api/v1/admin/namespaces/${encodeURIComponent(handle)}/claim`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
}

export async function releaseNamespace(
  handle: string,
  request: ReleaseNamespaceRequest = {},
): Promise<void> {
  await fetchNoBody(`/api/v1/admin/namespaces/${encodeURIComponent(handle)}/release`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
}

export async function revokeNamespace(handle: string): Promise<void> {
  await fetchNoBody(`/api/v1/admin/namespaces/${encodeURIComponent(handle)}/revoke`, {
    method: "POST",
  });
}

export function fetchAccountNamespaceGrants(handle: string): Promise<NamespaceGrantListResponse> {
  return fetchJson(`/api/v1/account/namespaces/${encodeURIComponent(handle)}/grants`);
}

export function createAccountNamespaceGrant(
  handle: string,
  request: PutNamespaceGrantRequest,
): Promise<NamespaceGrant> {
  return fetchJson(`/api/v1/account/namespaces/${encodeURIComponent(handle)}/grants`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
}

export function updateAccountNamespaceGrant(
  handle: string,
  grantId: string,
  request: PatchNamespaceGrantRequest,
): Promise<NamespaceGrant> {
  return fetchJson(
    `/api/v1/account/namespaces/${encodeURIComponent(handle)}/grants/${encodeURIComponent(grantId)}`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    },
  );
}

export async function deleteAccountNamespaceGrant(handle: string, grantId: string): Promise<void> {
  await fetchNoBody(
    `/api/v1/account/namespaces/${encodeURIComponent(handle)}/grants/${encodeURIComponent(grantId)}`,
    { method: "DELETE" },
  );
}

export function fetchObservedUsers(q: string): Promise<ObservedIdentityListResponse> {
  return fetchJson(`/api/v1/account/observed-users${qs({ q, limit: 20 })}`);
}

export function fetchAdminNamespaceGrants(handle: string): Promise<NamespaceGrantListResponse> {
  return fetchJson(`/api/v1/admin/namespaces/${encodeURIComponent(handle)}/grants`);
}

export function createAdminNamespaceGrant(
  handle: string,
  request: PutNamespaceGrantRequest,
): Promise<NamespaceGrant> {
  return fetchJson(`/api/v1/admin/namespaces/${encodeURIComponent(handle)}/grants`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
}

export function updateAdminNamespaceGrant(
  handle: string,
  grantId: string,
  request: PatchNamespaceGrantRequest,
): Promise<NamespaceGrant> {
  return fetchJson(
    `/api/v1/admin/namespaces/${encodeURIComponent(handle)}/grants/${encodeURIComponent(grantId)}`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    },
  );
}

export async function deleteAdminNamespaceGrant(
  handle: string,
  grantId: string,
  reason: string,
): Promise<void> {
  await fetchNoBody(
    `/api/v1/admin/namespaces/${encodeURIComponent(handle)}/grants/${encodeURIComponent(grantId)}`,
    {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    },
  );
}

export function fetchAdminNamespaceGrantAudit(
  handle: string,
): Promise<NamespaceGrantAuditListResponse> {
  return fetchJson(`/api/v1/admin/namespaces/${encodeURIComponent(handle)}/grant-audit`);
}

export function fetchPolicySets(): Promise<PolicySet[]> {
  return fetchJson("/api/v1/admin/policies");
}

export async function putPolicySet(id: string, policy: PutPolicySetRequest): Promise<void> {
  await fetchNoBody(`/api/v1/admin/policies/${encodeURIComponent(id)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(policy),
    signal: AbortSignal.timeout(15000),
  });
}

export function validatePolicySet(policy: ValidatePolicyRequest): Promise<ValidatePolicyResponse> {
  return fetchJson("/api/v1/admin/policies/validate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(policy),
    signal: AbortSignal.timeout(15000),
  });
}

export async function deletePolicySet(id: string): Promise<void> {
  await fetchNoBody(`/api/v1/admin/policies/${encodeURIComponent(id)}`, {
    method: "DELETE",
    signal: AbortSignal.timeout(15000),
  });
}

export function createPersonalAccessToken(token: CreateTokenRequest): Promise<CreateTokenResponse> {
  return fetchJson("/api/v1/tokens", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(token),
  });
}

export async function deletePersonalAccessToken(id: string): Promise<void> {
  // Use a longer timeout (15s) for token deletion — the Raft commit may
  // take longer than the default 5s timeout used for read-only fetches.
  await fetchNoBody(`/api/v1/tokens/${encodeURIComponent(id)}`, {
    method: "DELETE",
    signal: AbortSignal.timeout(15000),
  });
}

// ---- Mirror Rules / Jobs ----

export function fetchMirrorRules(includeSecrets?: boolean): Promise<MirrorRule[]> {
  return fetchJson(`/api/v1/admin/mirror/rules${qs({ include_secrets: includeSecrets })}`);
}

export function fetchMirrorRule(id: string, includeSecrets?: boolean): Promise<MirrorRule> {
  return fetchJson(
    `/api/v1/admin/mirror/rules/${encodeURIComponent(id)}${qs({ include_secrets: includeSecrets })}`,
  );
}

export async function createMirrorRule(rule: MirrorRuleCreate): Promise<void> {
  await fetchNoBody(`/api/v1/admin/mirror/rules/${encodeURIComponent(rule.id)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(rule),
  });
}

export async function deleteMirrorRule(id: string): Promise<void> {
  await fetchNoBody(`/api/v1/admin/mirror/rules/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export function triggerMirrorRule(id: string): Promise<SyncJob> {
  return fetchJson(`/api/v1/admin/mirror/rules/${encodeURIComponent(id)}/trigger`, {
    method: "POST",
  });
}

export function fetchSyncJobs(): Promise<SyncJob[]> {
  return fetchJson("/api/v1/admin/mirror/jobs");
}

export function fetchSyncJobRuns(jobId: string, limit?: number): Promise<SyncJobRun[]> {
  return fetchJson(`/api/v1/admin/mirror/jobs/${encodeURIComponent(jobId)}/runs${qs({ limit })}`);
}

// Legacy endpoint kept for old pages.
export async function triggerSyncJob(id: string): Promise<void> {
  await fetchNoBody(`/api/v1/admin/jobs/${encodeURIComponent(id)}/trigger`, {
    method: "POST",
  });
}

// ---- Proxy Cache ----

export function fetchProxyCaches(): Promise<ProxyCache[]> {
  return fetchJson("/api/v1/admin/proxy-cache");
}

export async function createProxyCache(cache: ProxyCacheCreate): Promise<void> {
  await fetchNoBody(`/api/v1/admin/proxy-cache/${encodeURIComponent(cache.id)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(cache),
  });
}

export async function deleteProxyCache(id: string): Promise<void> {
  await fetchNoBody(`/api/v1/admin/proxy-cache/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export function triggerProxyCacheWarm(
  id: string,
): Promise<{ id: string; status: string; message: string }> {
  return fetchJson(`/api/v1/admin/proxy-cache/${encodeURIComponent(id)}/warm`, {
    method: "POST",
  });
}

// ---- Legacy Warm Images ----

export function fetchWarmImages(): Promise<WarmImage[]> {
  return fetchJson("/api/v1/admin/mirror/warm");
}

export async function createWarmImage(image: WarmImage): Promise<void> {
  await fetchNoBody(`/api/v1/admin/mirror/warm/${encodeURIComponent(image.id)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(image),
  });
}

export async function deleteWarmImage(id: string): Promise<void> {
  await fetchNoBody(`/api/v1/admin/mirror/warm/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

// ---- Helm Charts ----

export function fetchHelmCharts(): Promise<HelmChart[]> {
  return fetchJson("/api/v1/admin/helm/charts");
}

export function fetchHelmChartVersions(name: string): Promise<HelmChartVersion[]> {
  return fetchJson(`/api/v1/admin/helm/charts/${encodeURIComponent(name)}/versions`);
}
