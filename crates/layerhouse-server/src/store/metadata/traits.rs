use async_trait::async_trait;

use super::types::*;
use crate::auth::identity::Subject;
use crate::error::LayerhouseError;
use crate::oci::digest::Digest;

#[async_trait]
pub trait ManifestStore: Send + Sync + 'static {
    async fn get_manifest(
        &self,
        name: &str,
        reference: &str,
    ) -> Result<Option<ManifestEntry>, LayerhouseError>;

    async fn put_manifest(
        &self,
        name: &str,
        reference: &str,
        entry: ManifestEntry,
    ) -> Result<(), LayerhouseError>;

    async fn delete_manifest(&self, name: &str, digest: &Digest) -> Result<(), LayerhouseError>;

    async fn list_tags(
        &self,
        name: &str,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<Vec<String>, LayerhouseError>;

    async fn list_repositories(
        &self,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<Vec<String>, LayerhouseError>;

    async fn list_repository_summaries(&self) -> Result<Vec<RepositorySummary>, LayerhouseError>;

    async fn list_manifest_summaries(
        &self,
        name: &str,
    ) -> Result<Vec<ManifestSummary>, LayerhouseError>;

    async fn delete_tag(
        &self,
        name: &str,
        digest: &Digest,
        tag: &str,
    ) -> Result<bool, LayerhouseError>;

    async fn delete_repository(&self, name: &str) -> Result<DeleteCounts, LayerhouseError>;

    async fn delete_manifests(
        &self,
        name: &str,
        digests: &[Digest],
    ) -> Result<DeleteCounts, LayerhouseError>;

    async fn list_referrers(
        &self,
        name: &str,
        subject_digest: &Digest,
        artifact_type: Option<&str>,
    ) -> Result<Vec<ReferrerEntry>, LayerhouseError>;

    async fn mount_blob(
        &self,
        source_repo: &str,
        dest_repo: &str,
        digest: &Digest,
    ) -> Result<(), LayerhouseError>;

    async fn record_blob_delete_request(
        &self,
        digest: &Digest,
    ) -> Result<BlobDeleteStatus, LayerhouseError>;

    async fn blob_lifecycle_status(
        &self,
        digest: &Digest,
    ) -> Result<BlobLifecycleStatus, LayerhouseError>;

    async fn clear_blob_delete_request(&self, digest: &Digest) -> Result<(), LayerhouseError>;

    /// Return all blob reference counts (used by GC).
    #[allow(dead_code)]
    async fn blob_ref_counts(
        &self,
    ) -> Result<std::collections::BTreeMap<String, u64>, LayerhouseError>;
}

// ── Mirror configuration ──────────────────────────────────────────────

#[async_trait]
#[async_trait]
pub trait MirrorConfigStore: Send + Sync + 'static {
    // Mirror rule CRUD
    async fn list_mirror_rules(&self) -> Result<Vec<MirrorRule>, LayerhouseError>;
    async fn get_mirror_rule(&self, id: &str) -> Result<Option<MirrorRule>, LayerhouseError>;
    async fn put_mirror_rule(&self, rule: MirrorRule) -> Result<(), LayerhouseError>;
    async fn delete_mirror_rule(&self, id: &str) -> Result<(), LayerhouseError>;

    async fn trigger_mirror_rule(&self, id: &str) -> Result<Option<SyncJob>, LayerhouseError>;

    // Proxy cache CRUD
    async fn list_proxy_caches(&self) -> Result<Vec<ProxyCache>, LayerhouseError>;
    async fn get_proxy_cache(&self, id: &str) -> Result<Option<ProxyCache>, LayerhouseError>;
    async fn put_proxy_cache(&self, cache: ProxyCache) -> Result<(), LayerhouseError>;
    async fn delete_proxy_cache(&self, id: &str) -> Result<(), LayerhouseError>;
    async fn trigger_proxy_cache_warm(&self, id: &str) -> Result<Option<SyncJob>, LayerhouseError>;
    async fn get_proxy_cache_tag_validation(
        &self,
        cache_id: &str,
        repository: &str,
        tag: &str,
    ) -> Result<Option<ProxyCacheTagValidation>, LayerhouseError>;
    async fn put_proxy_cache_tag_validation(
        &self,
        validation: ProxyCacheTagValidation,
    ) -> Result<(), LayerhouseError>;

    // Warm image CRUD
    async fn list_warm_images(&self) -> Result<Vec<WarmImage>, LayerhouseError>;
    async fn get_warm_image(&self, id: &str) -> Result<Option<WarmImage>, LayerhouseError>;
    async fn put_warm_image(&self, image: WarmImage) -> Result<(), LayerhouseError>;
    async fn delete_warm_image(&self, id: &str) -> Result<(), LayerhouseError>;
}

// ── Sync job execution tracking ───────────────────────────────────────

#[async_trait]
#[async_trait]
pub trait JobStore: Send + Sync + 'static {
    async fn list_sync_jobs(&self) -> Result<Vec<SyncJob>, LayerhouseError>;
    async fn get_sync_job(&self, id: &str) -> Result<Option<SyncJob>, LayerhouseError>;
    async fn put_sync_job(&self, job: SyncJob) -> Result<(), LayerhouseError>;
    async fn delete_sync_job(&self, id: &str) -> Result<(), LayerhouseError>;
    async fn claim_sync_job(&self, id: &str, node_id: &str) -> Result<bool, LayerhouseError>;
    async fn trigger_sync_job(&self, id: &str) -> Result<bool, LayerhouseError>;

    // Sync job runs
    async fn list_sync_job_runs(
        &self,
        job_id: &str,
        limit: usize,
    ) -> Result<Vec<SyncJobRun>, LayerhouseError>;
    async fn put_sync_job_run(&self, run: SyncJobRun) -> Result<(), LayerhouseError>;
}

// ── Personal access tokens ────────────────────────────────────────────

#[async_trait]
#[async_trait]
pub trait TokenStore: Send + Sync + 'static {
    async fn list_personal_access_tokens(
        &self,
        subject: &str,
    ) -> Result<Vec<PersonalAccessToken>, LayerhouseError>;
    async fn get_personal_access_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<PersonalAccessToken>, LayerhouseError>;
    async fn put_personal_access_token(
        &self,
        token: PersonalAccessToken,
    ) -> Result<(), LayerhouseError>;
    async fn delete_personal_access_token(
        &self,
        id: &str,
        subject: &str,
    ) -> Result<bool, LayerhouseError>;
}

// ── Helm charts ───────────────────────────────────────────────────────

#[async_trait]
pub trait HelmStore: Send + Sync + 'static {
    async fn list_helm_charts(&self) -> Result<Vec<HelmChart>, LayerhouseError>;
    async fn list_helm_chart_versions(
        &self,
        name: &str,
    ) -> Result<Option<Vec<HelmChartVersion>>, LayerhouseError>;
}

// ── Domain supertrait aliases ─────────────────────────────────────────

/// First-class repository ("shadow repository") CRUD. A `Repository` can exist
/// before any blob is pushed and carries human metadata (description, created_by,
/// visibility). Persisted via Raft consensus, same as the other metadata.
#[async_trait]
pub trait RepositoryStore: Send + Sync + 'static {
    async fn get_repository(&self, name: &str) -> Result<Option<Repository>, LayerhouseError>;
    async fn put_repository(&self, repo: Repository) -> Result<(), LayerhouseError>;
    async fn delete_repository_meta(&self, name: &str) -> Result<bool, LayerhouseError>;
}

/// Namespace (first-segment handle) ownership. A live `Namespace` entry is the
/// authority that gates every content write under `<handle>/...`; a released
/// handle leaves a `ReleasedHandle` tombstone that blocks silent re-claim
/// unless an admin overrides. Claim/release/revoke carry the acting `Subject`
/// and a leader-minted timestamp because apply must stay deterministic across
/// followers.
///
/// The methods land ahead of their consumers (namespace routes and the
/// check_permission rewrite) so the store boundary is defined in one place;
/// `#[allow(dead_code)]` covers the gap until those follow-ups wire them in.
#[allow(dead_code)]
#[async_trait]
pub trait NamespaceStore: Send + Sync + 'static {
    async fn get_namespace(&self, handle: &str) -> Result<Option<Namespace>, LayerhouseError>;
    async fn list_namespaces(&self) -> Result<Vec<Namespace>, LayerhouseError>;
    async fn get_released_handle(
        &self,
        handle: &str,
    ) -> Result<Option<ReleasedHandle>, LayerhouseError>;

    #[allow(clippy::too_many_arguments)]
    async fn claim_namespace(
        &self,
        handle: &str,
        owner: Owner,
        owner_label: &str,
        actor: Subject,
        admin_override: bool,
        now: u64,
    ) -> Result<(), LayerhouseError>;

    async fn release_namespace(
        &self,
        handle: &str,
        actor: Subject,
        reason: ReleaseReason,
        now: u64,
    ) -> Result<(), LayerhouseError>;

    async fn admin_revoke_namespace(
        &self,
        handle: &str,
        actor: Subject,
        now: u64,
    ) -> Result<(), LayerhouseError>;
}

/// OCI registry core: manifest CRUD + mirror config + blob lifecycle.
pub trait RegistryStore: ManifestStore + MirrorConfigStore {}
impl<T: ManifestStore + MirrorConfigStore> RegistryStore for T {}

/// Admin API: mirror rules, proxy caches, warm images, sync jobs, helm.
pub trait AdminStore: MirrorConfigStore + JobStore + HelmStore {}
impl<T: MirrorConfigStore + JobStore + HelmStore> AdminStore for T {}

/// Scheduler: mirror config + sync job execution + manifest reads.
pub trait SchedulerStore: ManifestStore + MirrorConfigStore + JobStore {}
impl<T: ManifestStore + MirrorConfigStore + JobStore> SchedulerStore for T {}

// ── Supertrait for backward compatibility ─────────────────────────────

pub trait MetadataStore:
    ManifestStore
    + MirrorConfigStore
    + JobStore
    + TokenStore
    + HelmStore
    + RepositoryStore
    + NamespaceStore
{
}

impl<
    T: ManifestStore
        + MirrorConfigStore
        + JobStore
        + TokenStore
        + HelmStore
        + RepositoryStore
        + NamespaceStore,
> MetadataStore for T
{
}

#[derive(Debug, Clone)]
pub struct ReferrerEntry {
    pub digest: Digest,
    pub media_type: String,
    pub size: u64,
    pub artifact_type: Option<String>,
    pub annotations: Option<serde_json::Value>,
}
