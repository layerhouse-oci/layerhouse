use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::auth::identity::Subject;
use crate::oci::digest::Digest;
use crate::oci::manifest::{
    SizedDescriptor, extract_sized_referenced_descriptors, stored_size_bytes,
    stored_size_from_descriptors,
};
use crate::store::metadata::typed_id::OrgId;

pub(crate) fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Build manifest summaries from a repository's manifests and tags.
///
/// Shared by both StateMachineData and InMemoryMetadataStore to
/// guarantee identical output from both read paths.
pub(crate) fn build_manifest_summaries(
    repo_manifests: &BTreeMap<String, ManifestEntry>,
    repo_tags: Option<&BTreeMap<String, String>>,
) -> Vec<ManifestSummary> {
    let mut by_digest: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if let Some(repo_tags) = repo_tags {
        for (tag, digest) in repo_tags {
            by_digest
                .entry(digest.clone())
                .or_default()
                .push(tag.clone());
        }
    }

    let mut summaries = Vec::new();
    for (digest, entry) in repo_manifests {
        let body = serde_json::from_slice(&entry.body).unwrap_or(serde_json::Value::Null);
        let mut tags = by_digest.remove(digest).unwrap_or_default();
        tags.sort();
        summaries.push(ManifestSummary {
            digest: digest.clone(),
            media_type: entry.content_type.clone(),
            artifact_type: entry.artifact_type.clone(),
            stored_size_bytes: manifest_stored_size_bytes(entry),
            manifest_size_bytes: entry.manifest_size_bytes,
            created_at: entry.created_at,
            last_modified: entry.last_modified,
            tags,
            subject: entry.subject.as_ref().map(ToString::to_string),
            annotations: entry.annotations.clone(),
            config_summary: entry.config_summary.clone(),
            body,
        });
    }
    summaries
}

pub(crate) fn manifest_stored_size_bytes(entry: &ManifestEntry) -> u64 {
    let descriptors = sized_descriptors_from_entry(entry);
    if descriptors.is_empty() {
        if entry.stored_size_bytes > 0 {
            entry.stored_size_bytes
        } else {
            entry.manifest_size_bytes
        }
    } else {
        stored_size_from_descriptors(descriptors)
    }
}

pub(crate) fn repository_manifest_size_bytes(
    repo_manifests: &BTreeMap<String, ManifestEntry>,
) -> u64 {
    repo_manifests
        .values()
        .map(|entry| entry.manifest_size_bytes)
        .sum()
}

pub(crate) fn repository_stored_size_bytes(
    repo_manifests: &BTreeMap<String, ManifestEntry>,
) -> u64 {
    let mut by_digest: BTreeMap<String, u64> = BTreeMap::new();
    let mut fallback_size = 0;

    for entry in repo_manifests.values() {
        let descriptors = sized_descriptors_from_entry(entry);
        if descriptors.is_empty() {
            fallback_size += entry.stored_size_bytes.max(entry.manifest_size_bytes);
            continue;
        }

        for descriptor in descriptors {
            by_digest
                .entry(descriptor.digest.to_string())
                .and_modify(|size| *size = (*size).max(descriptor.size))
                .or_insert(descriptor.size);
        }
    }

    by_digest.values().sum::<u64>() + fallback_size
}

fn sized_descriptors_from_entry(entry: &ManifestEntry) -> Vec<SizedDescriptor> {
    serde_json::from_slice::<serde_json::Value>(&entry.body)
        .map(|value| extract_sized_referenced_descriptors(&value))
        .unwrap_or_default()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    #[serde(with = "crate::oci::digest::serde_string")]
    pub digest: Digest,
    pub content_type: String,
    pub body: Vec<u8>,
    #[serde(default, with = "crate::oci::digest::serde_string_vec")]
    pub referenced_blobs: Vec<Digest>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::oci::digest::serde_string_opt"
    )]
    pub subject: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
    #[serde(default)]
    pub stored_size_bytes: u64,
    #[serde(default)]
    pub manifest_size_bytes: u64,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub last_modified: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_summary: Option<serde_json::Value>,
}

impl ManifestEntry {
    /// Build a `ManifestEntry` from a parsed OCI manifest JSON value.
    /// The caller should provide the content type, raw body, and already-checked
    /// referenced blob digests.
    pub fn from_parsed_json(
        parsed: &serde_json::Value,
        content_type: String,
        body: Vec<u8>,
        referenced_blobs: Vec<Digest>,
    ) -> Self {
        let manifest_size_bytes = body.len() as u64;
        let stored_size_bytes = stored_size_bytes(parsed);
        let digest = Digest::sha256(&body);
        let subject = crate::oci::manifest::extract_subject_digest(parsed);
        let artifact_type = crate::oci::manifest::extract_artifact_type(parsed);
        let annotations = crate::oci::manifest::extract_annotations(parsed);
        let config_summary = crate::oci::manifest::extract_config_summary(parsed);
        let now = now_epoch();
        Self {
            digest,
            content_type,
            body,
            referenced_blobs,
            subject,
            artifact_type,
            annotations,
            stored_size_bytes,
            manifest_size_bytes,
            created_at: now,
            last_modified: now,
            config_summary,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MirrorDirection {
    #[default]
    Pull,
    Push,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MirrorStrategy {
    #[default]
    All,
    Latest {
        count: u32,
    },
    Pattern {
        pattern: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OutboundProxyProtocol {
    #[default]
    None,
    Http,
    Https,
    Socks4,
    Socks5,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct OutboundProxy {
    #[serde(default)]
    pub protocol: OutboundProxyProtocol,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundProxyPublic {
    pub protocol: OutboundProxyProtocol,
    pub url: Option<String>,
    pub username_configured: bool,
    pub password_configured: bool,
}

impl From<&OutboundProxy> for OutboundProxyPublic {
    fn from(proxy: &OutboundProxy) -> Self {
        Self {
            protocol: proxy.protocol.clone(),
            url: proxy.url.clone(),
            username_configured: proxy.username.as_ref().is_some_and(|v| !v.is_empty()),
            password_configured: proxy.password.as_ref().is_some_and(|v| !v.is_empty()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalAccessToken {
    pub id: String,
    pub subject: String,
    /// Human-readable username snapshotted from the creating identity. Frozen
    /// at creation because PATs outlive the OIDC session that minted them;
    /// used to grant the personal namespace (`users/<username>/*`) on the PAT
    /// auth path. Optional for forward-compat with pre-field token rows.
    #[serde(default)]
    pub username: Option<String>,
    pub name: String,
    pub token_hash: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub created_at: u64,
    #[serde(default)]
    pub last_used_at: Option<u64>,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

/// Visibility of a repository. Controls whether anonymous clients may pull.
/// `Private` (the default) requires authentication for every operation;
/// `PublicPull` additionally allows unauthenticated `GET`/`HEAD` of manifests
/// and blobs (write operations still require auth). The public-pull middleware
/// short-circuit that honors this is a follow-on (see TODOS.md); Phase 1 only
/// carries the label so the schema is stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    #[default]
    Private,
    PublicPull,
}

/// Owning principal of a namespace. Users own by immutable OIDC `subject`;
/// orgs own by the Layerhouse-generated `OrgId`. Authorization decisions key
/// on the variant, never on the surface handle, so a username rename never
/// shifts ownership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
#[allow(dead_code)]
pub enum Owner {
    User(Subject),
    Org(OrgId),
}

/// A claimed first-segment handle. The `(handle, owner)` pair is the unit of
/// namespace ownership: pushes under `<handle>/...` are gated on the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Namespace {
    pub handle: String,
    pub owner: Owner,
    /// Frozen username/org-name captured at claim time. Persisted because the
    /// IdP-side label (preferred_username, displayName) is mutable; freezing
    /// at claim lets a later release record the originally-claimed label even
    /// if the IdP label has since drifted.
    #[serde(default)]
    pub owner_label: String,
    pub created_at: u64,
}

/// Tombstone for a previously claimed handle. Recorded when a namespace is
/// released so reclaim is admin-gated and the prior-owner UX context (frozen
/// label, release reason, timestamp) survives the deletion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ReleasedHandle {
    pub handle: String,
    pub prior_owner: Owner,
    /// Frozen username/org-name at the moment of release. Stored explicitly
    /// because the IdP-side label is mutable and may diverge after release.
    pub prior_owner_label: String,
    pub released_at: u64,
    pub released_by: Subject,
    pub release_reason: ReleaseReason,
}

/// Why a handle was released. Drives the reclaim UX (rename promises a
/// follow-up `Namespace` row at the new handle; admin-revoke triggers an
/// admin-only reclaim path; owner-deleted is the self-serve case).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[allow(dead_code)]
pub enum ReleaseReason {
    OwnerDeleted,
    AdminRevoked,
    Renamed { new_handle: String },
}

/// A first-class repository object ("shadow repository"). Unlike a manifest
/// map keyed by pushed content, a `Repository` can exist before any blob is
/// pushed, carrying human metadata (description, owner) and a visibility label.
/// Phase 1 defines the shape and persists an empty collection; the creation
/// flow (`POST /api/v1/repositories`) and listing integration land in Phase 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Subject of the identity that owns this repository, if any.
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub visibility: Visibility,
    #[serde(default)]
    pub created_at: u64,
}

/// Where a permission rule came from. `Config` rules are loaded from
/// `[[auth.permissions]]` at startup and are read-only at runtime; `Raft`
/// rules are created through the dashboard and persisted via consensus, so
/// they are editable. OIDC-sourced bindings (Phase 3) are also read-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleSource {
    #[default]
    Config,
    Raft,
    Oidc,
}

/// A path-based permission grant binding groups to an action on a repository
/// path pattern. First-class so admins can edit Raft-sourced rules through the
/// dashboard. Phase 1 defines the shape and persists an empty collection; the
/// editing flow and enforcement-from-Raft land in Phase 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRule {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub groups: Vec<String>,
    /// Scope strings (`repository:<pattern>:<action>`), same vocabulary as
    /// `[[auth.permissions]]` config and PAT scopes.
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub source: RuleSource,
    #[serde(default)]
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorRule {
    pub id: String,
    #[serde(default)]
    pub direction: MirrorDirection,
    pub local_prefix: String,
    pub upstream_registry: String,
    #[serde(default)]
    pub upstream_prefix: Option<String>,
    #[serde(default)]
    pub schedule: Option<String>,
    #[serde(default)]
    pub strategy: MirrorStrategy,
    #[serde(default)]
    pub plain_http: bool,
    #[serde(default)]
    pub insecure_tls: bool,
    #[serde(default)]
    pub outbound_proxy: OutboundProxy,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub created_at: u64,
}

/// UI-safe mirror rule — credentials are never serialized.
#[derive(Debug, Clone, Serialize)]
pub struct MirrorRulePublic {
    pub id: String,
    pub direction: MirrorDirection,
    pub local_prefix: String,
    pub upstream_registry: String,
    pub upstream_prefix: Option<String>,
    pub schedule: Option<String>,
    pub strategy: MirrorStrategy,
    pub plain_http: bool,
    pub insecure_tls: bool,
    pub outbound_proxy: OutboundProxyPublic,
    pub username_configured: bool,
    pub password_configured: bool,
    pub created_at: u64,
}

impl From<&MirrorRule> for MirrorRulePublic {
    fn from(r: &MirrorRule) -> Self {
        Self {
            id: r.id.clone(),
            direction: r.direction.clone(),
            local_prefix: r.local_prefix.clone(),
            upstream_registry: r.upstream_registry.clone(),
            upstream_prefix: r.upstream_prefix.clone(),
            schedule: r.schedule.clone(),
            strategy: r.strategy.clone(),
            plain_http: r.plain_http,
            insecure_tls: r.insecure_tls,
            outbound_proxy: OutboundProxyPublic::from(&r.outbound_proxy),
            username_configured: r.username.as_ref().is_some_and(|v| !v.is_empty()),
            password_configured: r.password.as_ref().is_some_and(|v| !v.is_empty()),
            created_at: r.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WarmFilter {
    None,
    All,
    Latest { count: u32, sort_by: WarmSortBy },
    Pattern { pattern: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WarmSortBy {
    Created,
    #[default]
    Pushed,
    Pulled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyCache {
    pub id: String,
    pub local_prefix: String,
    pub upstream_registry: String,
    #[serde(default)]
    pub upstream_prefix: Option<String>,
    #[serde(default)]
    pub warm_filters: Vec<WarmFilter>,
    #[serde(default)]
    pub warm_schedule: Option<String>,
    #[serde(default)]
    pub plain_http: bool,
    #[serde(default)]
    pub insecure_tls: bool,
    #[serde(default)]
    pub outbound_proxy: OutboundProxy,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyCacheTagValidation {
    pub cache_id: String,
    pub repository: String,
    pub tag: String,
    pub upstream_digest: String,
    pub last_validated_at: u64,
}

pub type ProxyCacheTagValidations =
    BTreeMap<String, BTreeMap<String, BTreeMap<String, ProxyCacheTagValidation>>>;

pub(crate) fn get_proxy_cache_tag_validation(
    validations: &ProxyCacheTagValidations,
    cache_id: &str,
    repository: &str,
    tag: &str,
) -> Option<ProxyCacheTagValidation> {
    validations
        .get(cache_id)?
        .get(repository)?
        .get(tag)
        .cloned()
}

pub(crate) fn put_proxy_cache_tag_validation(
    validations: &mut ProxyCacheTagValidations,
    validation: ProxyCacheTagValidation,
) {
    validations
        .entry(validation.cache_id.clone())
        .or_default()
        .entry(validation.repository.clone())
        .or_default()
        .insert(validation.tag.clone(), validation);
}

pub(crate) fn clear_proxy_cache_tag_validations_for_cache(
    validations: &mut ProxyCacheTagValidations,
    cache_id: &str,
) {
    validations.remove(cache_id);
}

pub(crate) fn clear_proxy_cache_tag_validations_for_repository(
    validations: &mut ProxyCacheTagValidations,
    repository: &str,
) {
    validations.retain(|_, repos| {
        repos.remove(repository);
        !repos.is_empty()
    });
}

pub(crate) fn clear_proxy_cache_tag_validations_for_tag(
    validations: &mut ProxyCacheTagValidations,
    repository: &str,
    tag: &str,
) {
    validations.retain(|_, repos| {
        if let Some(tags) = repos.get_mut(repository) {
            tags.remove(tag);
            if tags.is_empty() {
                repos.remove(repository);
            }
        }
        !repos.is_empty()
    });
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyCachePublic {
    pub id: String,
    pub local_prefix: String,
    pub upstream_registry: String,
    pub upstream_prefix: Option<String>,
    pub warm_filters: Vec<WarmFilter>,
    pub warm_schedule: Option<String>,
    pub plain_http: bool,
    pub insecure_tls: bool,
    pub outbound_proxy: OutboundProxyPublic,
    pub username_configured: bool,
    pub password_configured: bool,
    pub created_at: u64,
}

impl From<&ProxyCache> for ProxyCachePublic {
    fn from(cache: &ProxyCache) -> Self {
        Self {
            id: cache.id.clone(),
            local_prefix: cache.local_prefix.clone(),
            upstream_registry: cache.upstream_registry.clone(),
            upstream_prefix: cache.upstream_prefix.clone(),
            warm_filters: cache.warm_filters.clone(),
            warm_schedule: cache.warm_schedule.clone(),
            plain_http: cache.plain_http,
            insecure_tls: cache.insecure_tls,
            outbound_proxy: OutboundProxyPublic::from(&cache.outbound_proxy),
            username_configured: cache.username.as_ref().is_some_and(|v| !v.is_empty()),
            password_configured: cache.password.as_ref().is_some_and(|v| !v.is_empty()),
            created_at: cache.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmImage {
    pub id: String,
    pub image: String,
    pub tags: Vec<String>,
    #[serde(default = "default_warm_interval")]
    pub interval_secs: u64,
}

fn default_warm_interval() -> u64 {
    3600
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncJob {
    pub id: String,
    #[serde(default)]
    pub kind: SyncJobKind,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub rule_name: Option<String>,
    pub image: String,
    pub tags: Vec<String>,
    pub interval_secs: u64,
    pub status: SyncJobStatus,
    pub claimed_by: Option<String>,
    pub claimed_at: Option<u64>,
    pub last_run_at: Option<u64>,
    pub next_run_at: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SyncJobKind {
    #[default]
    LegacyWarm,
    Mirror,
    ProxyCache,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyncJobStatus {
    Idle,
    Running,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncJobRun {
    pub id: String,
    pub job_id: String,
    pub node_id: String,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub status: SyncRunStatus,
    #[serde(default = "default_sync_run_phase")]
    pub phase: String,
    #[serde(default)]
    pub total_tags: usize,
    #[serde(default)]
    pub completed_tags: usize,
    #[serde(default)]
    pub current_tag: Option<String>,
    #[serde(default)]
    pub updated_at: u64,
    #[serde(default)]
    pub recent_events: Vec<SyncRunEvent>,
    pub tags_synced: Vec<String>,
    pub tags_failed: Vec<(String, String)>,
}

const MAX_SYNC_RUN_EVENTS: usize = 50;

fn default_sync_run_phase() -> String {
    "Queued".to_string()
}

impl SyncJobRun {
    pub(crate) fn running(id: String, job_id: String, node_id: String, started_at: u64) -> Self {
        Self {
            id,
            job_id,
            node_id,
            started_at,
            finished_at: None,
            status: SyncRunStatus::Running,
            phase: default_sync_run_phase(),
            total_tags: 0,
            completed_tags: 0,
            current_tag: None,
            updated_at: started_at,
            recent_events: Vec::new(),
            tags_synced: Vec::new(),
            tags_failed: Vec::new(),
        }
    }

    pub(crate) fn mark_resolution_started(&mut self, now: u64) {
        self.phase = "Resolving tags".to_string();
        self.current_tag = None;
        self.updated_at = now;
        self.push_event(SyncRunEventKind::Info, None, "Resolving job target", now);
    }

    pub(crate) fn mark_resolution_finished(&mut self, total_tags: usize, now: u64) {
        self.total_tags = total_tags;
        self.completed_tags = 0;
        self.current_tag = None;
        self.phase = if total_tags == 0 {
            "No tags resolved".to_string()
        } else {
            "Syncing tags".to_string()
        };
        self.updated_at = now;
        self.push_event(
            SyncRunEventKind::Info,
            None,
            format!("Resolved {total_tags} tags"),
            now,
        );
    }

    pub(crate) fn mark_resolution_failed(&mut self, message: &str, now: u64) {
        self.total_tags = 0;
        self.completed_tags = 0;
        self.current_tag = None;
        self.phase = "Resolve failed".to_string();
        self.updated_at = now;
        self.push_event(SyncRunEventKind::Error, None, message, now);
    }

    pub(crate) fn mark_tag_started(&mut self, tag: &str, phase: &str, now: u64) {
        self.phase = phase.to_string();
        self.current_tag = Some(tag.to_string());
        self.updated_at = now;
        self.push_event(SyncRunEventKind::Info, Some(tag), "Started tag sync", now);
    }

    pub(crate) fn mark_tag_finished(
        &mut self,
        tag: &str,
        kind: SyncRunEventKind,
        message: impl Into<String>,
        completed_tags: usize,
        now: u64,
    ) {
        self.completed_tags = completed_tags.min(self.total_tags);
        self.current_tag = Some(tag.to_string());
        self.updated_at = now;
        self.push_event(kind, Some(tag), message, now);
    }

    pub(crate) fn mark_finished(
        &mut self,
        status: SyncRunStatus,
        tags_synced: Vec<String>,
        tags_failed: Vec<(String, String)>,
        now: u64,
    ) {
        self.finished_at = Some(now);
        self.status = status;
        self.phase = match self.status {
            SyncRunStatus::Running => "Running".to_string(),
            SyncRunStatus::Succeeded => "Succeeded".to_string(),
            SyncRunStatus::PartialFailure => "Partial failure".to_string(),
            SyncRunStatus::Failed => "Failed".to_string(),
        };
        self.current_tag = None;
        self.updated_at = now;
        self.completed_tags = if self.total_tags == 0 {
            0
        } else {
            (tags_synced.len() + tags_failed.len()).min(self.total_tags)
        };
        self.tags_synced = tags_synced;
        self.tags_failed = tags_failed;
        let kind = match self.status {
            SyncRunStatus::Succeeded => SyncRunEventKind::Success,
            SyncRunStatus::PartialFailure => SyncRunEventKind::Warning,
            SyncRunStatus::Failed => SyncRunEventKind::Error,
            SyncRunStatus::Running => SyncRunEventKind::Info,
        };
        self.push_event(kind, None, self.phase.clone(), now);
    }

    fn push_event(
        &mut self,
        kind: SyncRunEventKind,
        tag: Option<&str>,
        message: impl Into<String>,
        at: u64,
    ) {
        self.recent_events.push(SyncRunEvent {
            at,
            kind,
            tag: tag.map(ToString::to_string),
            message: message.into(),
        });
        if self.recent_events.len() > MAX_SYNC_RUN_EVENTS {
            let excess = self.recent_events.len() - MAX_SYNC_RUN_EVENTS;
            self.recent_events.drain(..excess);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SyncRunEvent {
    pub at: u64,
    pub kind: SyncRunEventKind,
    pub tag: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyncRunEventKind {
    Info,
    Success,
    Warning,
    Error,
}

pub(crate) fn proxy_cache_warm_job(cache: &ProxyCache, now: u64) -> SyncJob {
    SyncJob {
        id: format!("{}-warm-{}", cache.id, now),
        kind: SyncJobKind::ProxyCache,
        rule_id: Some(cache.id.clone()),
        rule_name: Some(cache.id.clone()),
        image: cache.local_prefix.clone(),
        tags: warm_filter_labels(&cache.warm_filters),
        interval_secs: 0,
        status: SyncJobStatus::Idle,
        claimed_by: None,
        claimed_at: None,
        last_run_at: None,
        next_run_at: now,
        last_error: None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyncRunStatus {
    Running,
    Succeeded,
    PartialFailure,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelmChart {
    pub name: String,
    pub description: String,
    pub latest_version: String,
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelmChartVersion {
    pub name: String,
    pub version: String,
    pub app_version: Option<String>,
    pub description: String,
    pub created: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepositorySummary {
    pub name: String,
    pub tag_count: usize,
    pub manifest_count: usize,
    pub stored_size_bytes: u64,
    pub manifest_size_bytes: u64,
    pub last_modified: u64,
    /// Shadow-repository metadata, populated when a first-class `Repository`
    /// object exists for this name. Defaults are used for repos that only have
    /// pushed content and no explicit metadata.
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub visibility: Visibility,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestSummary {
    pub digest: String,
    pub media_type: String,
    pub artifact_type: Option<String>,
    pub stored_size_bytes: u64,
    pub manifest_size_bytes: u64,
    pub created_at: u64,
    pub last_modified: u64,
    pub tags: Vec<String>,
    pub subject: Option<String>,
    pub annotations: Option<serde_json::Value>,
    pub config_summary: Option<serde_json::Value>,
    pub body: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteCounts {
    pub deleted_manifests: usize,
    pub deleted_tags: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlobDeleteStatus {
    pub digest: String,
    pub referenced: bool,
    pub ref_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobLifecycleStatus {
    pub digest: String,
    pub referenced: bool,
    pub ref_count: u64,
    pub delete_requested: bool,
}

pub(crate) fn mirror_strategy_labels(strategy: &MirrorStrategy) -> Vec<String> {
    match strategy {
        MirrorStrategy::All => vec!["all".to_string()],
        MirrorStrategy::Latest { count } => vec![format!("latest {}", count)],
        MirrorStrategy::Pattern { pattern } => vec![pattern.clone()],
    }
}

pub(crate) fn warm_filter_labels(filters: &[WarmFilter]) -> Vec<String> {
    filters
        .iter()
        .filter_map(|filter| match filter {
            WarmFilter::None => None,
            WarmFilter::All => Some("all".to_string()),
            WarmFilter::Latest { count, .. } => Some(format!("latest {}", count)),
            WarmFilter::Pattern { pattern } => Some(pattern.clone()),
        })
        .collect()
}

pub(crate) fn mirror_rule_job(
    rule: &MirrorRule,
    id: String,
    now: u64,
    interval_secs: u64,
) -> SyncJob {
    SyncJob {
        id,
        kind: SyncJobKind::Mirror,
        rule_id: Some(rule.id.clone()),
        rule_name: Some(rule.id.clone()),
        image: rule.local_prefix.clone(),
        tags: mirror_strategy_labels(&rule.strategy),
        interval_secs,
        status: SyncJobStatus::Idle,
        claimed_by: None,
        claimed_at: None,
        last_run_at: None,
        next_run_at: now,
        last_error: None,
    }
}

pub(crate) fn sync_job_blocks_trigger(
    job: &SyncJob,
    kind: SyncJobKind,
    rule_id: &str,
    now: u64,
) -> bool {
    job.kind == kind
        && job.rule_id.as_deref() == Some(rule_id)
        && (job.status == SyncJobStatus::Running
            || (job.interval_secs == 0 && job.next_run_at <= now))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(id: u64) -> String {
        format!("sha256:{id:064x}")
    }

    fn image_manifest_body(config_id: u64, config_size: u64, layers: &[(u64, u64)]) -> Vec<u8> {
        serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": digest(config_id),
                "size": config_size
            },
            "layers": layers
                .iter()
                .map(|(digest_id, size)| serde_json::json!({
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": digest(*digest_id),
                    "size": size
                }))
                .collect::<Vec<_>>()
        })
        .to_string()
        .into_bytes()
    }

    fn manifest_entry(body: Vec<u8>) -> ManifestEntry {
        let parsed = serde_json::from_slice::<serde_json::Value>(&body).unwrap();
        let referenced_blobs = crate::oci::manifest::extract_referenced_digests(&parsed);
        ManifestEntry::from_parsed_json(
            &parsed,
            "application/vnd.oci.image.manifest.v1+json".to_string(),
            body,
            referenced_blobs,
        )
    }

    #[test]
    fn manifest_summary_reports_stored_and_manifest_sizes() {
        let body = image_manifest_body(1, 2, &[(2, 4), (2, 4)]);
        let manifest_size = body.len() as u64;
        let entry = manifest_entry(body);
        let mut manifests = std::collections::BTreeMap::new();
        manifests.insert(entry.digest.to_string(), entry);

        let summaries = build_manifest_summaries(&manifests, None);

        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].stored_size_bytes, 6);
        assert_eq!(summaries[0].manifest_size_bytes, manifest_size);
    }

    #[test]
    fn manifest_summary_preserves_zero_byte_descriptor_size() {
        let body = image_manifest_body(1, 0, &[]);
        let manifest_size = body.len() as u64;
        let entry = manifest_entry(body);
        let mut manifests = std::collections::BTreeMap::new();
        manifests.insert(entry.digest.to_string(), entry);

        let summaries = build_manifest_summaries(&manifests, None);

        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].stored_size_bytes, 0);
        assert_eq!(summaries[0].manifest_size_bytes, manifest_size);
    }

    #[test]
    fn repository_stored_size_dedupes_shared_blob_descriptors() {
        let first = manifest_entry(image_manifest_body(1, 2, &[(2, 4)]));
        let second = manifest_entry(image_manifest_body(1, 2, &[(3, 8)]));
        let manifest_size = first.manifest_size_bytes + second.manifest_size_bytes;
        let mut manifests = std::collections::BTreeMap::new();
        manifests.insert(first.digest.to_string(), first);
        manifests.insert(second.digest.to_string(), second);

        assert_eq!(repository_stored_size_bytes(&manifests), 14);
        assert_eq!(repository_manifest_size_bytes(&manifests), manifest_size);
    }

    fn run() -> SyncJobRun {
        SyncJobRun::running(
            "run-1".to_string(),
            "job-1".to_string(),
            "node-1".to_string(),
            10,
        )
    }

    #[test]
    fn sync_run_progress_tracks_successful_tag_completion() {
        let mut run = run();
        run.mark_resolution_started(11);
        run.mark_resolution_finished(2, 12);
        run.mark_tag_started("3.20", "Pulling tag", 13);
        run.mark_tag_finished("3.20", SyncRunEventKind::Success, "Synced tag", 1, 14);
        run.mark_tag_started("3.21", "Pulling tag", 15);
        run.mark_tag_finished("3.21", SyncRunEventKind::Success, "Synced tag", 2, 16);
        run.mark_finished(
            SyncRunStatus::Succeeded,
            vec!["3.20".to_string(), "3.21".to_string()],
            Vec::new(),
            17,
        );

        assert_eq!(run.status, SyncRunStatus::Succeeded);
        assert_eq!(run.phase, "Succeeded");
        assert_eq!(run.total_tags, 2);
        assert_eq!(run.completed_tags, 2);
        assert_eq!(run.current_tag, None);
        assert_eq!(run.updated_at, 17);
        assert_eq!(run.tags_synced, vec!["3.20", "3.21"]);
        assert!(run.tags_failed.is_empty());
        assert_eq!(
            run.recent_events.last().map(|event| &event.kind),
            Some(&SyncRunEventKind::Success)
        );
    }

    #[test]
    fn sync_run_progress_tracks_partial_failure() {
        let mut run = run();
        run.mark_resolution_finished(2, 11);
        run.mark_tag_finished("3.20", SyncRunEventKind::Success, "Synced tag", 1, 12);
        run.mark_tag_finished("3.21", SyncRunEventKind::Error, "manifest unknown", 2, 13);
        run.mark_finished(
            SyncRunStatus::PartialFailure,
            vec!["3.20".to_string()],
            vec![("3.21".to_string(), "manifest unknown".to_string())],
            14,
        );

        assert_eq!(run.status, SyncRunStatus::PartialFailure);
        assert_eq!(run.phase, "Partial failure");
        assert_eq!(run.completed_tags, 2);
        assert_eq!(run.tags_failed.len(), 1);
        assert_eq!(
            run.recent_events.last().map(|event| &event.kind),
            Some(&SyncRunEventKind::Warning)
        );
    }

    #[test]
    fn sync_run_progress_tracks_resolution_failure() {
        let mut run = run();
        run.mark_resolution_started(11);
        run.mark_resolution_failed("registry unavailable", 12);
        run.mark_finished(
            SyncRunStatus::Failed,
            Vec::new(),
            vec![("resolve".to_string(), "registry unavailable".to_string())],
            13,
        );

        assert_eq!(run.status, SyncRunStatus::Failed);
        assert_eq!(run.phase, "Failed");
        assert_eq!(run.total_tags, 0);
        assert_eq!(run.completed_tags, 0);
        assert_eq!(run.tags_failed[0].0, "resolve");
        assert_eq!(
            run.recent_events.last().map(|event| &event.kind),
            Some(&SyncRunEventKind::Error)
        );
    }

    #[test]
    fn sync_run_recent_events_are_bounded() {
        let mut run = run();
        run.mark_resolution_finished(100, 11);
        for idx in 0..75 {
            run.mark_tag_finished(
                &format!("tag-{idx}"),
                SyncRunEventKind::Info,
                "progress",
                idx,
                12 + idx as u64,
            );
        }

        assert_eq!(run.recent_events.len(), 50);
        assert_eq!(run.recent_events[0].tag.as_deref(), Some("tag-25"));
        assert_eq!(run.recent_events[49].tag.as_deref(), Some("tag-74"));
    }
}
