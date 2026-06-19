use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;

use openraft::storage::Snapshot;
use openraft::{
    Entry, EntryPayload, LogId, SnapshotMeta, StorageError, StorageIOError, StoredMembership,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::{
    JobRequest, JobResponse, ManifestRequest, ManifestResponse, MirrorConfigRequest,
    MirrorConfigResponse, NamespaceRequest, NamespaceResponse, RepositoryRequest,
    RepositoryResponse, Request, Response, TokenRequest, TokenResponse, TypeConfig,
};
use crate::error::LayerhouseError;
use crate::oci::digest::Digest;
use crate::oci::manifest::extract_referenced_digests;
use crate::store::metadata::handle::{handle_of, is_handle_reserved, validate_handle};
use crate::store::metadata::{
    BlobDeleteStatus, BlobLifecycleStatus, DeleteCounts, HelmChart, HelmChartVersion,
    ManifestEntry, ManifestSummary, MirrorRule, Namespace, NamespaceGrant,
    NamespaceGrantAuditEvent, NamespaceGrantAuditOperation, NamespaceGrantGrantee,
    ObservedIdentity, PermissionRule, PersonalAccessToken, ProxyCache, ReferrerEntry,
    ReleaseReason, ReleasedHandle, Repository, RepositorySummary, SyncJob, SyncJobKind, SyncJobRun,
    SyncJobStatus, WarmImage, clear_proxy_cache_tag_validations_for_cache,
    clear_proxy_cache_tag_validations_for_repository, clear_proxy_cache_tag_validations_for_tag,
    get_proxy_cache_tag_validation, mirror_rule_job, now_epoch, proxy_cache_warm_job,
    put_proxy_cache_tag_validation, repository_manifest_size_bytes, repository_stored_size_bytes,
    sync_job_blocks_trigger,
};

/// On-disk snapshot format version. The single source of truth for both the
/// Raft `install_snapshot` path here and the S3 cold-start path in `main.rs`
/// (which aliases this constant), so the two can never drift. Layerhouse is
/// not yet deployed, so the format starts fresh at 1 with no legacy versions
/// to accept — any other version is rejected outright.
pub(crate) const SNAPSHOT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateMachineData {
    #[serde(default)]
    pub last_applied_log: Option<LogId<u64>>,
    #[serde(default)]
    pub last_membership: StoredMembership<u64, openraft::BasicNode>,
    #[serde(default)]
    pub manifests: BTreeMap<String, BTreeMap<String, ManifestEntry>>,
    #[serde(default)]
    pub tags: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    pub blob_ref_counts: BTreeMap<String, u64>,
    #[serde(default)]
    pub blob_delete_requests: BTreeMap<String, u64>,
    #[serde(default)]
    pub mirror_rules: BTreeMap<String, MirrorRule>,
    #[serde(default)]
    pub proxy_caches: BTreeMap<String, ProxyCache>,
    #[serde(default)]
    pub proxy_cache_tag_validations: crate::store::metadata::ProxyCacheTagValidations,
    #[serde(default)]
    pub warm_images: BTreeMap<String, WarmImage>,
    #[serde(default)]
    pub sync_jobs: BTreeMap<String, SyncJob>,
    #[serde(default)]
    pub sync_job_runs: BTreeMap<String, Vec<SyncJobRun>>,
    #[serde(default)]
    pub helm_charts: BTreeMap<String, HelmChart>,
    #[serde(default)]
    pub helm_chart_versions: BTreeMap<String, Vec<HelmChartVersion>>,
    #[serde(default)]
    pub personal_access_tokens: BTreeMap<String, PersonalAccessToken>,
    /// First-class repository objects (shadow repositories). Keyed by repo
    /// name. Empty in Phase 1; populated by the creation flow in Phase 2.
    #[serde(default)]
    pub repositories: BTreeMap<String, Repository>,
    /// Raft-sourced permission rules, keyed by rule id. Empty in Phase 1;
    /// the dashboard editing flow lands in Phase 3.
    #[serde(default)]
    pub permission_rules: BTreeMap<String, PermissionRule>,
    /// Live first-segment claims. The presence of `namespaces[handle]` is the
    /// apply-time precondition for any write that creates content under that
    /// handle (manifest push, repository create, blob mount).
    #[serde(default)]
    pub namespaces: BTreeMap<String, Namespace>,
    /// Tombstones for previously-claimed handles. Reclaim is admin-gated; the
    /// frozen `prior_owner_label` survives release so the UX can show the
    /// last-known owner even after the IdP-side label changes.
    #[serde(default)]
    pub released_handles: BTreeMap<String, ReleasedHandle>,
    /// Namespace-scoped grants. Outer key is namespace handle, inner key is
    /// grant id, so auth checks never scan unrelated namespaces.
    #[serde(default)]
    pub namespace_grants: BTreeMap<String, BTreeMap<String, NamespaceGrant>>,
    /// Login-observed identities for one-off user grants. This intentionally
    /// does not model a full IdP directory.
    #[serde(default)]
    pub observed_identities: BTreeMap<crate::auth::identity::Subject, ObservedIdentity>,
    /// Durable grant-change audit, grouped by namespace.
    #[serde(default)]
    pub namespace_grant_audit: BTreeMap<String, Vec<NamespaceGrantAuditEvent>>,
}

pub struct StateMachine {
    data: Arc<RwLock<StateMachineData>>,
    snapshot: Option<(SnapshotMeta<u64, openraft::BasicNode>, Vec<u8>)>,
}

impl StateMachine {
    pub fn new(data: Arc<RwLock<StateMachineData>>) -> Self {
        Self {
            data,
            snapshot: None,
        }
    }

    pub fn new_with_snapshot(
        data: Arc<RwLock<StateMachineData>>,
        meta: SnapshotMeta<u64, openraft::BasicNode>,
        bytes: Vec<u8>,
    ) -> Self {
        let snapshot = Some((meta, bytes));
        Self { data, snapshot }
    }

    fn apply_request(data: &mut StateMachineData, req: Request) -> Response {
        match req {
            Request::Manifest(r) => match Self::apply_manifest(data, r) {
                Ok(r) => Response::Manifest(r),
                Err(e) => Self::error_to_response(e),
            },
            Request::MirrorConfig(r) => Response::MirrorConfig(Self::apply_mirror_config(data, r)),
            Request::Job(r) => Response::Job(Self::apply_job(data, r)),
            Request::Token(r) => Response::Token(Self::apply_token(data, r)),
            Request::Repository(r) => match Self::apply_repository(data, r) {
                Ok(r) => Response::Repository(r),
                Err(e) => Self::error_to_response(e),
            },
            Request::Namespace(r) => match apply_namespace(data, r) {
                Ok(r) => Response::Namespace(r),
                Err(e) => Self::error_to_response(e),
            },
        }
    }

    fn error_to_response(e: LayerhouseError) -> Response {
        match e {
            LayerhouseError::NameUnknown(msg) => Response::NameUnknown(msg),
            LayerhouseError::Denied(msg) => Response::Denied(msg),
            LayerhouseError::Conflict(msg) => Response::Conflict(msg),
            LayerhouseError::NameInvalid(msg) => Response::NameInvalid(msg),
            LayerhouseError::BlobUnknown(msg)
            | LayerhouseError::BlobUploadInvalid(msg)
            | LayerhouseError::BlobUploadUnknown(msg)
            | LayerhouseError::DigestInvalid(msg)
            | LayerhouseError::ManifestBlobUnknown(msg)
            | LayerhouseError::ManifestInvalid(msg)
            | LayerhouseError::ManifestUnknown(msg)
            | LayerhouseError::SizeInvalid(msg)
            | LayerhouseError::Unsupported(msg)
            | LayerhouseError::TooManyRequests(msg)
            | LayerhouseError::S3(msg)
            | LayerhouseError::Serialization(msg)
            | LayerhouseError::Upstream(msg)
            | LayerhouseError::NotLeader(msg)
            | LayerhouseError::Consensus(msg)
            | LayerhouseError::Internal(msg) => Response::InternalError(msg),
            LayerhouseError::Unauthorized { message, .. } => Response::InternalError(message),
            LayerhouseError::Io(e) => Response::InternalError(e.to_string()),
        }
    }

    fn apply_manifest(
        data: &mut StateMachineData,
        req: ManifestRequest,
    ) -> Result<ManifestResponse, LayerhouseError> {
        match req {
            ManifestRequest::PutManifest {
                name,
                reference,
                digest,
                content_type,
                body,
                subject,
                artifact_type,
                annotations,
                stored_size_bytes,
                manifest_size_bytes,
                created_at,
                last_modified,
                config_summary,
                referenced_blobs,
            } => {
                require_live_namespace(data, &name)?;
                let digest_parsed =
                    Digest::from_str_checked(&digest).unwrap_or_else(|| Digest::sha256(&body));
                let subject_parsed = subject.and_then(|s| Digest::from_str_checked(&s));
                let mut refs: Vec<Digest> = referenced_blobs
                    .iter()
                    .filter_map(|s| Digest::from_str_checked(s))
                    .collect();
                if refs.is_empty()
                    && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body)
                {
                    refs = extract_referenced_digests(&value);
                }
                refs.sort_by_key(|a| a.to_string());
                refs.dedup_by(|a, b| a.to_string() == b.to_string());

                let entry = ManifestEntry {
                    digest: digest_parsed,
                    content_type,
                    body,
                    referenced_blobs: refs,
                    subject: subject_parsed,
                    artifact_type,
                    annotations,
                    stored_size_bytes,
                    manifest_size_bytes,
                    created_at,
                    last_modified,
                    config_summary,
                };

                let entry_key = entry.digest.to_string();
                let previous = data
                    .manifests
                    .entry(name.clone())
                    .or_default()
                    .insert(entry_key.clone(), entry.clone());
                if let Some(previous) = previous {
                    data.decrement_blob_refs(&previous);
                }
                data.increment_blob_refs(&entry);

                let is_digest = reference.contains(':');
                if !is_digest {
                    clear_proxy_cache_tag_validations_for_tag(
                        &mut data.proxy_cache_tag_validations,
                        &name,
                        &reference,
                    );
                    data.tags
                        .entry(name)
                        .or_default()
                        .insert(reference, entry_key);
                }

                Ok(ManifestResponse::Ok)
            }
            ManifestRequest::DeleteManifest { name, digest } => {
                let mut removed = None;
                if let Some(repo) = data.manifests.get_mut(&name) {
                    removed = repo.remove(&digest);
                }
                if let Some(entry) = removed.as_ref() {
                    data.decrement_blob_refs(entry);
                }
                let mut removed_tags = Vec::new();
                if let Some(repo_tags) = data.tags.get_mut(&name) {
                    repo_tags.retain(|tag, d| {
                        let keep = *d != digest;
                        if !keep {
                            removed_tags.push(tag.clone());
                        }
                        keep
                    });
                }
                for tag in removed_tags {
                    clear_proxy_cache_tag_validations_for_tag(
                        &mut data.proxy_cache_tag_validations,
                        &name,
                        &tag,
                    );
                }
                Ok(ManifestResponse::Ok)
            }
            ManifestRequest::DeleteTag { name, digest, tag } => {
                let removed = data
                    .tags
                    .get_mut(&name)
                    .and_then(|repo_tags| {
                        let matches = repo_tags.get(&tag).map(|d| *d == digest).unwrap_or(false);
                        if matches {
                            repo_tags.remove(&tag)
                        } else {
                            None
                        }
                    })
                    .is_some();
                if removed {
                    clear_proxy_cache_tag_validations_for_tag(
                        &mut data.proxy_cache_tag_validations,
                        &name,
                        &tag,
                    );
                }
                Ok(ManifestResponse::Bool(removed))
            }
            ManifestRequest::DeleteRepository { name } => {
                let removed = data.manifests.remove(&name);
                if let Some(manifests) = removed.as_ref() {
                    for entry in manifests.values() {
                        data.decrement_blob_refs(entry);
                    }
                }
                let deleted_manifests = removed.map(|m| m.len()).unwrap_or(0);
                let deleted_tags = data.tags.remove(&name).map(|t| t.len()).unwrap_or(0);
                clear_proxy_cache_tag_validations_for_repository(
                    &mut data.proxy_cache_tag_validations,
                    &name,
                );
                Ok(ManifestResponse::DeleteCounts(DeleteCounts {
                    deleted_manifests,
                    deleted_tags,
                }))
            }
            ManifestRequest::DeleteManifests { name, digests } => {
                let digest_set: std::collections::BTreeSet<String> = digests.into_iter().collect();
                let mut deleted_manifests = 0;
                let mut deleted_tags = 0;
                let mut removed = Vec::new();
                if let Some(repo) = data.manifests.get_mut(&name) {
                    for digest in &digest_set {
                        if let Some(entry) = repo.remove(digest) {
                            removed.push(entry);
                            deleted_manifests += 1;
                        }
                    }
                }
                for entry in &removed {
                    data.decrement_blob_refs(entry);
                }
                let mut removed_tags = Vec::new();
                if let Some(repo_tags) = data.tags.get_mut(&name) {
                    let before = repo_tags.len();
                    repo_tags.retain(|tag, digest| {
                        let keep = !digest_set.contains(digest);
                        if !keep {
                            removed_tags.push(tag.clone());
                        }
                        keep
                    });
                    deleted_tags = before.saturating_sub(repo_tags.len());
                }
                for tag in removed_tags {
                    clear_proxy_cache_tag_validations_for_tag(
                        &mut data.proxy_cache_tag_validations,
                        &name,
                        &tag,
                    );
                }
                Ok(ManifestResponse::DeleteCounts(DeleteCounts {
                    deleted_manifests,
                    deleted_tags,
                }))
            }
            ManifestRequest::MountBlob {
                source_repo: _,
                dest_repo,
                digest: _,
            } => {
                require_live_namespace(data, &dest_repo)?;
                Ok(ManifestResponse::Ok)
            }
            ManifestRequest::RecordBlobDelete {
                digest,
                requested_at,
            } => {
                let ref_count = data.blob_ref_count_str(&digest);
                data.blob_delete_requests
                    .insert(digest.clone(), requested_at);
                Ok(ManifestResponse::BlobDeleteStatus(BlobDeleteStatus {
                    digest,
                    referenced: ref_count > 0,
                    ref_count,
                }))
            }
            ManifestRequest::ClearBlobDelete { digest } => {
                data.blob_delete_requests.remove(&digest);
                Ok(ManifestResponse::Ok)
            }
        }
    }

    fn apply_mirror_config(
        data: &mut StateMachineData,
        req: MirrorConfigRequest,
    ) -> MirrorConfigResponse {
        match req {
            MirrorConfigRequest::PutMirrorRule(rule) => {
                data.mirror_rules.insert(rule.id.clone(), rule);
                MirrorConfigResponse::Ok
            }
            MirrorConfigRequest::DeleteMirrorRule { id } => {
                data.mirror_rules.remove(&id);
                MirrorConfigResponse::Ok
            }
            MirrorConfigRequest::TriggerMirrorRule { id } => {
                let Some(rule) = data.mirror_rules.get(&id).cloned() else {
                    return MirrorConfigResponse::SyncJob(None);
                };
                let now = now_epoch();
                if data
                    .sync_jobs
                    .values()
                    .any(|job| sync_job_blocks_trigger(job, SyncJobKind::Mirror, &id, now))
                {
                    return MirrorConfigResponse::Bool(false);
                }

                let job = mirror_rule_job(&rule, format!("{}-{}", id, now), now, 0);
                data.sync_jobs.insert(job.id.clone(), job.clone());
                MirrorConfigResponse::SyncJob(Some(job))
            }
            MirrorConfigRequest::PutProxyCache(cache) => {
                clear_proxy_cache_tag_validations_for_cache(
                    &mut data.proxy_cache_tag_validations,
                    &cache.id,
                );
                data.proxy_caches.insert(cache.id.clone(), cache);
                MirrorConfigResponse::Ok
            }
            MirrorConfigRequest::DeleteProxyCache { id } => {
                data.proxy_caches.remove(&id);
                clear_proxy_cache_tag_validations_for_cache(
                    &mut data.proxy_cache_tag_validations,
                    &id,
                );
                MirrorConfigResponse::Ok
            }
            MirrorConfigRequest::TriggerProxyCacheWarm { id } => {
                let Some(cache) = data.proxy_caches.get(&id).cloned() else {
                    return MirrorConfigResponse::SyncJob(None);
                };
                let now = now_epoch();
                if data
                    .sync_jobs
                    .values()
                    .any(|job| sync_job_blocks_trigger(job, SyncJobKind::ProxyCache, &id, now))
                {
                    return MirrorConfigResponse::Bool(false);
                }
                let job = proxy_cache_warm_job(&cache, now);
                data.sync_jobs.insert(job.id.clone(), job.clone());
                MirrorConfigResponse::SyncJob(Some(job))
            }
            MirrorConfigRequest::PutProxyCacheTagValidation(validation) => {
                put_proxy_cache_tag_validation(&mut data.proxy_cache_tag_validations, validation);
                MirrorConfigResponse::Ok
            }
            MirrorConfigRequest::PutWarmImage(image) => {
                data.warm_images.insert(image.id.clone(), image);
                MirrorConfigResponse::Ok
            }
            MirrorConfigRequest::DeleteWarmImage { id } => {
                data.warm_images.remove(&id);
                MirrorConfigResponse::Ok
            }
        }
    }

    fn apply_job(data: &mut StateMachineData, req: JobRequest) -> JobResponse {
        match req {
            JobRequest::PutSyncJob(job) => {
                data.sync_jobs.insert(job.id.clone(), job);
                JobResponse::Ok
            }
            JobRequest::DeleteSyncJob { id } => {
                data.sync_jobs.remove(&id);
                data.sync_job_runs.remove(&id);
                JobResponse::Ok
            }
            JobRequest::ClaimSyncJob { id, node_id } => {
                let Some(job) = data.sync_jobs.get_mut(&id) else {
                    return JobResponse::Bool(false);
                };
                if job.status != SyncJobStatus::Idle {
                    return JobResponse::Bool(false);
                }
                job.status = SyncJobStatus::Running;
                job.claimed_by = Some(node_id);
                job.claimed_at = Some(now_epoch());
                JobResponse::Bool(true)
            }
            JobRequest::TriggerSyncJob { id } => {
                let Some(job) = data.sync_jobs.get_mut(&id) else {
                    return JobResponse::Bool(false);
                };
                if job.status == SyncJobStatus::Running {
                    return JobResponse::Bool(false);
                }
                job.status = SyncJobStatus::Idle;
                job.claimed_by = None;
                job.claimed_at = None;
                job.last_error = None;
                job.next_run_at = now_epoch();
                JobResponse::Bool(true)
            }
            JobRequest::PutSyncJobRun(run) => {
                let runs = data.sync_job_runs.entry(run.job_id.clone()).or_default();
                if let Some(pos) = runs.iter().position(|r| r.id == run.id) {
                    runs[pos] = run;
                } else {
                    runs.push(run);
                    if runs.len() > 50 {
                        let excess = runs.len() - 50;
                        runs.drain(..excess);
                    }
                }
                JobResponse::Ok
            }
        }
    }

    fn apply_token(data: &mut StateMachineData, req: TokenRequest) -> TokenResponse {
        match req {
            TokenRequest::PutPersonalAccessToken(token) => {
                data.personal_access_tokens.insert(token.id.clone(), token);
                TokenResponse::Ok
            }
            TokenRequest::DeletePersonalAccessToken { id, subject } => {
                let should_delete = data
                    .personal_access_tokens
                    .get(&id)
                    .map(|t| t.subject == subject)
                    .unwrap_or(false);
                if should_delete {
                    data.personal_access_tokens.remove(&id);
                }
                TokenResponse::Bool(should_delete)
            }
        }
    }

    fn apply_repository(
        data: &mut StateMachineData,
        req: RepositoryRequest,
    ) -> Result<RepositoryResponse, LayerhouseError> {
        match req {
            RepositoryRequest::PutRepository(repo) => {
                require_live_namespace(data, &repo.name)?;
                data.repositories.insert(repo.name.clone(), repo);
                Ok(RepositoryResponse::Ok)
            }
            RepositoryRequest::DeleteRepository { name } => {
                let removed = data.repositories.remove(&name).is_some();
                Ok(RepositoryResponse::Bool(removed))
            }
        }
    }
}

/// Apply a namespace mutation against the full state machine data. Thin wrapper
/// over [`apply_namespace_core`]: it splits out the namespace/tombstone maps
/// (mutated) from the content collections (read-only) so the core logic has a
/// single home and the test-only in-memory store can drive the exact same
/// claim / release / revoke rules without re-implementing them.
pub(crate) fn apply_namespace(
    data: &mut StateMachineData,
    req: NamespaceRequest,
) -> Result<NamespaceResponse, LayerhouseError> {
    let StateMachineData {
        namespaces,
        released_handles,
        namespace_grants,
        namespace_grant_audit,
        observed_identities,
        manifests,
        tags,
        repositories,
        ..
    } = data;
    apply_namespace_core(
        namespaces,
        released_handles,
        namespace_grants,
        namespace_grant_audit,
        observed_identities,
        req,
        |handle| {
            let prefix = format!("{handle}/");
            any_key_with_prefix(manifests, &prefix)
                || any_key_with_prefix(tags, &prefix)
                || any_key_with_prefix(repositories, &prefix)
        },
    )
}

/// Core claim / release / revoke logic, parameterized over the two namespace
/// maps and a `has_content` predicate. Both the Raft apply path and the
/// in-memory test double call this so the conflict-detection and tombstone
/// rules cannot drift between them.
///
/// `has_content` reports whether any apply-tracked content still lives under
/// the handle; release is rejected while it returns true so callers must delete
/// repositories first (avoids unbounded Raft commits at release time).
pub(crate) fn apply_namespace_core(
    namespaces: &mut BTreeMap<String, Namespace>,
    released_handles: &mut BTreeMap<String, ReleasedHandle>,
    namespace_grants: &mut BTreeMap<String, BTreeMap<String, NamespaceGrant>>,
    namespace_grant_audit: &mut BTreeMap<String, Vec<NamespaceGrantAuditEvent>>,
    observed_identities: &mut BTreeMap<crate::auth::identity::Subject, ObservedIdentity>,
    req: NamespaceRequest,
    has_content: impl Fn(&str) -> bool,
) -> Result<NamespaceResponse, LayerhouseError> {
    match req {
        NamespaceRequest::Claim {
            handle,
            owner,
            owner_label,
            actor,
            admin_override,
            now,
        } => {
            validate_handle(&handle)?;
            if is_handle_reserved(&handle) {
                return Err(LayerhouseError::Denied(format!(
                    "handle {handle:?} is reserved by the system and cannot be claimed"
                )));
            }
            if namespaces.contains_key(&handle) {
                // Conflict body intentionally omits the prior owner id —
                // exposing it would leak cross-tenant subject/org ids to
                // an unrelated caller. Surface the kind only.
                let owner_kind = match namespaces.get(&handle).map(|n| &n.owner) {
                    Some(crate::store::metadata::Owner::User(_)) => "user",
                    Some(crate::store::metadata::Owner::Org(_)) => "org",
                    None => "unknown",
                };
                return Err(LayerhouseError::Conflict(format!(
                    "handle {handle:?} is already claimed by a {owner_kind}"
                )));
            }
            if let Some(tomb) = released_handles.get(&handle) {
                if !admin_override {
                    return Err(LayerhouseError::Denied(format!(
                        "handle {handle:?} was previously released ({}); reclaim requires admin override",
                        release_reason_label(&tomb.release_reason)
                    )));
                }
                released_handles.remove(&handle);
            }
            let _ = actor;
            namespaces.insert(
                handle.clone(),
                Namespace {
                    handle,
                    owner,
                    owner_label,
                    created_at: now,
                },
            );
            Ok(NamespaceResponse::Ok)
        }
        NamespaceRequest::Delete {
            handle,
            actor,
            reason,
            now,
        } => {
            let Some(ns) = namespaces.get(&handle) else {
                return Err(LayerhouseError::NameUnknown(format!(
                    "handle {handle:?} is not currently claimed"
                )));
            };
            // Only the namespace owner may release it. Admins use
            // AdminRevoke, not Delete. Org-owned namespaces always
            // require admin intervention until org membership lands.
            let is_owner = match &ns.owner {
                crate::store::metadata::Owner::User(subject) => actor == *subject,
                crate::store::metadata::Owner::Org(_) => false,
            };
            if !is_owner {
                return Err(LayerhouseError::Denied(format!(
                    "handle {handle:?} is not owned by the caller"
                )));
            }
            if has_content(&handle) {
                return Err(LayerhouseError::Conflict(format!(
                    "handle {handle:?} still owns repositories or manifests; delete them before releasing"
                )));
            }
            let ns = namespaces.remove(&handle).expect("namespace just verified");
            namespace_grants.remove(&handle);
            released_handles.insert(
                handle.clone(),
                ReleasedHandle {
                    handle: handle.clone(),
                    prior_owner: ns.owner,
                    prior_owner_label: ns.owner_label,
                    released_at: now,
                    released_by: actor,
                    release_reason: reason,
                },
            );
            Ok(NamespaceResponse::Ok)
        }
        NamespaceRequest::AdminRevoke { handle, actor, now } => {
            let Some(ns) = namespaces.remove(&handle) else {
                return Err(LayerhouseError::NameUnknown(format!(
                    "handle {handle:?} is not currently claimed"
                )));
            };
            namespace_grants.remove(&handle);
            released_handles.insert(
                handle.clone(),
                ReleasedHandle {
                    handle: handle.clone(),
                    prior_owner: ns.owner,
                    prior_owner_label: ns.owner_label,
                    released_at: now,
                    released_by: actor,
                    release_reason: ReleaseReason::AdminRevoked,
                },
            );
            Ok(NamespaceResponse::Ok)
        }
        NamespaceRequest::PutGrant {
            mut grant,
            actor_label,
            reason,
            audit_id,
        } => {
            validate_namespace_grant(namespaces, &grant)?;
            let grants = namespace_grants.entry(grant.namespace.clone()).or_default();
            let before = grants.get(&grant.id).cloned();
            if let Some(existing) = &before {
                grant.created_by = existing.created_by.clone();
                grant.created_at = existing.created_at;
            }
            let operation = if before.is_some() {
                NamespaceGrantAuditOperation::Update
            } else {
                NamespaceGrantAuditOperation::Create
            };
            grants.insert(grant.id.clone(), grant.clone());
            namespace_grant_audit
                .entry(grant.namespace.clone())
                .or_default()
                .push(NamespaceGrantAuditEvent {
                    id: audit_id,
                    namespace: grant.namespace.clone(),
                    grant_id: Some(grant.id.clone()),
                    operation,
                    actor: grant.updated_by.clone(),
                    actor_label,
                    reason,
                    before,
                    after: Some(grant.clone()),
                    created_at: grant.updated_at,
                });
            Ok(NamespaceResponse::Grant(grant))
        }
        NamespaceRequest::DeleteGrant {
            handle,
            grant_id,
            actor,
            actor_label,
            reason,
            now,
            audit_id,
        } => {
            validate_handle(&handle)?;
            if !namespaces.contains_key(&handle) {
                return Err(LayerhouseError::NameUnknown(format!(
                    "namespace {handle:?} is not currently claimed"
                )));
            }
            let before = namespace_grants
                .get_mut(&handle)
                .and_then(|grants| grants.remove(&grant_id));
            let should_remove_map = namespace_grants
                .get(&handle)
                .is_some_and(BTreeMap::is_empty);
            if should_remove_map {
                namespace_grants.remove(&handle);
            }
            if let Some(before) = before.clone() {
                namespace_grant_audit
                    .entry(handle.clone())
                    .or_default()
                    .push(NamespaceGrantAuditEvent {
                        id: audit_id,
                        namespace: handle,
                        grant_id: Some(grant_id),
                        operation: NamespaceGrantAuditOperation::Delete,
                        actor,
                        actor_label,
                        reason,
                        before: Some(before),
                        after: None,
                        created_at: now,
                    });
                Ok(NamespaceResponse::Bool(true))
            } else {
                Ok(NamespaceResponse::Bool(false))
            }
        }
        NamespaceRequest::PutObservedIdentity { identity } => {
            observed_identities.insert(identity.subject.clone(), identity);
            Ok(NamespaceResponse::Ok)
        }
    }
}

fn validate_namespace_grant(
    namespaces: &BTreeMap<String, Namespace>,
    grant: &NamespaceGrant,
) -> Result<(), LayerhouseError> {
    validate_handle(&grant.namespace)?;
    if !namespaces.contains_key(&grant.namespace) {
        return Err(LayerhouseError::NameUnknown(format!(
            "namespace {:?} is not currently claimed",
            grant.namespace
        )));
    }
    match &grant.grantee {
        NamespaceGrantGrantee::Group { id } => {
            crate::auth::principal::PrincipalRef::group(id.clone())?;
            Ok(())
        }
        NamespaceGrantGrantee::User { id } => {
            crate::auth::principal::PrincipalRef::user(id.clone())?;
            Ok(())
        }
        NamespaceGrantGrantee::Public
            if grant.action != crate::auth::permissions::OciAction::Pull =>
        {
            Err(LayerhouseError::Denied(
                "public namespace grants are pull-only".to_string(),
            ))
        }
        _ => Ok(()),
    }
}

/// Apply-time precondition: every write that creates content under a handle
/// must observe a live namespace claim for that handle. Rejecting here closes
/// the race where a namespace is released between route-layer authorization
/// and Raft commit.
fn require_live_namespace(
    data: &StateMachineData,
    repository: &str,
) -> Result<(), LayerhouseError> {
    let handle = handle_of(repository)?;
    if is_handle_reserved(handle) {
        return Ok(());
    }
    if !data.namespaces.contains_key(handle) {
        return Err(LayerhouseError::NameUnknown(format!(
            "namespace {handle:?} does not exist (referenced by {repository:?})"
        )));
    }
    Ok(())
}

/// True if any key in `map` begins with `prefix`. Used to detect apply-tracked
/// content (`<handle>/...`) still living under a namespace.
///
/// The union of manifests + tags + repositories mirrors the write paths gated
/// by `require_live_namespace`. Scoped configuration state — sync jobs, mirror
/// rules, proxy caches, warm images — is not yet considered because those
/// collections store free-form ids without a structural handle field. When the
/// namespace routes land and those configs gain a `handle` association, fold
/// them into the release-time content check (and into `require_live_namespace`)
/// so admin-reclaim cannot inherit the previous owner's automation.
fn any_key_with_prefix<V>(map: &BTreeMap<String, V>, prefix: &str) -> bool {
    map.keys().any(|k| k.starts_with(prefix))
}

fn release_reason_label(reason: &ReleaseReason) -> &'static str {
    match reason {
        ReleaseReason::OwnerDeleted => "owner-deleted",
        ReleaseReason::AdminRevoked => "admin-revoked",
        ReleaseReason::Renamed { .. } => "renamed",
    }
}

impl openraft::storage::RaftStateMachine<TypeConfig> for StateMachine {
    type SnapshotBuilder = StateMachineSnapshot;

    async fn applied_state(
        &mut self,
    ) -> Result<
        (
            Option<LogId<u64>>,
            StoredMembership<u64, openraft::BasicNode>,
        ),
        StorageError<u64>,
    > {
        let data = self.data.read().await;
        Ok((data.last_applied_log, data.last_membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<Response>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let mut data = self.data.write().await;
        let mut results = Vec::new();

        for entry in entries {
            data.last_applied_log = Some(entry.log_id);

            match entry.payload {
                EntryPayload::Blank => {
                    results.push(Response::Manifest(ManifestResponse::Ok));
                }
                EntryPayload::Membership(membership) => {
                    data.last_membership = StoredMembership::new(Some(entry.log_id), membership);
                    results.push(Response::Manifest(ManifestResponse::Ok));
                }
                EntryPayload::Normal(req) => {
                    let resp = Self::apply_request(&mut data, req);
                    results.push(resp);
                }
            }
        }

        Ok(results)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        let data = self.data.read().await;
        StateMachineSnapshot { data: data.clone() }
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<u64>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, openraft::BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        let bytes = snapshot.into_inner();
        if bytes.len() < 4 {
            return Err(StorageError::IO {
                source: StorageIOError::read_snapshot(
                    None,
                    openraft::AnyError::new(&std::io::Error::other("snapshot too short")),
                ),
            });
        }

        let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let payload = &bytes[4..];

        let mut new_data: StateMachineData = if version == SNAPSHOT_VERSION {
            serde_json::from_slice(payload).map_err(|e| StorageError::IO {
                source: StorageIOError::read_snapshot(None, openraft::AnyError::new(&e)),
            })?
        } else {
            return Err(StorageError::IO {
                source: StorageIOError::read_snapshot(
                    None,
                    openraft::AnyError::new(&std::io::Error::other(format!(
                        "unsupported snapshot version: {}",
                        version
                    ))),
                ),
            });
        };
        new_data.normalize_restored_metadata();

        let mut data = self.data.write().await;
        *data = new_data;
        data.last_applied_log = meta.last_log_id;
        data.last_membership = meta.last_membership.clone();
        drop(data);

        self.snapshot = Some((meta.clone(), bytes));

        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<u64>> {
        Ok(self.snapshot.as_ref().map(|(meta, data)| Snapshot {
            meta: meta.clone(),
            snapshot: Box::new(Cursor::new(data.clone())),
        }))
    }
}

pub struct StateMachineSnapshot {
    data: StateMachineData,
}

impl openraft::storage::RaftSnapshotBuilder<TypeConfig> for StateMachineSnapshot {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<u64>> {
        let payload = serde_json::to_vec(&self.data).map_err(|e| StorageError::IO {
            source: StorageIOError::write_snapshot(None, openraft::AnyError::new(&e)),
        })?;

        let mut bytes = Vec::with_capacity(4 + payload.len());
        bytes.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&payload);

        let last_applied_log = self.data.last_applied_log;
        let last_membership = self.data.last_membership.clone();

        let snapshot_id = last_applied_log
            .map(|id| format!("{}-{}", id.leader_id, id.index))
            .unwrap_or_else(|| "empty".to_string());

        let meta = SnapshotMeta {
            last_log_id: last_applied_log,
            last_membership,
            snapshot_id,
        };

        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(bytes)),
        })
    }
}

// Read-only helpers for the router
impl StateMachineData {
    pub fn normalize_restored_metadata(&mut self) {
        let now = now_epoch();
        for repo in self.manifests.values_mut() {
            for entry in repo.values_mut() {
                if entry.referenced_blobs.is_empty()
                    && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&entry.body)
                {
                    entry.referenced_blobs = extract_referenced_digests(&value);
                }
                entry.referenced_blobs.sort_by_key(|a| a.to_string());
                entry
                    .referenced_blobs
                    .dedup_by(|a, b| a.to_string() == b.to_string());
                if entry.manifest_size_bytes == 0 {
                    entry.manifest_size_bytes = entry.body.len() as u64;
                }
                if entry.stored_size_bytes == 0
                    && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&entry.body)
                {
                    entry.stored_size_bytes = crate::oci::manifest::stored_size_bytes(&value);
                }
                if entry.created_at == 0 {
                    entry.created_at = now;
                }
                if entry.last_modified == 0 {
                    entry.last_modified = entry.created_at;
                }
            }
        }
        self.rebuild_blob_ref_counts();
    }

    pub fn rebuild_blob_ref_counts(&mut self) {
        self.blob_ref_counts.clear();
        for repo in self.manifests.values() {
            for entry in repo.values() {
                for digest in &entry.referenced_blobs {
                    *self.blob_ref_counts.entry(digest.to_string()).or_default() += 1;
                }
            }
        }
    }

    fn increment_blob_refs(&mut self, entry: &ManifestEntry) {
        for digest in &entry.referenced_blobs {
            *self.blob_ref_counts.entry(digest.to_string()).or_default() += 1;
        }
    }

    fn decrement_blob_refs(&mut self, entry: &ManifestEntry) {
        for digest in &entry.referenced_blobs {
            let key = digest.to_string();
            if let Some(count) = self.blob_ref_counts.get_mut(&key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.blob_ref_counts.remove(&key);
                }
            }
        }
    }

    pub fn blob_ref_count_str(&self, digest: &str) -> u64 {
        self.blob_ref_counts.get(digest).copied().unwrap_or(0)
    }

    pub fn blob_lifecycle_status(&self, digest: &Digest) -> BlobLifecycleStatus {
        let digest = digest.to_string();
        let ref_count = self.blob_ref_count_str(&digest);
        BlobLifecycleStatus {
            delete_requested: self.blob_delete_requests.contains_key(&digest),
            digest,
            referenced: ref_count > 0,
            ref_count,
        }
    }

    pub fn get_manifest(&self, name: &str, reference: &str) -> Option<ManifestEntry> {
        if reference.starts_with("sha256:") || reference.starts_with("sha512:") {
            return self.manifests.get(name)?.get(reference).cloned();
        }

        let digest = self.tags.get(name)?.get(reference)?;
        self.manifests.get(name)?.get(digest).cloned()
    }

    pub fn list_tags(&self, name: &str, n: Option<usize>, last: Option<&str>) -> Vec<String> {
        let Some(repo_tags) = self.tags.get(name) else {
            return Vec::new();
        };

        let mut tags: Vec<String> = if let Some(last) = last {
            repo_tags
                .keys()
                .filter(|k| k.as_str() > last)
                .cloned()
                .collect()
        } else {
            repo_tags.keys().cloned().collect()
        };

        tags.sort();
        if let Some(n) = n {
            tags.truncate(n);
        }
        tags
    }

    pub fn list_repositories(&self, n: Option<usize>, last: Option<&str>) -> Vec<String> {
        let mut repos: Vec<String> = if let Some(last) = last {
            self.manifests
                .keys()
                .filter(|k| k.as_str() > last)
                .cloned()
                .collect()
        } else {
            self.manifests.keys().cloned().collect()
        };

        repos.sort();
        if let Some(n) = n {
            repos.truncate(n);
        }
        repos
    }

    pub fn list_repository_summaries(&self) -> Vec<RepositorySummary> {
        let mut summaries = Vec::new();
        for (name, repo_manifests) in &self.manifests {
            let tag_count = self.tags.get(name).map(|t| t.len()).unwrap_or(0);
            let stored_size_bytes = repository_stored_size_bytes(repo_manifests);
            let manifest_size_bytes = repository_manifest_size_bytes(repo_manifests);
            let last_modified = repo_manifests
                .values()
                .map(|m| m.last_modified)
                .max()
                .unwrap_or(0);
            let meta = self.repositories.get(name);
            summaries.push(RepositorySummary {
                name: name.clone(),
                tag_count,
                manifest_count: repo_manifests.len(),
                stored_size_bytes,
                manifest_size_bytes,
                last_modified,
                description: meta.map(|r| r.description.clone()).unwrap_or_default(),
                created_by: meta.and_then(|r| r.created_by.clone()),
                visibility: meta.map(|r| r.visibility).unwrap_or_default(),
            });
        }
        // Include shadow repositories that exist as first-class objects but have
        // no pushed manifests yet, so they appear in the listing immediately
        // after creation.
        for (name, repo) in &self.repositories {
            if self.manifests.contains_key(name) {
                continue;
            }
            summaries.push(RepositorySummary {
                name: name.clone(),
                tag_count: 0,
                manifest_count: 0,
                stored_size_bytes: 0,
                manifest_size_bytes: 0,
                last_modified: repo.created_at,
                description: repo.description.clone(),
                created_by: repo.created_by.clone(),
                visibility: repo.visibility,
            });
        }
        summaries
    }

    pub fn list_manifest_summaries(&self, name: &str) -> Vec<ManifestSummary> {
        let Some(repo_manifests) = self.manifests.get(name) else {
            return Vec::new();
        };
        crate::store::metadata::build_manifest_summaries(repo_manifests, self.tags.get(name))
    }

    pub fn list_referrers(
        &self,
        name: &str,
        subject_digest: &str,
        artifact_type: Option<&str>,
    ) -> Vec<ReferrerEntry> {
        let Some(repo_manifests) = self.manifests.get(name) else {
            return Vec::new();
        };

        let mut entries = Vec::new();
        for entry in repo_manifests.values() {
            if entry.subject.as_ref().map(|d| d.to_string()).as_deref() == Some(subject_digest) {
                let re = ReferrerEntry {
                    digest: entry.digest.clone(),
                    media_type: entry.content_type.clone(),
                    size: entry.body.len() as u64,
                    artifact_type: entry.artifact_type.clone(),
                    annotations: entry.annotations.clone(),
                };

                if let Some(filter) = artifact_type {
                    if re.artifact_type.as_deref() == Some(filter) {
                        entries.push(re);
                    }
                } else {
                    entries.push(re);
                }
            }
        }

        entries
    }

    pub fn list_mirror_rules(&self) -> Vec<MirrorRule> {
        self.mirror_rules.values().cloned().collect()
    }

    pub fn get_mirror_rule(&self, id: &str) -> Option<MirrorRule> {
        self.mirror_rules.get(id).cloned()
    }

    pub fn get_repository(&self, name: &str) -> Option<Repository> {
        self.repositories.get(name).cloned()
    }

    pub fn get_namespace(&self, handle: &str) -> Option<Namespace> {
        self.namespaces.get(handle).cloned()
    }

    // Consumed by the namespace listing route in a follow-up.
    #[allow(dead_code)]
    pub fn list_namespaces(&self) -> Vec<Namespace> {
        self.namespaces.values().cloned().collect()
    }

    pub fn list_namespace_grants(&self, handle: &str) -> Vec<NamespaceGrant> {
        self.namespace_grants
            .get(handle)
            .map(|grants| grants.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_namespace_grant(&self, handle: &str, grant_id: &str) -> Option<NamespaceGrant> {
        self.namespace_grants
            .get(handle)
            .and_then(|grants| grants.get(grant_id))
            .cloned()
    }

    pub fn list_namespace_grant_audit(&self, handle: &str) -> Vec<NamespaceGrantAuditEvent> {
        self.namespace_grant_audit
            .get(handle)
            .cloned()
            .unwrap_or_default()
    }

    pub fn search_observed_identities(&self, query: &str, limit: usize) -> Vec<ObservedIdentity> {
        let query = query.trim().to_lowercase();
        let mut identities: Vec<_> = self
            .observed_identities
            .values()
            .filter(|identity| {
                query.is_empty()
                    || identity.subject.as_str().to_lowercase().contains(&query)
                    || identity
                        .username
                        .as_deref()
                        .is_some_and(|value| value.to_lowercase().contains(&query))
                    || identity
                        .display_name
                        .as_deref()
                        .is_some_and(|value| value.to_lowercase().contains(&query))
                    || identity
                        .email
                        .as_deref()
                        .is_some_and(|value| value.to_lowercase().contains(&query))
            })
            .cloned()
            .collect();
        identities.sort_by(|a, b| {
            b.last_seen_at
                .cmp(&a.last_seen_at)
                .then_with(|| a.subject.cmp(&b.subject))
        });
        identities.truncate(limit);
        identities
    }

    // Consumed by the reclaim/reserved-handle flow in a follow-up.
    #[allow(dead_code)]
    pub fn get_released_handle(&self, handle: &str) -> Option<ReleasedHandle> {
        self.released_handles.get(handle).cloned()
    }

    pub fn list_proxy_caches(&self) -> Vec<ProxyCache> {
        self.proxy_caches.values().cloned().collect()
    }

    pub fn get_proxy_cache(&self, id: &str) -> Option<ProxyCache> {
        self.proxy_caches.get(id).cloned()
    }

    pub fn get_proxy_cache_tag_validation(
        &self,
        cache_id: &str,
        repository: &str,
        tag: &str,
    ) -> Option<crate::store::metadata::ProxyCacheTagValidation> {
        get_proxy_cache_tag_validation(&self.proxy_cache_tag_validations, cache_id, repository, tag)
    }

    pub fn list_warm_images(&self) -> Vec<WarmImage> {
        self.warm_images.values().cloned().collect()
    }

    pub fn get_warm_image(&self, id: &str) -> Option<WarmImage> {
        self.warm_images.get(id).cloned()
    }

    pub fn list_sync_jobs(&self) -> Vec<SyncJob> {
        self.sync_jobs.values().cloned().collect()
    }

    pub fn get_sync_job(&self, id: &str) -> Option<SyncJob> {
        self.sync_jobs.get(id).cloned()
    }

    pub fn list_sync_job_runs(&self, job_id: &str, limit: usize) -> Vec<SyncJobRun> {
        let runs = self.sync_job_runs.get(job_id).cloned().unwrap_or_default();
        let start = runs.len().saturating_sub(limit);
        runs[start..].to_vec()
    }

    pub fn list_helm_charts(&self) -> Vec<HelmChart> {
        self.helm_charts.values().cloned().collect()
    }

    pub fn list_helm_chart_versions(&self, name: &str) -> Option<Vec<HelmChartVersion>> {
        self.helm_chart_versions.get(name).cloned()
    }

    pub fn list_personal_access_tokens(&self, subject: &str) -> Vec<PersonalAccessToken> {
        self.personal_access_tokens
            .values()
            .filter(|t| t.subject == subject)
            .cloned()
            .collect()
    }

    pub fn get_personal_access_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Option<PersonalAccessToken> {
        self.personal_access_tokens
            .values()
            .find(|t| t.token_hash == token_hash)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::Subject;
    use crate::store::metadata::Owner;

    /// Insert a live namespace claim so D21-gated writes (`PutManifest`,
    /// `PutRepository`, `MountBlob`) can land. Tests that exercise content
    /// under a handle must seed the handle first.
    fn seed_namespace(data: &mut StateMachineData, handle: &str) {
        data.namespaces.insert(
            handle.to_string(),
            Namespace {
                handle: handle.to_string(),
                owner: Owner::User(Subject::new(format!("test-{handle}"))),
                owner_label: handle.to_string(),
                created_at: 1,
            },
        );
    }

    fn digest(id: u8) -> String {
        format!("sha256:{id:064x}")
    }

    fn manifest_body(config: &str, layers: &[&str]) -> Vec<u8> {
        serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config,
                "size": 2
            },
            "layers": layers
                .iter()
                .map(|digest| serde_json::json!({
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": digest,
                    "size": 4
                }))
                .collect::<Vec<_>>()
        })
        .to_string()
        .into_bytes()
    }

    fn put_manifest(
        repo: &str,
        reference: &str,
        manifest_digest: &str,
        referenced_blobs: &[&str],
    ) -> Request {
        let default_config = digest(1);
        let config_digest = referenced_blobs
            .first()
            .copied()
            .unwrap_or(default_config.as_str());
        let body = manifest_body(config_digest, referenced_blobs);
        let stored_size_bytes = serde_json::from_slice::<serde_json::Value>(&body)
            .map(|value| crate::oci::manifest::stored_size_bytes(&value))
            .unwrap_or(0);
        Request::Manifest(ManifestRequest::PutManifest {
            name: repo.to_string(),
            reference: reference.to_string(),
            digest: manifest_digest.to_string(),
            content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            manifest_size_bytes: body.len() as u64,
            body,
            subject: None,
            artifact_type: None,
            annotations: None,
            stored_size_bytes,
            created_at: 1,
            last_modified: 1,
            config_summary: None,
            referenced_blobs: referenced_blobs
                .iter()
                .map(|digest| digest.to_string())
                .collect(),
        })
    }

    fn entry(manifest_digest: &str, body: Vec<u8>, referenced_blobs: Vec<String>) -> ManifestEntry {
        ManifestEntry {
            digest: Digest::from_str_checked(manifest_digest).unwrap(),
            content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            manifest_size_bytes: body.len() as u64,
            body,
            subject: None,
            artifact_type: None,
            annotations: None,
            stored_size_bytes: 0,
            created_at: 0,
            last_modified: 0,
            config_summary: None,
            referenced_blobs: referenced_blobs
                .iter()
                .filter_map(|s| Digest::from_str_checked(s))
                .collect(),
        }
    }

    #[test]
    fn blob_ref_counts_track_manifest_lifecycle() {
        let blob_a = digest(10);
        let blob_b = digest(11);
        let manifest_a = digest(20);
        let manifest_b = digest(21);
        let mut data = StateMachineData::default();
        seed_namespace(&mut data, "alice");

        StateMachine::apply_request(
            &mut data,
            put_manifest(
                "alice/repo",
                "latest",
                &manifest_a,
                &[&blob_a, &blob_b, &blob_b],
            ),
        );
        assert_eq!(data.blob_ref_count_str(&blob_a), 1);
        assert_eq!(data.blob_ref_count_str(&blob_b), 1);

        StateMachine::apply_request(
            &mut data,
            put_manifest("alice/repo", "latest", &manifest_a, &[&blob_a, &blob_b]),
        );
        assert_eq!(data.blob_ref_count_str(&blob_a), 1);
        assert_eq!(data.blob_ref_count_str(&blob_b), 1);

        StateMachine::apply_request(
            &mut data,
            put_manifest("alice/repo", "latest", &manifest_b, &[&blob_a]),
        );
        assert_eq!(data.blob_ref_count_str(&blob_a), 2);
        assert_eq!(data.blob_ref_count_str(&blob_b), 1);

        let response = StateMachine::apply_request(
            &mut data,
            Request::Manifest(ManifestRequest::DeleteTag {
                name: "alice/repo".to_string(),
                digest: manifest_b.clone(),
                tag: "latest".to_string(),
            }),
        );
        assert!(matches!(
            response,
            Response::Manifest(ManifestResponse::Bool(true))
        ));
        assert_eq!(data.blob_ref_count_str(&blob_a), 2);
        assert_eq!(data.blob_ref_count_str(&blob_b), 1);

        StateMachine::apply_request(
            &mut data,
            Request::Manifest(ManifestRequest::DeleteManifest {
                name: "alice/repo".to_string(),
                digest: manifest_a,
            }),
        );
        assert_eq!(data.blob_ref_count_str(&blob_a), 1);
        assert_eq!(data.blob_ref_count_str(&blob_b), 0);

        StateMachine::apply_request(
            &mut data,
            Request::Manifest(ManifestRequest::DeleteManifests {
                name: "alice/repo".to_string(),
                digests: vec![manifest_b],
            }),
        );
        assert!(data.blob_ref_counts.is_empty());
    }

    #[test]
    fn repository_delete_decrements_all_manifest_blob_refs() {
        let blob_a = digest(30);
        let blob_b = digest(31);
        let mut data = StateMachineData::default();
        seed_namespace(&mut data, "alice");

        StateMachine::apply_request(
            &mut data,
            put_manifest("alice/repo", "one", &digest(40), &[&blob_a]),
        );
        StateMachine::apply_request(
            &mut data,
            put_manifest("alice/repo", "two", &digest(41), &[&blob_a, &blob_b]),
        );

        let response = StateMachine::apply_request(
            &mut data,
            Request::Manifest(ManifestRequest::DeleteRepository {
                name: "alice/repo".to_string(),
            }),
        );

        assert!(matches!(
            response,
            Response::Manifest(ManifestResponse::DeleteCounts(DeleteCounts {
                deleted_manifests: 2,
                deleted_tags: 2
            }))
        ));
        assert!(data.blob_ref_counts.is_empty());
    }

    #[test]
    fn snapshot_restore_rebuilds_blob_ref_count_index() {
        let blob_a = digest(50);
        let blob_b = digest(51);
        let blob_c = digest(52);
        let mut data = StateMachineData {
            blob_ref_counts: [(blob_c.clone(), 99)].into_iter().collect(),
            ..StateMachineData::default()
        };

        data.manifests
            .entry("alice/repo".to_string())
            .or_default()
            .insert(
                digest(60),
                entry(
                    &digest(60),
                    manifest_body(&blob_a, &[&blob_b, &blob_b]),
                    Vec::new(),
                ),
            );
        data.manifests
            .entry("alice/repo".to_string())
            .or_default()
            .insert(
                digest(61),
                entry(
                    &digest(61),
                    Vec::new(),
                    vec![blob_b.clone(), blob_c.clone(), blob_c.clone()],
                ),
            );

        data.normalize_restored_metadata();

        assert_eq!(data.blob_ref_count_str(&blob_a), 1);
        assert_eq!(data.blob_ref_count_str(&blob_b), 2);
        assert_eq!(data.blob_ref_count_str(&blob_c), 1);
        assert_eq!(data.blob_ref_counts.len(), 3);
    }

    #[test]
    fn personal_access_tokens_are_owned_by_subject() {
        let mut data = StateMachineData::default();
        let token = PersonalAccessToken {
            id: "pat-1".to_string(),
            subject: "subject-a".to_string(),
            username: None,
            name: "token".to_string(),
            token_hash: "hash".to_string(),
            token_prefix: "layerhouse-abc".to_string(),
            scopes: vec!["repository:*:pull".to_string()],
            created_at: 1,
            last_used_at: None,
            expires_at: None,
        };

        StateMachine::apply_request(
            &mut data,
            Request::Token(TokenRequest::PutPersonalAccessToken(token)),
        );

        assert_eq!(data.list_personal_access_tokens("subject-a").len(), 1);
        assert!(data.list_personal_access_tokens("subject-b").is_empty());

        let response = StateMachine::apply_request(
            &mut data,
            Request::Token(TokenRequest::DeletePersonalAccessToken {
                id: "pat-1".to_string(),
                subject: "subject-b".to_string(),
            }),
        );
        assert!(matches!(
            response,
            Response::Token(TokenResponse::Bool(false))
        ));
        assert_eq!(data.list_personal_access_tokens("subject-a").len(), 1);

        let response = StateMachine::apply_request(
            &mut data,
            Request::Token(TokenRequest::DeletePersonalAccessToken {
                id: "pat-1".to_string(),
                subject: "subject-a".to_string(),
            }),
        );
        assert!(matches!(
            response,
            Response::Token(TokenResponse::Bool(true))
        ));
        assert!(data.list_personal_access_tokens("subject-a").is_empty());
    }

    fn proxy_cache(id: &str) -> ProxyCache {
        ProxyCache {
            id: id.to_string(),
            local_prefix: "cache/app".to_string(),
            upstream_registry: "registry.example".to_string(),
            upstream_prefix: Some("upstream/app".to_string()),
            warm_filters: vec![crate::store::metadata::WarmFilter::None],
            warm_schedule: None,
            plain_http: false,
            insecure_tls: false,
            outbound_proxy: crate::store::metadata::OutboundProxy::default(),
            username: None,
            password: None,
            created_at: 1,
        }
    }

    fn proxy_validation(
        cache_id: &str,
        repository: &str,
        tag: &str,
    ) -> crate::store::metadata::ProxyCacheTagValidation {
        crate::store::metadata::ProxyCacheTagValidation {
            cache_id: cache_id.to_string(),
            repository: repository.to_string(),
            tag: tag.to_string(),
            upstream_digest: digest(70),
            last_validated_at: 42,
        }
    }

    #[test]
    fn proxy_cache_tag_validation_persists_and_cache_cleanup_clears_it() {
        let mut data = StateMachineData::default();

        StateMachine::apply_request(
            &mut data,
            Request::MirrorConfig(MirrorConfigRequest::PutProxyCacheTagValidation(
                proxy_validation("docker", "cache/app", "latest"),
            )),
        );
        let found = data
            .get_proxy_cache_tag_validation("docker", "cache/app", "latest")
            .expect("validation should exist");
        assert_eq!(found.last_validated_at, 42);

        StateMachine::apply_request(
            &mut data,
            Request::MirrorConfig(MirrorConfigRequest::PutProxyCache(proxy_cache("docker"))),
        );
        assert!(
            data.get_proxy_cache_tag_validation("docker", "cache/app", "latest")
                .is_none()
        );

        StateMachine::apply_request(
            &mut data,
            Request::MirrorConfig(MirrorConfigRequest::PutProxyCacheTagValidation(
                proxy_validation("docker", "cache/app", "latest"),
            )),
        );
        StateMachine::apply_request(
            &mut data,
            Request::MirrorConfig(MirrorConfigRequest::DeleteProxyCache {
                id: "docker".to_string(),
            }),
        );
        assert!(
            data.get_proxy_cache_tag_validation("docker", "cache/app", "latest")
                .is_none()
        );
    }

    #[test]
    fn proxy_cache_tag_validation_is_cleared_by_manifest_deletes() {
        let mut data = StateMachineData::default();
        seed_namespace(&mut data, "alice");
        let manifest = digest(71);

        StateMachine::apply_request(
            &mut data,
            put_manifest("alice/repo", "latest", &manifest, &[]),
        );
        StateMachine::apply_request(
            &mut data,
            Request::MirrorConfig(MirrorConfigRequest::PutProxyCacheTagValidation(
                proxy_validation("docker", "alice/repo", "latest"),
            )),
        );
        StateMachine::apply_request(
            &mut data,
            Request::Manifest(ManifestRequest::DeleteManifests {
                name: "alice/repo".to_string(),
                digests: vec![manifest],
            }),
        );

        assert!(
            data.get_proxy_cache_tag_validation("docker", "alice/repo", "latest")
                .is_none()
        );
    }

    #[test]
    fn proxy_cache_tag_validations_default_when_restoring_snapshot_json() {
        let data: StateMachineData = serde_json::from_value(serde_json::json!({
            "manifests": {},
            "tags": {}
        }))
        .expect("state machine data should deserialize");

        assert!(data.proxy_cache_tag_validations.is_empty());
    }

    #[tokio::test]
    async fn v1_snapshot_roundtrips_namespaces_and_released_handles() {
        use openraft::storage::{RaftSnapshotBuilder, RaftStateMachine};

        let mut data = StateMachineData::default();
        data.repositories.insert(
            "alice/app".to_string(),
            Repository {
                name: "alice/app".to_string(),
                description: "alice's app".to_string(),
                created_by: Some(Subject::new("subject-alice")),
                visibility: crate::store::metadata::Visibility::PublicPull,
                created_at: 7,
            },
        );
        data.permission_rules.insert(
            "rule-1".to_string(),
            PermissionRule {
                id: "rule-1".to_string(),
                name: "team-a-devs".to_string(),
                groups: vec!["team-a".to_string()],
                scopes: vec!["repository:team-a/*:pull,create".to_string()],
                source: crate::store::metadata::RuleSource::Raft,
                created_at: 9,
            },
        );
        data.namespaces.insert(
            "alice".to_string(),
            Namespace {
                handle: "alice".to_string(),
                owner: Owner::User(Subject::new("subject-alice")),
                owner_label: "alice".to_string(),
                created_at: 100,
            },
        );
        let grant = NamespaceGrant {
            id: "grant-1".to_string(),
            namespace: "alice".to_string(),
            grantee: NamespaceGrantGrantee::Group {
                id: crate::auth::principal::ProviderQualifiedId::new(
                    "test",
                    crate::auth::principal::PrincipalKind::Group,
                    "550e8400-e29b-41d4-a716-446655440000",
                )
                .unwrap(),
            },
            action: crate::auth::permissions::OciAction::Create,
            label: "team-a".to_string(),
            created_by: Subject::new("subject-alice"),
            created_at: 102,
            updated_by: Subject::new("subject-alice"),
            updated_at: 103,
        };
        data.namespace_grants
            .entry("alice".to_string())
            .or_default()
            .insert(grant.id.clone(), grant.clone());
        data.observed_identities.insert(
            Subject::new("subject-ci"),
            ObservedIdentity {
                subject: Subject::new("subject-ci"),
                username: Some("ci".to_string()),
                display_name: Some("CI User".to_string()),
                email: Some("ci@example.test".to_string()),
                groups: vec!["team-a".to_string()],
                last_seen_at: 104,
            },
        );
        data.namespace_grant_audit
            .entry("alice".to_string())
            .or_default()
            .push(NamespaceGrantAuditEvent {
                id: "audit-1".to_string(),
                namespace: "alice".to_string(),
                grant_id: Some("grant-1".to_string()),
                operation: NamespaceGrantAuditOperation::Create,
                actor: Subject::new("subject-alice"),
                actor_label: "alice".to_string(),
                reason: "initial grant".to_string(),
                before: None,
                after: Some(grant),
                created_at: 105,
            });
        data.released_handles.insert(
            "bob".to_string(),
            ReleasedHandle {
                handle: "bob".to_string(),
                prior_owner: Owner::User(Subject::new("subject-bob")),
                prior_owner_label: "bob".to_string(),
                released_at: 101,
                released_by: Subject::new("subject-admin"),
                release_reason: ReleaseReason::AdminRevoked,
            },
        );

        // Drive the actual on-disk pipeline (version prefix + payload), not
        // raw serde, so the test fails if the version gate or the snapshot
        // builder regresses.
        let source = Arc::new(RwLock::new(data));
        let mut sm_out = StateMachine::new(source);
        let mut builder = sm_out.get_snapshot_builder().await;
        let snapshot = builder.build_snapshot().await.expect("build snapshot");
        let bytes = snapshot.snapshot.into_inner();

        assert_eq!(
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            SNAPSHOT_VERSION,
            "snapshot must carry the v1 prefix"
        );

        let mut sm_in = StateMachine::new(Arc::new(RwLock::new(StateMachineData::default())));
        sm_in
            .install_snapshot(&snapshot.meta, Box::new(Cursor::new(bytes)))
            .await
            .expect("install v1 snapshot");

        let restored = sm_in.data.read().await;

        let repo = restored
            .repositories
            .get("alice/app")
            .expect("repository preserved");
        assert_eq!(
            repo.created_by.as_ref().map(|s| s.as_str()),
            Some("subject-alice")
        );
        assert_eq!(
            repo.visibility,
            crate::store::metadata::Visibility::PublicPull
        );

        let rule = restored
            .permission_rules
            .get("rule-1")
            .expect("permission rule preserved");
        assert_eq!(rule.groups, vec!["team-a".to_string()]);
        assert_eq!(rule.source, crate::store::metadata::RuleSource::Raft);

        let ns = restored
            .namespaces
            .get("alice")
            .expect("namespace preserved");
        assert_eq!(ns.owner_label, "alice");
        assert_eq!(ns.created_at, 100);

        let grant = restored
            .namespace_grants
            .get("alice")
            .and_then(|grants| grants.get("grant-1"))
            .expect("grant preserved");
        assert_eq!(grant.action, crate::auth::permissions::OciAction::Create);
        assert!(matches!(
            grant.grantee,
            NamespaceGrantGrantee::Group { ref id } if id.as_str() == "test:group:550e8400-e29b-41d4-a716-446655440000"
        ));

        let observed = restored
            .observed_identities
            .get(&Subject::new("subject-ci"))
            .expect("observed identity preserved");
        assert_eq!(observed.email.as_deref(), Some("ci@example.test"));

        let audit = restored
            .namespace_grant_audit
            .get("alice")
            .expect("grant audit preserved");
        assert_eq!(audit[0].reason, "initial grant");

        let released = restored
            .released_handles
            .get("bob")
            .expect("released handle preserved");
        assert_eq!(released.prior_owner_label, "bob");
        assert!(matches!(
            released.release_reason,
            ReleaseReason::AdminRevoked
        ));
        assert_eq!(released.released_by, "subject-admin");
    }

    // ── Shared read tests against StateMachineData ────────────────────
    // Mirror the shared_read_tests assertions in store/metadata.rs.
    // StateMachineData is seeded via apply_request (the Raft path),
    // then read directly through its public read helpers.

    fn seed_manifest_entry_json() -> (Vec<u8>, String) {
        let config_digest = format!("sha256:{:064x}", 99u64);
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": config_digest,
                "size": 2
            },
            "layers": []
        })
        .to_string()
        .into_bytes();
        let manifest_digest = Digest::sha256(&body).to_string();
        (body, manifest_digest)
    }

    #[test]
    fn state_machine_get_manifest_by_tag_and_digest() {
        let mut data = StateMachineData::default();
        seed_namespace(&mut data, "alice");
        let (body, manifest_digest) = seed_manifest_entry_json();

        StateMachine::apply_request(
            &mut data,
            Request::Manifest(ManifestRequest::PutManifest {
                name: "alice/shared-repo".to_string(),
                reference: "v1".to_string(),
                digest: manifest_digest.clone(),
                content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                body: body.clone(),
                subject: None,
                artifact_type: None,
                annotations: None,
                stored_size_bytes: 200,
                manifest_size_bytes: body.len() as u64,
                created_at: 100,
                last_modified: 200,
                config_summary: None,
                referenced_blobs: vec![format!("sha256:{:064x}", 99u64)],
            }),
        );

        let found = data.get_manifest("alice/shared-repo", "v1");
        assert!(found.is_some(), "manifest should be found by tag");
        assert_eq!(found.unwrap().digest.to_string(), manifest_digest);

        let found = data.get_manifest("alice/shared-repo", &manifest_digest);
        assert!(found.is_some(), "manifest should be found by digest");

        let found = data.get_manifest("alice/shared-repo", "nonexistent");
        assert!(found.is_none(), "unknown reference should return None");
    }

    #[test]
    fn state_machine_list_tags() {
        let mut data = StateMachineData::default();
        seed_namespace(&mut data, "alice");
        let (body, manifest_digest) = seed_manifest_entry_json();

        for tag in &["v1", "v2"] {
            StateMachine::apply_request(
                &mut data,
                Request::Manifest(ManifestRequest::PutManifest {
                    name: "alice/shared-repo".to_string(),
                    reference: (*tag).to_string(),
                    digest: manifest_digest.clone(),
                    content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                    body: body.clone(),
                    subject: None,
                    artifact_type: None,
                    annotations: None,
                    stored_size_bytes: 200,
                    manifest_size_bytes: body.len() as u64,
                    created_at: 100,
                    last_modified: 200,
                    config_summary: None,
                    referenced_blobs: vec![],
                }),
            );
        }

        let tags = data.list_tags("alice/shared-repo", None, None);
        assert_eq!(tags, vec!["v1", "v2"]);
        assert!(data.list_tags("alice/nonexistent", None, None).is_empty());
    }

    #[test]
    fn state_machine_list_repositories() {
        let mut data = StateMachineData::default();
        seed_namespace(&mut data, "alice");
        let (body, manifest_digest) = seed_manifest_entry_json();

        for repo in &["alice/repo-a", "alice/repo-b"] {
            StateMachine::apply_request(
                &mut data,
                Request::Manifest(ManifestRequest::PutManifest {
                    name: (*repo).to_string(),
                    reference: "latest".to_string(),
                    digest: manifest_digest.clone(),
                    content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                    body: body.clone(),
                    subject: None,
                    artifact_type: None,
                    annotations: None,
                    stored_size_bytes: 200,
                    manifest_size_bytes: body.len() as u64,
                    created_at: 100,
                    last_modified: 200,
                    config_summary: None,
                    referenced_blobs: vec![],
                }),
            );
        }

        let repos = data.list_repositories(None, None);
        assert_eq!(repos, vec!["alice/repo-a", "alice/repo-b"]);
    }

    #[test]
    fn state_machine_list_manifest_summaries() {
        let mut data = StateMachineData::default();
        seed_namespace(&mut data, "alice");
        let (body, manifest_digest) = seed_manifest_entry_json();

        StateMachine::apply_request(
            &mut data,
            Request::Manifest(ManifestRequest::PutManifest {
                name: "alice/shared-repo".to_string(),
                reference: "v1".to_string(),
                digest: manifest_digest,
                content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                manifest_size_bytes: body.len() as u64,
                body,
                subject: None,
                artifact_type: None,
                annotations: None,
                stored_size_bytes: 200,
                created_at: 100,
                last_modified: 200,
                config_summary: None,
                referenced_blobs: vec![],
            }),
        );

        let summaries = data.list_manifest_summaries("alice/shared-repo");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].tags, vec!["v1"]);
    }

    fn claim_request(handle: &str, owner_label: &str, admin_override: bool) -> Request {
        Request::Namespace(NamespaceRequest::Claim {
            handle: handle.to_string(),
            owner: Owner::User(Subject::new(format!("idp-{handle}"))),
            owner_label: owner_label.to_string(),
            actor: Subject::new(format!("idp-{handle}")),
            admin_override,
            now: 100,
        })
    }

    #[test]
    fn namespace_claim_inserts_live_namespace() {
        let mut data = StateMachineData::default();
        let resp = StateMachine::apply_request(&mut data, claim_request("alice", "Alice", false));
        assert!(matches!(resp, Response::Namespace(NamespaceResponse::Ok)));
        let ns = data.namespaces.get("alice").expect("namespace claimed");
        assert_eq!(ns.handle, "alice");
        assert_eq!(ns.owner_label, "Alice");
        assert!(matches!(ns.owner, Owner::User(_)));
    }

    #[test]
    fn namespace_claim_conflict_omits_owner_id() {
        let mut data = StateMachineData::default();
        // Pre-claim by a sensitive subject id that must NOT leak.
        data.namespaces.insert(
            "alice".to_string(),
            Namespace {
                handle: "alice".to_string(),
                owner: Owner::User(Subject::new("secret-subject-uuid-do-not-leak")),
                owner_label: "Alice".to_string(),
                created_at: 1,
            },
        );
        let resp = StateMachine::apply_request(&mut data, claim_request("alice", "Other", false));
        let Response::Conflict(msg) = resp else {
            panic!("expected Response::Conflict, got {resp:?}");
        };
        assert!(
            !msg.contains("secret-subject-uuid-do-not-leak"),
            "conflict body must not leak prior owner id: {msg:?}"
        );
        assert!(
            msg.contains("user"),
            "conflict body should mention owner kind: {msg:?}"
        );
    }

    #[test]
    fn namespace_reclaim_requires_admin_override() {
        let mut data = StateMachineData::default();
        data.released_handles.insert(
            "alice".to_string(),
            ReleasedHandle {
                handle: "alice".to_string(),
                prior_owner: Owner::User(Subject::new("idp-alice")),
                prior_owner_label: "Alice".to_string(),
                released_at: 1,
                released_by: Subject::new("idp-alice"),
                release_reason: ReleaseReason::OwnerDeleted,
            },
        );

        let resp = StateMachine::apply_request(&mut data, claim_request("alice", "Alice2", false));
        assert!(
            matches!(resp, Response::Denied(_)),
            "reclaim without admin override must fail: {resp:?}"
        );
        assert!(data.released_handles.contains_key("alice"));
        assert!(!data.namespaces.contains_key("alice"));

        let resp = StateMachine::apply_request(&mut data, claim_request("alice", "Alice2", true));
        assert!(matches!(resp, Response::Namespace(NamespaceResponse::Ok)));
        assert!(!data.released_handles.contains_key("alice"));
        assert!(data.namespaces.contains_key("alice"));
    }

    #[test]
    fn namespace_delete_blocks_when_content_exists() {
        let mut data = StateMachineData::default();
        seed_namespace(&mut data, "alice");
        let (_body, manifest_digest) = seed_manifest_entry_json();
        StateMachine::apply_request(
            &mut data,
            put_manifest("alice/repo", "v1", &manifest_digest, &[]),
        );

        let resp = StateMachine::apply_request(
            &mut data,
            Request::Namespace(NamespaceRequest::Delete {
                handle: "alice".to_string(),
                actor: Subject::new("test-alice"),
                reason: ReleaseReason::OwnerDeleted,
                now: 200,
            }),
        );
        assert!(
            matches!(resp, Response::Conflict(_)),
            "delete with content must fail: {resp:?}"
        );
        // Namespace must be restored on the failure path.
        assert!(data.namespaces.contains_key("alice"));
        assert!(!data.released_handles.contains_key("alice"));
    }

    #[test]
    fn namespace_delete_creates_tombstone() {
        let mut data = StateMachineData::default();
        seed_namespace(&mut data, "alice");

        let resp = StateMachine::apply_request(
            &mut data,
            Request::Namespace(NamespaceRequest::Delete {
                handle: "alice".to_string(),
                actor: Subject::new("test-alice"),
                reason: ReleaseReason::OwnerDeleted,
                now: 200,
            }),
        );
        assert!(matches!(resp, Response::Namespace(NamespaceResponse::Ok)));
        assert!(!data.namespaces.contains_key("alice"));
        let tomb = data
            .released_handles
            .get("alice")
            .expect("tombstone present");
        assert_eq!(tomb.prior_owner_label, "alice");
        assert!(matches!(tomb.release_reason, ReleaseReason::OwnerDeleted));
        assert_eq!(tomb.released_at, 200);
    }

    #[test]
    fn namespace_admin_revoke_creates_tombstone() {
        let mut data = StateMachineData::default();
        seed_namespace(&mut data, "alice");

        let resp = StateMachine::apply_request(
            &mut data,
            Request::Namespace(NamespaceRequest::AdminRevoke {
                handle: "alice".to_string(),
                actor: Subject::new("admin-1"),
                now: 300,
            }),
        );
        assert!(matches!(resp, Response::Namespace(NamespaceResponse::Ok)));
        let tomb = data
            .released_handles
            .get("alice")
            .expect("tombstone present");
        assert!(matches!(tomb.release_reason, ReleaseReason::AdminRevoked));
        assert_eq!(tomb.released_at, 300);
    }

    #[test]
    fn put_manifest_rejected_without_live_namespace() {
        let mut data = StateMachineData::default();
        let (_body, manifest_digest) = seed_manifest_entry_json();
        let resp = StateMachine::apply_request(
            &mut data,
            put_manifest("ghost/repo", "v1", &manifest_digest, &[]),
        );
        let Response::NameUnknown(msg) = resp else {
            panic!("expected Response::NameUnknown, got {resp:?}");
        };
        assert!(msg.contains("ghost"), "{msg:?}");
        assert!(!data.manifests.contains_key("ghost/repo"));
    }

    #[test]
    fn mount_blob_rejected_without_live_namespace() {
        let mut data = StateMachineData::default();
        seed_namespace(&mut data, "alice");
        let blob = digest(42);

        let resp = StateMachine::apply_request(
            &mut data,
            Request::Manifest(ManifestRequest::MountBlob {
                source_repo: "alice/source".to_string(),
                dest_repo: "ghost/dest".to_string(),
                digest: blob.clone(),
            }),
        );
        assert!(
            matches!(resp, Response::NameUnknown(_)),
            "mount into ghost namespace must fail: {resp:?}"
        );
    }

    #[test]
    fn put_repository_rejected_without_live_namespace() {
        let mut data = StateMachineData::default();
        let repo = Repository {
            name: "ghost/repo".to_string(),
            description: String::new(),
            created_by: None,
            visibility: crate::store::metadata::Visibility::default(),
            created_at: 1,
        };
        let resp = StateMachine::apply_request(
            &mut data,
            Request::Repository(RepositoryRequest::PutRepository(repo)),
        );
        assert!(
            matches!(resp, Response::NameUnknown(_)),
            "put_repository under ghost namespace must fail: {resp:?}"
        );
    }

    #[test]
    fn namespace_delete_unknown_handle_errors() {
        let mut data = StateMachineData::default();
        let resp = StateMachine::apply_request(
            &mut data,
            Request::Namespace(NamespaceRequest::Delete {
                handle: "ghost".to_string(),
                actor: Subject::new("idp-ghost"),
                reason: ReleaseReason::OwnerDeleted,
                now: 1,
            }),
        );
        let Response::NameUnknown(msg) = resp else {
            panic!("expected Response::NameUnknown, got {resp:?}");
        };
        assert!(msg.contains("ghost"), "{msg:?}");
        assert!(!data.released_handles.contains_key("ghost"));
    }

    #[test]
    fn namespace_admin_revoke_unknown_handle_errors() {
        let mut data = StateMachineData::default();
        let resp = StateMachine::apply_request(
            &mut data,
            Request::Namespace(NamespaceRequest::AdminRevoke {
                handle: "ghost".to_string(),
                actor: Subject::new("admin-1"),
                now: 1,
            }),
        );
        assert!(
            matches!(resp, Response::NameUnknown(_)),
            "admin-revoke of unknown handle must fail: {resp:?}"
        );
        assert!(!data.released_handles.contains_key("ghost"));
    }

    #[test]
    fn namespace_delete_with_renamed_reason_persists_new_handle() {
        let mut data = StateMachineData::default();
        seed_namespace(&mut data, "alice");

        let resp = StateMachine::apply_request(
            &mut data,
            Request::Namespace(NamespaceRequest::Delete {
                handle: "alice".to_string(),
                actor: Subject::new("test-alice"),
                reason: ReleaseReason::Renamed {
                    new_handle: "alice2".to_string(),
                },
                now: 400,
            }),
        );
        assert!(matches!(resp, Response::Namespace(NamespaceResponse::Ok)));
        let tomb = data
            .released_handles
            .get("alice")
            .expect("tombstone present");
        match &tomb.release_reason {
            ReleaseReason::Renamed { new_handle } => assert_eq!(new_handle, "alice2"),
            other => panic!("expected Renamed reason, got {other:?}"),
        }
    }
}
