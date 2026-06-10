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
    MirrorConfigResponse, Request, Response, TokenRequest, TokenResponse, TypeConfig,
};
use crate::oci::digest::Digest;
use crate::oci::manifest::extract_referenced_digests;
use crate::store::metadata::{
    BlobDeleteStatus, BlobLifecycleStatus, DeleteCounts, HelmChart, HelmChartVersion,
    ManifestEntry, ManifestSummary, MirrorRule, PersonalAccessToken, ProxyCache, ReferrerEntry,
    RepositorySummary, SyncJob, SyncJobKind, SyncJobRun, SyncJobStatus, WarmImage,
    clear_proxy_cache_tag_validations_for_cache, clear_proxy_cache_tag_validations_for_repository,
    clear_proxy_cache_tag_validations_for_tag, get_proxy_cache_tag_validation, mirror_rule_job,
    now_epoch, proxy_cache_warm_job, put_proxy_cache_tag_validation,
    repository_manifest_size_bytes, repository_stored_size_bytes, sync_job_blocks_trigger,
};

const SNAPSHOT_VERSION: u32 = 4;

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
            Request::Manifest(r) => Response::Manifest(Self::apply_manifest(data, r)),
            Request::MirrorConfig(r) => Response::MirrorConfig(Self::apply_mirror_config(data, r)),
            Request::Job(r) => Response::Job(Self::apply_job(data, r)),
            Request::Token(r) => Response::Token(Self::apply_token(data, r)),
        }
    }

    fn apply_manifest(data: &mut StateMachineData, req: ManifestRequest) -> ManifestResponse {
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

                ManifestResponse::Ok
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
                ManifestResponse::Ok
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
                ManifestResponse::Bool(removed)
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
                ManifestResponse::DeleteCounts(DeleteCounts {
                    deleted_manifests,
                    deleted_tags,
                })
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
                ManifestResponse::DeleteCounts(DeleteCounts {
                    deleted_manifests,
                    deleted_tags,
                })
            }
            ManifestRequest::MountBlob {
                source_repo: _,
                dest_repo: _,
                digest: _,
            } => ManifestResponse::Ok,
            ManifestRequest::RecordBlobDelete {
                digest,
                requested_at,
            } => {
                let ref_count = data.blob_ref_count_str(&digest);
                data.blob_delete_requests
                    .insert(digest.clone(), requested_at);
                ManifestResponse::BlobDeleteStatus(BlobDeleteStatus {
                    digest,
                    referenced: ref_count > 0,
                    ref_count,
                })
            }
            ManifestRequest::ClearBlobDelete { digest } => {
                data.blob_delete_requests.remove(&digest);
                ManifestResponse::Ok
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

        let mut new_data: StateMachineData = match version {
            2 | SNAPSHOT_VERSION => {
                serde_json::from_slice(payload).map_err(|e| StorageError::IO {
                    source: StorageIOError::read_snapshot(None, openraft::AnyError::new(&e)),
                })?
            }
            _ => {
                return Err(StorageError::IO {
                    source: StorageIOError::read_snapshot(
                        None,
                        openraft::AnyError::new(&std::io::Error::other(format!(
                            "unsupported snapshot version: {}",
                            version
                        ))),
                    ),
                });
            }
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
            summaries.push(RepositorySummary {
                name: name.clone(),
                tag_count,
                manifest_count: repo_manifests.len(),
                stored_size_bytes,
                manifest_size_bytes,
                last_modified,
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

    fn put_manifest(reference: &str, manifest_digest: &str, referenced_blobs: &[&str]) -> Request {
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
            name: "repo".to_string(),
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

        StateMachine::apply_request(
            &mut data,
            put_manifest("latest", &manifest_a, &[&blob_a, &blob_b, &blob_b]),
        );
        assert_eq!(data.blob_ref_count_str(&blob_a), 1);
        assert_eq!(data.blob_ref_count_str(&blob_b), 1);

        StateMachine::apply_request(
            &mut data,
            put_manifest("latest", &manifest_a, &[&blob_a, &blob_b]),
        );
        assert_eq!(data.blob_ref_count_str(&blob_a), 1);
        assert_eq!(data.blob_ref_count_str(&blob_b), 1);

        StateMachine::apply_request(&mut data, put_manifest("latest", &manifest_b, &[&blob_a]));
        assert_eq!(data.blob_ref_count_str(&blob_a), 2);
        assert_eq!(data.blob_ref_count_str(&blob_b), 1);

        let response = StateMachine::apply_request(
            &mut data,
            Request::Manifest(ManifestRequest::DeleteTag {
                name: "repo".to_string(),
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
                name: "repo".to_string(),
                digest: manifest_a,
            }),
        );
        assert_eq!(data.blob_ref_count_str(&blob_a), 1);
        assert_eq!(data.blob_ref_count_str(&blob_b), 0);

        StateMachine::apply_request(
            &mut data,
            Request::Manifest(ManifestRequest::DeleteManifests {
                name: "repo".to_string(),
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

        StateMachine::apply_request(&mut data, put_manifest("one", &digest(40), &[&blob_a]));
        StateMachine::apply_request(
            &mut data,
            put_manifest("two", &digest(41), &[&blob_a, &blob_b]),
        );

        let response = StateMachine::apply_request(
            &mut data,
            Request::Manifest(ManifestRequest::DeleteRepository {
                name: "repo".to_string(),
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
            .entry("repo".to_string())
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
            .entry("repo".to_string())
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
        let manifest = digest(71);

        StateMachine::apply_request(&mut data, put_manifest("latest", &manifest, &[]));
        StateMachine::apply_request(
            &mut data,
            Request::MirrorConfig(MirrorConfigRequest::PutProxyCacheTagValidation(
                proxy_validation("docker", "repo", "latest"),
            )),
        );
        StateMachine::apply_request(
            &mut data,
            Request::Manifest(ManifestRequest::DeleteManifests {
                name: "repo".to_string(),
                digests: vec![manifest],
            }),
        );

        assert!(
            data.get_proxy_cache_tag_validation("docker", "repo", "latest")
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
        let (body, manifest_digest) = seed_manifest_entry_json();

        StateMachine::apply_request(
            &mut data,
            Request::Manifest(ManifestRequest::PutManifest {
                name: "shared-repo".to_string(),
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

        let found = data.get_manifest("shared-repo", "v1");
        assert!(found.is_some(), "manifest should be found by tag");
        assert_eq!(found.unwrap().digest.to_string(), manifest_digest);

        let found = data.get_manifest("shared-repo", &manifest_digest);
        assert!(found.is_some(), "manifest should be found by digest");

        let found = data.get_manifest("shared-repo", "nonexistent");
        assert!(found.is_none(), "unknown reference should return None");
    }

    #[test]
    fn state_machine_list_tags() {
        let mut data = StateMachineData::default();
        let (body, manifest_digest) = seed_manifest_entry_json();

        for tag in &["v1", "v2"] {
            StateMachine::apply_request(
                &mut data,
                Request::Manifest(ManifestRequest::PutManifest {
                    name: "shared-repo".to_string(),
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

        let tags = data.list_tags("shared-repo", None, None);
        assert_eq!(tags, vec!["v1", "v2"]);
        assert!(data.list_tags("nonexistent", None, None).is_empty());
    }

    #[test]
    fn state_machine_list_repositories() {
        let mut data = StateMachineData::default();
        let (body, manifest_digest) = seed_manifest_entry_json();

        for repo in &["repo-a", "repo-b"] {
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
        assert_eq!(repos, vec!["repo-a", "repo-b"]);
    }

    #[test]
    fn state_machine_list_manifest_summaries() {
        let mut data = StateMachineData::default();
        let (body, manifest_digest) = seed_manifest_entry_json();

        StateMachine::apply_request(
            &mut data,
            Request::Manifest(ManifestRequest::PutManifest {
                name: "shared-repo".to_string(),
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

        let summaries = data.list_manifest_summaries("shared-repo");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].tags, vec!["v1"]);
    }
}
