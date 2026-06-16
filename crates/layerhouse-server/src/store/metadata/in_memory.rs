use super::{traits::*, types::*};
use crate::auth::identity::Subject;
use crate::error::LayerhouseError;
use crate::oci::digest::Digest;
use crate::raft::{NamespaceRequest, NamespaceResponse};
use async_trait::async_trait;
use std::collections::BTreeMap;

// re-exported via super::types::*

#[cfg(test)]
#[derive(Debug, Default, Clone)]
pub struct InMemoryMetadataStore {
    inner: std::sync::Arc<tokio::sync::RwLock<InMemoryState>>,
}

#[cfg(test)]
#[derive(Debug, Default, Clone)]
struct InMemoryState {
    manifests: BTreeMap<String, BTreeMap<String, ManifestEntry>>,
    tags: BTreeMap<String, BTreeMap<String, Digest>>,
    blob_ref_counts: BTreeMap<String, u64>,
    blob_delete_requests: BTreeMap<String, u64>,
    mirror_rules: BTreeMap<String, MirrorRule>,
    proxy_caches: BTreeMap<String, ProxyCache>,
    proxy_cache_tag_validations: ProxyCacheTagValidations,
    warm_images: BTreeMap<String, WarmImage>,
    sync_jobs: BTreeMap<String, SyncJob>,
    sync_job_runs: BTreeMap<String, Vec<SyncJobRun>>,
    personal_access_tokens: BTreeMap<String, PersonalAccessToken>,
    repositories: BTreeMap<String, Repository>,
    namespaces: BTreeMap<String, Namespace>,
    released_handles: BTreeMap<String, ReleasedHandle>,
    namespace_grants: BTreeMap<String, BTreeMap<String, NamespaceGrant>>,
    observed_identities: BTreeMap<Subject, ObservedIdentity>,
    namespace_grant_audit: BTreeMap<String, Vec<NamespaceGrantAuditEvent>>,
}

#[cfg(test)]
impl InMemoryState {
    fn increment_blob_refs(&mut self, entry: &ManifestEntry) {
        for digest in unique_blob_refs(&entry.referenced_blobs) {
            *self.blob_ref_counts.entry(digest).or_default() += 1;
        }
    }

    fn decrement_blob_refs(&mut self, entry: &ManifestEntry) {
        for digest in unique_blob_refs(&entry.referenced_blobs) {
            if let Some(count) = self.blob_ref_counts.get_mut(&digest) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.blob_ref_counts.remove(&digest);
                }
            }
        }
    }

    /// Drive a namespace mutation through the shared core so the test double's
    /// claim / release / revoke rules cannot drift from the Raft apply path.
    fn apply_namespace(
        &mut self,
        req: NamespaceRequest,
    ) -> Result<NamespaceResponse, LayerhouseError> {
        let Self {
            namespaces,
            released_handles,
            namespace_grants,
            observed_identities,
            namespace_grant_audit,
            manifests,
            tags,
            repositories,
            ..
        } = self;
        crate::raft::state_machine::apply_namespace_core(
            namespaces,
            released_handles,
            namespace_grants,
            namespace_grant_audit,
            observed_identities,
            req,
            |handle| {
                let prefix = format!("{handle}/");
                manifests.keys().any(|k| k.starts_with(&prefix))
                    || tags.keys().any(|k| k.starts_with(&prefix))
                    || repositories.keys().any(|k| k.starts_with(&prefix))
            },
        )
    }
}

/// Sort and deduplicate a list of digest strings.
#[allow(dead_code)]
pub(crate) fn unique_blob_refs(digests: &[Digest]) -> Vec<String> {
    let mut refs: Vec<String> = digests.iter().map(ToString::to_string).collect();
    refs.sort();
    refs.dedup();
    refs
}

#[cfg(test)]
#[async_trait]
impl ManifestStore for InMemoryMetadataStore {
    async fn get_manifest(
        &self,
        name: &str,
        reference: &str,
    ) -> Result<Option<ManifestEntry>, LayerhouseError> {
        let state = self.inner.read().await;

        if let Some(digest) = reference
            .strip_prefix("sha256:")
            .or_else(|| reference.strip_prefix("sha512:"))
        {
            let _ = digest;
            if let Some(repo_manifests) = state.manifests.get(name) {
                return Ok(repo_manifests.get(reference).cloned());
            }
            return Ok(None);
        }

        if let Some(repo_tags) = state.tags.get(name)
            && let Some(digest) = repo_tags.get(reference)
            && let Some(repo_manifests) = state.manifests.get(name)
        {
            return Ok(repo_manifests.get(&digest.to_string()).cloned());
        }
        Ok(None)
    }

    async fn put_manifest(
        &self,
        name: &str,
        reference: &str,
        entry: ManifestEntry,
    ) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        let digest_str = entry.digest.to_string();
        let digest = entry.digest.clone();

        let previous = state
            .manifests
            .entry(name.to_string())
            .or_default()
            .insert(digest_str.clone(), entry.clone());
        if let Some(previous) = previous {
            state.decrement_blob_refs(&previous);
        }
        state.increment_blob_refs(&entry);

        let is_digest = reference.contains(':');
        if !is_digest {
            clear_proxy_cache_tag_validations_for_tag(
                &mut state.proxy_cache_tag_validations,
                name,
                reference,
            );
            state
                .tags
                .entry(name.to_string())
                .or_default()
                .insert(reference.to_string(), digest);
        }

        Ok(())
    }

    async fn delete_manifest(&self, name: &str, digest: &Digest) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        let digest_str = digest.to_string();

        if let Some(repo_manifests) = state.manifests.get_mut(name)
            && let Some(entry) = repo_manifests.remove(&digest_str)
        {
            state.decrement_blob_refs(&entry);
        }

        let mut removed_tags = Vec::new();
        if let Some(repo_tags) = state.tags.get_mut(name) {
            repo_tags.retain(|tag, d| {
                let keep = d.to_string() != digest_str;
                if !keep {
                    removed_tags.push(tag.clone());
                }
                keep
            });
        }
        for tag in removed_tags {
            clear_proxy_cache_tag_validations_for_tag(
                &mut state.proxy_cache_tag_validations,
                name,
                &tag,
            );
        }

        Ok(())
    }

    async fn list_tags(
        &self,
        name: &str,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<Vec<String>, LayerhouseError> {
        let state = self.inner.read().await;
        let Some(repo_tags) = state.tags.get(name) else {
            return Ok(Vec::new());
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
        Ok(tags)
    }

    async fn list_repositories(
        &self,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<Vec<String>, LayerhouseError> {
        let state = self.inner.read().await;
        let mut repos: Vec<String> = if let Some(last) = last {
            state
                .manifests
                .keys()
                .filter(|k| k.as_str() > last)
                .cloned()
                .collect()
        } else {
            state.manifests.keys().cloned().collect()
        };

        repos.sort();
        if let Some(n) = n {
            repos.truncate(n);
        }
        Ok(repos)
    }

    async fn list_repository_summaries(&self) -> Result<Vec<RepositorySummary>, LayerhouseError> {
        let state = self.inner.read().await;
        let mut summaries = Vec::new();

        for (name, repo_manifests) in &state.manifests {
            let tag_count = state.tags.get(name).map(|t| t.len()).unwrap_or(0);
            let stored_size_bytes = repository_stored_size_bytes(repo_manifests);
            let manifest_size_bytes = repository_manifest_size_bytes(repo_manifests);
            let last_modified = repo_manifests
                .values()
                .map(|m| m.last_modified)
                .max()
                .unwrap_or(0);
            let meta = state.repositories.get(name);
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

        // Shadow repositories with no pushed manifests still appear in the list.
        for (name, repo) in &state.repositories {
            if state.manifests.contains_key(name) {
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

        Ok(summaries)
    }

    async fn list_manifest_summaries(
        &self,
        name: &str,
    ) -> Result<Vec<ManifestSummary>, LayerhouseError> {
        let state = self.inner.read().await;
        let Some(repo_manifests) = state.manifests.get(name) else {
            return Ok(Vec::new());
        };
        let tag_strings: Option<std::collections::BTreeMap<String, String>> =
            state.tags.get(name).map(|tags| {
                tags.iter()
                    .map(|(k, v)| (k.clone(), v.to_string()))
                    .collect()
            });
        Ok(build_manifest_summaries(
            repo_manifests,
            tag_strings.as_ref(),
        ))
    }

    async fn delete_tag(
        &self,
        name: &str,
        digest: &Digest,
        tag: &str,
    ) -> Result<bool, LayerhouseError> {
        let mut state = self.inner.write().await;
        let Some(repo_tags) = state.tags.get_mut(name) else {
            return Ok(false);
        };
        let matches = repo_tags
            .get(tag)
            .map(|existing| existing.to_string() == digest.to_string())
            .unwrap_or(false);
        if matches {
            repo_tags.remove(tag);
            clear_proxy_cache_tag_validations_for_tag(
                &mut state.proxy_cache_tag_validations,
                name,
                tag,
            );
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn delete_repository(&self, name: &str) -> Result<DeleteCounts, LayerhouseError> {
        let mut state = self.inner.write().await;
        let removed = state.manifests.remove(name);
        if let Some(manifests) = removed.as_ref() {
            for entry in manifests.values() {
                state.decrement_blob_refs(entry);
            }
        }
        let deleted_manifests = removed.map(|m| m.len()).unwrap_or(0);
        let deleted_tags = state.tags.remove(name).map(|t| t.len()).unwrap_or(0);
        clear_proxy_cache_tag_validations_for_repository(
            &mut state.proxy_cache_tag_validations,
            name,
        );
        Ok(DeleteCounts {
            deleted_manifests,
            deleted_tags,
        })
    }

    async fn delete_manifests(
        &self,
        name: &str,
        digests: &[Digest],
    ) -> Result<DeleteCounts, LayerhouseError> {
        let mut state = self.inner.write().await;
        let digest_set: std::collections::BTreeSet<String> =
            digests.iter().map(ToString::to_string).collect();
        let mut deleted_manifests = 0;
        let mut deleted_tags = 0;

        let mut removed = Vec::new();
        if let Some(repo_manifests) = state.manifests.get_mut(name) {
            for digest in &digest_set {
                if let Some(entry) = repo_manifests.remove(digest) {
                    removed.push(entry);
                    deleted_manifests += 1;
                }
            }
        }
        for entry in &removed {
            state.decrement_blob_refs(entry);
        }

        let mut removed_tags = Vec::new();
        if let Some(repo_tags) = state.tags.get_mut(name) {
            let before = repo_tags.len();
            repo_tags.retain(|tag, digest| {
                let keep = !digest_set.contains(&digest.to_string());
                if !keep {
                    removed_tags.push(tag.clone());
                }
                keep
            });
            deleted_tags = before.saturating_sub(repo_tags.len());
        }
        for tag in removed_tags {
            clear_proxy_cache_tag_validations_for_tag(
                &mut state.proxy_cache_tag_validations,
                name,
                &tag,
            );
        }

        Ok(DeleteCounts {
            deleted_manifests,
            deleted_tags,
        })
    }

    async fn list_referrers(
        &self,
        name: &str,
        subject_digest: &Digest,
        artifact_type: Option<&str>,
    ) -> Result<Vec<ReferrerEntry>, LayerhouseError> {
        let state = self.inner.read().await;
        let Some(repo_manifests) = state.manifests.get(name) else {
            return Ok(Vec::new());
        };

        let subject_str = subject_digest.to_string();
        let mut entries = Vec::new();

        for entry in repo_manifests.values() {
            if entry.subject.as_ref().map(|d| d.to_string()) == Some(subject_str.clone()) {
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

        Ok(entries)
    }

    async fn mount_blob(
        &self,
        _source_repo: &str,
        _dest_repo: &str,
        _digest: &Digest,
    ) -> Result<(), LayerhouseError> {
        Ok(())
    }

    async fn record_blob_delete_request(
        &self,
        digest: &Digest,
    ) -> Result<BlobDeleteStatus, LayerhouseError> {
        let mut state = self.inner.write().await;
        let digest = digest.to_string();
        let ref_count = state.blob_ref_counts.get(&digest).copied().unwrap_or(0);
        state
            .blob_delete_requests
            .insert(digest.clone(), now_epoch());
        Ok(BlobDeleteStatus {
            digest,
            referenced: ref_count > 0,
            ref_count,
        })
    }

    async fn blob_lifecycle_status(
        &self,
        digest: &Digest,
    ) -> Result<BlobLifecycleStatus, LayerhouseError> {
        let state = self.inner.read().await;
        let digest = digest.to_string();
        let ref_count = state.blob_ref_counts.get(&digest).copied().unwrap_or(0);
        Ok(BlobLifecycleStatus {
            delete_requested: state.blob_delete_requests.contains_key(&digest),
            digest,
            referenced: ref_count > 0,
            ref_count,
        })
    }

    async fn clear_blob_delete_request(&self, digest: &Digest) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        state.blob_delete_requests.remove(&digest.to_string());
        Ok(())
    }

    async fn blob_ref_counts(
        &self,
    ) -> Result<std::collections::BTreeMap<String, u64>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state.blob_ref_counts.clone())
    }
}

#[cfg(test)]
#[async_trait]
impl MirrorConfigStore for InMemoryMetadataStore {
    // Mirror rule CRUD

    async fn list_mirror_rules(&self) -> Result<Vec<MirrorRule>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state.mirror_rules.values().cloned().collect())
    }

    async fn get_mirror_rule(&self, id: &str) -> Result<Option<MirrorRule>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state.mirror_rules.get(id).cloned())
    }

    async fn put_mirror_rule(&self, rule: MirrorRule) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        state.mirror_rules.insert(rule.id.clone(), rule);
        Ok(())
    }

    async fn delete_mirror_rule(&self, id: &str) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        state.mirror_rules.remove(id);
        Ok(())
    }

    async fn trigger_mirror_rule(&self, id: &str) -> Result<Option<SyncJob>, LayerhouseError> {
        let mut state = self.inner.write().await;
        let Some(rule) = state.mirror_rules.get(id).cloned() else {
            return Ok(None);
        };
        let now = now_epoch();
        if state
            .sync_jobs
            .values()
            .any(|job| sync_job_blocks_trigger(job, SyncJobKind::Mirror, id, now))
        {
            return Err(LayerhouseError::Conflict(
                "Rule is already running".to_string(),
            ));
        }

        let job = mirror_rule_job(&rule, format!("{}-{}", rule.id, now), now, 0);
        state.sync_jobs.insert(job.id.clone(), job.clone());
        Ok(Some(job))
    }

    async fn list_proxy_caches(&self) -> Result<Vec<ProxyCache>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state.proxy_caches.values().cloned().collect())
    }

    async fn get_proxy_cache(&self, id: &str) -> Result<Option<ProxyCache>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state.proxy_caches.get(id).cloned())
    }

    async fn put_proxy_cache(&self, cache: ProxyCache) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        clear_proxy_cache_tag_validations_for_cache(
            &mut state.proxy_cache_tag_validations,
            &cache.id,
        );
        state.proxy_caches.insert(cache.id.clone(), cache);
        Ok(())
    }

    async fn delete_proxy_cache(&self, id: &str) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        state.proxy_caches.remove(id);
        clear_proxy_cache_tag_validations_for_cache(&mut state.proxy_cache_tag_validations, id);
        Ok(())
    }

    async fn trigger_proxy_cache_warm(&self, id: &str) -> Result<Option<SyncJob>, LayerhouseError> {
        let mut state = self.inner.write().await;
        let Some(cache) = state.proxy_caches.get(id).cloned() else {
            return Ok(None);
        };
        let now = now_epoch();
        if state
            .sync_jobs
            .values()
            .any(|job| sync_job_blocks_trigger(job, SyncJobKind::ProxyCache, id, now))
        {
            return Err(LayerhouseError::Conflict(
                "Proxy cache warm-up is already running".to_string(),
            ));
        }

        let job = proxy_cache_warm_job(&cache, now);
        state.sync_jobs.insert(job.id.clone(), job.clone());
        Ok(Some(job))
    }

    async fn get_proxy_cache_tag_validation(
        &self,
        cache_id: &str,
        repository: &str,
        tag: &str,
    ) -> Result<Option<ProxyCacheTagValidation>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(get_proxy_cache_tag_validation(
            &state.proxy_cache_tag_validations,
            cache_id,
            repository,
            tag,
        ))
    }

    async fn put_proxy_cache_tag_validation(
        &self,
        validation: ProxyCacheTagValidation,
    ) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        put_proxy_cache_tag_validation(&mut state.proxy_cache_tag_validations, validation);
        Ok(())
    }

    // Warm image CRUD

    async fn list_warm_images(&self) -> Result<Vec<WarmImage>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state.warm_images.values().cloned().collect())
    }

    async fn get_warm_image(&self, id: &str) -> Result<Option<WarmImage>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state.warm_images.get(id).cloned())
    }

    async fn put_warm_image(&self, image: WarmImage) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        state.warm_images.insert(image.id.clone(), image);
        Ok(())
    }

    async fn delete_warm_image(&self, id: &str) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        state.warm_images.remove(id);
        Ok(())
    }
}

#[cfg(test)]
#[async_trait]
impl JobStore for InMemoryMetadataStore {
    // Sync jobs

    async fn list_sync_jobs(&self) -> Result<Vec<SyncJob>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state.sync_jobs.values().cloned().collect())
    }

    async fn get_sync_job(&self, id: &str) -> Result<Option<SyncJob>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state.sync_jobs.get(id).cloned())
    }

    async fn put_sync_job(&self, job: SyncJob) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        state.sync_jobs.insert(job.id.clone(), job);
        Ok(())
    }

    async fn delete_sync_job(&self, id: &str) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        state.sync_jobs.remove(id);
        state.sync_job_runs.remove(id);
        Ok(())
    }

    async fn claim_sync_job(&self, id: &str, node_id: &str) -> Result<bool, LayerhouseError> {
        let mut state = self.inner.write().await;
        let Some(job) = state.sync_jobs.get_mut(id) else {
            return Ok(false);
        };
        if job.status != SyncJobStatus::Idle {
            return Ok(false);
        }
        job.status = SyncJobStatus::Running;
        job.claimed_by = Some(node_id.to_string());
        job.claimed_at = Some(now_epoch());
        Ok(true)
    }

    async fn trigger_sync_job(&self, id: &str) -> Result<bool, LayerhouseError> {
        let mut state = self.inner.write().await;
        let Some(job) = state.sync_jobs.get_mut(id) else {
            return Ok(false);
        };
        if job.status == SyncJobStatus::Running {
            return Ok(false);
        }
        job.status = SyncJobStatus::Idle;
        job.claimed_by = None;
        job.claimed_at = None;
        job.last_error = None;
        job.next_run_at = now_epoch();
        Ok(true)
    }

    // Sync job runs

    async fn list_sync_job_runs(
        &self,
        job_id: &str,
        limit: usize,
    ) -> Result<Vec<SyncJobRun>, LayerhouseError> {
        let state = self.inner.read().await;
        let runs = state.sync_job_runs.get(job_id).cloned().unwrap_or_default();
        let start = runs.len().saturating_sub(limit);
        Ok(runs[start..].to_vec())
    }

    async fn put_sync_job_run(&self, run: SyncJobRun) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        let runs = state.sync_job_runs.entry(run.job_id.clone()).or_default();
        if let Some(pos) = runs.iter().position(|r| r.id == run.id) {
            runs[pos] = run;
        } else {
            runs.push(run);
            if runs.len() > 50 {
                let excess = runs.len() - 50;
                runs.drain(..excess);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[async_trait]
impl HelmStore for InMemoryMetadataStore {
    async fn list_helm_charts(&self) -> Result<Vec<HelmChart>, LayerhouseError> {
        Ok(Vec::new())
    }

    async fn list_helm_chart_versions(
        &self,
        _name: &str,
    ) -> Result<Option<Vec<HelmChartVersion>>, LayerhouseError> {
        Ok(None)
    }
}

#[cfg(test)]
#[async_trait]
impl TokenStore for InMemoryMetadataStore {
    // Personal Access Tokens

    async fn list_personal_access_tokens(
        &self,
        subject: &str,
    ) -> Result<Vec<PersonalAccessToken>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state
            .personal_access_tokens
            .values()
            .filter(|t| t.subject == subject)
            .cloned()
            .collect())
    }

    async fn get_personal_access_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<PersonalAccessToken>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state
            .personal_access_tokens
            .values()
            .find(|t| t.token_hash == token_hash)
            .cloned())
    }

    async fn put_personal_access_token(
        &self,
        token: PersonalAccessToken,
    ) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        state.personal_access_tokens.insert(token.id.clone(), token);
        Ok(())
    }

    async fn delete_personal_access_token(
        &self,
        id: &str,
        subject: &str,
    ) -> Result<bool, LayerhouseError> {
        let mut state = self.inner.write().await;
        let should_delete = state
            .personal_access_tokens
            .get(id)
            .map(|t| t.subject == subject)
            .unwrap_or(false);
        if should_delete {
            state.personal_access_tokens.remove(id);
        }
        Ok(should_delete)
    }
}

#[cfg(test)]
#[async_trait]
impl RepositoryStore for InMemoryMetadataStore {
    async fn get_repository(&self, name: &str) -> Result<Option<Repository>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state.repositories.get(name).cloned())
    }

    async fn put_repository(&self, repo: Repository) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        state.repositories.insert(repo.name.clone(), repo);
        Ok(())
    }

    async fn delete_repository_meta(&self, name: &str) -> Result<bool, LayerhouseError> {
        let mut state = self.inner.write().await;
        Ok(state.repositories.remove(name).is_some())
    }
}

#[cfg(test)]
#[async_trait]
impl NamespaceStore for InMemoryMetadataStore {
    async fn get_namespace(&self, handle: &str) -> Result<Option<Namespace>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state.namespaces.get(handle).cloned())
    }

    async fn list_namespaces(&self) -> Result<Vec<Namespace>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state.namespaces.values().cloned().collect())
    }

    async fn get_released_handle(
        &self,
        handle: &str,
    ) -> Result<Option<ReleasedHandle>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state.released_handles.get(handle).cloned())
    }

    async fn claim_namespace(
        &self,
        handle: &str,
        owner: Owner,
        owner_label: &str,
        actor: Subject,
        admin_override: bool,
        now: u64,
    ) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        state.apply_namespace(NamespaceRequest::Claim {
            handle: handle.to_string(),
            owner,
            owner_label: owner_label.to_string(),
            actor,
            admin_override,
            now,
        })?;
        Ok(())
    }

    async fn release_namespace(
        &self,
        handle: &str,
        actor: Subject,
        reason: ReleaseReason,
        now: u64,
    ) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        state.apply_namespace(NamespaceRequest::Delete {
            handle: handle.to_string(),
            actor,
            reason,
            now,
        })?;
        Ok(())
    }

    async fn admin_revoke_namespace(
        &self,
        handle: &str,
        actor: Subject,
        now: u64,
    ) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        state.apply_namespace(NamespaceRequest::AdminRevoke {
            handle: handle.to_string(),
            actor,
            now,
        })?;
        Ok(())
    }

    async fn list_namespace_grants(
        &self,
        handle: &str,
    ) -> Result<Vec<NamespaceGrant>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state
            .namespace_grants
            .get(handle)
            .map(|grants| grants.values().cloned().collect())
            .unwrap_or_default())
    }

    async fn get_namespace_grant(
        &self,
        handle: &str,
        grant_id: &str,
    ) -> Result<Option<NamespaceGrant>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state
            .namespace_grants
            .get(handle)
            .and_then(|grants| grants.get(grant_id))
            .cloned())
    }

    async fn put_namespace_grant(
        &self,
        grant: NamespaceGrant,
        actor_label: &str,
        reason: &str,
    ) -> Result<NamespaceGrant, LayerhouseError> {
        let mut state = self.inner.write().await;
        match state.apply_namespace(NamespaceRequest::PutGrant {
            grant,
            actor_label: actor_label.to_string(),
            reason: reason.to_string(),
            audit_id: uuid::Uuid::now_v7().to_string(),
        })? {
            NamespaceResponse::Grant(grant) => Ok(grant),
            NamespaceResponse::Ok | NamespaceResponse::Bool(_) => Err(LayerhouseError::Internal(
                "unexpected namespace grant response".to_string(),
            )),
        }
    }

    async fn delete_namespace_grant(
        &self,
        handle: &str,
        grant_id: &str,
        actor: Subject,
        actor_label: &str,
        reason: &str,
        now: u64,
    ) -> Result<bool, LayerhouseError> {
        let mut state = self.inner.write().await;
        match state.apply_namespace(NamespaceRequest::DeleteGrant {
            handle: handle.to_string(),
            grant_id: grant_id.to_string(),
            actor,
            actor_label: actor_label.to_string(),
            reason: reason.to_string(),
            now,
            audit_id: uuid::Uuid::now_v7().to_string(),
        })? {
            NamespaceResponse::Bool(deleted) => Ok(deleted),
            NamespaceResponse::Ok | NamespaceResponse::Grant(_) => Err(LayerhouseError::Internal(
                "unexpected namespace grant delete response".to_string(),
            )),
        }
    }

    async fn list_namespace_grant_audit(
        &self,
        handle: &str,
    ) -> Result<Vec<NamespaceGrantAuditEvent>, LayerhouseError> {
        let state = self.inner.read().await;
        Ok(state
            .namespace_grant_audit
            .get(handle)
            .cloned()
            .unwrap_or_default())
    }

    async fn put_observed_identity(
        &self,
        identity: ObservedIdentity,
    ) -> Result<(), LayerhouseError> {
        let mut state = self.inner.write().await;
        state.apply_namespace(NamespaceRequest::PutObservedIdentity { identity })?;
        Ok(())
    }

    async fn search_observed_identities(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<ObservedIdentity>, LayerhouseError> {
        let state = self.inner.read().await;
        let query = query.trim().to_lowercase();
        let mut identities: Vec<_> = state
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
        Ok(identities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy_cache(id: &str) -> ProxyCache {
        ProxyCache {
            id: id.to_string(),
            local_prefix: "cache/app".to_string(),
            upstream_registry: "registry.example".to_string(),
            upstream_prefix: Some("upstream/app".to_string()),
            warm_filters: vec![WarmFilter::None],
            warm_schedule: None,
            plain_http: false,
            insecure_tls: false,
            outbound_proxy: OutboundProxy::default(),
            username: None,
            password: None,
            created_at: 1,
        }
    }

    fn validation(cache_id: &str, repository: &str, tag: &str) -> ProxyCacheTagValidation {
        ProxyCacheTagValidation {
            cache_id: cache_id.to_string(),
            repository: repository.to_string(),
            tag: tag.to_string(),
            upstream_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            last_validated_at: 42,
        }
    }

    #[tokio::test]
    async fn inmemory_get_manifest() {
        shared_read_tests::assert_get_manifest(&InMemoryMetadataStore::default()).await;
    }

    #[tokio::test]
    async fn inmemory_list_tags() {
        shared_read_tests::assert_list_tags(&InMemoryMetadataStore::default()).await;
    }

    #[tokio::test]
    async fn inmemory_list_repositories() {
        shared_read_tests::assert_list_repositories(&InMemoryMetadataStore::default()).await;
    }

    #[tokio::test]
    async fn inmemory_list_manifest_summaries() {
        shared_read_tests::assert_list_manifest_summaries(&InMemoryMetadataStore::default()).await;
    }

    #[tokio::test]
    async fn inmemory_proxy_cache_tag_validation_persists_and_cache_cleanup_clears_it() {
        let store = InMemoryMetadataStore::default();
        store
            .put_proxy_cache_tag_validation(validation("docker", "cache/app", "latest"))
            .await
            .unwrap();

        let found = store
            .get_proxy_cache_tag_validation("docker", "cache/app", "latest")
            .await
            .unwrap()
            .expect("validation should exist");
        assert_eq!(found.last_validated_at, 42);

        store.put_proxy_cache(proxy_cache("docker")).await.unwrap();
        assert!(
            store
                .get_proxy_cache_tag_validation("docker", "cache/app", "latest")
                .await
                .unwrap()
                .is_none()
        );

        store
            .put_proxy_cache_tag_validation(validation("docker", "cache/app", "latest"))
            .await
            .unwrap();
        store.delete_proxy_cache("docker").await.unwrap();
        assert!(
            store
                .get_proxy_cache_tag_validation("docker", "cache/app", "latest")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn inmemory_proxy_cache_tag_validation_is_cleared_by_tag_mutations() {
        let store = InMemoryMetadataStore::default();
        let (entry, _) = shared_read_tests::seed_entry();
        store
            .put_manifest("cache/app", "latest", entry.clone())
            .await
            .unwrap();
        store
            .put_proxy_cache_tag_validation(validation("docker", "cache/app", "latest"))
            .await
            .unwrap();

        assert!(
            store
                .delete_tag("cache/app", &entry.digest, "latest")
                .await
                .unwrap()
        );
        assert!(
            store
                .get_proxy_cache_tag_validation("docker", "cache/app", "latest")
                .await
                .unwrap()
                .is_none()
        );
    }

    fn user_owner(subject: &str) -> Owner {
        Owner::User(Subject::new(subject))
    }

    #[tokio::test]
    async fn namespace_claim_persists_and_reads_back() {
        let store = InMemoryMetadataStore::default();
        store
            .claim_namespace(
                "alice",
                user_owner("subject-alice"),
                "alice",
                Subject::new("subject-alice"),
                false,
                100,
            )
            .await
            .unwrap();

        let ns = store
            .get_namespace("alice")
            .await
            .unwrap()
            .expect("claimed");
        assert_eq!(ns.handle, "alice");
        assert_eq!(ns.owner_label, "alice");
        assert_eq!(ns.created_at, 100);
        assert_eq!(ns.owner, user_owner("subject-alice"));
        assert_eq!(store.list_namespaces().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn namespace_claim_conflict_is_rejected_without_leaking_owner() {
        let store = InMemoryMetadataStore::default();
        store
            .claim_namespace(
                "alice",
                user_owner("subject-alice"),
                "alice",
                Subject::new("subject-alice"),
                false,
                100,
            )
            .await
            .unwrap();

        let err = store
            .claim_namespace(
                "alice",
                user_owner("subject-bob"),
                "bob",
                Subject::new("subject-bob"),
                false,
                101,
            )
            .await
            .expect_err("second claim must conflict");
        let msg = err.to_string();
        assert!(msg.contains("already claimed"), "got: {msg}");
        // Conflict must not leak the prior owner's subject id.
        assert!(!msg.contains("subject-alice"), "leaked owner id: {msg}");
    }

    #[tokio::test]
    async fn namespace_release_records_tombstone_and_blocks_silent_reclaim() {
        let store = InMemoryMetadataStore::default();
        store
            .claim_namespace(
                "alice",
                user_owner("subject-alice"),
                "alice",
                Subject::new("subject-alice"),
                false,
                100,
            )
            .await
            .unwrap();
        store
            .release_namespace(
                "alice",
                Subject::new("subject-alice"),
                ReleaseReason::OwnerDeleted,
                200,
            )
            .await
            .unwrap();

        assert!(store.get_namespace("alice").await.unwrap().is_none());
        let tomb = store
            .get_released_handle("alice")
            .await
            .unwrap()
            .expect("tombstone");
        assert_eq!(tomb.prior_owner_label, "alice");
        assert!(matches!(tomb.release_reason, ReleaseReason::OwnerDeleted));

        // Re-claim without admin override is rejected by the tombstone.
        let err = store
            .claim_namespace(
                "alice",
                user_owner("subject-bob"),
                "bob",
                Subject::new("subject-bob"),
                false,
                300,
            )
            .await
            .expect_err("reclaim must require admin override");
        assert!(err.to_string().contains("admin override"));
    }

    #[tokio::test]
    async fn namespace_release_rejected_while_content_remains() {
        let store = InMemoryMetadataStore::default();
        store
            .claim_namespace(
                "alice",
                user_owner("subject-alice"),
                "alice",
                Subject::new("subject-alice"),
                false,
                100,
            )
            .await
            .unwrap();
        let (entry, _) = shared_read_tests::seed_entry();
        store
            .put_manifest("alice/app", "latest", entry)
            .await
            .unwrap();

        let err = store
            .release_namespace(
                "alice",
                Subject::new("subject-alice"),
                ReleaseReason::OwnerDeleted,
                200,
            )
            .await
            .expect_err("release must be blocked by remaining content");
        assert!(err.to_string().contains("delete them before releasing"));
        // The namespace is restored on the failed release.
        assert!(store.get_namespace("alice").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn namespace_admin_override_reclaims_released_handle() {
        let store = InMemoryMetadataStore::default();
        store
            .claim_namespace(
                "alice",
                user_owner("subject-alice"),
                "alice",
                Subject::new("subject-alice"),
                false,
                100,
            )
            .await
            .unwrap();
        store
            .release_namespace(
                "alice",
                Subject::new("subject-alice"),
                ReleaseReason::OwnerDeleted,
                200,
            )
            .await
            .unwrap();

        store
            .claim_namespace(
                "alice",
                user_owner("subject-bob"),
                "bob",
                Subject::new("subject-admin"),
                true,
                300,
            )
            .await
            .unwrap();

        let ns = store
            .get_namespace("alice")
            .await
            .unwrap()
            .expect("reclaimed");
        assert_eq!(ns.owner, user_owner("subject-bob"));
        // Tombstone is consumed by the override reclaim.
        assert!(store.get_released_handle("alice").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn namespace_admin_revoke_records_tombstone() {
        let store = InMemoryMetadataStore::default();
        store
            .claim_namespace(
                "alice",
                user_owner("subject-alice"),
                "alice",
                Subject::new("subject-alice"),
                false,
                100,
            )
            .await
            .unwrap();
        store
            .admin_revoke_namespace("alice", Subject::new("subject-admin"), 200)
            .await
            .unwrap();

        assert!(store.get_namespace("alice").await.unwrap().is_none());
        let tomb = store
            .get_released_handle("alice")
            .await
            .unwrap()
            .expect("tombstone");
        assert!(matches!(tomb.release_reason, ReleaseReason::AdminRevoked));
        assert_eq!(tomb.released_by, "subject-admin");
    }
}

// ── Shared read tests ─────────────────────────────────────────────────
// Parameterized tests that verify both InMemoryMetadataStore and
// StateMachineData produce identical results for the same seed data.
// Callers seed the store then invoke these shared assertion functions.

#[cfg(test)]
pub(crate) mod shared_read_tests {
    use super::*;

    /// Seed a manifest and tag, returning the entry and digest for assertions.
    pub(crate) fn seed_entry() -> (ManifestEntry, String) {
        let digest_str = format!("sha256:{:064x}", 1u64);
        let digest = Digest::from_str_checked(&digest_str).unwrap();
        let body = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},"layers":[]}"#.to_vec();
        let entry = ManifestEntry {
            digest: digest.clone(),
            content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            manifest_size_bytes: body.len() as u64,
            body,
            referenced_blobs: vec![],
            subject: None,
            artifact_type: None,
            annotations: None,
            stored_size_bytes: 2,
            created_at: 100,
            last_modified: 200,
            config_summary: None,
        };
        (entry, digest_str)
    }

    /// Shared assertions for get_manifest — takes any ManifestStore impl.
    pub(crate) async fn assert_get_manifest<M: ManifestStore>(store: &M) {
        let (entry, digest_str) = seed_entry();
        store
            .put_manifest("shared-repo", "v1", entry.clone())
            .await
            .unwrap();

        // Lookup by tag
        let found = store.get_manifest("shared-repo", "v1").await.unwrap();
        assert!(found.is_some(), "manifest should be found by tag");
        assert_eq!(found.unwrap().digest, entry.digest);

        // Lookup by digest
        let found = store
            .get_manifest("shared-repo", &digest_str)
            .await
            .unwrap();
        assert!(found.is_some(), "manifest should be found by digest");

        // Unknown reference
        let found = store
            .get_manifest("shared-repo", "nonexistent")
            .await
            .unwrap();
        assert!(found.is_none(), "unknown reference should return None");
    }

    /// Shared assertions for list_tags
    pub(crate) async fn assert_list_tags<M: ManifestStore>(store: &M) {
        let (entry, _) = seed_entry();
        store
            .put_manifest("shared-repo", "v1", entry.clone())
            .await
            .unwrap();
        store
            .put_manifest("shared-repo", "v2", entry)
            .await
            .unwrap();

        let tags = store.list_tags("shared-repo", None, None).await.unwrap();
        assert_eq!(tags, vec!["v1", "v2"]);

        let tags = store.list_tags("nonexistent", None, None).await.unwrap();
        assert!(tags.is_empty());
    }

    /// Shared assertions for list_repositories
    pub(crate) async fn assert_list_repositories<M: ManifestStore>(store: &M) {
        let (entry, _) = seed_entry();
        store
            .put_manifest("repo-a", "latest", entry.clone())
            .await
            .unwrap();
        store.put_manifest("repo-b", "latest", entry).await.unwrap();

        let repos = store.list_repositories(None, None).await.unwrap();
        assert_eq!(repos, vec!["repo-a", "repo-b"]);
    }

    /// Shared assertions for list_manifest_summaries
    pub(crate) async fn assert_list_manifest_summaries<M: ManifestStore>(store: &M) {
        let (entry, _) = seed_entry();
        store
            .put_manifest("shared-repo", "v1", entry)
            .await
            .unwrap();

        let summaries = store.list_manifest_summaries("shared-repo").await.unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].tags, vec!["v1"]);
        assert_eq!(
            summaries[0].media_type,
            "application/vnd.oci.image.manifest.v1+json"
        );
    }
}
