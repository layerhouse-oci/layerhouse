use std::sync::Arc;

use async_trait::async_trait;
use openraft::error::ClientWriteError;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use super::state_machine::StateMachineData;
use super::{
    JobRequest, JobResponse, ManifestRequest, ManifestResponse, MirrorConfigRequest,
    MirrorConfigResponse, RaftInstance, RepositoryRequest, RepositoryResponse, Request, Response,
    TokenRequest, TokenResponse,
};
use crate::config::RaftTlsConfig;
use crate::error::LayerhouseError;
use crate::oci::digest::Digest;
use crate::raft::network;
use crate::store::metadata::{
    BlobDeleteStatus, BlobLifecycleStatus, DeleteCounts, HelmChart, HelmChartVersion, HelmStore,
    JobStore, ManifestEntry, ManifestStore, ManifestSummary, MirrorConfigStore, MirrorRule,
    PersonalAccessToken, ProxyCache, ProxyCacheTagValidation, ReferrerEntry, Repository,
    RepositoryStore, RepositorySummary, SyncJob, SyncJobRun, TokenStore, WarmImage,
};

const FOLLOWER_READ_LAG_THRESHOLD: u64 = 100;

struct ReadMetrics {
    is_leader: bool,
    last_log_index: Option<u64>,
    last_applied: u64,
}

pub struct RaftMetadataStore {
    raft: Arc<RaftInstance>,
    state: Arc<RwLock<StateMachineData>>,
    node_id: u64,
    tls: Option<Arc<RaftTlsConfig>>,
}

impl RaftMetadataStore {
    pub fn new(
        raft: Arc<RaftInstance>,
        state: Arc<RwLock<StateMachineData>>,
        node_id: u64,
        tls: Option<Arc<RaftTlsConfig>>,
    ) -> Self {
        Self {
            raft,
            state,
            node_id,
            tls,
        }
    }

    fn read_metrics(&self) -> ReadMetrics {
        let raft_metrics = self.raft.metrics().borrow().clone();
        let is_leader = raft_metrics.current_leader == Some(self.node_id);
        let last_log_index = raft_metrics.last_log_index;
        let raft_last_applied = raft_metrics.last_applied.map(|l| l.index).unwrap_or(0);
        ReadMetrics {
            is_leader,
            last_log_index,
            last_applied: raft_last_applied,
        }
    }

    fn emit_read_metrics(&self, method: &str) {
        let m = self.read_metrics();
        debug!(
            is_leader = m.is_leader,
            last_log_index = m.last_log_index,
            last_applied = m.last_applied,
            method,
            "follower read",
        );
        if !m.is_leader
            && m.last_log_index.unwrap_or(0).saturating_sub(m.last_applied)
                > FOLLOWER_READ_LAG_THRESHOLD
        {
            warn!(
                lag = m.last_log_index.unwrap_or(0) - m.last_applied,
                "follower read lag exceeds threshold"
            );
        }
    }

    async fn write(&self, req: Request) -> Result<Response, LayerhouseError> {
        let resp = match self.raft.client_write(req.clone()).await {
            Ok(resp) => resp.data,
            Err(openraft::error::RaftError::APIError(ClientWriteError::ForwardToLeader(fwd))) => {
                let leader_addr = fwd
                    .leader_node
                    .as_ref()
                    .map(|n| n.addr.clone())
                    .unwrap_or_default();
                network::forward_client_write(&leader_addr, self.tls.clone(), &req)
                    .await
                    .map_err(LayerhouseError::Consensus)?
            }
            Err(e) => return Err(LayerhouseError::Consensus(format!("{}", e))),
        };
        // Apply-time errors travel back as `Response::Error(msg)` because
        // `LayerhouseError` is not `Deserialize`. Decode into `Internal` here
        // so callers see a normal `LayerhouseError`.
        if let Response::Error(msg) = resp {
            return Err(LayerhouseError::Internal(msg));
        }
        Ok(resp)
    }

    async fn write_manifest(
        &self,
        req: ManifestRequest,
    ) -> Result<ManifestResponse, LayerhouseError> {
        match self.write(Request::Manifest(req)).await? {
            Response::Manifest(r) => Ok(r),
            other => Err(LayerhouseError::Internal(format!(
                "unexpected manifest response: {:?}",
                other
            ))),
        }
    }

    async fn write_mirror_config(
        &self,
        req: MirrorConfigRequest,
    ) -> Result<MirrorConfigResponse, LayerhouseError> {
        match self.write(Request::MirrorConfig(req)).await? {
            Response::MirrorConfig(r) => Ok(r),
            other => Err(LayerhouseError::Internal(format!(
                "unexpected mirror config response: {:?}",
                other
            ))),
        }
    }

    async fn write_job(&self, req: JobRequest) -> Result<JobResponse, LayerhouseError> {
        match self.write(Request::Job(req)).await? {
            Response::Job(r) => Ok(r),
            other => Err(LayerhouseError::Internal(format!(
                "unexpected job response: {:?}",
                other
            ))),
        }
    }

    async fn write_token(&self, req: TokenRequest) -> Result<TokenResponse, LayerhouseError> {
        match self.write(Request::Token(req)).await? {
            Response::Token(r) => Ok(r),
            other => Err(LayerhouseError::Internal(format!(
                "unexpected token response: {:?}",
                other
            ))),
        }
    }

    async fn write_repository(
        &self,
        req: RepositoryRequest,
    ) -> Result<RepositoryResponse, LayerhouseError> {
        match self.write(Request::Repository(req)).await? {
            Response::Repository(r) => Ok(r),
            other => Err(LayerhouseError::Internal(format!(
                "unexpected repository response: {:?}",
                other
            ))),
        }
    }
}

#[async_trait]
impl ManifestStore for RaftMetadataStore {
    async fn get_manifest(
        &self,
        name: &str,
        reference: &str,
    ) -> Result<Option<ManifestEntry>, LayerhouseError> {
        self.emit_read_metrics("get_manifest");
        let state = self.state.read().await;
        Ok(state.get_manifest(name, reference))
    }

    async fn put_manifest(
        &self,
        name: &str,
        reference: &str,
        entry: ManifestEntry,
    ) -> Result<(), LayerhouseError> {
        self.write_manifest(ManifestRequest::PutManifest {
            name: name.to_string(),
            reference: reference.to_string(),
            digest: entry.digest.to_string(),
            content_type: entry.content_type,
            body: entry.body,
            subject: entry.subject.map(|d| d.to_string()),
            artifact_type: entry.artifact_type,
            annotations: entry.annotations,
            stored_size_bytes: entry.stored_size_bytes,
            manifest_size_bytes: entry.manifest_size_bytes,
            created_at: entry.created_at,
            last_modified: entry.last_modified,
            config_summary: entry.config_summary,
            referenced_blobs: entry
                .referenced_blobs
                .iter()
                .map(ToString::to_string)
                .collect(),
        })
        .await?;
        Ok(())
    }

    async fn delete_manifest(&self, name: &str, digest: &Digest) -> Result<(), LayerhouseError> {
        self.write_manifest(ManifestRequest::DeleteManifest {
            name: name.to_string(),
            digest: digest.to_string(),
        })
        .await?;
        Ok(())
    }

    async fn list_tags(
        &self,
        name: &str,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<Vec<String>, LayerhouseError> {
        self.emit_read_metrics("list_tags");
        let state = self.state.read().await;
        Ok(state.list_tags(name, n, last))
    }

    async fn list_repositories(
        &self,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<Vec<String>, LayerhouseError> {
        self.emit_read_metrics("list_repositories");
        let state = self.state.read().await;
        Ok(state.list_repositories(n, last))
    }

    async fn list_repository_summaries(&self) -> Result<Vec<RepositorySummary>, LayerhouseError> {
        self.emit_read_metrics("list_repository_summaries");
        let state = self.state.read().await;
        Ok(state.list_repository_summaries())
    }

    async fn list_manifest_summaries(
        &self,
        name: &str,
    ) -> Result<Vec<ManifestSummary>, LayerhouseError> {
        self.emit_read_metrics("list_manifest_summaries");
        let state = self.state.read().await;
        Ok(state.list_manifest_summaries(name))
    }

    async fn delete_tag(
        &self,
        name: &str,
        digest: &Digest,
        tag: &str,
    ) -> Result<bool, LayerhouseError> {
        let resp = self
            .write_manifest(ManifestRequest::DeleteTag {
                name: name.to_string(),
                digest: digest.to_string(),
                tag: tag.to_string(),
            })
            .await?;
        match resp {
            ManifestResponse::Bool(b) => Ok(b),
            ManifestResponse::Ok
            | ManifestResponse::DeleteCounts(_)
            | ManifestResponse::BlobDeleteStatus(_) => Err(LayerhouseError::Internal(
                "unexpected response for delete_tag".to_string(),
            )),
        }
    }

    async fn delete_repository(&self, name: &str) -> Result<DeleteCounts, LayerhouseError> {
        let resp = self
            .write_manifest(ManifestRequest::DeleteRepository {
                name: name.to_string(),
            })
            .await?;
        match resp {
            ManifestResponse::DeleteCounts(counts) => Ok(counts),
            ManifestResponse::Ok
            | ManifestResponse::Bool(_)
            | ManifestResponse::BlobDeleteStatus(_) => Err(LayerhouseError::Internal(
                "unexpected response for delete_repository".to_string(),
            )),
        }
    }

    async fn delete_manifests(
        &self,
        name: &str,
        digests: &[Digest],
    ) -> Result<DeleteCounts, LayerhouseError> {
        let resp = self
            .write_manifest(ManifestRequest::DeleteManifests {
                name: name.to_string(),
                digests: digests.iter().map(ToString::to_string).collect(),
            })
            .await?;
        match resp {
            ManifestResponse::DeleteCounts(counts) => Ok(counts),
            ManifestResponse::Ok
            | ManifestResponse::Bool(_)
            | ManifestResponse::BlobDeleteStatus(_) => Err(LayerhouseError::Internal(
                "unexpected response for delete_manifests".to_string(),
            )),
        }
    }

    async fn list_referrers(
        &self,
        name: &str,
        subject_digest: &Digest,
        artifact_type: Option<&str>,
    ) -> Result<Vec<ReferrerEntry>, LayerhouseError> {
        self.emit_read_metrics("list_referrers");
        let state = self.state.read().await;
        Ok(state.list_referrers(name, &subject_digest.to_string(), artifact_type))
    }

    async fn mount_blob(
        &self,
        source_repo: &str,
        dest_repo: &str,
        digest: &Digest,
    ) -> Result<(), LayerhouseError> {
        self.write_manifest(ManifestRequest::MountBlob {
            source_repo: source_repo.to_string(),
            dest_repo: dest_repo.to_string(),
            digest: digest.to_string(),
        })
        .await?;
        Ok(())
    }

    async fn record_blob_delete_request(
        &self,
        digest: &Digest,
    ) -> Result<BlobDeleteStatus, LayerhouseError> {
        let resp = self
            .write_manifest(ManifestRequest::RecordBlobDelete {
                digest: digest.to_string(),
                requested_at: crate::store::metadata::now_epoch(),
            })
            .await?;
        match resp {
            ManifestResponse::BlobDeleteStatus(status) => Ok(status),
            ManifestResponse::Ok
            | ManifestResponse::Bool(_)
            | ManifestResponse::DeleteCounts(_) => Err(LayerhouseError::Internal(
                "unexpected blob delete response".to_string(),
            )),
        }
    }

    async fn blob_lifecycle_status(
        &self,
        digest: &Digest,
    ) -> Result<BlobLifecycleStatus, LayerhouseError> {
        self.emit_read_metrics("blob_lifecycle_status");
        let state = self.state.read().await;
        Ok(state.blob_lifecycle_status(digest))
    }

    async fn clear_blob_delete_request(&self, digest: &Digest) -> Result<(), LayerhouseError> {
        self.write_manifest(ManifestRequest::ClearBlobDelete {
            digest: digest.to_string(),
        })
        .await?;
        Ok(())
    }

    async fn blob_ref_counts(
        &self,
    ) -> Result<std::collections::BTreeMap<String, u64>, LayerhouseError> {
        self.emit_read_metrics("blob_ref_counts");
        let state = self.state.read().await;
        Ok(state.blob_ref_counts.clone())
    }
}

#[async_trait]
impl MirrorConfigStore for RaftMetadataStore {
    async fn list_mirror_rules(&self) -> Result<Vec<MirrorRule>, LayerhouseError> {
        self.emit_read_metrics("list_mirror_rules");
        let state = self.state.read().await;
        Ok(state.list_mirror_rules())
    }

    async fn get_mirror_rule(&self, id: &str) -> Result<Option<MirrorRule>, LayerhouseError> {
        self.emit_read_metrics("get_mirror_rule");
        let state = self.state.read().await;
        Ok(state.get_mirror_rule(id))
    }

    async fn put_mirror_rule(&self, rule: MirrorRule) -> Result<(), LayerhouseError> {
        self.write_mirror_config(MirrorConfigRequest::PutMirrorRule(rule))
            .await?;
        Ok(())
    }

    async fn delete_mirror_rule(&self, id: &str) -> Result<(), LayerhouseError> {
        self.write_mirror_config(MirrorConfigRequest::DeleteMirrorRule { id: id.to_string() })
            .await?;
        Ok(())
    }

    async fn trigger_mirror_rule(&self, id: &str) -> Result<Option<SyncJob>, LayerhouseError> {
        let resp = self
            .write_mirror_config(MirrorConfigRequest::TriggerMirrorRule { id: id.to_string() })
            .await?;
        match resp {
            MirrorConfigResponse::SyncJob(job) => Ok(job),
            MirrorConfigResponse::Bool(false) => Err(LayerhouseError::Conflict(
                "Rule is already running".to_string(),
            )),
            _ => Ok(None),
        }
    }

    async fn list_proxy_caches(&self) -> Result<Vec<ProxyCache>, LayerhouseError> {
        self.emit_read_metrics("list_proxy_caches");
        let state = self.state.read().await;
        Ok(state.list_proxy_caches())
    }

    async fn get_proxy_cache(&self, id: &str) -> Result<Option<ProxyCache>, LayerhouseError> {
        self.emit_read_metrics("get_proxy_cache");
        let state = self.state.read().await;
        Ok(state.get_proxy_cache(id))
    }

    async fn put_proxy_cache(&self, cache: ProxyCache) -> Result<(), LayerhouseError> {
        self.write_mirror_config(MirrorConfigRequest::PutProxyCache(cache))
            .await?;
        Ok(())
    }

    async fn delete_proxy_cache(&self, id: &str) -> Result<(), LayerhouseError> {
        self.write_mirror_config(MirrorConfigRequest::DeleteProxyCache { id: id.to_string() })
            .await?;
        Ok(())
    }

    async fn trigger_proxy_cache_warm(&self, id: &str) -> Result<Option<SyncJob>, LayerhouseError> {
        let resp = self
            .write_mirror_config(MirrorConfigRequest::TriggerProxyCacheWarm { id: id.to_string() })
            .await?;
        match resp {
            MirrorConfigResponse::SyncJob(job) => Ok(job),
            MirrorConfigResponse::Bool(false) => Err(LayerhouseError::Conflict(
                "Proxy cache warm-up is already running".to_string(),
            )),
            _ => Ok(None),
        }
    }

    async fn get_proxy_cache_tag_validation(
        &self,
        cache_id: &str,
        repository: &str,
        tag: &str,
    ) -> Result<Option<ProxyCacheTagValidation>, LayerhouseError> {
        self.emit_read_metrics("get_proxy_cache_tag_validation");
        let state = self.state.read().await;
        Ok(state.get_proxy_cache_tag_validation(cache_id, repository, tag))
    }

    async fn put_proxy_cache_tag_validation(
        &self,
        validation: ProxyCacheTagValidation,
    ) -> Result<(), LayerhouseError> {
        self.write_mirror_config(MirrorConfigRequest::PutProxyCacheTagValidation(validation))
            .await?;
        Ok(())
    }

    async fn list_warm_images(&self) -> Result<Vec<WarmImage>, LayerhouseError> {
        self.emit_read_metrics("list_warm_images");
        let state = self.state.read().await;
        Ok(state.list_warm_images())
    }

    async fn get_warm_image(&self, id: &str) -> Result<Option<WarmImage>, LayerhouseError> {
        self.emit_read_metrics("get_warm_image");
        let state = self.state.read().await;
        Ok(state.get_warm_image(id))
    }

    async fn put_warm_image(&self, image: WarmImage) -> Result<(), LayerhouseError> {
        self.write_mirror_config(MirrorConfigRequest::PutWarmImage(image))
            .await?;
        Ok(())
    }

    async fn delete_warm_image(&self, id: &str) -> Result<(), LayerhouseError> {
        self.write_mirror_config(MirrorConfigRequest::DeleteWarmImage { id: id.to_string() })
            .await?;
        Ok(())
    }
}

#[async_trait]
impl JobStore for RaftMetadataStore {
    async fn list_sync_jobs(&self) -> Result<Vec<SyncJob>, LayerhouseError> {
        self.emit_read_metrics("list_sync_jobs");
        let state = self.state.read().await;
        Ok(state.list_sync_jobs())
    }

    async fn get_sync_job(&self, id: &str) -> Result<Option<SyncJob>, LayerhouseError> {
        self.emit_read_metrics("get_sync_job");
        let state = self.state.read().await;
        Ok(state.get_sync_job(id))
    }

    async fn put_sync_job(&self, job: SyncJob) -> Result<(), LayerhouseError> {
        self.write_job(JobRequest::PutSyncJob(job)).await?;
        Ok(())
    }

    async fn delete_sync_job(&self, id: &str) -> Result<(), LayerhouseError> {
        self.write_job(JobRequest::DeleteSyncJob { id: id.to_string() })
            .await?;
        Ok(())
    }

    async fn claim_sync_job(&self, id: &str, node_id: &str) -> Result<bool, LayerhouseError> {
        let resp = self
            .write_job(JobRequest::ClaimSyncJob {
                id: id.to_string(),
                node_id: node_id.to_string(),
            })
            .await?;
        match resp {
            JobResponse::Bool(b) => Ok(b),
            JobResponse::Ok => Ok(false),
        }
    }

    async fn trigger_sync_job(&self, id: &str) -> Result<bool, LayerhouseError> {
        let resp = self
            .write_job(JobRequest::TriggerSyncJob { id: id.to_string() })
            .await?;
        match resp {
            JobResponse::Bool(b) => Ok(b),
            JobResponse::Ok => Ok(false),
        }
    }

    async fn list_sync_job_runs(
        &self,
        job_id: &str,
        limit: usize,
    ) -> Result<Vec<SyncJobRun>, LayerhouseError> {
        self.emit_read_metrics("list_sync_job_runs");
        let state = self.state.read().await;
        Ok(state.list_sync_job_runs(job_id, limit))
    }

    async fn put_sync_job_run(&self, run: SyncJobRun) -> Result<(), LayerhouseError> {
        self.write_job(JobRequest::PutSyncJobRun(run)).await?;
        Ok(())
    }
}

#[async_trait]
impl HelmStore for RaftMetadataStore {
    async fn list_helm_charts(&self) -> Result<Vec<HelmChart>, LayerhouseError> {
        self.emit_read_metrics("list_helm_charts");
        let state = self.state.read().await;
        Ok(state.list_helm_charts())
    }

    async fn list_helm_chart_versions(
        &self,
        name: &str,
    ) -> Result<Option<Vec<HelmChartVersion>>, LayerhouseError> {
        self.emit_read_metrics("list_helm_chart_versions");
        let state = self.state.read().await;
        Ok(state.list_helm_chart_versions(name))
    }
}

#[async_trait]
impl TokenStore for RaftMetadataStore {
    // Personal Access Tokens

    async fn list_personal_access_tokens(
        &self,
        subject: &str,
    ) -> Result<Vec<PersonalAccessToken>, LayerhouseError> {
        self.emit_read_metrics("list_personal_access_tokens");
        let state = self.state.read().await;
        Ok(state.list_personal_access_tokens(subject))
    }

    async fn get_personal_access_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<PersonalAccessToken>, LayerhouseError> {
        self.emit_read_metrics("get_personal_access_token_by_hash");
        let state = self.state.read().await;
        Ok(state.get_personal_access_token_by_hash(token_hash))
    }

    async fn put_personal_access_token(
        &self,
        token: PersonalAccessToken,
    ) -> Result<(), LayerhouseError> {
        self.write_token(TokenRequest::PutPersonalAccessToken(token))
            .await?;
        Ok(())
    }

    async fn delete_personal_access_token(
        &self,
        id: &str,
        subject: &str,
    ) -> Result<bool, LayerhouseError> {
        let resp = self
            .write_token(TokenRequest::DeletePersonalAccessToken {
                id: id.to_string(),
                subject: subject.to_string(),
            })
            .await?;
        match resp {
            TokenResponse::Bool(deleted) => Ok(deleted),
            TokenResponse::Ok => Err(LayerhouseError::Internal(
                "unexpected response for delete_personal_access_token".to_string(),
            )),
        }
    }
}

#[async_trait]
impl RepositoryStore for RaftMetadataStore {
    async fn get_repository(&self, name: &str) -> Result<Option<Repository>, LayerhouseError> {
        self.emit_read_metrics("get_repository");
        let state = self.state.read().await;
        Ok(state.get_repository(name))
    }

    async fn put_repository(&self, repo: Repository) -> Result<(), LayerhouseError> {
        self.write_repository(RepositoryRequest::PutRepository(repo))
            .await?;
        Ok(())
    }

    async fn delete_repository_meta(&self, name: &str) -> Result<bool, LayerhouseError> {
        let resp = self
            .write_repository(RepositoryRequest::DeleteRepository {
                name: name.to_string(),
            })
            .await?;
        match resp {
            RepositoryResponse::Bool(deleted) => Ok(deleted),
            RepositoryResponse::Ok => Ok(false),
        }
    }
}
