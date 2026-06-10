pub mod kubernetes;
pub mod log_store;
pub mod membership;
pub mod network;
pub mod router;
pub mod snapshot_s3;
pub mod state_machine;

use std::io::Cursor;

use openraft::BasicNode;
use openraft::TokioRuntime;
use serde::{Deserialize, Serialize};

use crate::store::metadata::{
    BlobDeleteStatus, DeleteCounts, MirrorRule, PersonalAccessToken, ProxyCache,
    ProxyCacheTagValidation, SyncJob, SyncJobRun, WarmImage,
};

openraft::declare_raft_types!(
    pub TypeConfig:
        D            = Request,
        R            = Response,
        NodeId       = u64,
        Node         = BasicNode,
        Entry        = openraft::Entry<TypeConfig>,
        SnapshotData = Cursor<Vec<u8>>,
        AsyncRuntime = TokioRuntime,
);

pub type RaftInstance = openraft::Raft<TypeConfig>;

// ── Manifest domain ──────────────────────────────────────────────────

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ManifestRequest {
    PutManifest {
        name: String,
        reference: String,
        digest: String,
        content_type: String,
        body: Vec<u8>,
        subject: Option<String>,
        artifact_type: Option<String>,
        annotations: Option<serde_json::Value>,
        size_bytes: u64,
        created_at: u64,
        last_modified: u64,
        config_summary: Option<serde_json::Value>,
        referenced_blobs: Vec<String>,
    },
    DeleteManifest {
        name: String,
        digest: String,
    },
    DeleteTag {
        name: String,
        digest: String,
        tag: String,
    },
    DeleteRepository {
        name: String,
    },
    DeleteManifests {
        name: String,
        digests: Vec<String>,
    },
    MountBlob {
        source_repo: String,
        dest_repo: String,
        digest: String,
    },
    RecordBlobDelete {
        digest: String,
        requested_at: u64,
    },
    ClearBlobDelete {
        digest: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ManifestResponse {
    Ok,
    Bool(bool),
    DeleteCounts(DeleteCounts),
    BlobDeleteStatus(BlobDeleteStatus),
}

// ── Mirror config domain ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MirrorConfigRequest {
    PutMirrorRule(MirrorRule),
    DeleteMirrorRule { id: String },
    TriggerMirrorRule { id: String },
    PutProxyCache(ProxyCache),
    DeleteProxyCache { id: String },
    TriggerProxyCacheWarm { id: String },
    PutProxyCacheTagValidation(ProxyCacheTagValidation),
    PutWarmImage(WarmImage),
    DeleteWarmImage { id: String },
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MirrorConfigResponse {
    Ok,
    Bool(bool),
    SyncJob(Option<SyncJob>),
}

// ── Job domain ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobRequest {
    PutSyncJob(SyncJob),
    DeleteSyncJob { id: String },
    ClaimSyncJob { id: String, node_id: String },
    TriggerSyncJob { id: String },
    PutSyncJobRun(SyncJobRun),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobResponse {
    Ok,
    Bool(bool),
}

// ── Token domain ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenRequest {
    PutPersonalAccessToken(PersonalAccessToken),
    DeletePersonalAccessToken { id: String, subject: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenResponse {
    Ok,
    Bool(bool),
}

// ── Outer wrappers (for OpenRaft TypeConfig) ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Manifest(ManifestRequest),
    MirrorConfig(MirrorConfigRequest),
    Job(JobRequest),
    Token(TokenRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Manifest(ManifestResponse),
    MirrorConfig(MirrorConfigResponse),
    Job(JobResponse),
    Token(TokenResponse),
}
