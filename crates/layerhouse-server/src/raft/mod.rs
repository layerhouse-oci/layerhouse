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

use crate::auth::identity::Subject;
use crate::store::metadata::{
    BlobDeleteStatus, DeleteCounts, MirrorRule, NamespaceEpoch, NamespaceGrant, ObservedIdentity,
    Owner, PersonalAccessToken, ProxyCache, ProxyCacheTagValidation, ReleaseReason, Repository,
    SyncJob, SyncJobRun, WarmImage,
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
        expected_namespace: Option<NamespaceEpoch>,
        reference: String,
        require_reference_absent: bool,
        digest: String,
        content_type: String,
        body: Vec<u8>,
        subject: Option<String>,
        artifact_type: Option<String>,
        annotations: Option<serde_json::Value>,
        stored_size_bytes: u64,
        manifest_size_bytes: u64,
        created_at: u64,
        last_modified: u64,
        config_summary: Option<serde_json::Value>,
        referenced_blobs: Vec<String>,
    },
    DeleteManifest {
        name: String,
        expected_namespace: Option<NamespaceEpoch>,
        digest: String,
    },
    DeleteTag {
        name: String,
        expected_namespace: Option<NamespaceEpoch>,
        digest: String,
        tag: String,
    },
    DeleteRepository {
        name: String,
        expected_namespace: Option<NamespaceEpoch>,
    },
    DeleteManifests {
        name: String,
        expected_namespace: Option<NamespaceEpoch>,
        digests: Vec<String>,
    },
    MountBlob {
        source_repo: String,
        dest_repo: String,
        expected_namespace: Option<NamespaceEpoch>,
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

// ── Repository domain ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RepositoryRequest {
    PutRepository {
        repository: Repository,
        expected_namespace: Option<NamespaceEpoch>,
    },
    DeleteRepository {
        name: String,
        expected_namespace: Option<NamespaceEpoch>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RepositoryResponse {
    Ok,
    Bool(bool),
}

// ── Namespace domain ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NamespaceRequest {
    Claim {
        handle: String,
        owner: Owner,
        owner_label: String,
        actor: Subject,
        admin_override: bool,
        /// Wall-clock timestamp captured on the leader before the request
        /// enters Raft consensus. Apply must be deterministic across followers,
        /// so timestamps cannot be minted inside the state machine.
        now: u64,
    },
    Delete {
        handle: String,
        actor: Subject,
        reason: ReleaseReason,
        now: u64,
    },
    AdminRevoke {
        handle: String,
        actor: Subject,
        now: u64,
    },
    PutGrant {
        grant: NamespaceGrant,
        actor_label: String,
        reason: String,
        audit_id: String,
    },
    DeleteGrant {
        handle: String,
        grant_id: String,
        actor: Subject,
        actor_label: String,
        reason: String,
        now: u64,
        audit_id: String,
    },
    PutObservedIdentity {
        identity: ObservedIdentity,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NamespaceResponse {
    Ok,
    Grant(NamespaceGrant),
    Bool(bool),
}

// ── Outer wrappers (for OpenRaft TypeConfig) ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Manifest(ManifestRequest),
    MirrorConfig(MirrorConfigRequest),
    Job(JobRequest),
    Token(TokenRequest),
    Repository(RepositoryRequest),
    Namespace(NamespaceRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Manifest(ManifestResponse),
    MirrorConfig(MirrorConfigResponse),
    Job(JobResponse),
    Token(TokenResponse),
    Repository(RepositoryResponse),
    Namespace(NamespaceResponse),
    /// Apply-time error — handle is not claimed / doesn't exist.
    NameUnknown(String),
    /// Apply-time error — caller lacks permission for this operation.
    Denied(String),
    /// Apply-time error — operation conflicts with current state.
    Conflict(String),
    /// Apply-time error — name fails grammar validation.
    NameInvalid(String),
    /// Apply-time error — internal / unknown catch-all.
    InternalError(String),
}
