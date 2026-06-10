mod auth;
mod config;
mod dashboard;
mod error;
mod gc;
mod mirror;
mod oci;
mod raft;
mod routes;
mod store;

use std::sync::Arc;

use thiserror::Error;
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::config::{
    Config, CookieSecureMode, RaftTlsConfig, resolve_advertise_addr, resolve_node_id,
};
use crate::mirror::MirrorManager;
use crate::raft::kubernetes;
use crate::raft::log_store::RedbLogStore;
use crate::raft::membership;
use crate::raft::network::NetworkFactory;
use crate::raft::router::RaftMetadataStore;
use crate::raft::snapshot_s3::{S3SnapshotStore, SnapshotError};
use crate::raft::state_machine::{StateMachine, StateMachineData};
use crate::routes::{AppState, RegistryCore, build_router};
use crate::store::s3::S3BlobStore;
use crate::store::upload::UploadTracker;

const SNAPSHOT_FORMAT_VERSION: u32 = 5;
const SNAPSHOT_HEADER_LEN: usize = 4;

#[derive(Debug, Error)]
enum AppError {
    #[error("{0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("{0}")]
    LogStore(#[from] crate::raft::log_store::LogStoreError),
    #[error("{0}")]
    Snapshot(#[from] SnapshotError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("openraft: {0}")]
    Raft(String),
    #[error("invalid tracing filter: {0}")]
    TracingFilter(#[from] tracing_subscriber::filter::ParseError),
    #[error("{0}")]
    AddrParse(#[from] std::net::AddrParseError),
    #[error("--config requires a path argument")]
    MissingConfigPath,
    #[error("raft.listen '{0}' must include a port")]
    RaftListenNoPort(String),
    #[error("snapshot too short")]
    SnapshotTooShort,
    #[error("unsupported snapshot version: {0}")]
    SnapshotVersion(u32),
    #[error("serialization: {0}")]
    Json(#[from] serde_json::Error),
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let env_filter = EnvFilter::from_default_env().add_directive("layerhouse_server=info".parse()?);
    match std::env::var("LAYERHOUSE_LOG_FORMAT").as_deref() {
        Ok("json") => tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init(),
        _ => tracing_subscriber::fmt().with_env_filter(env_filter).init(),
    }

    let config = match std::env::args().nth(1) {
        Some(ref path) if path == "--config" => {
            let path = std::env::args().nth(2).ok_or(AppError::MissingConfigPath)?;
            Config::from_file(&path)?
        }
        Some(ref path) => Config::from_file(path)?,
        None => Config::default_dev(),
    };
    let listen = config.server.listen.clone();

    let node_id = resolve_node_id()?;
    let advertise_addr = resolve_advertise_addr(&config.raft.listen)?;
    tracing::info!(node_id, advertise_addr = %advertise_addr, "resolved node identity");

    let blob_store = S3BlobStore::new(&config.storage.s3).await;
    let upload_tracker =
        UploadTracker::s3(blob_store.client().clone(), blob_store.bucket().to_string());

    // S3 snapshot restore
    let snapshot_store = Arc::new(S3SnapshotStore::new(&config.storage.s3, node_id).await);
    let restored_snapshot_bytes = snapshot_store.download().await?;
    let restored_data = match restored_snapshot_bytes.as_ref() {
        Some(bytes) => {
            tracing::info!(bytes = bytes.len(), "restoring state from S3 snapshot");
            deserialize_snapshot(bytes)?
        }
        None => StateMachineData::default(),
    };
    if let Some(ref la) = restored_data.last_applied_log {
        tracing::info!(
            last_applied_index = la.index,
            last_applied_leader = la.leader_id.node_id,
            "restored snapshot state"
        );
    }
    let has_restored = restored_data.last_applied_log.is_some();

    // Raft setup — ephemeral redb
    std::fs::create_dir_all(&config.raft.data_dir)?;
    let log_path = format!("{}/raft-log.redb", config.raft.data_dir);
    let log_store = RedbLogStore::new(&log_path)?;
    if let Some(last_applied) = restored_data.last_applied_log {
        let restored_vote = openraft::Vote::new(last_applied.leader_id.term, node_id);
        log_store
            .seed_vote(restored_vote)
            .await
            .map_err(|e| AppError::Raft(e.to_string()))?;
        tracing::info!(
            vote = %restored_vote,
            restored_last_applied = %last_applied,
            "seeded raft vote from restored snapshot"
        );
    }

    let shared_state = Arc::new(RwLock::new(restored_data));
    let state_machine = if let Some(bytes) = restored_snapshot_bytes {
        let data = shared_state.read().await;
        let meta = openraft::SnapshotMeta {
            last_log_id: data.last_applied_log,
            last_membership: data.last_membership.clone(),
            snapshot_id: data
                .last_applied_log
                .map(|id| format!("{}-{}", id.leader_id, id.index))
                .unwrap_or_else(|| "restored-empty".to_string()),
        };
        drop(data);
        StateMachine::new_with_snapshot(shared_state.clone(), meta, bytes)
    } else {
        StateMachine::new(shared_state.clone())
    };

    let raft_config = openraft::Config {
        heartbeat_interval: 500,
        election_timeout_min: 1_500,
        election_timeout_max: 3_000,
        install_snapshot_timeout: 10_000,
        snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(1000),
        max_in_snapshot_log_to_keep: 100,
        ..Default::default()
    };
    let raft_config = Arc::new(raft_config);

    let tls_config = config.raft.tls.clone().map(Arc::new);
    let server_tls_config = config.server.tls.clone();

    let raft = Arc::new(
        openraft::Raft::new(
            node_id,
            raft_config,
            NetworkFactory {
                tls: tls_config.clone(),
            },
            log_store,
            state_machine,
        )
        .await
        .map_err(|e| AppError::Raft(e.to_string()))?,
    );

    // Cluster join logic
    let listen_port: u16 = config
        .raft
        .listen
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| AppError::RaftListenNoPort(config.raft.listen.clone()))?;

    match has_restored {
        true => {
            tracing::info!("resumed from S3 snapshot, Raft replication will catch up");
            // Spawn a background task to verify membership — if we were removed
            // while offline, re-join the cluster
            let raft_clone = raft.clone();
            let addr = advertise_addr.clone();
            let dns = config.raft.discovery_dns.clone();
            let tls = tls_config.clone();
            tokio::spawn(async move {
                membership::verify_or_rejoin(raft_clone, node_id, addr, dns, listen_port, tls)
                    .await;
            });
        }
        false => {
            let raft_clone = raft.clone();
            let addr = advertise_addr.clone();
            let dns = config.raft.discovery_dns.clone();
            let tls = tls_config.clone();
            tokio::spawn(async move {
                membership::join_cluster(raft_clone, node_id, addr, dns, listen_port, tls).await;
            });
        }
    }
    {
        let raft_clone = raft.clone();
        let kubernetes_config = config.raft.kubernetes.clone();
        tokio::spawn(async move {
            kubernetes::reconcile_statefulset_replicas(raft_clone, kubernetes_config).await;
        });
    }

    // Snapshot upload watcher
    {
        let raft_clone = raft.clone();
        let ss = snapshot_store.clone();
        let state = shared_state.clone();
        tokio::spawn(snapshot_upload_loop(raft_clone, ss, state));
    }

    let metadata_store = RaftMetadataStore::new(
        raft.clone(),
        shared_state.clone(),
        node_id,
        tls_config.clone(),
    );
    let scheduler_node_id = node_id.to_string();

    let gc_blob_store =
        crate::gc::S3GcBlobStore::new(blob_store.client().clone(), blob_store.bucket().to_string());
    let gc_status = Arc::new(RwLock::new(crate::gc::GcStatus::default()));

    // Initialise auth service when [auth] config section is present
    let auth_service = match config.auth.as_ref() {
        Some(auth_config) => {
            tracing::info!(
                issuer_url = %auth_config.issuer_url,
                issuer_internal_url = %auth_config.issuer_internal_url(),
                issuer_internal_urls = ?auth_config.issuer_internal_urls(),
                "initialising auth service"
            );
            let svc = Arc::new(
                crate::auth::AuthService::new(auth_config.clone(), Some(&config.storage.s3))
                    .await
                    .map_err(|e| AppError::Raft(e.to_string()))?,
            );
            svc.start_jwks_refresh();
            Some(svc)
        }
        None => None,
    };

    let cookie_secure_mode = config
        .auth
        .as_ref()
        .map(|a| a.cookie_secure_mode.clone())
        .unwrap_or(CookieSecureMode::Auto);

    let state = Arc::new(AppState {
        core: RegistryCore {
            metadata: metadata_store,
            blobs: blob_store,
            uploads: upload_tracker,
            upload_semaphore: tokio::sync::Semaphore::new(
                config.server.limits.max_concurrent_uploads,
            ),
        },
        mirror: MirrorManager::new(),
        gc_status: gc_status.clone(),
        raft: Some(raft.clone()),
        raft_tls: tls_config.clone(),
        auth: auth_service,
        server_tls_enabled: config.server.tls.is_some(),
        cookie_secure_mode,
    });

    let scheduler_state = state.clone();
    tokio::spawn(crate::mirror::scheduler::run_scheduler(
        scheduler_state,
        scheduler_node_id,
    ));

    // GC sweep (leader-only)
    {
        let gc_raft = raft.clone();
        let gc_state = shared_state.clone();
        let gc_status = gc_status.clone();
        let gc_config = config.gc.clone();
        tokio::spawn(crate::gc::run_gc_loop(
            gc_raft,
            node_id,
            gc_state,
            gc_blob_store,
            gc_status,
            gc_config,
        ));
    }

    // Graceful shutdown signal
    let shutdown_raft = raft.clone();
    let shutdown_ss = snapshot_store.clone();
    let shutdown_addr = advertise_addr.clone();
    let shutdown_tls = tls_config.clone();
    let shutdown_state = shared_state.clone();
    let shutdown_signal = async move {
        shutdown_signal_impl(
            shutdown_raft,
            node_id,
            shutdown_addr,
            shutdown_ss,
            shutdown_state,
            shutdown_tls,
        )
        .await;
    };

    {
        let raft_app =
            crate::raft::network::raft_routes(raft.clone()).layer(TraceLayer::new_for_http());
        let raft_addr: std::net::SocketAddr = config.raft.listen.parse()?;
        if let Some(ref tls_cfg) = config.raft.tls {
            let rustls_config = crate::raft::network::raft_rustls_config(tls_cfg).await?;
            let raft_listener = std::net::TcpListener::bind(raft_addr)?;
            raft_listener.set_nonblocking(true)?;
            let raft_server = axum_server::from_tcp_rustls(raft_listener, rustls_config)?;
            tracing::info!("raft mTLS listener on {}", config.raft.listen);
            tokio::spawn(async move {
                if let Err(err) = raft_server.serve(raft_app.into_make_service()).await {
                    tracing::error!(err = %err, "raft mTLS listener failed");
                }
            });
        } else {
            let raft_listener = tokio::net::TcpListener::bind(&config.raft.listen).await?;
            tracing::info!("raft HTTP listener on {}", config.raft.listen);
            tokio::spawn(async move {
                if let Err(err) = axum::serve(raft_listener, raft_app).await {
                    tracing::error!(err = %err, "raft HTTP listener failed");
                }
            });
        }
    }

    let app = build_router(state.clone(), true)
        .merge(dashboard_router(state))
        .fallback(dashboard::serve_not_found)
        .layer(TraceLayer::new_for_http())
        .layer(tower::limit::ConcurrencyLimitLayer::new(
            config.server.limits.max_concurrent_requests,
        ));

    if let Some(ref tls_cfg) = server_tls_config {
        let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            &tls_cfg.cert_path,
            &tls_cfg.key_path,
        )
        .await?;
        let server_addr: std::net::SocketAddr = listen.parse()?;
        tracing::info!("layerhouse HTTPS listening on {}", listen);
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            shutdown_signal.await;
            shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
        });
        axum_server::bind_rustls(server_addr, rustls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(&listen).await?;
        tracing::info!("layerhouse listening on {}", listen);
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal)
            .await?;
    }

    Ok(())
}

fn deserialize_snapshot(bytes: &[u8]) -> Result<StateMachineData, AppError> {
    if bytes.len() < SNAPSHOT_HEADER_LEN {
        return Err(AppError::SnapshotTooShort);
    }
    let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let payload = &bytes[SNAPSHOT_HEADER_LEN..];
    match version {
        // v2 and v4 are accepted for forward-compat: the v5 collections
        // (`repositories`, `permission_rules`) default to empty via
        // `#[serde(default)]`, so older S3 snapshots load cleanly.
        2 | 4 | SNAPSHOT_FORMAT_VERSION => {
            let mut data: StateMachineData = serde_json::from_slice(payload)?;
            data.normalize_restored_metadata();
            Ok(data)
        }
        _ => Err(AppError::SnapshotVersion(version)),
    }
}

fn serialize_snapshot(data: &StateMachineData) -> Result<Vec<u8>, serde_json::Error> {
    let payload = serde_json::to_vec(data)?;
    let mut bytes = Vec::with_capacity(SNAPSHOT_HEADER_LEN + payload.len());
    bytes.extend_from_slice(&SNAPSHOT_FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn dashboard_router<M, B>(state: Arc<crate::routes::AppState<M, B>>) -> axum::Router
where
    M: crate::store::metadata::MetadataStore,
    B: crate::store::blob::BlobStore,
{
    dashboard::dashboard_router().route_layer(axum::middleware::from_fn_with_state(
        state,
        crate::auth::middleware::auth_middleware::<M, B>,
    ))
}

async fn snapshot_upload_loop(
    raft: Arc<crate::raft::RaftInstance>,
    store: Arc<S3SnapshotStore>,
    state: Arc<RwLock<StateMachineData>>,
) {
    use openraft::LogId;

    let mut last_uploaded: Option<LogId<u64>> = None;
    let mut rx = raft.metrics();

    loop {
        rx.changed().await.ok();
        let metrics = rx.borrow().clone();

        let snapshot_log_id = metrics.snapshot;
        if snapshot_log_id.is_some() && snapshot_log_id != last_uploaded {
            // Serialize under read lock to get a consistent point-in-time snapshot
            let bytes = {
                let data = state.read().await;
                match serialize_snapshot(&data) {
                    Ok(bytes) => Some(bytes),
                    Err(e) => {
                        tracing::warn!(err = %e, "failed to serialize state for S3 upload");
                        None
                    }
                }
            };

            if let Some(bytes) = bytes {
                if let Err(e) = store.upload(&bytes).await {
                    tracing::warn!(err = %e, "failed to upload snapshot to S3");
                } else {
                    last_uploaded = snapshot_log_id;
                }
            }
        }
    }
}

async fn upload_snapshot_now(
    store: &S3SnapshotStore,
    state: &RwLock<StateMachineData>,
) -> Result<(), UploadSnapshotError> {
    let data = state.read().await;
    let bytes = serialize_snapshot(&data)?;
    drop(data);
    store.upload(&bytes).await?;
    Ok(())
}

#[derive(Debug, Error)]
enum UploadSnapshotError {
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Snapshot(#[from] SnapshotError),
}

async fn shutdown_signal_impl(
    raft: Arc<crate::raft::RaftInstance>,
    node_id: u64,
    advertise_addr: String,
    snapshot_store: Arc<S3SnapshotStore>,
    shared_state: Arc<RwLock<StateMachineData>>,
    tls: Option<Arc<crate::config::RaftTlsConfig>>,
) {
    use tokio::signal;

    #[cfg(unix)]
    {
        let sigterm = signal::unix::signal(signal::unix::SignalKind::terminate());
        match sigterm {
            Ok(mut s) => {
                tokio::select! {
                    _ = signal::ctrl_c() => {}
                    _ = s.recv() => {}
                }
            }
            Err(_) => {
                signal::ctrl_c().await.ok();
            }
        }
    }
    #[cfg(not(unix))]
    {
        signal::ctrl_c().await.ok();
    }

    tracing::info!("shutdown signal received, beginning graceful shutdown");

    wait_for_membership_change_to_commit(&raft).await;

    // Upload final snapshot (best-effort, 5s timeout)
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        if let Err(e) = upload_snapshot_now(&snapshot_store, &shared_state).await {
            tracing::warn!(err = %e, "failed to upload final snapshot");
        } else {
            tracing::info!("uploaded final snapshot to S3");
        }
    })
    .await;

    let leave_timeout = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        leave_cluster_on_shutdown(raft.clone(), node_id, tls.clone()),
    );

    if leave_timeout.await.is_err() {
        tracing::warn!("leave timeout exceeded, shutting down anyway");
    }

    let _ = advertise_addr;
}

async fn wait_for_membership_change_to_commit(raft: &Arc<raft::RaftInstance>) {
    // Wait for in-flight membership changes to commit before snapshot or retrying
    // leave, so the node does not race against a pending config change.
    for _ in 0..20 {
        let m = raft.metrics().borrow().clone();
        let membership_index = m.membership_config.log_id().map(|l| l.index);
        let applied_index = m.last_applied.map(|l| l.index);
        if membership_index == applied_index {
            break;
        }
        drop(m);
        tracing::debug!("waiting for membership change to commit");
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

async fn leave_cluster_on_shutdown(
    raft: Arc<raft::RaftInstance>,
    node_id: u64,
    tls: Option<Arc<RaftTlsConfig>>,
) {
    let mut next_leader_addr = None;

    for attempt in 1..=5 {
        let metrics = raft.metrics().borrow().clone();
        let voter_ids: std::collections::BTreeSet<u64> =
            metrics.membership_config.voter_ids().collect();
        if !voter_ids.contains(&node_id) {
            tracing::info!("local node is not a Raft voter, skipping shutdown leave");
            return;
        }
        if voter_ids.len() <= 1 {
            tracing::info!("local node is the last Raft voter, skipping shutdown leave");
            return;
        }

        let leader_id = metrics.current_leader;
        let leader_addr = next_leader_addr.take().or_else(|| {
            leader_id.and_then(|lid| {
                metrics
                    .membership_config
                    .nodes()
                    .find(|(id, _)| **id == lid)
                    .map(|(_, node)| node.addr.clone())
            })
        });
        drop(metrics);

        if leader_id == Some(node_id) {
            let remaining_voters = voter_ids
                .into_iter()
                .filter(|id| *id != node_id)
                .collect::<std::collections::BTreeSet<_>>();
            match membership::replace_voters(&raft, remaining_voters, "shutdown_leave").await {
                Ok(()) => {
                    tracing::info!(node_id, "local leader left Raft membership during shutdown");
                    return;
                }
                Err(e) => {
                    tracing::warn!(
                        node_id,
                        attempt,
                        err = %e,
                        "local shutdown leave failed"
                    );
                }
            }
        } else if let Some(addr) = leader_addr {
            let req = membership::LeaveRequest { node_id };
            let leave = membership::request_leave(&addr, tls.as_deref(), &req);
            match tokio::time::timeout(std::time::Duration::from_secs(40), leave).await {
                Ok(Ok(resp)) => match resp.result {
                    membership::LeaveResult::Ok => {
                        tracing::info!(
                            node_id,
                            leader_addr = %addr,
                            "node left Raft membership during shutdown"
                        );
                        return;
                    }
                    membership::LeaveResult::LastVoter | membership::LeaveResult::NotMember => {
                        tracing::info!(
                            node_id,
                            result = ?resp.result,
                            "shutdown leave is not required"
                        );
                        return;
                    }
                    membership::LeaveResult::NotLeader => {
                        next_leader_addr = resp.leader_addr;
                    }
                },
                Ok(Err(e)) => {
                    tracing::warn!(
                        node_id,
                        attempt,
                        leader_addr = %addr,
                        err = %e,
                        "shutdown leave request failed"
                    );
                }
                Err(_) => {
                    tracing::warn!(
                        node_id,
                        attempt,
                        leader_addr = %addr,
                        "shutdown leave request timed out"
                    );
                }
            }
        } else {
            tracing::warn!(node_id, attempt, "no Raft leader known for shutdown leave");
        }

        tokio::time::sleep(std::time::Duration::from_secs(attempt)).await;
    }

    tracing::warn!(node_id, "failed to leave Raft membership before shutdown");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_round_trips_current_format() {
        let data = StateMachineData::default();
        let bytes = serialize_snapshot(&data).expect("snapshot serializes");

        assert_eq!(
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            SNAPSHOT_FORMAT_VERSION
        );
        deserialize_snapshot(&bytes).expect("snapshot deserializes");
    }

    #[test]
    fn snapshot_rejects_short_header() {
        let error = deserialize_snapshot(&[1, 2, 3]).expect_err("short snapshot fails");
        assert!(matches!(error, AppError::SnapshotTooShort));
    }

    #[test]
    fn snapshot_rejects_unknown_version() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&999u32.to_le_bytes());
        bytes.extend_from_slice(b"{}");

        let error = deserialize_snapshot(&bytes).expect_err("unknown snapshot version fails");
        assert!(matches!(error, AppError::SnapshotVersion(999)));
    }

    #[test]
    fn snapshot_restores_previous_format_and_rebuilds_metadata_indexes() {
        let manifest_body = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000001",
                "size": 1
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000002",
                "size": 2
            }]
        })
        .to_string()
        .into_bytes();
        let payload = serde_json::json!({
            "manifests": {
                "repo": {
                    "sha256:0000000000000000000000000000000000000000000000000000000000000010": {
                        "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000010",
                        "content_type": "application/vnd.oci.image.manifest.v1+json",
                        "body": manifest_body
                    }
                }
            }
        });
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&serde_json::to_vec(&payload).unwrap());

        let data = deserialize_snapshot(&bytes).expect("v2 snapshot restores");

        assert_eq!(
            data.blob_ref_count_str(
                "sha256:0000000000000000000000000000000000000000000000000000000000000001"
            ),
            1
        );
        assert_eq!(
            data.blob_ref_count_str(
                "sha256:0000000000000000000000000000000000000000000000000000000000000002"
            ),
            1
        );
    }

    #[test]
    fn snapshot_restores_v4_with_empty_v5_collections() {
        // A v4 S3 snapshot predates `repositories`/`permission_rules`. It must
        // still load, with those collections defaulting to empty.
        let payload = serde_json::json!({ "manifests": {}, "tags": {} });
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&serde_json::to_vec(&payload).unwrap());

        let data = deserialize_snapshot(&bytes).expect("v4 snapshot restores");
        assert!(data.repositories.is_empty());
        assert!(data.permission_rules.is_empty());
    }
}
