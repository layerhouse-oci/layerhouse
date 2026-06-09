//! Raft cluster membership: handlers, clients, discovery, join loop.

pub mod types;

// Re-export for backward compatibility
pub use types::*;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use openraft::{BasicNode, ChangeMembers};

use crate::config::RaftTlsConfig;

use super::RaftInstance;
use super::network;

pub fn build_cluster_status(raft: &RaftInstance) -> ClusterStatus {
    let metrics = raft.metrics().borrow().clone();
    let node_id = metrics.id;

    let state = match metrics.state {
        openraft::ServerState::Leader => NodeState::Leader,
        openraft::ServerState::Follower => NodeState::Follower,
        openraft::ServerState::Candidate => NodeState::Candidate,
        openraft::ServerState::Learner => NodeState::Learner,
        _ => NodeState::Follower,
    };

    let membership = &metrics.membership_config;
    let nodes = membership.nodes();

    let voter_ids: BTreeSet<u64> = membership.voter_ids().collect();

    let mut voters = Vec::new();
    let mut learners = Vec::new();
    for (id, node) in nodes {
        let info = NodeInfo {
            id: *id,
            addr: node.addr.clone(),
        };
        if voter_ids.contains(id) {
            voters.push(info);
        } else {
            learners.push(info);
        }
    }

    let leader_addr = metrics.current_leader.and_then(|lid| {
        membership
            .nodes()
            .find(|(id, _)| **id == lid)
            .map(|(_, n)| n.addr.clone())
    });

    let last_applied_log = metrics.last_applied.map(|l| l.index);
    let last_membership_log_id = membership.log_id().map(|l| l.index);
    let replication = metrics
        .replication
        .unwrap_or_default()
        .into_iter()
        .map(|(id, log_id)| (id, log_id.map(|l| l.index)))
        .collect();

    ClusterStatus {
        node_id,
        state,
        leader_id: metrics.current_leader,
        leader_addr,
        voters,
        learners,
        term: metrics.current_term,
        last_log_index: metrics.last_log_index,
        last_applied_log,
        last_membership_log_id,
        millis_since_quorum_ack: metrics.millis_since_quorum_ack,
        replication,
    }
}

pub async fn handle_status(State(raft): State<Arc<RaftInstance>>) -> Response {
    Json(build_cluster_status(&raft)).into_response()
}

async fn acquire_membership_change_lock() -> tokio::sync::MutexGuard<'static, ()> {
    MEMBERSHIP_CHANGE_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

fn committed_membership_log_index(raft: &RaftInstance) -> Option<u64> {
    raft.metrics()
        .borrow()
        .membership_config
        .log_id()
        .map(|log_id| log_id.index)
}

async fn wait_for_committed_membership_log_advance(
    raft: &RaftInstance,
    previous_index: Option<u64>,
) -> bool {
    for _ in 0..150 {
        let current_index = committed_membership_log_index(raft);
        if current_index > previous_index {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    false
}

async fn settle_after_membership_change() {
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
}

/// Parse openraft's "already undergoing a configuration change" error to detect
/// stale pending changes. Returns true if the pending change is from an old term
/// (pending_term < committed_term), indicating it can never be committed.
fn is_stale_config_change(error_msg: &str) -> bool {
    if !error_msg.contains("already undergoing a configuration change") {
        return false;
    }

    // Extract term numbers from: "at log Some(LogId { term: T1, ... }), ... log id: Some(LogId { term: T2, ... })"
    let mut terms = Vec::new();
    let mut rest = error_msg;
    while let Some(pos) = rest.find("term: ") {
        let after = &rest[pos + 6..];
        if let Some(end) = after.find(|c: char| !c.is_ascii_digit()) {
            if let Ok(t) = after[..end].parse::<u64>() {
                terms.push(t);
            }
            rest = &after[end..];
        } else if let Ok(t) = after.parse::<u64>() {
            terms.push(t);
            break;
        } else {
            break;
        }
    }

    // First "term:" is the pending change, second is the committed membership
    if terms.len() >= 2 {
        let pending_term = terms[0];
        let committed_term = terms[1];
        pending_term < committed_term
    } else {
        false
    }
}

pub async fn handle_join(
    State(raft): State<Arc<RaftInstance>>,
    Json(req): Json<JoinRequest>,
) -> Response {
    if let Some(response) = precheck_join(&raft, req.node_id) {
        return response;
    }

    let _guard = acquire_membership_change_lock().await;
    if let Some(response) = precheck_join(&raft, req.node_id) {
        return response;
    }

    let node = BasicNode {
        addr: req.addr.clone(),
    };
    if let Err(e) = raft.add_learner(req.node_id, node, true).await {
        tracing::warn!(node_id = req.node_id, err = %e, "add_learner failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
    }

    let mut add_voter = BTreeSet::new();
    add_voter.insert(req.node_id);
    let previous_membership_log = committed_membership_log_index(&raft);
    if let Err(e) = raft
        .change_membership(ChangeMembers::AddVoterIds(add_voter), false)
        .await
    {
        if is_stale_config_change(&e.to_string()) {
            tracing::warn!(
                node_id = req.node_id,
                err = %e,
                "stale pending config change detected, returning conflict"
            );
            return (
                StatusCode::CONFLICT,
                Json(JoinResponse {
                    result: JoinResult::NotLeader,
                    leader_addr: None,
                }),
            )
                .into_response();
        }
        tracing::warn!(node_id = req.node_id, err = %e, "change_membership failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
    }

    if !wait_for_committed_membership_log_advance(&raft, previous_membership_log).await {
        tracing::warn!(
            node_id = req.node_id,
            previous_membership_log,
            "timed out waiting for join membership change to commit"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "timed out waiting for membership change to commit",
        )
            .into_response();
    }
    settle_after_membership_change().await;

    tracing::info!(node_id = req.node_id, addr = %req.addr, "node joined cluster");
    Json(JoinResponse {
        result: JoinResult::Ok,
        leader_addr: None,
    })
    .into_response()
}

pub async fn handle_leave(
    State(raft): State<Arc<RaftInstance>>,
    Json(req): Json<LeaveRequest>,
) -> Response {
    if let Some(response) = precheck_leave(&raft, req.node_id) {
        return response;
    }

    let _guard = acquire_membership_change_lock().await;
    if let Some(response) = precheck_leave(&raft, req.node_id) {
        return response;
    }

    let previous_membership_log = committed_membership_log_index(&raft);
    let remaining_voters: BTreeSet<u64> = raft
        .metrics()
        .borrow()
        .membership_config
        .voter_ids()
        .filter(|id| *id != req.node_id)
        .collect();
    let change = raft.change_membership(ChangeMembers::ReplaceAllVoters(remaining_voters), false);
    match tokio::time::timeout(std::time::Duration::from_secs(35), change).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            if is_stale_config_change(&e.to_string()) {
                tracing::warn!(
                    node_id = req.node_id,
                    err = %e,
                    "stale pending config change detected during leave, returning conflict"
                );
                return (
                    StatusCode::CONFLICT,
                    Json(LeaveResponse {
                        result: LeaveResult::NotLeader,
                        leader_addr: None,
                    }),
                )
                    .into_response();
            }
            tracing::warn!(node_id = req.node_id, err = %e, "remove voter failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
        }
        Err(_) => {
            tracing::warn!(
                node_id = req.node_id,
                "timed out waiting for leave membership change"
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "timed out waiting for membership change",
            )
                .into_response();
        }
    }

    if !wait_for_committed_membership_log_advance(&raft, previous_membership_log).await {
        tracing::warn!(
            node_id = req.node_id,
            previous_membership_log,
            "timed out waiting for leave membership change to commit"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "timed out waiting for membership change to commit",
        )
            .into_response();
    }
    settle_after_membership_change().await;

    tracing::info!(node_id = req.node_id, "node left cluster");
    Json(LeaveResponse {
        result: LeaveResult::Ok,
        leader_addr: None,
    })
    .into_response()
}

fn precheck_join(raft: &RaftInstance, node_id: u64) -> Option<Response> {
    let metrics = raft.metrics().borrow().clone();

    if metrics.current_leader != Some(metrics.id) {
        let leader_addr = metrics.current_leader.and_then(|lid| {
            metrics
                .membership_config
                .nodes()
                .find(|(id, _)| **id == lid)
                .map(|(_, n)| n.addr.clone())
        });
        return Some(
            (
                StatusCode::TEMPORARY_REDIRECT,
                Json(JoinResponse {
                    result: JoinResult::NotLeader,
                    leader_addr,
                }),
            )
                .into_response(),
        );
    }

    let voter_ids: BTreeSet<u64> = metrics.membership_config.voter_ids().collect();
    if voter_ids.contains(&node_id) {
        return Some(
            Json(JoinResponse {
                result: JoinResult::AlreadyMember,
                leader_addr: None,
            })
            .into_response(),
        );
    }

    None
}

fn precheck_leave(raft: &RaftInstance, node_id: u64) -> Option<Response> {
    let metrics = raft.metrics().borrow().clone();

    if metrics.current_leader != Some(metrics.id) {
        let leader_addr = metrics.current_leader.and_then(|lid| {
            metrics
                .membership_config
                .nodes()
                .find(|(id, _)| **id == lid)
                .map(|(_, n)| n.addr.clone())
        });
        return Some(
            (
                StatusCode::TEMPORARY_REDIRECT,
                Json(LeaveResponse {
                    result: LeaveResult::NotLeader,
                    leader_addr,
                }),
            )
                .into_response(),
        );
    }

    let voter_ids: BTreeSet<u64> = metrics.membership_config.voter_ids().collect();
    if !voter_ids.contains(&node_id) {
        return Some(
            Json(LeaveResponse {
                result: LeaveResult::NotMember,
                leader_addr: None,
            })
            .into_response(),
        );
    }

    if voter_ids.len() <= 1 {
        return Some(
            Json(LeaveResponse {
                result: LeaveResult::LastVoter,
                leader_addr: None,
            })
            .into_response(),
        );
    }

    None
}

// ── Client helpers ──

fn raft_scheme(tls: Option<&RaftTlsConfig>) -> &'static str {
    if tls.is_some() { "https" } else { "http" }
}

pub async fn get_status(
    addr: &str,
    tls: Option<&RaftTlsConfig>,
) -> Result<ClusterStatus, MembershipError> {
    let scheme = raft_scheme(tls);
    let url = format!("{}://{}/raft/status", scheme, addr);
    let client = network::build_rpc_client_with_timeout(tls, std::time::Duration::from_secs(5))
        .map_err(MembershipError::Http)?;

    let resp = client
        .get(&url)
        .map_err(|e| MembershipError::Http(e.to_string()))?
        .send()
        .await
        .map_err(|e| MembershipError::Http(e.to_string()))?
        .error_for_status()
        .map_err(|e| MembershipError::Http(e.to_string()))?;

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| MembershipError::Http(e.to_string()))?;
    let status: ClusterStatus = serde_json::from_slice(&bytes)?;
    Ok(status)
}

pub async fn request_join(
    addr: &str,
    tls: Option<&RaftTlsConfig>,
    req: &JoinRequest,
) -> Result<JoinResponse, MembershipError> {
    let scheme = raft_scheme(tls);
    let url = format!("{}://{}/raft/join", scheme, addr);
    let body = serde_json::to_vec(req)?;
    let client = network::build_rpc_client_with_timeout(tls, std::time::Duration::from_secs(35))
        .map_err(MembershipError::Http)?;

    let resp = client
        .post(&url)
        .map_err(|e| MembershipError::Http(e.to_string()))?
        .header_str("content-type", "application/json")
        .map_err(|e| MembershipError::Http(e.to_string()))?
        .body(bytes::Bytes::from(body))
        .send()
        .await
        .map_err(|e| MembershipError::Http(e.to_string()))?
        .error_for_status()
        .map_err(|e| MembershipError::Http(e.to_string()))?;

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| MembershipError::Http(e.to_string()))?;
    let join_resp: JoinResponse = serde_json::from_slice(&bytes)?;
    Ok(join_resp)
}

pub async fn request_leave(
    addr: &str,
    tls: Option<&RaftTlsConfig>,
    req: &LeaveRequest,
) -> Result<LeaveResponse, MembershipError> {
    let scheme = raft_scheme(tls);
    let url = format!("{}://{}/raft/leave", scheme, addr);
    let body = serde_json::to_vec(req)?;
    let client = network::build_rpc_client_with_timeout(tls, std::time::Duration::from_secs(35))
        .map_err(MembershipError::Http)?;

    let resp = client
        .post(&url)
        .map_err(|e| MembershipError::Http(e.to_string()))?
        .header_str("content-type", "application/json")
        .map_err(|e| MembershipError::Http(e.to_string()))?
        .body(bytes::Bytes::from(body))
        .send()
        .await
        .map_err(|e| MembershipError::Http(e.to_string()))?
        .error_for_status()
        .map_err(|e| MembershipError::Http(e.to_string()))?;

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| MembershipError::Http(e.to_string()))?;
    let leave_resp: LeaveResponse = serde_json::from_slice(&bytes)?;
    Ok(leave_resp)
}

// ── DNS Discovery ──

pub async fn discover_peers(dns_name: &str, port: u16) -> Vec<String> {
    discover_peer_targets(dns_name, port, false).await
}

async fn discover_peer_targets(dns_name: &str, port: u16, preserve_dns_name: bool) -> Vec<String> {
    let lookup = format!("{}:{}", dns_name, port);
    match tokio::net::lookup_host(lookup.as_str()).await {
        Ok(addrs) => {
            let addrs = addrs.map(|a| a.to_string()).collect::<Vec<_>>();
            if preserve_dns_name && !addrs.is_empty() {
                vec![lookup.clone()]
            } else {
                addrs
            }
        }
        Err(e) => {
            tracing::debug!(dns = %dns_name, err = %e, "DNS discovery found no peers");
            Vec::new()
        }
    }
}

fn restored_membership_peer_targets<I>(nodes: I, self_node_id: u64) -> Vec<String>
where
    I: IntoIterator<Item = (u64, String)>,
{
    nodes
        .into_iter()
        .filter(|(id, addr)| *id != self_node_id && !addr.trim().is_empty())
        .map(|(_, addr)| addr)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn select_verification_peer_targets(
    restored_peers: Vec<String>,
    discovered_peers: Vec<String>,
) -> Vec<String> {
    if restored_peers.is_empty() {
        discovered_peers
    } else {
        restored_peers
    }
}

fn restored_peer_targets_from_raft(raft: &RaftInstance, self_node_id: u64) -> Vec<String> {
    let metrics = raft.metrics().borrow().clone();
    restored_membership_peer_targets(
        metrics
            .membership_config
            .nodes()
            .map(|(id, node)| (*id, node.addr.clone())),
        self_node_id,
    )
}

// ── Join loop ──

pub async fn join_cluster(
    raft: Arc<RaftInstance>,
    node_id: u64,
    advertise_addr: String,
    discovery_dns: String,
    listen_port: u16,
    tls: Option<Arc<RaftTlsConfig>>,
) {
    let seed_peers = if node_id == 1 {
        Vec::new()
    } else {
        ordinal_zero_peer_target(&advertise_addr)
            .into_iter()
            .collect()
    };

    join_cluster_with_seed_peers(
        raft,
        node_id,
        advertise_addr,
        discovery_dns,
        listen_port,
        tls,
        seed_peers,
    )
    .await;
}

pub(crate) async fn replace_voters(
    raft: &Arc<RaftInstance>,
    new_voters: BTreeSet<u64>,
    reason: &'static str,
) -> Result<(), String> {
    if new_voters.is_empty() {
        return Err("replacement voter set must not be empty".to_string());
    }

    let _guard = acquire_membership_change_lock().await;
    let current_voters: BTreeSet<u64> = raft
        .metrics()
        .borrow()
        .membership_config
        .voter_ids()
        .collect();
    if current_voters == new_voters {
        return Ok(());
    }

    let previous_membership_log = committed_membership_log_index(raft);
    let change = raft.change_membership(ChangeMembers::ReplaceAllVoters(new_voters.clone()), false);
    match tokio::time::timeout(std::time::Duration::from_secs(35), change).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("timed out waiting for replace-voters membership change".to_string()),
    }

    if !wait_for_committed_membership_log_advance(raft, previous_membership_log).await {
        return Err("timed out waiting for replace-voters membership change to commit".to_string());
    }
    settle_after_membership_change().await;

    tracing::info!(
        ?current_voters,
        ?new_voters,
        reason = %reason,
        "replaced Raft voters"
    );
    Ok(())
}

async fn join_cluster_with_seed_peers(
    raft: Arc<RaftInstance>,
    node_id: u64,
    advertise_addr: String,
    discovery_dns: String,
    listen_port: u16,
    tls: Option<Arc<RaftTlsConfig>>,
    seed_peers: Vec<String>,
) {
    let req = JoinRequest {
        node_id,
        addr: advertise_addr.clone(),
    };

    let mut delay_ms: u64 = 500;
    let max_delay_ms: u64 = 10_000;

    loop {
        let peers = if tls.is_some() {
            discover_peer_targets(&discovery_dns, listen_port, true).await
        } else {
            discover_peers(&discovery_dns, listen_port).await
        };
        let peers = merge_seed_and_discovered_peers(&seed_peers, peers);

        for peer in &peers {
            let status = match get_status(peer, tls.as_deref()).await {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Skip if we're talking to ourselves
            if status.node_id == node_id {
                continue;
            }

            let Some(target) = join_target_for_status(peer, &status) else {
                continue;
            };

            match request_join(target, tls.as_deref(), &req).await {
                Ok(resp)
                    if resp.result == JoinResult::Ok
                        || resp.result == JoinResult::AlreadyMember =>
                {
                    // Verify we're actually a voter — the join may have
                    // succeeded on the leader but not yet replicated.
                    if local_join_is_confirmed(&raft, node_id, target, tls.as_deref()).await {
                        tracing::info!(node_id, "successfully joined cluster");
                        return;
                    }
                    let m = raft.metrics().borrow().clone();
                    tracing::warn!(
                        node_id,
                        leader_id = ?m.current_leader,
                        local_membership_log = ?m.membership_config.log_id().map(|log_id| log_id.index),
                        "join returned ok but local Raft view has not caught up, retrying"
                    );
                }
                Ok(resp) if resp.result == JoinResult::NotLeader => {
                    if let Some(ref real_leader) = resp.leader_addr
                        && let Ok(r) = request_join(real_leader, tls.as_deref(), &req).await
                        && matches!(r.result, JoinResult::Ok | JoinResult::AlreadyMember)
                    {
                        if local_join_is_confirmed(&raft, node_id, real_leader, tls.as_deref())
                            .await
                        {
                            tracing::info!(node_id, "successfully joined cluster");
                            return;
                        }
                        let m = raft.metrics().borrow().clone();
                        tracing::warn!(
                            node_id,
                            leader_id = ?m.current_leader,
                            local_membership_log = ?m.membership_config.log_id().map(|log_id| log_id.index),
                            "leader accepted join but local Raft view has not caught up, retrying"
                        );
                    }
                }
                _ => {}
            }
        }

        if node_id == 1 {
            // Check if we're already initialized (from a previous bootstrap or S3 restore)
            let metrics = raft.metrics().borrow().clone();
            if metrics.current_leader.is_some() {
                tracing::info!("already part of a cluster");
                return;
            }
            let mut members = BTreeMap::new();
            members.insert(
                node_id,
                BasicNode {
                    addr: advertise_addr.clone(),
                },
            );
            if raft.initialize(members).await.is_ok() {
                tracing::info!("ordinal-0: self-bootstrapped as single-node cluster");
                return;
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        delay_ms = (delay_ms * 2).min(max_delay_ms);
    }
}

fn merge_seed_and_discovered_peers(
    seed_peers: &[String],
    discovered_peers: Vec<String>,
) -> Vec<String> {
    let mut seen = BTreeSet::new();
    seed_peers
        .iter()
        .cloned()
        .chain(discovered_peers)
        .filter(|peer| seen.insert(peer.clone()))
        .collect()
}

fn join_target_for_status<'a>(peer: &'a str, status: &'a ClusterStatus) -> Option<&'a str> {
    if status.state == NodeState::Leader {
        Some(peer)
    } else {
        status.leader_addr.as_deref()
    }
}

fn ordinal_zero_peer_target(advertise_addr: &str) -> Option<String> {
    let (host, port) = advertise_addr.rsplit_once(':')?;
    let (pod_name, suffix) = host.split_once('.')?;
    let (prefix, ordinal) = pod_name.rsplit_once('-')?;
    ordinal.parse::<u64>().ok()?;
    Some(format!("{prefix}-0.{suffix}:{port}"))
}

fn local_membership_confirms_join(
    current_leader: Option<u64>,
    voter_ids: impl IntoIterator<Item = u64>,
    local_membership_log_id: Option<u64>,
    leader_membership_log_id: Option<u64>,
    leader_has_node: bool,
    node_id: u64,
) -> bool {
    current_leader.is_some()
        && leader_has_node
        && voter_ids.into_iter().any(|id| id == node_id)
        && local_membership_log_id.unwrap_or(0) >= leader_membership_log_id.unwrap_or(0)
}

async fn local_join_is_confirmed(
    raft: &RaftInstance,
    node_id: u64,
    leader_addr: &str,
    tls: Option<&RaftTlsConfig>,
) -> bool {
    let Ok(leader_status) = get_status(leader_addr, tls).await else {
        return false;
    };
    let metrics = raft.metrics().borrow().clone();
    local_membership_confirms_join(
        metrics.current_leader,
        metrics.membership_config.voter_ids(),
        metrics
            .membership_config
            .log_id()
            .map(|log_id| log_id.index),
        leader_status.last_membership_log_id,
        leader_status.voters.iter().any(|v| v.id == node_id),
        node_id,
    )
}

/// After restoring from S3 snapshot, verify we're still in the cluster membership.
/// If we were removed while offline, re-join.
///
/// Queries the restored membership's peer-specific advertise addresses
/// concurrently and requires a strict majority of authoritative peers to confirm
/// membership. This prevents a stale peer from falsely confirming membership and
/// causing permanent split-brain.
const AUTHORITATIVE_LOG_TOLERANCE: u64 = 10;

pub async fn verify_or_rejoin(
    raft: Arc<RaftInstance>,
    node_id: u64,
    advertise_addr: String,
    discovery_dns: String,
    listen_port: u16,
    tls: Option<Arc<RaftTlsConfig>>,
) {
    // Give the Raft instance a moment to process restored state
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let restored_peers = restored_peer_targets_from_raft(&raft, node_id);
    let discovered_peers = if restored_peers.is_empty() {
        if tls.is_some() {
            discover_peer_targets(&discovery_dns, listen_port, true).await
        } else {
            discover_peers(&discovery_dns, listen_port).await
        }
    } else {
        Vec::new()
    };
    let peers = select_verification_peer_targets(restored_peers, discovered_peers);

    // Collect status from all peers concurrently with 2s timeout each
    let mut handles = Vec::new();
    for peer in &peers {
        let peer = peer.clone();
        let tls = tls.clone();
        handles.push(tokio::spawn(async move {
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                get_status(&peer, tls.as_deref()),
            )
            .await
            .ok()
            .and_then(|r| r.ok())
        }));
    }
    let mut peer_statuses: Vec<ClusterStatus> = Vec::new();
    for handle in handles {
        if let Ok(Some(status)) = handle.await
            && status.node_id != node_id
        {
            peer_statuses.push(status);
        }
    }

    // No peers reachable — might be first to restart after total cluster loss
    if peer_statuses.is_empty() {
        if node_id == 1 {
            let mut members = BTreeMap::new();
            members.insert(
                node_id,
                BasicNode {
                    addr: advertise_addr,
                },
            );
            if raft.initialize(members).await.is_ok() {
                tracing::info!("re-bootstrapped cluster from restored snapshot");
            }
        } else {
            tracing::warn!("no peers reachable for membership verification");
        }
        return;
    }

    // Find the highest last_applied_log among peers to determine the authoritative view
    let max_applied = peer_statuses
        .iter()
        .filter_map(|s| s.last_applied_log)
        .max()
        .unwrap_or(0);

    // Only consider peers close to the most up-to-date state authoritative
    let authoritative: Vec<&ClusterStatus> = peer_statuses
        .iter()
        .filter(|s| {
            s.last_applied_log.unwrap_or(0)
                >= max_applied.saturating_sub(AUTHORITATIVE_LOG_TOLERANCE)
        })
        .collect();

    let total_auth = authoritative.len();
    if total_auth == 0 {
        tracing::info!("no authoritative peers found, re-joining cluster");
        join_cluster_with_seed_peers(
            raft,
            node_id,
            advertise_addr,
            discovery_dns,
            listen_port,
            tls,
            peers,
        )
        .await;
        return;
    }

    // Count how many authoritative peers include us as a voter. A restored node
    // can appear as a learner after re-adding itself; that still needs the join
    // path to promote it back to voter in this deployment model.
    let in_membership = authoritative
        .iter()
        .filter(|s| s.voters.iter().any(|v| v.id == node_id))
        .count();

    // Strict majority: must exceed half. Integer division means:
    //   1 peer:  1 > 0 → confirmed
    //   2 peers: 2 > 1 → confirmed, but 1 > 1 is false → re-join
    //   3 peers: 2 > 1 → confirmed, 3 > 1 → confirmed
    if in_membership > total_auth / 2 {
        tracing::info!(
            in_membership,
            total_auth,
            max_applied,
            "quorum of authoritative peers confirms cluster membership"
        );
        return;
    }

    tracing::info!(
        in_membership,
        total_auth,
        max_applied,
        "membership not confirmed by quorum, re-joining cluster"
    );
    join_cluster_with_seed_peers(
        raft,
        node_id,
        advertise_addr,
        discovery_dns,
        listen_port,
        tls,
        peers,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restored_peer_targets_exclude_self_and_deduplicate() {
        let peers = restored_membership_peer_targets(
            vec![
                (
                    1,
                    "layerhouse-0.layerhouse-headless.ns.svc.cluster.local:5051".to_string(),
                ),
                (
                    2,
                    "layerhouse-1.layerhouse-headless.ns.svc.cluster.local:5051".to_string(),
                ),
                (
                    3,
                    "layerhouse-2.layerhouse-headless.ns.svc.cluster.local:5051".to_string(),
                ),
                (
                    4,
                    "layerhouse-2.layerhouse-headless.ns.svc.cluster.local:5051".to_string(),
                ),
                (5, "   ".to_string()),
            ],
            1,
        );

        assert_eq!(
            peers,
            vec![
                "layerhouse-1.layerhouse-headless.ns.svc.cluster.local:5051".to_string(),
                "layerhouse-2.layerhouse-headless.ns.svc.cluster.local:5051".to_string(),
            ]
        );
    }

    #[test]
    fn verification_targets_prefer_restored_membership_peers() {
        let restored = vec![
            "layerhouse-1.layerhouse-headless.ns.svc.cluster.local:5051".to_string(),
            "layerhouse-2.layerhouse-headless.ns.svc.cluster.local:5051".to_string(),
        ];
        let discovered = vec!["layerhouse-headless:5051".to_string()];

        assert_eq!(
            select_verification_peer_targets(restored.clone(), discovered),
            restored
        );
    }

    #[test]
    fn verification_targets_fall_back_to_discovery_when_membership_empty() {
        let discovered = vec!["layerhouse-headless:5051".to_string()];

        assert_eq!(
            select_verification_peer_targets(Vec::new(), discovered.clone()),
            discovered
        );
    }

    #[test]
    fn join_peer_targets_try_restored_peers_before_discovery() {
        assert_eq!(
            merge_seed_and_discovered_peers(
                &[
                    "layerhouse-0.layerhouse-headless.ns.svc.cluster.local:5051".to_string(),
                    "layerhouse-1.layerhouse-headless.ns.svc.cluster.local:5051".to_string(),
                ],
                vec![
                    "layerhouse-1.layerhouse-headless.ns.svc.cluster.local:5051".to_string(),
                    "layerhouse-headless:5051".to_string(),
                ],
            ),
            vec![
                "layerhouse-0.layerhouse-headless.ns.svc.cluster.local:5051".to_string(),
                "layerhouse-1.layerhouse-headless.ns.svc.cluster.local:5051".to_string(),
                "layerhouse-headless:5051".to_string(),
            ]
        );
    }

    #[test]
    fn join_target_uses_reachable_peer_when_peer_is_leader() {
        let status = ClusterStatus {
            node_id: 1,
            state: NodeState::Leader,
            leader_id: Some(1),
            leader_addr: Some("layerhouse-0.layerhouse-headless.ns.svc.cluster.local:5051".into()),
            voters: Vec::new(),
            learners: Vec::new(),
            term: 1,
            last_log_index: Some(1),
            last_applied_log: Some(1),
            last_membership_log_id: Some(1),
            millis_since_quorum_ack: None,
            replication: BTreeMap::new(),
        };

        assert_eq!(
            join_target_for_status("layerhouse-0.layerhouse-headless.ns.svc:5051", &status),
            Some("layerhouse-0.layerhouse-headless.ns.svc:5051")
        );
    }

    #[test]
    fn join_target_follows_advertised_leader_when_peer_is_follower() {
        let status = ClusterStatus {
            node_id: 2,
            state: NodeState::Follower,
            leader_id: Some(1),
            leader_addr: Some("layerhouse-0.layerhouse-headless.ns.svc:5051".into()),
            voters: Vec::new(),
            learners: Vec::new(),
            term: 1,
            last_log_index: Some(1),
            last_applied_log: Some(1),
            last_membership_log_id: Some(1),
            millis_since_quorum_ack: None,
            replication: BTreeMap::new(),
        };

        assert_eq!(
            join_target_for_status("layerhouse-1.layerhouse-headless.ns.svc:5051", &status),
            Some("layerhouse-0.layerhouse-headless.ns.svc:5051")
        );
    }

    #[test]
    fn restored_stale_voter_without_leader_does_not_confirm_join() {
        assert!(!local_membership_confirms_join(
            None,
            [2],
            Some(7),
            Some(22),
            true,
            2
        ));
        assert!(!local_membership_confirms_join(
            Some(1),
            [1, 2],
            Some(7),
            Some(22),
            true,
            2
        ));
        assert!(local_membership_confirms_join(
            Some(1),
            [1, 2],
            Some(22),
            Some(22),
            true,
            2
        ));
    }

    #[test]
    fn fresh_join_derives_ordinal_zero_seed_from_advertise_addr() {
        assert_eq!(
            ordinal_zero_peer_target("layerhouse-2.layerhouse-headless.ns.svc.cluster.local:5051"),
            Some("layerhouse-0.layerhouse-headless.ns.svc.cluster.local:5051".to_string())
        );
    }

    #[test]
    fn fresh_join_seed_ignores_unparseable_advertise_addr() {
        assert_eq!(ordinal_zero_peer_target("layerhouse-headless:5051"), None);
        assert_eq!(
            ordinal_zero_peer_target("layerhouse-a.layerhouse-headless:5051"),
            None
        );
    }
}
