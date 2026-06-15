import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import { ApiError, fetchClusterStatus, fetchSession, joinCluster, leaveCluster } from "../lib/api";
import type { ClusterMember, DashboardClusterStatus, DashboardSession } from "../lib/types";
import { formatAgo } from "../lib/format";
import { t } from "../lib/i18n";
import LoadingSpinner from "../components/LoadingSpinner";
import EmptyState from "../components/EmptyState";
import ErrorBanner from "../components/ErrorBanner";

export default function Cluster() {
  const [status, setStatus] = createSignal<DashboardClusterStatus | null>(null);
  const [session, setSession] = createSignal<DashboardSession | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [errorCount, setErrorCount] = createSignal(0);
  const [showJoin, setShowJoin] = createSignal(false);
  const [joinForm, setJoinForm] = createSignal({ node_id: 0, addr: "" });
  const [confirmNode, setConfirmNode] = createSignal<ClusterMember | null>(null);
  const [busy, setBusy] = createSignal(false);

  async function load() {
    try {
      const [s, clusterStatus] = await Promise.all([fetchSession(), fetchClusterStatus()]);
      setSession(s);
      setStatus(clusterStatus);
      setError(null);
      setErrorCount(0);
    } catch (e) {
      setError(e instanceof Error ? e.message : t("cluster.fetchError"));
      setErrorCount((c) => c + 1);
    } finally {
      setLoading(false);
    }
  }

  createEffect(() => {
    load();
    const id = setInterval(load, 10_000);
    onCleanup(() => clearInterval(id));
  });

  async function handleJoin() {
    setBusy(true);
    try {
      await joinCluster(joinForm().node_id, joinForm().addr);
      setShowJoin(false);
      setJoinForm({ node_id: 0, addr: "" });
      await load();
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        setError(t("cluster.adminRequired"));
      } else {
        setError(e instanceof Error ? e.message : t("cluster.joinError"));
      }
    } finally {
      setBusy(false);
    }
  }

  async function handleRemove() {
    const node = confirmNode();
    if (!node) return;
    setBusy(true);
    try {
      await leaveCluster(node.node_id);
      await load();
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        setError(t("cluster.adminRequired"));
      } else {
        setError(e instanceof Error ? e.message : t("cluster.removeError"));
      }
    } finally {
      setConfirmNode(null);
      setBusy(false);
    }
  }

  function memberRows() {
    const s = status();
    return s ? [...s.voters, ...s.learners] : [];
  }

  if (errorCount() >= 3) {
    return <ErrorBanner message={error() ?? t("common.unknown")} onRetry={load} fullPage />;
  }

  return (
    <div>
      <div class="page-header">
        <div>
          <p class="eyebrow">{t("cluster.eyebrow")}</p>
          <h1>{t("cluster.title")}</h1>
        </div>
        <Show when={session()?.is_admin}>
          <button class="btn btn-primary" onClick={() => setShowJoin(true)}>
            {t("cluster.joinNode")}
          </button>
        </Show>
      </div>

      {error() && <ErrorBanner message={error()!} onRetry={load} />}

      {loading() ? (
        <LoadingSpinner label={t("cluster.loading")} />
      ) : !status() ? (
        <EmptyState title={t("cluster.unavailable")} description={t("cluster.unavailableDesc")} />
      ) : (
        <>
          <div class="stats">
            <div class="stat glass">
              <div class="label">{t("cluster.leader")}</div>
              <div class="value small">{status()!.leader_id ?? "-"}</div>
              <p class="note">
                {t("cluster.term")} {status()!.term}
              </p>
            </div>
            <div class="stat glass">
              <div class="label">{t("cluster.quorum")}</div>
              <div class="value small">{status()!.quorum}</div>
              <p class="note">{t("cluster.healthyVoters", { count: status()!.healthy_voters })}</p>
            </div>
            <div class="stat glass">
              <div class="label">{t("app.nav.cluster")}</div>
              <div class="value small">{status()!.cluster_id}</div>
              <p class="note">
                {t("common.updated")} {formatAgo(status()!.updated_at)}
              </p>
            </div>
            <div class="stat glass">
              <div class="label">{t("cluster.members")}</div>
              <div class="value small">{memberRows().length}</div>
              <p class="note">{t("cluster.learnersCount", { count: status()!.learners.length })}</p>
            </div>
          </div>

          <div class="card">
            <table>
              <thead>
                <tr>
                  <th>{t("cluster.node")}</th>
                  <th>{t("cluster.address")}</th>
                  <th>{t("cluster.role")}</th>
                  <th>{t("common.status")}</th>
                  <th>{t("cluster.commit")}</th>
                  <th>{t("cluster.lag")}</th>
                  <th>{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={memberRows()}>
                  {(node) => (
                    <tr>
                      <td>
                        <code>{node.node_id}</code>
                      </td>
                      <td>{node.address}</td>
                      <td>
                        <span
                          class={`badge ${node.role === "leader" ? "badge-blue" : "badge-gray"}`}
                        >
                          {node.role}
                        </span>
                      </td>
                      <td>
                        <span class="badge badge-success">{node.status}</span>
                      </td>
                      <td>{node.commit_index ?? "-"}</td>
                      <td>
                        {node.replication_lag_ms === null ? "-" : `${node.replication_lag_ms}ms`}
                      </td>
                      <td>
                        <Show when={session()?.is_admin}>
                          <button
                            class="btn btn-compact btn-danger"
                            onClick={() => setConfirmNode(node)}
                          >
                            {node.role === "leader" ? t("common.leave") : t("common.unlink")}
                          </button>
                        </Show>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </>
      )}

      <Show when={showJoin()}>
        <div class="modal-overlay" onClick={() => setShowJoin(false)}>
          <div class="modal" onClick={(e) => e.stopPropagation()}>
            <h2>{t("cluster.joinTitle")}</h2>
            <div class="form-group">
              <label>{t("cluster.nodeId")}</label>
              <input
                type="number"
                value={joinForm().node_id || ""}
                onInput={(e) =>
                  setJoinForm({ ...joinForm(), node_id: Number(e.currentTarget.value) || 0 })
                }
              />
            </div>
            <div class="form-group">
              <label>{t("cluster.address")}</label>
              <input
                value={joinForm().addr}
                placeholder="host:port"
                onInput={(e) => setJoinForm({ ...joinForm(), addr: e.currentTarget.value })}
              />
            </div>
            <div class="modal-actions">
              <button class="btn" disabled={busy()} onClick={() => setShowJoin(false)}>
                {t("common.cancel")}
              </button>
              <button class="btn btn-primary" disabled={busy()} onClick={handleJoin}>
                {busy() ? t("cluster.joining") : t("cluster.join")}
              </button>
            </div>
          </div>
        </div>
      </Show>

      <Show when={confirmNode()}>
        {(node) => (
          <div class="modal-overlay" onClick={() => setConfirmNode(null)}>
            <div class="modal" onClick={(e) => e.stopPropagation()}>
              <h2>
                {node().role === "leader"
                  ? t("cluster.leaveLeaderTitle")
                  : t("cluster.removeNodeTitle", { id: node().node_id })}
              </h2>
              <p class="warning">
                {node().role === "leader"
                  ? t("cluster.leaveWarning")
                  : t("cluster.removeWarning", { id: node().node_id, address: node().address })}
              </p>
              <div class="modal-actions">
                <button class="btn" disabled={busy()} onClick={() => setConfirmNode(null)}>
                  {t("common.cancel")}
                </button>
                <button class="btn btn-danger" disabled={busy()} onClick={handleRemove}>
                  {busy() ? t("common.apply") : t("common.confirm")}
                </button>
              </div>
            </div>
          </div>
        )}
      </Show>
    </div>
  );
}
