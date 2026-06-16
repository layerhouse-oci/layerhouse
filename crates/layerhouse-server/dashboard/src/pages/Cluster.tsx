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

  if (errorCount() >= 3) {
    return (
      <div class="cluster-page">
        <ErrorBanner message={error() ?? t("common.unknown")} onRetry={load} fullPage />
      </div>
    );
  }

  return (
    <div class="cluster-page">
      <section class="hero glass">
        <div>
          <p class="eyebrow">
            <span class="status-dot" aria-hidden="true" />
            {t("cluster.eyebrow")}
          </p>
          <h1>{t("cluster.title")}</h1>
          <p class="hero-copy">{t("cluster.heroCopy")}</p>
        </div>
      </section>

      {error() && <ErrorBanner message={error()!} onRetry={load} />}

      <Show when={!loading()} fallback={<LoadingSpinner label={t("cluster.loading")} />}>
        <Show
          when={status()}
          fallback={
            <EmptyState
              title={t("cluster.unavailable")}
              description={t("cluster.unavailableDesc")}
            />
          }
        >
          <section class="panel glass">
            <div class="panel-head">
              <div>
                <p class="section-label">{t("cluster.votingMembers")}</p>
                <h2>{t("cluster.voters")}</h2>
              </div>
              <Show when={session()?.is_admin}>
                <button class="button" onClick={() => setShowJoin(true)}>
                  {t("cluster.joinNode")}
                </button>
              </Show>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{t("cluster.nodeId")}</th>
                    <th>{t("cluster.address")}</th>
                    <th>{t("cluster.role")}</th>
                    <th>{t("common.status")}</th>
                    <th>{t("common.actions")}</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={status()!.voters}>
                    {(node) => {
                      const isLeader = () => node.role === "leader";
                      const nodeActionId = () => `cluster-action-${node.node_id}`;
                      const isConfirming = () => confirmNode()?.node_id === node.node_id;
                      return (
                        <tr classList={{ "leader-row": isLeader() }}>
                          <td class="node-id">{node.node_id}</td>
                          <td class="address">{node.address}</td>
                          <td>
                            <span classList={{ "role-badge": true, leader: isLeader() }}>
                              {isLeader() ? "Leader" : "Voter"}
                            </span>
                          </td>
                          <td>
                            <span
                              classList={{
                                state: true,
                                catchup: node.status !== "healthy",
                              }}
                            >
                              {node.status}
                            </span>
                          </td>
                          <td>
                            <Show when={session()?.is_admin}>
                              <div class="confirm-actions">
                                <input
                                  class="membership-confirm"
                                  type="checkbox"
                                  id={nodeActionId()}
                                  checked={isConfirming()}
                                  onChange={(e) =>
                                    setConfirmNode(e.currentTarget.checked ? node : null)
                                  }
                                />
                                <label class="action danger" for={nodeActionId()}>
                                  {isLeader() ? t("common.leave") : t("common.unlink")}
                                </label>
                                <span class="confirm-preview">
                                  <span class="warning-copy">
                                    {isLeader()
                                      ? t("cluster.leaveWarning")
                                      : t("cluster.removeWarning", {
                                          id: node.node_id,
                                          address: node.address,
                                        })}
                                  </span>
                                  <label class="action" for={nodeActionId()}>
                                    {t("common.cancel")}
                                  </label>
                                  <button
                                    class="action confirm"
                                    disabled={busy()}
                                    onClick={handleRemove}
                                  >
                                    {isLeader()
                                      ? t("cluster.confirmLeave")
                                      : t("cluster.confirmRemove")}
                                  </button>
                                </span>
                              </div>
                            </Show>
                          </td>
                        </tr>
                      );
                    }}
                  </For>
                </tbody>
              </table>
            </div>
            <div class="count-footer">
              <span class="count">
                {t("cluster.memberCount", {
                  count: status()!.voters.length,
                })}
              </span>
            </div>
          </section>

          <section class="panel glass">
            <div class="panel-head">
              <div>
                <p class="section-label">{t("cluster.catchUpMembers")}</p>
                <h2>{t("cluster.learners")}</h2>
              </div>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{t("cluster.nodeId")}</th>
                    <th>{t("cluster.address")}</th>
                    <th>{t("cluster.role")}</th>
                    <th>{t("common.status")}</th>
                    <th>{t("common.actions")}</th>
                  </tr>
                </thead>
                <tbody>
                  <Show
                    when={status()!.learners.length > 0}
                    fallback={
                      <tr class="empty">
                        <td colspan="5">
                          <strong>{t("cluster.noLearners")}</strong>
                          {t("cluster.noLearnersDesc")}
                        </td>
                      </tr>
                    }
                  >
                    <For each={status()!.learners}>
                      {(node) => {
                        const nodeActionId = () => `cluster-action-${node.node_id}`;
                        const isConfirming = () => confirmNode()?.node_id === node.node_id;
                        return (
                          <tr>
                            <td class="node-id">{node.node_id}</td>
                            <td class="address">{node.address}</td>
                            <td>
                              <span class="role-badge">Learner</span>
                            </td>
                            <td>
                              <span
                                classList={{
                                  state: true,
                                  catchup: node.status !== "healthy",
                                }}
                              >
                                {node.status}
                              </span>
                            </td>
                            <td>
                              <Show when={session()?.is_admin}>
                                <div class="confirm-actions">
                                  <input
                                    class="membership-confirm"
                                    type="checkbox"
                                    id={nodeActionId()}
                                    checked={isConfirming()}
                                    onChange={(e) =>
                                      setConfirmNode(e.currentTarget.checked ? node : null)
                                    }
                                  />
                                  <label class="action danger" for={nodeActionId()}>
                                    {t("common.unlink")}
                                  </label>
                                  <span class="confirm-preview">
                                    <span class="warning-copy">
                                      {t("cluster.removeWarning", {
                                        id: node.node_id,
                                        address: node.address,
                                      })}
                                    </span>
                                    <label class="action" for={nodeActionId()}>
                                      {t("common.cancel")}
                                    </label>
                                    <button
                                      class="action confirm"
                                      disabled={busy()}
                                      onClick={handleRemove}
                                    >
                                      {t("cluster.confirmRemove")}
                                    </button>
                                  </span>
                                </div>
                              </Show>
                            </td>
                          </tr>
                        );
                      }}
                    </For>
                  </Show>
                </tbody>
              </table>
            </div>
            <div class="count-footer">
              <span class="count">
                {t("cluster.learnerCount", {
                  count: status()!.learners.length,
                })}
              </span>
            </div>
          </section>

          <footer class="footer">
            <span>
              <strong>{t("common.updated")}:</strong> {formatAgo(status()!.updated_at)}
            </span>
            <span>{t("app.brandName")} Container Registry</span>
          </footer>
        </Show>
      </Show>

      <Show when={showJoin()}>
        <div class="modal-backdrop visible" onClick={() => setShowJoin(false)}>
          <div
            class="modal glass"
            role="dialog"
            aria-modal="true"
            onClick={(e) => e.stopPropagation()}
          >
            <div class="modal-head">
              <div>
                <p class="section-label">{t("cluster.eyebrow")}</p>
                <h2 class="modal-title">{t("cluster.joinTitle")}</h2>
              </div>
              <button class="close" aria-label="Close modal" onClick={() => setShowJoin(false)}>
                x
              </button>
            </div>
            <div class="form">
              <div class="field">
                <label for="join-node-id">{t("cluster.nodeId")}</label>
                <input
                  id="join-node-id"
                  type="number"
                  value={joinForm().node_id || ""}
                  onInput={(e) =>
                    setJoinForm({
                      ...joinForm(),
                      node_id: Number(e.currentTarget.value) || 0,
                    })
                  }
                />
              </div>
              <div class="field">
                <label for="join-node-addr">{t("cluster.address")}</label>
                <input
                  id="join-node-addr"
                  value={joinForm().addr}
                  placeholder="host:port"
                  onInput={(e) => setJoinForm({ ...joinForm(), addr: e.currentTarget.value })}
                />
              </div>
              <div class="modal-actions">
                <button
                  class="button secondary"
                  disabled={busy()}
                  onClick={() => setShowJoin(false)}
                >
                  {t("common.cancel")}
                </button>
                <button class="button" disabled={busy()} onClick={handleJoin}>
                  {busy() ? t("cluster.joining") : t("cluster.join")}
                </button>
              </div>
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
}
