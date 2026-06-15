import { createEffect, createSignal, Show } from "solid-js";
import { fetchStatus, joinCluster, leaveCluster } from "../lib/api";
import type { ClusterStatus } from "../lib/types";
import LoadingSpinner from "../components/LoadingSpinner";
import ErrorBanner from "../components/ErrorBanner";

export default function ClusterMembers() {
  const [status, setStatus] = createSignal<ClusterStatus | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [errorCount, setErrorCount] = createSignal(0);
  const [showJoin, setShowJoin] = createSignal(false);
  const [joinForm, setJoinForm] = createSignal({ node_id: 0, addr: "" });
  const [actionError, setActionError] = createSignal<string | null>(null);

  async function load() {
    try {
      setStatus(await fetchStatus());
      setError(null);
      setErrorCount(0);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch cluster status");
      setErrorCount((c) => c + 1);
    } finally {
      setLoading(false);
    }
  }

  createEffect(() => {
    load();
    const id = setInterval(load, 10_000);
    return () => clearInterval(id);
  });

  async function handleJoin() {
    setActionError(null);
    try {
      await joinCluster(joinForm().node_id, joinForm().addr);
      setShowJoin(false);
      setJoinForm({ node_id: 0, addr: "" });
      await load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Failed to join node");
    }
  }

  async function handleLeave(nodeId: number) {
    if (!confirm(`Remove node ${nodeId} from the cluster?`)) return;
    setActionError(null);
    try {
      await leaveCluster(nodeId);
      await load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Failed to remove node");
    }
  }

  if (errorCount() >= 3) {
    return <ErrorBanner message={error() ?? "Unknown error"} onRetry={load} fullPage />;
  }

  return (
    <div>
      <div class="page-header">
        <h1>Cluster Members</h1>
        <button
          class="btn btn-primary"
          onClick={() => {
            setActionError(null);
            setShowJoin(true);
          }}
        >
          Join Node
        </button>
      </div>

      {error() && <ErrorBanner message={error()!} onRetry={load} />}
      {actionError() && <ErrorBanner message={actionError()!} />}

      {loading() ? (
        <LoadingSpinner label="Loading cluster members..." />
      ) : (
        <>
          {status() && (
            <div class="card">
              <div class="card-header">Voters ({status()!.voters.length})</div>
              <table>
                <thead>
                  <tr>
                    <th>Node ID</th>
                    <th>Address</th>
                    <th>Role</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {status()!.voters.map((node) => (
                    <tr>
                      <td>
                        <code>{node.id}</code>
                        {status()!.leader_id === node.id && (
                          <span class="badge badge-success" style="margin-left:0.5rem">
                            Leader
                          </span>
                        )}
                      </td>
                      <td>{node.addr}</td>
                      <td>Voter</td>
                      <td>
                        <button class="btn btn-danger" onClick={() => handleLeave(node.id)}>
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {status() && status()!.learners.length > 0 && (
            <div class="card">
              <div class="card-header">Learners ({status()!.learners.length})</div>
              <table>
                <thead>
                  <tr>
                    <th>Node ID</th>
                    <th>Address</th>
                    <th>Role</th>
                  </tr>
                </thead>
                <tbody>
                  {status()!.learners.map((node) => (
                    <tr>
                      <td>
                        <code>{node.id}</code>
                      </td>
                      <td>{node.addr}</td>
                      <td>Learner</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      <Show when={showJoin()}>
        <div class="modal-overlay" onClick={() => setShowJoin(false)}>
          <div class="modal" onClick={(e) => e.stopPropagation()}>
            <h2>Join Node to Cluster</h2>
            <div class="form-group">
              <label>Node ID</label>
              <input
                type="number"
                value={joinForm().node_id || ""}
                onInput={(e) =>
                  setJoinForm({
                    ...joinForm(),
                    node_id: parseInt(e.currentTarget.value) || 0,
                  })
                }
              />
            </div>
            <div class="form-group">
              <label>Address (host:port)</label>
              <input
                type="text"
                value={joinForm().addr}
                onInput={(e) => setJoinForm({ ...joinForm(), addr: e.currentTarget.value })}
              />
            </div>
            <div class="modal-actions">
              <button class="btn" onClick={() => setShowJoin(false)}>
                Cancel
              </button>
              <button class="btn btn-primary" onClick={handleJoin}>
                Join
              </button>
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
}
