import { createEffect, createSignal, For, onCleanup } from "solid-js";
import { fetchStatus } from "../lib/api";
import type { ClusterStatus } from "../lib/types";
import LoadingSpinner from "../components/LoadingSpinner";
import ErrorBanner from "../components/ErrorBanner";
import { formatAgo } from "../lib/format";
import { t } from "../lib/i18n";

export default function Overview() {
  const [status, setStatus] = createSignal<ClusterStatus | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [errorCount, setErrorCount] = createSignal(0);
  const [lastUpdated, setLastUpdated] = createSignal<number | null>(null);

  async function poll() {
    try {
      const s = await fetchStatus();
      setStatus(s);
      setError(null);
      setErrorCount(0);
      setLastUpdated(Date.now());
    } catch (e) {
      setError(e instanceof Error ? e.message : t("overview.fetchError"));
      setErrorCount((c) => c + 1);
    } finally {
      setLoading(false);
    }
  }

  createEffect(() => {
    poll();
    const id = setInterval(poll, 10_000);
    onCleanup(() => clearInterval(id));
  });

  function healthy(): "green" | "yellow" | "red" {
    const s = status();
    if (!s) return "red";
    if (s.leader_id != null && s.voters.length > 0) return "green";
    if (s.state === "candidate") return "yellow";
    return "red";
  }

  const healthText = () => {
    const h = healthy();
    if (h === "green") return t("overview.health.operational");
    if (h === "yellow") return t("overview.health.degraded");
    return t("overview.health.unhealthy");
  };

  const stateLabel = () => {
    const s = status();
    if (!s) return t("overview.unknown");
    if (s.leader_id != null && s.voters.length > 0) return t("overview.stable");
    if (s.state === "candidate") return t("overview.electing");
    return t("overview.offline");
  };

  const totalNodes = () => (status()?.voters.length ?? 0) + (status()?.learners.length ?? 0);

  const hasQuorum = () => {
    const v = status()?.voters.length ?? 0;
    return v > 0
      ? t("overview.quorumCount", { available: Math.floor(v / 2) + 1, total: v })
      : t("common.none");
  };

  if (errorCount() >= 3) {
    return <ErrorBanner message={error() ?? t("common.unknown")} onRetry={poll} fullPage />;
  }

  return (
    <>
      {error() && <ErrorBanner message={error()!} onRetry={poll} />}

      {loading() ? (
        <LoadingSpinner label={t("overview.loading")} />
      ) : (
        <>
          {/* Hero section */}
          <section class="hero glass">
            <div>
              <p class="eyebrow">
                <span class={`status-dot${healthy() !== "green" ? ` ${healthy()}` : ""}`} />
                {t("overview.eyebrow")}
              </p>
              <h1>{t("overview.title")}</h1>
              <p class="hero-copy">{t("overview.copy")}</p>
            </div>
            <aside class="health-panel">
              <div class="health-title">
                <span class={`pulse${healthy() !== "green" ? ` ${healthy()}` : ""}`} />
                <span>{healthText()}</span>
              </div>
              <div class="health-list">
                <div class="health-row">
                  <span>{t("overview.consensus")}</span>
                  <strong>{stateLabel()}</strong>
                </div>
                <div class="health-row">
                  <span>{t("overview.leader")}</span>
                  <strong>
                    {status()?.leader_id != null ? `node-${status()!.leader_id}` : t("common.none")}
                  </strong>
                </div>
                <div class="health-row">
                  <span>{t("overview.voters")}</span>
                  <strong>{status()?.voters.length ?? 0}</strong>
                </div>
                <div class="health-row">
                  <span>{t("overview.learners")}</span>
                  <strong>{status()?.learners.length ?? 0}</strong>
                </div>
              </div>
            </aside>
          </section>

          {/* Stat cards */}
          <section class="stats">
            <article class="stat glass">
              <div class="stat-top">
                <div class="label">{t("overview.nodes")}</div>
                <div class="icon">01</div>
              </div>
              <div class="value">{totalNodes()}</div>
              <div class="note">{t("overview.nodesNote")}</div>
            </article>
            <article class="stat glass">
              <div class="stat-top">
                <div class="label">{t("overview.leader")}</div>
                <div class="icon">02</div>
              </div>
              <div class="value small">
                {status()?.leader_id != null ? `node-${status()!.leader_id}` : "—"}
              </div>
              <div class="note">
                {status()?.leader_id != null
                  ? t("overview.consensusActive")
                  : t("overview.noLeader")}
              </div>
            </article>
            <article class="stat glass">
              <div class="stat-top">
                <div class="label">{t("overview.voters")}</div>
                <div class="icon">03</div>
              </div>
              <div class="value">{status()?.voters.length ?? 0}</div>
              <div class="note">{t("overview.quorumAvailable", { quorum: hasQuorum() })}</div>
            </article>
            <article class="stat glass">
              <div class="stat-top">
                <div class="label">{t("overview.learners")}</div>
                <div class="icon">04</div>
              </div>
              <div class="value">{status()?.learners.length ?? 0}</div>
              <div class="note">
                {status() && status()!.learners.length === 0
                  ? t("overview.noCatchUp")
                  : t("overview.nodesCatchingUp", { count: status()!.learners.length })}
              </div>
            </article>
          </section>

          {/* Topology */}
          {status() && totalNodes() > 0 && (
            <section class="topology-card glass">
              <div class="section-head">
                <div>
                  <p class="section-label">{t("overview.liveMembership")}</p>
                  <h2>{t("overview.topology")}</h2>
                  <p class="section-copy">
                    {t("overview.topologyCopy", {
                      voters: status()!.voters.length,
                      plural: status()!.voters.length !== 1 ? "s" : "",
                      leader:
                        status()!.leader_id != null
                          ? `. ${t("overview.topologyLeader", {
                              leader: String(status()!.leader_id),
                            })}.`
                          : `. ${t("overview.topologyNoLeader")}.`,
                    })}
                  </p>
                </div>
                <div class="cluster-badge">{t("overview.clusterProd")}</div>
              </div>
              <div class="diagram">
                <For each={status()!.voters}>
                  {(node) => (
                    <article class={`node${status()!.leader_id === node.id ? " leader" : ""}`}>
                      <div class="orb">{String(node.id).padStart(2, "0")}</div>
                      <div class="node-body">
                        <div class="node-name">node-{node.id}</div>
                        <div class="role">
                          {status()!.leader_id === node.id
                            ? t("overview.leader")
                            : t("overview.voters")}
                        </div>
                        <div class="node-meta">
                          <span>{node.addr}</span>
                          <span>
                            {t("overview.commitIndex", {
                              index: status()?.last_applied_log ?? "—",
                            })}
                          </span>
                        </div>
                      </div>
                    </article>
                  )}
                </For>
                <For each={status()!.learners}>
                  {(node) => (
                    <article class="node">
                      <div class="orb">{String(node.id).padStart(2, "0")}</div>
                      <div class="node-body">
                        <div class="node-name">node-{node.id}</div>
                        <div class="role">{t("overview.learners")}</div>
                        <div class="node-meta">
                          <span>{node.addr}</span>
                          <span>{t("overview.catchingUp")}</span>
                        </div>
                      </div>
                    </article>
                  )}
                </For>
              </div>
            </section>
          )}

          {/* Footer */}
          <footer class="footer">
            <span>
              <strong>{t("overview.lastUpdated")}</strong>{" "}
              {lastUpdated() ? formatAgo(lastUpdated()! / 1000) : "—"}
            </span>
            <span>{t("overview.footer")}</span>
          </footer>
        </>
      )}
    </>
  );
}
