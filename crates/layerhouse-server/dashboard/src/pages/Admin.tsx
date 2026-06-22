import { A } from "@solidjs/router";
import { createEffect, createSignal, Show } from "solid-js";
import EmptyState from "../components/EmptyState";
import ErrorBanner from "../components/ErrorBanner";
import LoadingSpinner from "../components/LoadingSpinner";
import { fetchSession, redirectToSignIn } from "../lib/api";
import { t } from "../lib/i18n";
import type { DashboardSession } from "../lib/types";
import Access from "./Access";
import Policies from "./Policies";

type AdminTab = "namespaces" | "policies";

export default function Admin() {
  const [session, setSession] = createSignal<DashboardSession | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [tab, setTab] = createSignal<AdminTab>("namespaces");

  createEffect(() => {
    fetchSession()
      .then((next) => {
        setSession(next);
        setError(null);
      })
      .catch((e) => setError(e instanceof Error ? e.message : t("admin.fetchError")))
      .finally(() => setLoading(false));
  });

  return (
    <div class="admin-page">
      <section class="hero glass admin-hero">
        <div>
          <p class="eyebrow">
            <span class="status-dot" aria-hidden="true" />
            {t("admin.eyebrow")}
          </p>
          <h1>{t("admin.title")}</h1>
          <p class="hero-copy">{t("admin.copy")}</p>
        </div>
      </section>

      <Show when={error()}>
        <ErrorBanner message={error()!} onRetry={() => window.location.reload()} />
      </Show>

      <Show when={!loading()} fallback={<LoadingSpinner label={t("admin.loading")} />}>
        <Show
          when={session()?.auth_enabled !== false}
          fallback={
            <section class="admin-open-mode glass">
              <div>
                <p class="eyebrow">{t("admin.authDisabledEyebrow")}</p>
                <h2>{t("admin.authDisabledTitle")}</h2>
                <p>{t("admin.authDisabledDesc")}</p>
              </div>
              <div class="admin-mode-grid">
                <div>
                  <span>{t("admin.openModeRepos")}</span>
                  <strong>{t("admin.openModeReposValue")}</strong>
                </div>
                <div>
                  <span>{t("admin.openModeTokens")}</span>
                  <strong>{t("admin.openModeTokensValue")}</strong>
                </div>
                <div>
                  <span>{t("admin.openModePolicies")}</span>
                  <strong>{t("admin.openModePoliciesValue")}</strong>
                </div>
              </div>
              <div class="admin-actions">
                <A class="button" href="/repos">
                  {t("admin.viewOpenRegistry")}
                </A>
              </div>
            </section>
          }
        >
          <Show
            when={session()?.subject}
            fallback={
              <section class="access-signin card">
                <div>
                  <p class="eyebrow">{t("access.signIn")}</p>
                  <h2>{t("admin.signInTitle")}</h2>
                  <p>{t("admin.signInDesc")}</p>
                </div>
                <button type="button" class="btn btn-primary" onClick={redirectToSignIn}>
                  {t("access.signInWithOidc")}
                </button>
              </section>
            }
          >
            <Show
              when={session()?.is_admin}
              fallback={
                <div class="card">
                  <EmptyState
                    title={t("admin.requiredTitle")}
                    description={t("admin.requiredDesc")}
                  />
                </div>
              }
            >
              <div class="admin-tabs" role="tablist" aria-label={t("admin.tabs")}>
                <button
                  class={tab() === "namespaces" ? "active" : ""}
                  type="button"
                  onClick={() => setTab("namespaces")}
                >
                  {t("admin.namespaces")}
                </button>
                <button
                  class={tab() === "policies" ? "active" : ""}
                  type="button"
                  onClick={() => setTab("policies")}
                >
                  {t("admin.policies")}
                </button>
              </div>

              <Show when={tab() === "namespaces"}>
                <Access mode="admin" />
              </Show>
              <Show when={tab() === "policies"}>
                <Policies embedded />
              </Show>
            </Show>
          </Show>
        </Show>
      </Show>
    </div>
  );
}
