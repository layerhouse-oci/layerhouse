import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import type { RouteSectionProps } from "@solidjs/router";
import {
  ApiError,
  deletePolicySet,
  fetchPolicySets,
  fetchSession,
  putPolicySet,
  redirectToSignIn,
  validatePolicySet,
} from "../lib/api";
import type { DashboardSession, PolicySet } from "../lib/types";
import { formatAgo } from "../lib/format";
import { t } from "../lib/i18n";
import EmptyState from "../components/EmptyState";
import ErrorBanner from "../components/ErrorBanner";
import LoadingSpinner from "../components/LoadingSpinner";

interface PolicyForm {
  id: string;
  name: string;
  cedar_text: string;
  enabled: boolean;
}

type ValidationStatus = "idle" | "validating" | "valid" | "invalid";

interface ValidationState {
  status: ValidationStatus;
  message: string | null;
}

const DEFAULT_CEDAR = `permit(
    principal in Group::"test:group:550e8400-e29b-41d4-a716-446655440000",
    action == Action::"pull",
    resource in Namespace::"acme#1"
);`;

const EMPTY_FORM: PolicyForm = {
  id: "",
  name: "",
  cedar_text: DEFAULT_CEDAR,
  enabled: true,
};

function policyForm(policy: PolicySet): PolicyForm {
  return {
    id: policy.id,
    name: policy.name,
    cedar_text: policy.cedar_text,
    enabled: policy.enabled,
  };
}

function sourceLabel(source: PolicySet["source"]) {
  return t(`admin.policySource.${source}`);
}

function policyEditable(policy: PolicySet): boolean {
  return policy.editable ?? policy.source === "raft";
}

type PoliciesProps = { embedded?: boolean } & Partial<RouteSectionProps>;

export default function Policies(props: PoliciesProps = {}) {
  const [session, setSession] = createSignal<DashboardSession | null>(null);
  const [policies, setPolicies] = createSignal<PolicySet[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [errorCount, setErrorCount] = createSignal(0);
  const [showForm, setShowForm] = createSignal(false);
  const [editingId, setEditingId] = createSignal<string | null>(null);
  const [form, setForm] = createSignal<PolicyForm>({ ...EMPTY_FORM });
  const [validation, setValidation] = createSignal<ValidationState>({
    status: "idle",
    message: null,
  });
  const [saving, setSaving] = createSignal(false);
  const [deleteTarget, setDeleteTarget] = createSignal<PolicySet | null>(null);

  async function load() {
    try {
      const [s, p] = await Promise.all([fetchSession(), fetchPolicySets()]);
      setSession(s);
      setPolicies(p);
      setError(null);
      setErrorCount(0);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        redirectToSignIn();
        return;
      }
      if (e instanceof ApiError && e.status === 403) {
        setError(t("cluster.adminRequired"));
        setErrorCount(0);
        setPolicies([]);
      } else {
        setError(e instanceof Error ? e.message : t("policies.fetchError"));
        setErrorCount((count) => count + 1);
      }
    } finally {
      setLoading(false);
    }
  }

  createEffect(() => {
    load();
    const id = setInterval(load, 15_000);
    onCleanup(() => clearInterval(id));
  });

  function createPolicy() {
    setEditingId(null);
    setForm({ ...EMPTY_FORM });
    setValidation({ status: "idle", message: null });
    setShowForm(true);
  }

  function editPolicy(policy: PolicySet) {
    setEditingId(policy.id);
    setForm(policyForm(policy));
    setValidation({ status: "idle", message: null });
    setShowForm(true);
  }

  function updateForm(next: PolicyForm) {
    setForm(next);
    setValidation({ status: "idle", message: null });
  }

  async function validateCurrentPolicy(): Promise<boolean> {
    const current = form();
    if (!current.cedar_text.trim()) {
      setValidation({ status: "invalid", message: t("policies.validationRequired") });
      return false;
    }

    setValidation({ status: "validating", message: t("policies.validating") });
    try {
      const result = await validatePolicySet({ cedar_text: current.cedar_text });
      if (result.valid) {
        setValidation({ status: "valid", message: t("policies.validationValid") });
        return true;
      }
      setValidation({
        status: "invalid",
        message: result.error || t("policies.validationInvalid"),
      });
      return false;
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        redirectToSignIn();
        return false;
      }
      setValidation({
        status: "invalid",
        message: e instanceof Error ? e.message : t("policies.validationError"),
      });
      return false;
    }
  }

  async function save() {
    const current = form();
    const id = editingId() ?? current.id.trim();
    if (!id || !current.name.trim() || !current.cedar_text.trim()) {
      setError(t("policies.required"));
      return;
    }

    setSaving(true);
    try {
      if (!(await validateCurrentPolicy())) return;
      await putPolicySet(id, {
        name: current.name.trim(),
        cedar_text: current.cedar_text,
        enabled: current.enabled,
      });
      setShowForm(false);
      setEditingId(null);
      setForm({ ...EMPTY_FORM });
      setValidation({ status: "idle", message: null });
      await load();
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        setError(t("cluster.adminRequired"));
      } else {
        setError(e instanceof Error ? e.message : t("policies.saveError"));
      }
    } finally {
      setSaving(false);
    }
  }

  async function confirmDelete() {
    const target = deleteTarget();
    if (!target) return;
    try {
      await deletePolicySet(target.id);
      setDeleteTarget(null);
      await load();
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        setError(t("cluster.adminRequired"));
      } else {
        setError(e instanceof Error ? e.message : t("policies.deleteError"));
      }
    }
  }

  if (errorCount() >= 3) {
    return <ErrorBanner message={error() ?? t("common.unknown")} onRetry={load} fullPage />;
  }

  return (
    <div classList={{ "policy-page": true, "policy-page-embedded": !!props.embedded }}>
      <Show when={!props.embedded}>
        <section class="hero glass">
          <div>
            <p class="eyebrow">
              <span class="status-dot" aria-hidden="true" />
              {t("policies.eyebrow")}
            </p>
            <h1>{t("policies.title")}</h1>
            <p class="hero-copy">{t("policies.heroCopy")}</p>
          </div>
        </section>
      </Show>

      <Show when={error()}>
        <ErrorBanner message={error()!} onRetry={load} />
      </Show>

      <section class="policy-board">
        <div class="policy-summary glass">
          <span>{t("policies.enabled")}</span>
          <strong>{policies().filter((policy) => policy.enabled).length}</strong>
        </div>
        <div class="policy-summary glass">
          <span>{t("policies.disabled")}</span>
          <strong>{policies().filter((policy) => !policy.enabled).length}</strong>
        </div>
        <div class="policy-summary glass">
          <span>{t("policies.total")}</span>
          <strong>{policies().length}</strong>
        </div>
      </section>

      <section class="panel glass">
        <div class="panel-head">
          <div>
            <p class="section-label">{t("policies.catalog")}</p>
            <h2 class="panel-title">{t("policies.policySets")}</h2>
          </div>
          <Show when={session()?.is_admin}>
            <button class="button" onClick={createPolicy}>
              {t("policies.create")}
            </button>
          </Show>
        </div>

        <Show
          when={!loading()}
          fallback={
            <div class="policy-empty-wrap">
              <LoadingSpinner label={t("policies.loading")} />
            </div>
          }
        >
          <Show
            when={policies().length > 0}
            fallback={
              <div class="policy-empty-wrap">
                <EmptyState title={t("policies.empty")} description={t("policies.emptyDesc")} />
              </div>
            }
          >
            <div class="table-wrap">
              <table aria-label={t("policies.policySets")}>
                <thead>
                  <tr>
                    <th scope="col">{t("common.id")}</th>
                    <th scope="col">{t("common.status")}</th>
                    <th scope="col">{t("policies.source")}</th>
                    <th scope="col">{t("common.updated")}</th>
                    <th scope="col">{t("common.actions")}</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={policies()}>
                    {(policy) => (
                      <tr>
                        <td>
                          <div class="policy-name-stack">
                            <strong>{policy.name}</strong>
                            <span class="mono">{policy.id}</span>
                          </div>
                        </td>
                        <td>
                          <span classList={{ state: true, active: policy.enabled }}>
                            {policy.enabled ? t("policies.enabled") : t("policies.disabled")}
                          </span>
                        </td>
                        <td>
                          <span class="source-badge">{sourceLabel(policy.source)}</span>
                        </td>
                        <td class="mono">{formatAgo(policy.updated_at)}</td>
                        <td>
                          <Show when={session()?.is_admin && policyEditable(policy)}>
                            <div class="actions">
                              <button class="action primary" onClick={() => editPolicy(policy)}>
                                {t("common.edit")}
                              </button>
                              <button class="action remove" onClick={() => setDeleteTarget(policy)}>
                                {t("common.delete")}
                              </button>
                            </div>
                          </Show>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
        </Show>
      </section>

      <Show when={showForm()}>
        <section class="panel glass policy-form-panel">
          <div class="panel-head">
            <div>
              <p class="section-label">{t("policies.editor")}</p>
              <h2 class="panel-title">{form().id ? form().id : t("policies.newPolicy")}</h2>
            </div>
            <button
              class="action secondary"
              onClick={() => {
                setShowForm(false);
                setEditingId(null);
              }}
            >
              {t("common.cancel")}
            </button>
          </div>
          <div class="form">
            <label class="field">
              <span>{t("common.id")}</span>
              <input
                value={form().id}
                disabled={editingId() !== null}
                placeholder="team-readers"
                onInput={(event) => updateForm({ ...form(), id: event.currentTarget.value })}
              />
            </label>
            <label class="field">
              <span>{t("policies.name")}</span>
              <input
                value={form().name}
                placeholder="Team readers"
                onInput={(event) => updateForm({ ...form(), name: event.currentTarget.value })}
              />
            </label>
            <label class="field field-toggle">
              <span>{t("common.status")}</span>
              <select
                value={form().enabled ? "enabled" : "disabled"}
                onChange={(event) =>
                  updateForm({ ...form(), enabled: event.currentTarget.value === "enabled" })
                }
              >
                <option value="enabled">{t("policies.enabled")}</option>
                <option value="disabled">{t("policies.disabled")}</option>
              </select>
            </label>
            <label class="field full cedar-field">
              <span>{t("policies.cedarText")}</span>
              <textarea
                spellcheck={false}
                value={form().cedar_text}
                onInput={(event) =>
                  updateForm({ ...form(), cedar_text: event.currentTarget.value })
                }
              />
            </label>
          </div>
          <p class="policy-hint">{t("policies.validationHint")}</p>
          <Show when={validation().status !== "idle"}>
            <p
              class="policy-validation"
              classList={{
                valid: validation().status === "valid",
                invalid: validation().status === "invalid",
              }}
            >
              {validation().message}
            </p>
          </Show>
          <div class="form-actions">
            <button
              class="action secondary"
              disabled={saving() || validation().status === "validating"}
              onClick={validateCurrentPolicy}
            >
              {validation().status === "validating"
                ? t("policies.validating")
                : t("policies.validate")}
            </button>
            <button class="button" disabled={saving()} onClick={save}>
              {saving() ? t("common.saving") : t("common.save")}
            </button>
          </div>
        </section>
      </Show>

      <Show when={deleteTarget()}>
        {(target) => (
          <div class="modal-backdrop" role="presentation">
            <div class="modal-card glass" role="dialog" aria-modal="true">
              <p class="eyebrow">{t("policies.deleteEyebrow")}</p>
              <h3>{t("policies.deleteTitle", { id: target().id })}</h3>
              <p>{t("policies.deleteWarning")}</p>
              <div class="modal-actions">
                <button class="action secondary" onClick={() => setDeleteTarget(null)}>
                  {t("common.cancel")}
                </button>
                <button class="action danger" onClick={confirmDelete}>
                  {t("common.delete")}
                </button>
              </div>
            </div>
          </div>
        )}
      </Show>
    </div>
  );
}
