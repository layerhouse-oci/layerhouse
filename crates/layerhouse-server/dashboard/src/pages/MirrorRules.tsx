import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import { fetchMirrorRules, createMirrorRule, deleteMirrorRule } from "../lib/api";
import type { MirrorRule, MirrorRuleCreate } from "../lib/types";
import { normalizeOptionalPrefix, normalizeRegistry, prefixLabel } from "../lib/format";
import LoadingSpinner from "../components/LoadingSpinner";
import EmptyState from "../components/EmptyState";
import ErrorBanner from "../components/ErrorBanner";

const EMPTY_FORM: MirrorRuleCreate & { username?: string; password?: string } = {
  id: "",
  direction: "pull",
  local_prefix: "",
  upstream_registry: "",
  upstream_prefix: "",
  strategy: { type: "all" },
  plain_http: false,
  insecure_tls: false,
  username: "",
  password: "",
};

export default function MirrorRules() {
  const [rules, setRules] = createSignal<MirrorRule[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [errorCount, setErrorCount] = createSignal(0);
  const [showForm, setShowForm] = createSignal(false);
  const [editId, setEditId] = createSignal<string | null>(null);
  const [form, setForm] = createSignal({ ...EMPTY_FORM });
  const [saving, setSaving] = createSignal(false);

  async function load() {
    try {
      setRules(await fetchMirrorRules());
      setError(null);
      setErrorCount(0);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch mirror rules");
      setErrorCount((c) => c + 1);
    } finally {
      setLoading(false);
    }
  }

  createEffect(() => {
    load();
    const id = setInterval(load, 15_000);
    onCleanup(() => clearInterval(id));
  });

  async function handleSave() {
    setSaving(true);
    try {
      const f = form();
      await createMirrorRule({
        id: f.id,
        direction: f.direction,
        local_prefix: f.local_prefix,
        upstream_registry: normalizeRegistry(f.upstream_registry),
        upstream_prefix: normalizeOptionalPrefix(f.upstream_prefix),
        strategy: f.strategy,
        plain_http: f.plain_http,
        insecure_tls: f.insecure_tls,
        username: f.username || undefined,
        password: f.password || undefined,
      });
      setShowForm(false);
      setEditId(null);
      setForm({ ...EMPTY_FORM });
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save rule");
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: string) {
    if (!confirm(`Delete mirror rule "${id}"?`)) return;
    try {
      await deleteMirrorRule(id);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete rule");
    }
  }

  function editRule(r: MirrorRule) {
    setForm({
      id: r.id,
      direction: r.direction,
      local_prefix: r.local_prefix,
      upstream_registry: r.upstream_registry,
      upstream_prefix: r.upstream_prefix ?? "",
      schedule: r.schedule,
      strategy: r.strategy,
      outbound_proxy: { protocol: r.outbound_proxy.protocol },
      plain_http: r.plain_http,
      insecure_tls: r.insecure_tls,
      username: "",
      password: "",
    });
    setEditId(r.id);
    setShowForm(true);
  }

  if (errorCount() >= 3) {
    return <ErrorBanner message={error() ?? "Unknown error"} onRetry={load} fullPage />;
  }

  return (
    <div>
      <div class="page-header">
        <h1>Mirror Rules</h1>
        <button
          class="btn btn-primary"
          onClick={() => {
            setEditId(null);
            setForm({ ...EMPTY_FORM });
            setShowForm(true);
          }}
        >
          Add Rule
        </button>
      </div>

      {error() && <ErrorBanner message={error()!} onRetry={load} />}

      {loading() ? (
        <LoadingSpinner label="Loading mirror rules..." />
      ) : rules().length === 0 ? (
        <EmptyState
          title="No mirror rules"
          description="Add a mirror rule to sync images from an upstream registry."
        />
      ) : (
        <div class="card">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Local Prefix</th>
                <th>Upstream</th>
                <th>Upstream Prefix</th>
                <th>HTTP</th>
                <th />
              </tr>
            </thead>
            <tbody>
              <For each={rules()}>
                {(rule) => (
                  <tr>
                    <td>
                      <code>{rule.id}</code>
                    </td>
                    <td>{rule.local_prefix}</td>
                    <td>{rule.upstream_registry}</td>
                    <td>{prefixLabel(rule.upstream_prefix)}</td>
                    <td>
                      {rule.plain_http ? "Plain" : rule.insecure_tls ? "Insecure TLS" : "TLS"}
                    </td>
                    <td>
                      <button class="btn" onClick={() => editRule(rule)}>
                        Edit
                      </button>{" "}
                      <button class="btn btn-danger" onClick={() => handleDelete(rule.id)}>
                        Delete
                      </button>
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
      )}

      <Show when={showForm()}>
        <div class="modal-overlay" onClick={() => setShowForm(false)}>
          <div class="modal" onClick={(e) => e.stopPropagation()}>
            <h2>{editId() ? "Edit Rule" : "Add Rule"}</h2>
            <div class="form-group">
              <label>ID</label>
              <input
                type="text"
                value={form().id}
                disabled={!!editId()}
                onInput={(e) => setForm({ ...form(), id: e.currentTarget.value })}
              />
            </div>
            <div class="form-group">
              <label>Local Prefix</label>
              <input
                type="text"
                value={form().local_prefix}
                onInput={(e) => setForm({ ...form(), local_prefix: e.currentTarget.value })}
              />
            </div>
            <div class="form-group">
              <label>Upstream Registry</label>
              <input
                type="text"
                value={form().upstream_registry}
                onInput={(e) =>
                  setForm({
                    ...form(),
                    upstream_registry: e.currentTarget.value,
                  })
                }
              />
            </div>
            <div class="form-group">
              <label>Upstream Prefix (optional)</label>
              <input
                type="text"
                value={form().upstream_prefix ?? ""}
                onInput={(e) =>
                  setForm({
                    ...form(),
                    upstream_prefix: e.currentTarget.value,
                  })
                }
              />
            </div>
            <div class="form-group">
              <label>
                <input
                  type="checkbox"
                  checked={form().plain_http}
                  onChange={(e) =>
                    setForm({
                      ...form(),
                      plain_http: e.currentTarget.checked,
                      insecure_tls: e.currentTarget.checked ? false : form().insecure_tls,
                    })
                  }
                />{" "}
                Plain HTTP
              </label>
            </div>
            <div class="form-group">
              <label>
                <input
                  type="checkbox"
                  checked={form().insecure_tls}
                  onChange={(e) =>
                    setForm({
                      ...form(),
                      insecure_tls: e.currentTarget.checked,
                      plain_http: e.currentTarget.checked ? false : form().plain_http,
                    })
                  }
                />{" "}
                Insecure TLS
              </label>
            </div>
            <div class="form-group">
              <label>Username (optional)</label>
              <input
                type="text"
                value={form().username ?? ""}
                autocomplete="off"
                onInput={(e) => setForm({ ...form(), username: e.currentTarget.value })}
              />
            </div>
            <div class="form-group">
              <label>Password (optional, write-only)</label>
              <input
                type="password"
                value={form().password ?? ""}
                autocomplete="new-password"
                onInput={(e) => setForm({ ...form(), password: e.currentTarget.value })}
              />
            </div>
            <div class="modal-actions">
              <button class="btn" onClick={() => setShowForm(false)}>
                Cancel
              </button>
              <button class="btn btn-primary" disabled={saving()} onClick={handleSave}>
                {saving() ? "Saving..." : "Save"}
              </button>
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
}
