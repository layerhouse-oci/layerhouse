import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import { fetchWarmImages, createWarmImage, deleteWarmImage } from "../lib/api";
import type { WarmImage } from "../lib/types";
import LoadingSpinner from "../components/LoadingSpinner";
import EmptyState from "../components/EmptyState";
import ErrorBanner from "../components/ErrorBanner";

const EMPTY_FORM: WarmImage = {
  id: "",
  image: "",
  tags: [],
  interval_secs: 3600,
};

export default function WarmImages() {
  const [images, setImages] = createSignal<WarmImage[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [errorCount, setErrorCount] = createSignal(0);
  const [showForm, setShowForm] = createSignal(false);
  const [form, setForm] = createSignal<WarmImage>({ ...EMPTY_FORM });
  const [tagsInput, setTagsInput] = createSignal("");
  const [saving, setSaving] = createSignal(false);

  async function load() {
    try {
      setImages(await fetchWarmImages());
      setError(null);
      setErrorCount(0);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch warm images");
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
      await createWarmImage(form());
      setShowForm(false);
      setForm({ ...EMPTY_FORM });
      setTagsInput("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save warm image");
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: string) {
    if (!confirm(`Delete warm image "${id}"?`)) return;
    try {
      await deleteWarmImage(id);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete warm image");
    }
  }

  if (errorCount() >= 3) {
    return <ErrorBanner message={error() ?? "Unknown error"} onRetry={load} fullPage />;
  }

  return (
    <div>
      <div class="page-header">
        <h1>Warm Images</h1>
        <button
          class="btn btn-primary"
          onClick={() => {
            setForm({ ...EMPTY_FORM });
            setTagsInput("");
            setShowForm(true);
          }}
        >
          Add Image
        </button>
      </div>

      {error() && <ErrorBanner message={error()!} onRetry={load} />}

      {loading() ? (
        <LoadingSpinner label="Loading warm images..." />
      ) : images().length === 0 ? (
        <EmptyState
          title="No warm images"
          description="Add an image to keep its tags pre-warmed in cache."
        />
      ) : (
        <div class="card">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Image</th>
                <th>Tags</th>
                <th>Interval (s)</th>
                <th />
              </tr>
            </thead>
            <tbody>
              <For each={images()}>
                {(img) => (
                  <tr>
                    <td>
                      <code>{img.id}</code>
                    </td>
                    <td>{img.image}</td>
                    <td>
                      <code>{img.tags.join(", ")}</code>
                    </td>
                    <td>{img.interval_secs}</td>
                    <td>
                      <button class="btn btn-danger" onClick={() => handleDelete(img.id)}>
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
            <h2>Add Warm Image</h2>
            <div class="form-group">
              <label>ID</label>
              <input
                type="text"
                value={form().id}
                onInput={(e) => setForm({ ...form(), id: e.currentTarget.value })}
              />
            </div>
            <div class="form-group">
              <label>Image</label>
              <input
                type="text"
                value={form().image}
                onInput={(e) => setForm({ ...form(), image: e.currentTarget.value })}
              />
            </div>
            <div class="form-group">
              <label>Tags (comma-separated)</label>
              <input
                type="text"
                value={tagsInput()}
                onInput={(e) => {
                  setTagsInput(e.currentTarget.value);
                  setForm({
                    ...form(),
                    tags: e.currentTarget.value
                      .split(",")
                      .map((t) => t.trim())
                      .filter(Boolean),
                  });
                }}
              />
            </div>
            <div class="form-group">
              <label>Interval (seconds)</label>
              <input
                type="number"
                value={form().interval_secs}
                onInput={(e) =>
                  setForm({
                    ...form(),
                    interval_secs: parseInt(e.currentTarget.value) || 3600,
                  })
                }
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
